use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use log::{debug, error, info, warn};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use tokio_tungstenite::accept_hdr_async_with_config;
use tokio_tungstenite::tungstenite::http::{Request, Response};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::bridge::BridgeManager;
use crate::config::Config;
use crate::handler::{handle_connection, RequestData};
use crate::tls;

pub async fn run_server(config: Arc<Config>) {
    let ws_addr = format!("{}:{}", config.ws_host, config.ws_port);
    let ws_listener = match TcpListener::bind(&ws_addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind WebSocket server to {}: {}", ws_addr, e);
            return;
        }
    };
    info!("WebSocket server listening on {}", ws_addr);

    let tcp_addr = format!("{}:{}", config.tcp_bind, config.tcp_port);
    let tcp_listener = match TcpListener::bind(&tcp_addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind TCP bridge server to {}: {}", tcp_addr, e);
            return;
        }
    };
    info!("TCP bridge server listening on {}", tcp_addr);

    let domains = vec![format!("{}:{}", config.ws_host, config.ws_port)];

    let tls_config: Option<tls::TlsConfig> = match config.to_tls_config() {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("Invalid TLS configuration: {}", e);
            return;
        }
    };

    let tls_acceptor = match tls_config.as_ref() {
        Some(cfg) => match cfg.build(&domains).await {
            Ok(a) => {
                info!("WSS (TLS) enabled on {}", ws_addr);
                Some(a)
            }
            Err(e) => {
                error!("Failed to initialize TLS: {}", e);
                return;
            }
        },
        None => None,
    };

    if tls_acceptor.is_none() {
        info!("WS (plain) enabled on {}", ws_addr);
    }

    let conn_semaphore = Arc::new(Semaphore::new(config.max_connections));
    let proc_semaphore = Arc::new(Semaphore::new(config.max_processes));

    let shared_acceptor: Arc<std::sync::Mutex<Option<tls::TlsAcceptor>>> =
        Arc::new(std::sync::Mutex::new(tls_acceptor));

    let (shutdown_tx, _shutdown_rx) = tokio::sync::watch::channel(false);

    if let Some(ref cfg) = tls_config {
        if matches!(cfg.mode, tls::TlsMode::Automate) {
            let cfg = Arc::new(cfg.clone());
            let doms = domains.clone();
            let acceptor = shared_acceptor.clone();
            let rx = shutdown_tx.subscribe();
            tokio::spawn(tls::setup_acme_renewal(cfg, doms, acceptor, rx));
        }
    }

    let bridge_manager = BridgeManager::new();

    // Spawn TCP bridge accept loop
    let tcp_bridge = bridge_manager.clone();
    let tcp_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        run_tcp_bridge(tcp_listener, tcp_bridge, tcp_shutdown).await;
    });

    let active_connections: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));

    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            result = ws_listener.accept() => {
                match result {
                    Ok((stream, peer_addr)) => {
                        let permit = match conn_semaphore.clone().try_acquire_owned() {
                            Ok(p) => p,
                            Err(_) => {
                                warn!(
                                    "Connection from {} rejected: max connections ({}) reached",
                                    peer_addr, config.max_connections
                                );
                                drop(stream);
                                continue;
                            }
                        };

                        let config = config.clone();
                        let proc_sem = proc_semaphore.clone();
                        let server_addr = stream.local_addr().ok();
                        let active = active_connections.clone();
                        let bridge = bridge_manager.clone();

                        active.fetch_add(1, Ordering::Release);

                        let has_tls = {
                            let guard = shared_acceptor.lock().unwrap();
                            guard.is_some()
                        };

                        if has_tls {
                            let acceptor = shared_acceptor.clone();
                            tokio::spawn(async move {
                                let tls_acceptor = {
                                    let guard = acceptor.lock().unwrap();
                                    guard.clone()
                                };
                                if let Some(acceptor) = tls_acceptor {
                                    match acceptor.accept(stream).await {
                                        Ok(tls_stream) => {
                                            handle_tcp_stream(
                                                tls_stream, peer_addr, server_addr,
                                                config, proc_sem, bridge,
                                            ).await;
                                        }
                                        Err(e) => {
                                            error!("TLS handshake failed for {}: {}", peer_addr, e);
                                        }
                                    }
                                } else {
                                    handle_tcp_stream(
                                        stream, peer_addr, server_addr,
                                        config, proc_sem, bridge,
                                    ).await;
                                }
                                drop(permit);
                                active.fetch_sub(1, Ordering::Release);
                            });
                        } else {
                            tokio::spawn(async move {
                                handle_tcp_stream(
                                    stream, peer_addr, server_addr,
                                    config, proc_sem, bridge,
                                ).await;
                                drop(permit);
                                active.fetch_sub(1, Ordering::Release);
                            });
                        }
                    }
                    Err(e) => {
                        error!("Error accepting connection: {}", e);
                    }
                }
            }
            _ = &mut shutdown => {
                info!("Shutdown signal received, stopping server");
                break;
            }
        }
    }

    let _ = shutdown_tx.send(true);

    let active = active_connections.load(Ordering::Acquire);
    if active > 0 {
        info!(
            "Waiting for {} active connection(s) to finish (30s timeout)...",
            active
        );
        let deadline = tokio::time::sleep(Duration::from_secs(30));
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = &mut deadline => {
                    warn!(
                        "Drain timeout reached, {} connection(s) still active. Forcing shutdown.",
                        active_connections.load(Ordering::Acquire)
                    );
                    break;
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    if active_connections.load(Ordering::Acquire) == 0 {
                        info!("All connections drained gracefully");
                        break;
                    }
                }
            }
        }
    }

    info!("Server stopped");
}

async fn run_tcp_bridge(
    listener: TcpListener,
    bridge_manager: Arc<BridgeManager>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, peer_addr)) => {
                        tokio::spawn(handle_php_connection(stream, peer_addr, bridge_manager.clone()));
                    }
                    Err(e) => {
                        error!("TCP bridge accept error: {}", e);
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                info!("TCP bridge server shutting down");
                break;
            }
        }
    }
}

async fn handle_php_connection(
    mut stream: tokio::net::TcpStream,
    peer_addr: std::net::SocketAddr,
    bridge_manager: Arc<BridgeManager>,
) {
    let read_id = async {
        let mut buf = [0u8; 1];
        let mut conn_id = String::with_capacity(36);
        loop {
            match stream.read(&mut buf).await {
                Ok(0) => return None,
                Ok(_) => {
                    if buf[0] == b'\n' {
                        break;
                    }
                    if conn_id.len() >= 64 {
                        return None;
                    }
                    conn_id.push(buf[0] as char);
                }
                Err(_) => return None,
            }
        }
        Some(conn_id)
    };

    let conn_id = match tokio::time::timeout(Duration::from_secs(10), read_id).await {
        Ok(Some(id)) => id,
        _ => {
            debug!(
                "PHP connection {} failed to send valid connection ID",
                peer_addr
            );
            return;
        }
    };

    debug!(
        "PHP connection {} identified as bridge {}",
        peer_addr, conn_id
    );

    if !bridge_manager.resolve(&conn_id, stream).await {
        warn!(
            "PHP connection {}: no pending bridge for connection ID {}",
            peer_addr, conn_id
        );
    }
}

#[allow(clippy::result_large_err)]
async fn handle_tcp_stream<S>(
    stream: S,
    peer_addr: std::net::SocketAddr,
    server_addr: Option<std::net::SocketAddr>,
    config: Arc<Config>,
    proc_semaphore: Arc<Semaphore>,
    bridge_manager: Arc<BridgeManager>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let ws_config = WebSocketConfig {
        max_message_size: if config.max_payload_size > 0 {
            Some(config.max_payload_size)
        } else {
            None
        },
        write_buffer_size: config.write_buffer_size,
        max_write_buffer_size: config.max_write_buffer,
        ..Default::default()
    };

    let mut request_data: Option<RequestData> = None;

    let ws_stream = accept_hdr_async_with_config(
        stream,
        |req: &Request<()>, res: Response<()>| {
            let mut data = RequestData {
                uri: req.uri().to_string(),
                ..Default::default()
            };
            for (key, value) in req.headers() {
                if let Ok(v) = value.to_str() {
                    data.headers.insert(key.to_string(), v.to_string());
                }
            }
            request_data = Some(data);
            Ok(res)
        },
        Some(ws_config),
    )
    .await;

    match ws_stream {
        Ok(ws) => {
            let data = request_data.take().unwrap_or_default();
            handle_connection(
                ws,
                peer_addr,
                server_addr,
                data,
                config,
                proc_semaphore,
                bridge_manager,
            )
            .await;
        }
        Err(e) => {
            error!("WebSocket handshake failed for {}: {}", peer_addr, e);
        }
    }
}
