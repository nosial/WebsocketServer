use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use log::{debug, error, info, warn};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, Semaphore};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use uuid::Uuid;

use crate::bridge::BridgeManager;
use crate::config::Config;
use crate::php;

#[derive(Default)]
pub struct RequestData {
    pub uri: String,
    pub headers: HashMap<String, String>,
}

type SharedWsWriter<S> =
    Arc<Mutex<futures_util::stream::SplitSink<WebSocketStream<S>, Message>>>;

pub async fn handle_connection<S>(
    ws_stream: WebSocketStream<S>,
    client_addr: std::net::SocketAddr,
    server_addr: Option<std::net::SocketAddr>,
    request: RequestData,
    config: Arc<Config>,
    proc_semaphore: Arc<Semaphore>,
    bridge_manager: Arc<BridgeManager>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let conn_id = Uuid::new_v4().to_string();

    let _proc_permit = match proc_semaphore.try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            warn!(
                "Connection {}: max PHP processes reached, rejecting",
                conn_id
            );
            return;
        }
    };

    debug!(
        "Connection {}: new WebSocket connection from {}",
        conn_id, client_addr
    );

    // Register pending bridge before spawning PHP
    let tcp_rx = bridge_manager.register(conn_id.clone()).await;

    let env_vars = build_env_vars(&conn_id, &client_addr, &server_addr, &request, &config);

    let php_config = php::PhpConfig {
        executable: config.php_executable.clone(),
        script: config.script.clone(),
        arguments: config.php_args.clone(),
        capture_stdout: !config.ignore_stdout,
    };

    let proc =
        spawn_php_with_retry(&php_config, env_vars, config.php_connect_retries, &conn_id).await;
    let (child, php_stdout) = match proc {
        Some(p) => {
            let stdout = p.stdout;
            (Arc::new(Mutex::new(Some(p.child))), stdout)
        }
        None => {
            error!(
                "Connection {}: failed to spawn PHP process after retries",
                conn_id
            );
            bridge_manager.remove(&conn_id).await;
            return;
        }
    };

    let tcp_stream =
        match tokio::time::timeout(Duration::from_secs(config.php_connect_timeout), tcp_rx).await {
            Ok(Ok(stream)) => {
                info!("Connection {}: PHP process connected", conn_id);
                stream
            }
            Ok(Err(_)) => {
                error!("Connection {}: bridge receiver cancelled", conn_id);
                cleanup_child(&child).await;
                return;
            }
            Err(_) => {
                warn!(
                    "Connection {}: PHP did not connect within {}s",
                    conn_id, config.php_connect_timeout
                );
                bridge_manager.remove(&conn_id).await;
                cleanup_child(&child).await;
                return;
            }
        };

    let (tcp_reader, tcp_writer) = tcp_stream.into_split();
    let (ws_writer, ws_reader) = ws_stream.split();

    let ws_writer: SharedWsWriter<S> = Arc::new(Mutex::new(ws_writer));

    let child_monitor = {
        let child = child.clone();
        async move {
            let mut guard = child.lock().await;
            if let Some(ref mut c) = *guard {
                let _ = c.wait().await;
            }
        }
    };

    let fwd_ws = forward_ws_to_tcp(ws_reader, tcp_writer, config.buffer_size);
    let fwd_tcp = forward_tcp_to_ws(tcp_reader, ws_writer.clone(), config.buffer_size);
    let mut fwd_stdout = php_stdout.map(|s| Box::pin(forward_stdout_to_ws(s, ws_writer, config.buffer_size)));
    let mut child_monitor = Box::pin(child_monitor);

    let mut conn_timeout = if config.connection_timeout > 0 {
        Some(Box::pin(tokio::time::sleep(Duration::from_secs(
            config.connection_timeout,
        ))))
    } else {
        None
    };

    let mut php_timeout = if config.php_timeout > 0 {
        Some(Box::pin(tokio::time::sleep(Duration::from_secs(
            config.php_timeout,
        ))))
    } else {
        None
    };

    tokio::pin!(fwd_ws, fwd_tcp);

    tokio::select! {
        _ = &mut fwd_ws => {},
        _ = &mut fwd_tcp => {},
        _ = async { if let Some(ref mut f) = fwd_stdout { f.await } else { std::future::pending::<()>().await } } => {},
        _ = &mut child_monitor => {},
        _ = async { if let Some(ref mut f) = conn_timeout { f.as_mut().await; debug!("Connection {}: connection timeout reached", conn_id); } else { std::future::pending::<()>().await; } } => {},
        _ = async { if let Some(ref mut f) = php_timeout { f.as_mut().await; debug!("Connection {}: PHP timeout reached", conn_id); } else { std::future::pending::<()>().await; } } => {},
    }

    info!("Connection {}: closing connection", conn_id);
    cleanup_child(&child).await;
}

async fn spawn_php_with_retry(
    php_config: &php::PhpConfig,
    env_vars: HashMap<String, String>,
    retries: u32,
    conn_id: &str,
) -> Option<php::PhpProcess> {
    for attempt in 0..=retries {
        match php::spawn_php(php_config, env_vars.clone(), conn_id) {
            Ok(p) => return Some(p),
            Err(e) => {
                if attempt < retries {
                    warn!(
                        "Failed to spawn PHP (attempt {}/{}): {}",
                        attempt + 1,
                        retries + 1,
                        e
                    );
                    tokio::time::sleep(Duration::from_millis(100)).await;
                } else {
                    error!("Failed to spawn PHP after {} attempts: {}", retries + 1, e);
                }
            }
        }
    }
    None
}

fn build_env_vars(
    conn_id: &str,
    client_addr: &std::net::SocketAddr,
    server_addr: &Option<std::net::SocketAddr>,
    request: &RequestData,
    config: &Config,
) -> HashMap<String, String> {
    let mut env = HashMap::with_capacity(18);

    env.insert("WSS_ENABLED".into(), "1".into());
    env.insert("WSS_CONNECTION_ID".into(), conn_id.to_string());
    env.insert("WSS_CLIENT_IP".into(), client_addr.ip().to_string());
    env.insert("WSS_CLIENT_PORT".into(), client_addr.port().to_string());

    if let Some(sa) = server_addr {
        env.insert("WSS_SERVER_HOST".into(), sa.ip().to_string());
        env.insert("WSS_SERVER_PORT".into(), sa.port().to_string());
    }

    env.insert("WSS_REQUEST_URI".into(), request.uri.clone());

    if let Some(path_start) = request.uri.find('/') {
        let after_slash = &request.uri[path_start..];
        let path_end = after_slash
            .find('?')
            .map(|i| path_start + i)
            .unwrap_or(request.uri.len());
        env.insert(
            "WSS_REQUEST_PATH".into(),
            request.uri[path_start..path_end].to_string(),
        );

        if path_end < request.uri.len() {
            env.insert(
                "WSS_REQUEST_QUERY".into(),
                request.uri[path_end + 1..].to_string(),
            );
        } else {
            env.insert("WSS_REQUEST_QUERY".into(), String::new());
        }
    }

    if let Ok(json) = serde_json::to_string(&request.headers) {
        env.insert("WSS_REQUEST_HEADERS".into(), json);
    }

    for key in [
        "sec-websocket-protocol",
        "sec-websocket-version",
        "origin",
        "user-agent",
        "host",
        "x-forwarded-for",
        "x-real-ip",
    ] {
        if let Some(val) = request.headers.get(key) {
            let env_key = format!("WSS_{}", key.to_uppercase().replace('-', "_"));
            env.insert(env_key, val.clone());
        }
    }

    env.insert("WSS_TCP_HOST".into(), config.tcp_bind.clone());
    env.insert("WSS_TCP_PORT".into(), config.tcp_port.to_string());

    env
}

async fn cleanup_child(child: &Arc<Mutex<Option<tokio::process::Child>>>) {
    let mut guard = child.lock().await;
    let c = guard.take();
    drop(guard);
    if let Some(mut c) = c {
        let _ = c.kill().await;
        let _ = c.wait().await;
    }
}

async fn forward_ws_to_tcp<S>(
    mut ws_reader: futures_util::stream::SplitStream<WebSocketStream<S>>,
    mut tcp_writer: tokio::net::tcp::OwnedWriteHalf,
    buffer_size: usize,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    while let Some(msg) = ws_reader.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                let bytes = text.as_bytes();
                let mut offset = 0;
                while offset < bytes.len() {
                    let end = std::cmp::min(offset + buffer_size, bytes.len());
                    if tcp_writer.write_all(&bytes[offset..end]).await.is_err() {
                        return;
                    }
                    offset = end;
                }
                let _ = tcp_writer.flush().await;
            }
            Ok(Message::Binary(data)) => {
                let bytes = &data;
                let mut offset = 0;
                while offset < bytes.len() {
                    let end = std::cmp::min(offset + buffer_size, bytes.len());
                    if tcp_writer.write_all(&bytes[offset..end]).await.is_err() {
                        return;
                    }
                    offset = end;
                }
                let _ = tcp_writer.flush().await;
            }
            Ok(Message::Close(_)) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

async fn forward_tcp_to_ws<S>(
    mut tcp_reader: tokio::net::tcp::OwnedReadHalf,
    ws_writer: SharedWsWriter<S>,
    buffer_size: usize,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut buf = vec![0u8; buffer_size];
    loop {
        match tcp_reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                let mut writer = ws_writer.lock().await;
                if writer
                    .send(Message::Binary(buf[..n].to_vec()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let mut writer = ws_writer.lock().await;
    let _ = writer.send(Message::Close(None)).await;
}

async fn forward_stdout_to_ws<S>(
    mut reader: tokio::process::ChildStdout,
    ws_writer: SharedWsWriter<S>,
    buffer_size: usize,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut buf = vec![0u8; buffer_size];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                let mut writer = ws_writer.lock().await;
                if writer
                    .send(Message::Binary(buf[..n].to_vec()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}
