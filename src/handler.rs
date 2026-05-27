use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use log::{debug, error, info, warn};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::Child;
use tokio::sync::{Mutex, Semaphore};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use uuid::Uuid;

use crate::bridge::BridgeManager;
use crate::config::Config;
use crate::php;

/// Describes why a WebSocket connection was closed.
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
enum CloseReason {
    ClientDisconnected,
    TcpClosedByPhp,
    StdoutEof,
    PhpProcessExited(Option<i32>),
    ConnectionTimeout,
    PhpTimeout,
}

impl fmt::Display for CloseReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CloseReason::ClientDisconnected => write!(f, "WebSocket client disconnected"),
            CloseReason::TcpClosedByPhp => write!(f, "TCP connection closed by PHP process"),
            CloseReason::StdoutEof => write!(f, "PHP stdout reached end-of-file"),
            CloseReason::PhpProcessExited(code) => {
                if let Some(c) = code {
                    write!(f, "PHP process exited with code {c}")
                } else {
                    write!(f, "PHP process exited (no status)")
                }
            }
            CloseReason::ConnectionTimeout => write!(f, "connection timeout reached"),
            CloseReason::PhpTimeout => write!(f, "PHP execution timeout reached"),
        }
    }
}

#[derive(Default)]
pub struct RequestData {
    pub uri: String,
    pub headers: HashMap<String, String>,
}

type SharedWsWriter<S> = Arc<Mutex<futures_util::stream::SplitSink<WebSocketStream<S>, Message>>>;

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

    let _proc_permit = if let Ok(p) = proc_semaphore.try_acquire_owned() {
        p
    } else {
        warn!("Connection {conn_id}: max PHP processes reached, rejecting");
        return;
    };

    debug!("Connection {conn_id}: new WebSocket connection from {client_addr}");

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
    let (child, php_stdout) = if let Some(p) = proc {
        let stdout = p.stdout;
        (Arc::new(Mutex::new(Some(p.child))), stdout)
    } else {
        error!("Connection {conn_id}: failed to spawn PHP process after retries");
        bridge_manager.remove(&conn_id).await;
        return;
    };

    let tcp_stream =
        match tokio::time::timeout(Duration::from_secs(config.php_connect_timeout), tcp_rx).await {
            Ok(Ok(stream)) => {
                info!("Connection {conn_id}: PHP process connected");
                stream
            }
            Ok(Err(_)) => {
                error!("Connection {conn_id}: bridge receiver cancelled");
                cleanup_child(&child, &conn_id).await;
                return;
            }
            Err(_) => {
                warn!(
                    "Connection {}: PHP did not connect within {}s",
                    conn_id, config.php_connect_timeout
                );
                bridge_manager.remove(&conn_id).await;
                cleanup_child(&child, &conn_id).await;
                return;
            }
        };

    let (tcp_reader, tcp_writer) = tcp_stream.into_split();
    let (ws_writer, ws_reader) = ws_stream.split();

    let ws_writer: SharedWsWriter<S> = Arc::new(Mutex::new(ws_writer));

    let child_monitor = {
        let child = child.clone();
        let conn_id = conn_id.clone();
        async move {
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;
                let mut guard = child.lock().await;
                match guard.as_mut().and_then(|c| c.try_wait().ok()).flatten() {
                    Some(status) => {
                        guard.take();
                        if let Some(code) = status.code() {
                            info!(
                                "Connection {conn_id}: PHP process exited with code {code}"
                            );
                        } else {
                            info!(
                                "Connection {conn_id}: PHP process killed by signal"
                            );
                        }
                        return;
                    }
                    None if guard.is_none() => return,
                    _ => {}
                }
            }
        }
    };

    let fwd_ws = forward_ws_to_tcp(
        ws_reader,
        tcp_writer,
        config.buffer_size,
        conn_id.clone(),
    );
    let fwd_tcp = forward_tcp_to_ws(
        tcp_reader,
        ws_writer.clone(),
        config.buffer_size,
        conn_id.clone(),
    );
    let mut fwd_stdout = php_stdout.map(|s| {
        Box::pin(forward_stdout_to_ws(
            s,
            ws_writer,
            config.buffer_size,
            conn_id.clone(),
        ))
    });
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

    let reason = tokio::select! {
        _ = &mut fwd_ws => CloseReason::ClientDisconnected,
        _ = &mut fwd_tcp => CloseReason::TcpClosedByPhp,
        _ = async {
            if let Some(ref mut f) = fwd_stdout {
                f.await
            } else {
                std::future::pending::<()>().await
            }
        } => CloseReason::StdoutEof,
        _ = &mut child_monitor => {
            // child_monitor already logs the exit reason; return a generic reason here
            // but we try to extract the status from the child one more time
            let status = {
                let mut guard = child.lock().await;
                guard.as_mut().and_then(|c| c.try_wait().ok()).flatten()
            };
            match status.and_then(|s| s.code()) {
                Some(code) => CloseReason::PhpProcessExited(Some(code)),
                None => CloseReason::PhpProcessExited(None),
            }
        }
        _ = async {
            if let Some(ref mut f) = conn_timeout {
                f.as_mut().await;
                debug!("Connection {conn_id}: connection timeout reached");
            } else {
                std::future::pending::<()>().await
            }
        } => CloseReason::ConnectionTimeout,
        _ = async {
            if let Some(ref mut f) = php_timeout {
                f.as_mut().await;
                debug!("Connection {conn_id}: PHP timeout reached");
            } else {
                std::future::pending::<()>().await
            }
        } => CloseReason::PhpTimeout,
    };

    info!("Connection {conn_id}: closing connection: {reason}");
    cleanup_child(&child, &conn_id).await;
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
            .map_or(request.uri.len(), |i| path_start + i);
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

async fn cleanup_child(child: &Arc<Mutex<Option<Child>>>, conn_id: &str) {
    let mut guard = child.lock().await;
    let c = guard.take();
    drop(guard);
    if let Some(mut c) = c {
        let _ = c.kill().await;
        match c.wait().await {
            Ok(status) => {
                if let Some(code) = status.code() {
                    debug!("Connection {conn_id}: cleaned up PHP process (exit code {code})");
                } else {
                    debug!("Connection {conn_id}: cleaned up PHP process (killed by signal)");
                }
            }
            Err(e) => {
                debug!("Connection {conn_id}: error waiting for PHP process cleanup: {e}");
            }
        }
    }
}

async fn forward_ws_to_tcp<S>(
    mut ws_reader: futures_util::stream::SplitStream<WebSocketStream<S>>,
    mut tcp_writer: tokio::net::tcp::OwnedWriteHalf,
    buffer_size: usize,
    conn_id: String,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use tokio_tungstenite::tungstenite::Error as WsError;
    while let Some(msg) = ws_reader.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                let bytes = text.as_bytes();
                let mut offset = 0;
                while offset < bytes.len() {
                    let end = std::cmp::min(offset + buffer_size, bytes.len());
                    if tcp_writer.write_all(&bytes[offset..end]).await.is_err() {
                        debug!("Connection {conn_id}: TCP write failed in ws→tcp forwarder");
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
                        debug!("Connection {conn_id}: TCP write failed in ws→tcp forwarder");
                        return;
                    }
                    offset = end;
                }
                let _ = tcp_writer.flush().await;
            }
            Ok(Message::Close(frame)) => {
                debug!(
                    "Connection {conn_id}: WebSocket client sent close frame: {frame:?}"
                );
                break;
            }
            Ok(Message::Ping(_)) | Ok(Message::Pong(_)) | Ok(Message::Frame(_)) => {}
            Err(e) => {
                match &e {
                    WsError::ConnectionClosed => {
                        debug!("Connection {conn_id}: WebSocket client connection closed");
                    }
                    WsError::Protocol(msg) => {
                        debug!("Connection {conn_id}: WebSocket protocol error: {msg}");
                    }
                    _ => {
                        debug!("Connection {conn_id}: WebSocket error: {e}");
                    }
                }
                break;
            }
        }
    }
}

async fn forward_tcp_to_ws<S>(
    mut tcp_reader: tokio::net::tcp::OwnedReadHalf,
    ws_writer: SharedWsWriter<S>,
    buffer_size: usize,
    conn_id: String,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut buf = vec![0u8; buffer_size];
    loop {
        match tcp_reader.read(&mut buf).await {
            Ok(0) => {
                debug!("Connection {conn_id}: TCP stream closed by PHP (clean EOF)");
                break;
            }
            Ok(n) => {
                let mut writer = ws_writer.lock().await;
                if writer
                    .send(Message::Binary(buf[..n].to_vec()))
                    .await
                    .is_err()
                {
                    debug!("Connection {conn_id}: WebSocket write failed in tcp→ws forwarder");
                    break;
                }
            }
            Err(e) => {
                debug!("Connection {conn_id}: TCP read error: {e}");
                break;
            }
        }
    }
    let mut writer = ws_writer.lock().await;
    let _ = writer.send(Message::Close(None)).await;
}

async fn forward_stdout_to_ws<S>(
    mut reader: tokio::process::ChildStdout,
    ws_writer: SharedWsWriter<S>,
    buffer_size: usize,
    conn_id: String,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut buf = vec![0u8; buffer_size];
    let mut total_bytes = 0usize;
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => {
                debug!(
                    "Connection {conn_id}: PHP stdout closed (EOF after {total_bytes} bytes)"
                );
                break;
            }
            Ok(n) => {
                total_bytes += n;
                let mut writer = ws_writer.lock().await;
                if writer
                    .send(Message::Binary(buf[..n].to_vec()))
                    .await
                    .is_err()
                {
                    debug!("Connection {conn_id}: WebSocket write failed in stdout→ws forwarder");
                    break;
                }
            }
            Err(e) => {
                debug!("Connection {conn_id}: PHP stdout read error: {e}");
                break;
            }
        }
    }
}
