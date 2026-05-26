use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::Connector;

/// Find the `echo_responder` test binary in the target directory.
/// Cargo compiles `tests/echo_responder.rs` as `echo_responder-<hash>` in `target/debug/deps/`.
fn find_echo_responder(manifest_dir: &Path) -> PathBuf {
    let search_dirs = ["debug", "release"]
        .iter()
        .flat_map(|&dir| {
            let base = manifest_dir.join("target").join(dir);
            [base.clone(), base.join("deps")]
        })
        .collect::<Vec<_>>();

    for dir in &search_dirs {
        if !dir.is_dir() {
            continue;
        }
        // Check exact name first (matches [[bin]] name from before the move)
        let exact = dir.join("echo-responder");
        if exact.exists() {
            return exact;
        }
        // Search for test binary name (echo_responder-<hash>)
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.starts_with("echo_responder-") || name.starts_with("echo-responder-") {
                        return path;
                    }
                }
            }
        }
    }
    panic!("echo_responder binary not found in target/debug or target/release");
}

/// A running server instance for integration tests.
pub struct TestServer {
    child: Child,
    port: u16,
}

impl TestServer {
    /// Start a plain WS server.
    pub fn start_ws(port: u16) -> Self {
        Self::start(port, None)
    }

    /// Start a WSS server with `--tls-mode internal`.
    pub fn start_wss_internal(port: u16) -> Self {
        Self::start(
            port,
            Some(&["--tls-mode", "internal", "--tls-key-type", "p256"]),
        )
    }

    /// Start a WSS server with manually provided cert/key PEMs.
    pub fn start_wss_manual(port: u16, cert: &Path, key: &Path) -> Self {
        Self::start(
            port,
            Some(&[
                "--tls-cert",
                &cert.to_string_lossy(),
                "--tls-key",
                &key.to_string_lossy(),
            ]),
        )
    }

    fn start(port: u16, tls_args: Option<&[&str]>) -> Self {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

        // Try release first, then debug (works with both `cargo test` and `make test`)
        let prefix = |name: &str| -> PathBuf {
            let release = manifest_dir.join("target").join("release").join(name);
            let debug = manifest_dir.join("target").join("debug").join(name);
            if release.exists() {
                release
            } else {
                debug
            }
        };

        let binary = prefix("websocket-server");
        let echo_responder = find_echo_responder(&manifest_dir);

        let mut cmd = Command::new(&binary);
        cmd.arg("--php-executable")
            .arg(&echo_responder)
            .arg("--script")
            .arg(&echo_responder)
            .arg("--ws-port")
            .arg(port.to_string())
            .arg("--tcp-port")
            .arg((port + 1000).to_string())
            .arg("--log-level")
            .arg("warn")
            .arg("--connection-timeout")
            .arg("10")
            .arg("--php-timeout")
            .arg("10");

        if let Some(args) = tls_args {
            cmd.args(args);
        }

        cmd.stdout(Stdio::null()).stderr(Stdio::null());

        let mut child = cmd.spawn().expect("Failed to start websocket-server");

        // Wait for the server to be ready
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("Server failed to start on port {port} within 10s");
            }
            if TcpStream::connect(format!("127.0.0.1:{port}")).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        Self { child, port }
    }

    pub const fn port(&self) -> u16 {
        self.port
    }

    pub fn ws_url(&self) -> String {
        format!("ws://127.0.0.1:{}", self.port)
    }

    pub fn wss_url(&self) -> String {
        format!("wss://127.0.0.1:{}", self.port)
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Create a `Connector::Rustls` that accepts any server certificate.
pub fn permissive_tls_connector() -> Connector {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::{DigitallySignedStruct, Error, SignatureScheme};
    use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

    #[derive(Debug)]
    struct NoopVerifier;

    impl ServerCertVerifier for NoopVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
            ]
        }
    }

    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoopVerifier))
        .with_no_client_auth();

    Connector::Rustls(Arc::new(config))
}

/// Generate a self-signed cert and key, write to temp files, return the paths.
pub fn generate_self_signed_cert() -> (PathBuf, PathBuf) {
    use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let params = CertificateParams::new(vec!["localhost".into()]).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();

    let dir = std::env::temp_dir().join(format!("wss_test_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();

    (cert_path, key_path)
}

/// Connect to a WebSocket server, send a message, and verify the echo response.
pub async fn assert_echo(url: &str, input: &str, connector: Option<Connector>) {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::connect_async;
    use tokio_tungstenite::tungstenite::Message;

    let (mut ws, _) = if let Some(conn) = connector {
        tokio_tungstenite::connect_async_tls_with_config(
            url.into_client_request().unwrap(),
            None,
            false,
            Some(conn),
        )
        .await
        .expect("WebSocket connect failed")
    } else {
        connect_async(url).await.expect("WebSocket connect failed")
    };

    ws.send(Message::Text(input.to_string()))
        .await
        .expect("Send failed");

    let resp = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("Timeout waiting for response")
        .expect("Stream ended")
        .expect("Recv error");

    let text = match resp {
        Message::Text(t) => t,
        Message::Binary(b) => String::from_utf8(b).unwrap(),
        _ => panic!("Unexpected message type"),
    };

    assert_eq!(text, input.to_uppercase(), "Echo should be uppercased");
}

/// Connect to a WebSocket server, send a binary message, and verify the echo response.
pub async fn assert_echo_binary(url: &str, connector: Option<Connector>) {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::connect_async;
    use tokio_tungstenite::tungstenite::Message;

    let (mut ws, _) = if let Some(conn) = connector {
        tokio_tungstenite::connect_async_tls_with_config(
            url.into_client_request().unwrap(),
            None,
            false,
            Some(conn),
        )
        .await
        .expect("WebSocket connect failed")
    } else {
        connect_async(url).await.expect("WebSocket connect failed")
    };

    let payload = b"binary data";
    ws.send(Message::Binary(payload.to_vec()))
        .await
        .expect("Send failed");

    let resp = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("Timeout waiting for response")
        .expect("Stream ended")
        .expect("Recv error");

    let Message::Binary(data) = resp else {
        panic!("Expected binary response")
    };

    let expected = b"BINARY DATA".to_vec();
    assert_eq!(data, expected, "Binary echo should be uppercased");
}
