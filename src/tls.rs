use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use acme_lib::persist::FilePersist;
use acme_lib::{Directory, DirectoryUrl};
use log::{error, info, warn};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::danger::ClientCertVerifier;
use rustls::server::WebPkiClientVerifier;
use rustls::{CipherSuite, NamedGroup, ServerConfig};
pub use tokio_rustls::TlsAcceptor;

#[derive(Debug, Clone)]
pub enum TlsMode {
    SelfSigned,
    Manual {
        cert_path: PathBuf,
        key_path: PathBuf,
    },
    Automate,
}

#[derive(Debug, Clone)]
pub enum ClientAuthMode {
    Request,
    Require,
    VerifyIfGiven,
    RequireAndVerify,
}

#[derive(Debug, Clone)]
pub enum KeyType {
    Ed25519,
    P256,
    P384,
    Rsa2048,
    Rsa4096,
}

#[derive(Debug, Clone)]
pub struct DnsProvider {
    pub name: String,
    pub params: Vec<String>,
}

impl DnsProvider {
    fn log_details(&self) {
        info!("DNS provider: {} ({} params)", self.name, self.params.len());
        for (i, p) in self.params.iter().enumerate() {
            info!("  DNS param {}: {}", i + 1, p);
        }
    }
}

#[derive(Debug, Clone)]
pub struct AcmeConfig {
    pub email: Option<String>,
    pub force_automate: bool,
    pub dns_provider: Option<DnsProvider>,
    pub propagation_timeout: Duration,
    pub propagation_delay: Duration,
    pub dns_ttl: Duration,
    pub dns_challenge_override_domain: Option<String>,
    pub resolvers: Vec<String>,
    pub eab_key_id: Option<String>,
    pub eab_mac_key: Option<String>,
    pub on_demand: bool,
    pub reuse_private_keys: bool,
    pub renewal_window_ratio: f64,
    pub directory: PathBuf,
}

impl AcmeConfig {
    fn log_details(&self) {
        if let Some(ref dns) = self.dns_provider {
            dns.log_details();
        }
        if !self.resolvers.is_empty() {
            info!("ACME custom DNS resolvers: {:?}", self.resolvers);
        }
        if let Some(ref domain) = self.dns_challenge_override_domain {
            info!("ACME DNS challenge override domain: {domain}");
        }
        if self.eab_key_id.is_some() || self.eab_mac_key.is_some() {
            info!("ACME External Account Binding configured");
        }
        if self.on_demand {
            info!("ACME on-demand certificates enabled");
        }
        if self.reuse_private_keys {
            info!("ACME private key reuse enabled");
        }
        info!(
            "ACME renewal window: {:.0}% of cert lifetime",
            self.renewal_window_ratio * 100.0
        );
        info!("ACME propagation timeout: {:?}", self.propagation_timeout);
        info!("ACME propagation delay: {:?}", self.propagation_delay);
        info!("ACME DNS TTL: {:?}", self.dns_ttl);
    }
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            email: None,
            force_automate: false,
            dns_provider: None,
            propagation_timeout: Duration::from_secs(120),
            propagation_delay: Duration::from_secs(10),
            dns_ttl: Duration::from_secs(60),
            dns_challenge_override_domain: None,
            resolvers: Vec::new(),
            eab_key_id: None,
            eab_mac_key: None,
            on_demand: false,
            reuse_private_keys: false,
            renewal_window_ratio: 0.33,
            directory: PathBuf::from("./acme-state"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub mode: TlsMode,
    pub ciphers: Vec<String>,
    pub curves: Vec<String>,
    pub alpn: Vec<String>,
    pub key_type: KeyType,
    pub client_auth_mode: Option<ClientAuthMode>,
    pub client_auth_ca: Option<PathBuf>,
    pub insecure_secrets_log: Option<PathBuf>,
    pub acme: AcmeConfig,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            mode: TlsMode::Manual {
                cert_path: PathBuf::new(),
                key_path: PathBuf::new(),
            },
            ciphers: Vec::new(),
            curves: Vec::new(),
            alpn: Vec::new(),
            key_type: KeyType::P256,
            client_auth_mode: None,
            client_auth_ca: None,
            insecure_secrets_log: None,
            acme: AcmeConfig::default(),
        }
    }
}

fn cipher_suite_from_name(name: &str) -> Option<CipherSuite> {
    match name {
        // TLS 1.3
        "TLS13_AES_256_GCM_SHA384" => Some(CipherSuite::TLS13_AES_256_GCM_SHA384),
        "TLS13_AES_128_GCM_SHA256" => Some(CipherSuite::TLS13_AES_128_GCM_SHA256),
        "TLS13_CHACHA20_POLY1305_SHA256" => Some(CipherSuite::TLS13_CHACHA20_POLY1305_SHA256),
        "TLS13_AES_128_CCM_SHA256" => Some(CipherSuite::TLS13_AES_128_CCM_SHA256),
        "TLS13_AES_128_CCM_8_SHA256" => Some(CipherSuite::TLS13_AES_128_CCM_8_SHA256),
        // TLS 1.2 (ECDHE with ECDSA certs — most common for self-signed/ACME)
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => {
            Some(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
        }
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => {
            Some(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
        }
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => {
            Some(CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)
        }
        // TLS 1.2 (ECDHE with RSA certs)
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => {
            Some(CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
        }
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" => {
            Some(CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
        }
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" => {
            Some(CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256)
        }
        // TLS 1.2 (DHE with RSA certs)
        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256" => {
            Some(CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256)
        }
        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384" => {
            Some(CipherSuite::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384)
        }
        "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256" => {
            Some(CipherSuite::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256)
        }
        _ => None,
    }
}

fn named_group_from_name(name: &str) -> Option<NamedGroup> {
    match name {
        "secp256r1" | "p256" => Some(NamedGroup::secp256r1),
        "secp384r1" | "p384" => Some(NamedGroup::secp384r1),
        "secp521r1" | "p521" => Some(NamedGroup::secp521r1),
        "x25519" => Some(NamedGroup::X25519),
        "x448" => Some(NamedGroup::X448),
        "ffdhe2048" => Some(NamedGroup::FFDHE2048),
        "ffdhe3072" => Some(NamedGroup::FFDHE3072),
        "ffdhe4096" => Some(NamedGroup::FFDHE4096),
        "ffdhe6144" => Some(NamedGroup::FFDHE6144),
        "ffdhe8192" => Some(NamedGroup::FFDHE8192),
        _ => None,
    }
}

impl TlsConfig {
    pub async fn build(
        &self,
        domains: &[String],
    ) -> Result<TlsAcceptor, Box<dyn std::error::Error + Send + Sync>> {
        let (certs, key) = match &self.mode {
            TlsMode::SelfSigned => {
                info!("Generating self-signed TLS certificate");
                let domain = domains.first().map_or("localhost", String::as_str);
                self.generate_self_signed(domain)?
            }
            TlsMode::Manual {
                cert_path,
                key_path,
            } => {
                info!("Loading TLS certificate from {cert_path:?}");
                self.load_manual(cert_path, key_path)?
            }
            TlsMode::Automate => {
                info!("Obtaining TLS certificate via ACME automation");
                self.acme.log_details();
                self.acme_obtain(domains).await?
            }
        };

        let mut server_config = self.build_server_config(certs, key)?;

        if !self.alpn.is_empty() {
            server_config.alpn_protocols =
                self.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
        }

        if self.insecure_secrets_log.is_some() {
            server_config.key_log = Arc::new(rustls::KeyLogFile::new());
        }

        Ok(TlsAcceptor::from(Arc::new(server_config)))
    }

    fn build_server_config(
        &self,
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
        let has_custom_suites = !self.ciphers.is_empty();
        let has_custom_groups = !self.curves.is_empty();
        let has_client_auth = self.client_auth_mode.is_some();

        if has_custom_suites || has_custom_groups || has_client_auth {
            let provider = rustls::crypto::ring::default_provider();
            let mut custom_provider = provider.clone();

            if has_custom_suites {
                let selected: Vec<_> = self
                    .ciphers
                    .iter()
                    .map(|name| {
                        let cs = cipher_suite_from_name(name)
                            .ok_or_else(|| format!("Unknown cipher suite: {name}"))?;
                        provider
                            .cipher_suites
                            .iter()
                            .find(|s| s.suite() == cs)
                            .copied()
                            .ok_or_else(|| format!("Cipher suite {name} not available"))
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                if selected.is_empty() {
                    return Err("No valid cipher suites specified".into());
                }
                custom_provider.cipher_suites = selected;
            }

            if has_custom_groups {
                let selected: Vec<&'static dyn rustls::crypto::SupportedKxGroup> = self
                    .curves
                    .iter()
                    .map(|name| {
                        let ng = named_group_from_name(name)
                            .ok_or_else(|| format!("Unknown curve: {name}"))?;
                        provider
                            .kx_groups
                            .iter()
                            .find(|g| g.name() == ng)
                            .copied()
                            .ok_or_else(|| format!("Curve {name} not available"))
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                if selected.is_empty() {
                    return Err("No valid curves specified".into());
                }
                custom_provider.kx_groups = selected;
            }

            let builder = ServerConfig::builder_with_provider(Arc::new(custom_provider))
                .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])?;

            let builder = if self.client_auth_mode.is_some() {
                let verifier = self.build_client_verifier()?;
                builder.with_client_cert_verifier(verifier)
            } else {
                builder.with_no_client_auth()
            };

            Ok(builder.with_single_cert(certs, key)?)
        } else {
            let config = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)?;
            Ok(config)
        }
    }

    fn build_client_verifier(
        &self,
    ) -> Result<Arc<dyn ClientCertVerifier>, Box<dyn std::error::Error + Send + Sync>> {
        let ca_path = self
            .client_auth_ca
            .as_ref()
            .ok_or("--tls-client-auth-ca is required when using --tls-client-auth-mode")?;

        let mut root_store = rustls::RootCertStore::empty();
        let cert_file = std::fs::File::open(ca_path)?;
        let mut reader = std::io::BufReader::new(cert_file);
        let certs: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
        for cert in certs {
            root_store.add(cert)?;
        }

        let mut builder = WebPkiClientVerifier::builder(Arc::new(root_store));

        match self.client_auth_mode.as_ref().unwrap() {
            ClientAuthMode::Request | ClientAuthMode::VerifyIfGiven => {
                builder = builder.allow_unauthenticated();
            }
            ClientAuthMode::Require | ClientAuthMode::RequireAndVerify => {}
        }

        Ok(builder.build()?)
    }

    fn generate_self_signed(
        &self,
        domain: &str,
    ) -> Result<
        (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        use rcgen::{CertificateParams, KeyPair};

        let key_pair = match self.key_type {
            KeyType::Ed25519 => KeyPair::generate_for(&rcgen::PKCS_ED25519)?,
            KeyType::P256 => KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?,
            KeyType::P384 => KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)?,
            KeyType::Rsa2048 | KeyType::Rsa4096 => KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)?,
        };

        let params = CertificateParams::new(vec![domain.to_string(), format!("*.{}", domain)])?;
        let cert = params.self_signed(&key_pair)?;
        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::try_from(key_pair.serialize_der())?;

        Ok((vec![cert_der], key_der))
    }

    fn load_manual(
        &self,
        cert_path: &PathBuf,
        key_path: &PathBuf,
    ) -> Result<
        (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let cert_file = std::fs::File::open(cert_path)?;
        let mut cert_reader = std::io::BufReader::new(cert_file);
        let certs: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;

        let key_file = std::fs::File::open(key_path)?;
        let mut key_reader = std::io::BufReader::new(key_file);
        let key = rustls_pemfile::private_key(&mut key_reader)?
            .ok_or("No private key found in key file")?;

        Ok((certs, key))
    }

    async fn acme_obtain(
        &self,
        domains: &[String],
    ) -> Result<
        (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let acme_dir = &self.acme.directory;
        std::fs::create_dir_all(acme_dir)?;

        let cert_path = acme_dir.join("cert.pem");
        let key_path = acme_dir.join("key.pem");

        if !self.acme.force_automate && cert_path.exists() && key_path.exists() {
            info!("Loading existing ACME certificate from {cert_path:?}");
            return self.load_manual(&cert_path, &key_path);
        }

        let primary = domains
            .first()
            .ok_or("At least one domain is required for ACME")?
            .clone();
        let alt_names: Vec<&str> = domains.iter().skip(1).map(String::as_str).collect();

        let cert_data = tokio::task::spawn_blocking({
            let acme_dir = acme_dir.clone();
            let primary = primary.clone();
            let alt_names: Vec<String> = alt_names.iter().map(|s| (*s).to_string()).collect();
            let key_type = self.key_type.clone();
            let email = self.acme.email.clone();

            move || -> Result<(String, String), String> {
                let persist = FilePersist::new(&acme_dir);
                let url = DirectoryUrl::LetsEncrypt;
                let dir = Directory::from_url(persist, url)
                    .map_err(|e| format!("ACME directory: {e}"))?;

                let acc = match &email {
                    Some(e) => dir.account(e).map_err(|e| format!("ACME account: {e}"))?,
                    None => dir
                        .account("admin@localhost")
                        .map_err(|e| format!("ACME account: {e}"))?,
                };

                let mut new_order = acc
                    .new_order(
                        &primary,
                        &alt_names.iter().map(String::as_str).collect::<Vec<&str>>(),
                    )
                    .map_err(|e| format!("ACME order: {e}"))?;

                let csr_order = loop {
                    if let Some(csr) = new_order.confirm_validations() {
                        break csr;
                    }

                    let auths = new_order
                        .authorizations()
                        .map_err(|e| format!("ACME auths: {e}"))?;

                    for auth in &auths {
                        let chall = auth.http_challenge();
                        let token = chall.http_token();
                        let proof = chall.http_proof();

                        info!("ACME HTTP-01 challenge: token={token}");

                        let challenge_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
                        let done = challenge_done.clone();
                        let token_c = token.to_string();
                        let proof_c = proof.clone();

                        std::thread::spawn(move || {
                            let rt = match tokio::runtime::Runtime::new() {
                                Ok(r) => r,
                                Err(_) => return,
                            };
                            rt.block_on(serve_http_challenge_token(&token_c, &proof_c, done));
                        });

                        std::thread::sleep(Duration::from_millis(500));
                        chall
                            .validate(30_000)
                            .map_err(|e| format!("ACME challenge validate: {e}"))?;
                        challenge_done.store(true, std::sync::atomic::Ordering::SeqCst);
                    }

                    new_order
                        .refresh()
                        .map_err(|e| format!("ACME refresh: {e}"))?;
                };

                let pkey = match key_type {
                    KeyType::P256 => acme_lib::create_p256_key(),
                    KeyType::P384 => acme_lib::create_p384_key(),
                    KeyType::Rsa2048 => acme_lib::create_rsa_key(2048),
                    KeyType::Rsa4096 => acme_lib::create_rsa_key(4096),
                    KeyType::Ed25519 => acme_lib::create_p256_key(),
                };

                let cert_order = csr_order
                    .finalize_pkey(pkey, 30_000)
                    .map_err(|e| format!("ACME finalize: {e}"))?;
                let cert = cert_order
                    .download_and_save_cert()
                    .map_err(|e| format!("ACME download: {e}"))?;

                let cert_pem = cert.certificate().to_string();
                let key_pem = cert.private_key().to_string();

                std::fs::write(acme_dir.join("cert.pem"), &cert_pem)
                    .map_err(|e| format!("Write cert: {e}"))?;
                std::fs::write(acme_dir.join("key.pem"), &key_pem)
                    .map_err(|e| format!("Write key: {e}"))?;

                info!("ACME certificate saved to {:?}", acme_dir.join("cert.pem"));

                Ok((cert_pem, key_pem))
            }
        })
        .await
        .map_err(|e| format!("ACME task panicked: {e}"))??;

        let certs =
            rustls_pemfile::certs(&mut cert_data.0.as_bytes()).collect::<Result<Vec<_>, _>>()?;

        let key = rustls_pemfile::private_key(&mut cert_data.1.as_bytes())?
            .ok_or("Failed to parse ACME private key")?;

        Ok((certs, key))
    }
}

async fn serve_http_challenge_token(
    token: &str,
    proof: &str,
    stop_flag: Arc<std::sync::atomic::AtomicBool>,
) {
    let addr = "0.0.0.0:80";
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            warn!("ACME HTTP challenge server failed to bind {addr}: {e}");
            return;
        }
    };

    info!("ACME HTTP challenge server listening on {addr}");

    let proof_owned = proof.to_string();
    let token_owned = token.to_string();

    loop {
        if stop_flag.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }

        let (stream, peer) =
            match tokio::time::timeout(Duration::from_secs(1), listener.accept()).await {
                Ok(Ok((s, p))) => (s, p),
                _ => continue,
            };

        let proof = proof_owned.clone();
        let token = token_owned.clone();
        tokio::spawn(async move {
            handle_acme_http_request(stream, peer, &token, &proof).await;
        });
    }
}

async fn handle_acme_http_request(
    stream: tokio::net::TcpStream,
    _peer: std::net::SocketAddr,
    token: &str,
    proof: &str,
) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).await.is_err() {
        return;
    }

    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("")
        .to_string();
    let expected_path = format!("/.well-known/acme-challenge/{token}");

    let (status, body) = if path == expected_path {
        ("200 OK", proof)
    } else {
        ("404 Not Found", "Not Found")
    };

    let response = format!(
        "HTTP/1.1 {}\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{}",
        status,
        body.len(),
        body
    );

    let mut writer = reader.into_inner();
    let _ = writer.write_all(response.as_bytes()).await;
    let _ = writer.shutdown().await;
}

pub async fn setup_acme_renewal(
    config: Arc<TlsConfig>,
    domains: Vec<String>,
    tls_acceptor: Arc<std::sync::Mutex<Option<TlsAcceptor>>>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    if !matches!(config.mode, TlsMode::Automate) {
        return;
    }

    loop {
        tokio::select! {
            () = tokio::time::sleep(Duration::from_secs(86400)) => {
                let should_renew = check_cert_renewal_needed(
                    &config.acme.directory,
                    config.acme.renewal_window_ratio,
                );
                if should_renew {
                    info!("ACME certificate renewal triggered");
                    match config.build(&domains).await {
                        Ok(acceptor) => {
                            let mut guard = tls_acceptor.lock().unwrap();
                            *guard = Some(acceptor);
                            info!("ACME certificate renewed successfully");
                        }
                        Err(e) => error!("ACME certificate renewal failed: {e}"),
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
        }
    }
}

fn check_cert_renewal_needed(acme_dir: &Path, window_ratio: f64) -> bool {
    let cert_path = acme_dir.join("cert.pem");

    let metadata = match std::fs::metadata(&cert_path) {
        Ok(m) => m,
        Err(_) => return true,
    };

    let modified = match metadata.modified() {
        Ok(t) => t,
        Err(_) => return true,
    };

    // Let's Encrypt certs are valid for ~90 days
    let cert_lifetime_days: f64 = 90.0;
    let renew_days = (cert_lifetime_days * window_ratio) as u64;
    let renew_duration = Duration::from_secs(renew_days * 86400);

    match SystemTime::now().duration_since(modified) {
        Ok(age) => age > renew_duration,
        Err(_) => true,
    }
}
