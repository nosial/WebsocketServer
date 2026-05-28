use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;

use crate::tls;

#[derive(Parser, Debug, Clone)]
#[command(name = "websocket-server")]
#[command(version = "1.0.2")]
#[command(author = "Nosial")]
#[command(about = "WebSocket to TCP bridge server for PHP applications")]
pub struct Config {
    #[arg(
        short = 'H',
        long = "ws-host",
        default_value = "0.0.0.0",
        env = "WSS_CONFIG_WS_HOST",
        help = "WebSocket server bind address"
    )]
    pub ws_host: String,

    #[arg(
        short = 'P',
        long = "ws-port",
        default_value = "8080",
        env = "WSS_CONFIG_WS_PORT",
        help = "WebSocket server port"
    )]
    pub ws_port: u16,

    #[arg(
        short = 'B',
        long = "tcp-bind",
        default_value = "127.0.0.1",
        env = "WSS_CONFIG_TCP_BIND",
        help = "TCP bind address for PHP back-connections"
    )]
    pub tcp_bind: String,

    #[arg(
        long = "tcp-port",
        default_value = "8081",
        env = "WSS_CONFIG_TCP_PORT",
        help = "TCP port for shared PHP back-connection server"
    )]
    pub tcp_port: u16,

    #[arg(
        short = 'e',
        long = "php-executable",
        required = true,
        env = "WSS_CONFIG_PHP_EXECUTABLE",
        help = "Path to PHP executable"
    )]
    pub php_executable: String,

    #[arg(
        short = 's',
        long = "script",
        required = true,
        env = "WSS_CONFIG_SCRIPT",
        help = "PHP script to execute per WebSocket connection"
    )]
    pub script: String,

    #[arg(
        short = 'a',
        long = "php-arg",
        env = "WSS_CONFIG_PHP_ARGS",
        help = "Additional argument to pass to PHP (can be specified multiple times)"
    )]
    pub php_args: Vec<String>,

    #[arg(
        short = 'M',
        long = "max-connections",
        default_value = "256",
        env = "WSS_CONFIG_MAX_CONNECTIONS",
        help = "Maximum number of simultaneous WebSocket connections"
    )]
    pub max_connections: usize,

    #[arg(
        short = 'm',
        long = "max-processes",
        default_value = "64",
        env = "WSS_CONFIG_MAX_PROCESSES",
        help = "Maximum number of simultaneous PHP processes"
    )]
    pub max_processes: usize,

    #[arg(
        short = 'T',
        long = "connection-timeout",
        default_value = "0",
        env = "WSS_CONFIG_CONNECTION_TIMEOUT",
        help = "Maximum lifetime of a WebSocket connection in seconds (0 = no limit)"
    )]
    pub connection_timeout: u64,

    #[arg(
        short = 't',
        long = "php-timeout",
        default_value = "0",
        env = "WSS_CONFIG_PHP_TIMEOUT",
        help = "Maximum runtime of a PHP process in seconds (0 = no limit)"
    )]
    pub php_timeout: u64,

    #[arg(
        short = 'b',
        long = "buffer-size",
        default_value = "65536",
        env = "WSS_CONFIG_BUFFER_SIZE",
        help = "TCP buffer size in bytes for forwarding data"
    )]
    pub buffer_size: usize,

    #[arg(
        short = 'l',
        long = "log-level",
        default_value = "info",
        env = "WSS_CONFIG_LOG_LEVEL",
        help = "Log level: trace, debug, info, warn, error"
    )]
    pub log_level: String,

    #[arg(
        long = "php-connect-timeout",
        default_value = "30",
        env = "WSS_CONFIG_PHP_CONNECT_TIMEOUT",
        help = "Timeout in seconds waiting for PHP to connect back after spawning"
    )]
    pub php_connect_timeout: u64,

    #[arg(
        long = "php-connect-retries",
        default_value = "3",
        env = "WSS_CONFIG_PHP_CONNECT_RETRIES",
        help = "Number of times to retry spawning PHP if it fails"
    )]
    pub php_connect_retries: u32,

    #[arg(
        long = "max-payload-size",
        default_value = "0",
        env = "WSS_CONFIG_MAX_PAYLOAD_SIZE",
        help = "Maximum allowed WebSocket payload size in bytes (0 = no limit)"
    )]
    pub max_payload_size: usize,

    #[arg(
        long = "write-buffer-size",
        default_value = "65536",
        env = "WSS_CONFIG_WRITE_BUFFER_SIZE",
        help = "Initial WebSocket write buffer size per connection in bytes"
    )]
    pub write_buffer_size: usize,

    #[arg(
        long = "max-write-buffer",
        default_value = "262144",
        env = "WSS_CONFIG_MAX_WRITE_BUFFER",
        help = "Maximum WebSocket write buffer size per connection in bytes"
    )]
    pub max_write_buffer: usize,

    #[arg(
        long = "ignore-stdout",
        env = "WSS_CONFIG_IGNORE_STDOUT",
        help = "Ignore PHP process stdout (disable forwarding echo'd data to WebSocket)"
    )]
    pub ignore_stdout: bool,

    // TLS options
    #[arg(
        long = "tls-mode",
        default_value = "manual",
        env = "WSS_CONFIG_TLS_MODE",
        help = "TLS mode: manual, internal (self-signed), or automate (Let's Encrypt)"
    )]
    pub tls_mode: String,

    #[arg(
        long = "tls-cert",
        env = "WSS_CONFIG_TLS_CERT",
        help = "Path to TLS certificate file (for manual mode)"
    )]
    pub tls_cert: Option<String>,

    #[arg(
        long = "tls-key",
        env = "WSS_CONFIG_TLS_KEY",
        help = "Path to TLS private key file (for manual mode)"
    )]
    pub tls_key: Option<String>,

    #[arg(
        long = "tls-email",
        env = "WSS_CONFIG_TLS_EMAIL",
        help = "Email for ACME/Let's Encrypt registration (for automate mode)"
    )]
    pub tls_email: Option<String>,

    #[arg(
        long = "tls-force-automate",
        env = "WSS_CONFIG_TLS_FORCE_AUTOMATE",
        help = "Always obtain a new certificate from ACME, even if a valid one exists"
    )]
    pub tls_force_automate: bool,

    #[arg(
        long = "tls-ciphers",
        env = "WSS_CONFIG_TLS_CIPHERS",
        help = "TLS cipher suites (space-separated)"
    )]
    pub tls_ciphers: Vec<String>,

    #[arg(
        long = "tls-curves",
        env = "WSS_CONFIG_TLS_CURVES",
        help = "TLS elliptic curves (space-separated)"
    )]
    pub tls_curves: Vec<String>,

    #[arg(
        long = "tls-alpn",
        env = "WSS_CONFIG_TLS_ALPN",
        help = "ALPN protocols (space-separated, e.g. h2 http/1.1)"
    )]
    pub tls_alpn: Vec<String>,

    #[arg(
        long = "tls-key-type",
        default_value = "p256",
        env = "WSS_CONFIG_TLS_KEY_TYPE",
        help = "Key type for cert generation: ed25519, p256, p384, rsa2048, rsa4096"
    )]
    pub tls_key_type: String,

    #[arg(
        long = "tls-client-auth-mode",
        env = "WSS_CONFIG_TLS_CLIENT_AUTH_MODE",
        help = "Client certificate auth mode: request, require, verify_if_given, require_and_verify"
    )]
    pub tls_client_auth_mode: Option<String>,

    #[arg(
        long = "tls-client-auth-ca",
        env = "WSS_CONFIG_TLS_CLIENT_AUTH_CA",
        help = "CA certificate file for client certificate verification"
    )]
    pub tls_client_auth_ca: Option<String>,

    #[arg(
        long = "tls-insecure-secrets-log",
        env = "WSS_CONFIG_TLS_INSECURE_SECRETS_LOG",
        help = "Path to TLS key log file (for debugging)"
    )]
    pub tls_insecure_secrets_log: Option<String>,

    // ACME-specific options
    #[arg(
        long = "tls-acme-dir",
        default_value = "./acme-state",
        env = "WSS_CONFIG_TLS_ACME_DIR",
        help = "Directory for ACME state persistence"
    )]
    pub tls_acme_dir: String,

    #[arg(
        long = "tls-dns-provider",
        env = "WSS_CONFIG_TLS_DNS_PROVIDER",
        help = "DNS provider for ACME DNS-01 challenge"
    )]
    pub tls_dns_provider: Option<String>,

    #[arg(
        long = "tls-dns-params",
        env = "WSS_CONFIG_TLS_DNS_PARAMS",
        help = "DNS provider parameters"
    )]
    pub tls_dns_params: Vec<String>,

    #[arg(
        long = "tls-propagation-timeout",
        default_value = "120",
        env = "WSS_CONFIG_TLS_PROPAGATION_TIMEOUT",
        help = "DNS propagation timeout in seconds"
    )]
    pub tls_propagation_timeout: u64,

    #[arg(
        long = "tls-propagation-delay",
        default_value = "10",
        env = "WSS_CONFIG_TLS_PROPAGATION_DELAY",
        help = "DNS propagation delay in seconds"
    )]
    pub tls_propagation_delay: u64,

    #[arg(
        long = "tls-dns-ttl",
        default_value = "60",
        env = "WSS_CONFIG_TLS_DNS_TTL",
        help = "DNS TTL in seconds"
    )]
    pub tls_dns_ttl: u64,

    #[arg(
        long = "tls-dns-challenge-override-domain",
        env = "WSS_CONFIG_TLS_DNS_CHALLENGE_OVERRIDE_DOMAIN",
        help = "Override domain for DNS challenge"
    )]
    pub tls_dns_challenge_override_domain: Option<String>,

    #[arg(
        long = "tls-resolvers",
        env = "WSS_CONFIG_TLS_RESOLVERS",
        help = "Custom DNS resolvers (space-separated)"
    )]
    pub tls_resolvers: Vec<String>,

    #[arg(
        long = "tls-eab-key-id",
        env = "WSS_CONFIG_TLS_EAB_KEY_ID",
        help = "External Account Binding key ID"
    )]
    pub tls_eab_key_id: Option<String>,

    #[arg(
        long = "tls-eab-mac-key",
        env = "WSS_CONFIG_TLS_EAB_MAC_KEY",
        help = "External Account Binding MAC key"
    )]
    pub tls_eab_mac_key: Option<String>,

    #[arg(
        long = "tls-on-demand",
        env = "WSS_CONFIG_TLS_ON_DEMAND",
        help = "Enable on-demand certificates"
    )]
    pub tls_on_demand: bool,

    #[arg(
        long = "tls-reuse-private-keys",
        env = "WSS_CONFIG_TLS_REUSE_PRIVATE_KEYS",
        help = "Reuse private keys across certificate renewals"
    )]
    pub tls_reuse_private_keys: bool,

    #[arg(
        long = "tls-renewal-window-ratio",
        default_value = "0.33",
        env = "WSS_CONFIG_TLS_RENEWAL_WINDOW_RATIO",
        help = "Fraction of cert lifetime before renewal (default: 0.33 = renew at 1/3 remaining)"
    )]
    pub tls_renewal_window_ratio: f64,
}

impl Config {
    pub fn to_tls_config(&self) -> Result<Option<tls::TlsConfig>, String> {
        let tls_specified = self.tls_mode != "manual"
            || self.tls_cert.is_some()
            || self.tls_key.is_some()
            || self.tls_email.is_some()
            || self.tls_force_automate
            || !self.tls_ciphers.is_empty()
            || !self.tls_alpn.is_empty()
            || self.tls_client_auth_mode.is_some()
            || self.tls_insecure_secrets_log.is_some()
            || self.tls_dns_provider.is_some();

        if !tls_specified {
            return Ok(None);
        }

        let mode = match self.tls_mode.as_str() {
            "internal" | "self-signed" => tls::TlsMode::SelfSigned,
            "manual" => {
                let cert = self
                    .tls_cert
                    .as_ref()
                    .ok_or("--tls-cert is required in manual mode")?;
                let key = self
                    .tls_key
                    .as_ref()
                    .ok_or("--tls-key is required in manual mode")?;
                tls::TlsMode::Manual {
                    cert_path: PathBuf::from(cert),
                    key_path: PathBuf::from(key),
                }
            }
            "automate" | "acme" => tls::TlsMode::Automate,
            other => {
                return Err(format!(
                    "Invalid --tls-mode: {other}. Expected: manual, internal, automate"
                ))
            }
        };

        let key_type = match self.tls_key_type.as_str() {
            "ed25519" => tls::KeyType::Ed25519,
            "p256" => tls::KeyType::P256,
            "p384" => tls::KeyType::P384,
            "rsa2048" => tls::KeyType::Rsa2048,
            "rsa4096" => tls::KeyType::Rsa4096,
            other => {
                return Err(format!(
                "Invalid --tls-key-type: {other}. Expected: ed25519, p256, p384, rsa2048, rsa4096"
            ))
            }
        };

        let client_auth_mode = match self.tls_client_auth_mode.as_deref() {
            None => None,
            Some("request") => Some(tls::ClientAuthMode::Request),
            Some("require") => Some(tls::ClientAuthMode::Require),
            Some("verify_if_given") => Some(tls::ClientAuthMode::VerifyIfGiven),
            Some("require_and_verify") => Some(tls::ClientAuthMode::RequireAndVerify),
            Some(other) => return Err(format!("Invalid --tls-client-auth-mode: {other}")),
        };

        let dns_provider = self.tls_dns_provider.as_ref().map(|name| tls::DnsProvider {
            name: name.clone(),
            params: self.tls_dns_params.clone(),
        });

        Ok(Some(tls::TlsConfig {
            mode,
            ciphers: self.tls_ciphers.clone(),
            curves: self.tls_curves.clone(),
            alpn: self.tls_alpn.clone(),
            key_type,
            client_auth_mode,
            client_auth_ca: self.tls_client_auth_ca.as_ref().map(PathBuf::from),
            insecure_secrets_log: self.tls_insecure_secrets_log.as_ref().map(PathBuf::from),
            acme: tls::AcmeConfig {
                email: self.tls_email.clone(),
                force_automate: self.tls_force_automate,
                dns_provider,
                propagation_timeout: Duration::from_secs(self.tls_propagation_timeout),
                propagation_delay: Duration::from_secs(self.tls_propagation_delay),
                dns_ttl: Duration::from_secs(self.tls_dns_ttl),
                dns_challenge_override_domain: self.tls_dns_challenge_override_domain.clone(),
                resolvers: self.tls_resolvers.clone(),
                eab_key_id: self.tls_eab_key_id.clone(),
                eab_mac_key: self.tls_eab_mac_key.clone(),
                on_demand: self.tls_on_demand,
                reuse_private_keys: self.tls_reuse_private_keys,
                renewal_window_ratio: self.tls_renewal_window_ratio,
                directory: PathBuf::from(&self.tls_acme_dir),
            },
        }))
    }
}
