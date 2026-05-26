mod bridge;
mod config;
mod handler;
mod php;
mod server;
mod tls;

use std::sync::Arc;

use clap::Parser;

use crate::config::Config;

fn main() {
    let config = Config::parse();

    let log_level = config.log_level.to_lowercase();
    let filter = match log_level.as_str() {
        "trace" => "trace",
        "debug" => "debug",
        "warn" | "warning" => "warn",
        "error" => "error",
        _ => "info",
    };

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(filter)).init();

    let config = Arc::new(config);

    let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
    rt.block_on(server::run_server(config));
}
