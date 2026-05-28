#![allow(
    clippy::uninlined_format_args,
    clippy::ignored_unit_patterns,
    clippy::match_same_arms,
    clippy::manual_let_else,
    clippy::single_match_else,
    clippy::option_if_let_else,
    clippy::struct_excessive_bools,
    clippy::too_many_lines,
    clippy::ref_option,
    clippy::map_unwrap_or,
    clippy::significant_drop_tightening,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::implicit_clone,
    clippy::unnecessary_debug_formatting,
    clippy::redundant_closure_for_method_calls,
    clippy::inefficient_to_string,
    clippy::items_after_statements,
    clippy::match_wild_err_arm,
    clippy::needless_pass_by_value,
    clippy::unused_self,
    clippy::use_self,
    clippy::missing_const_for_fn,
    clippy::multiple_crate_versions
)]

mod bridge;
mod config;
mod handler;
mod php;
mod server;
mod tls;

use std::sync::Arc;

use clap::Parser;
use log::info;

use crate::config::Config;

fn main() {
    let config = Config::parse();

    let log_level = config.log_level.to_lowercase();
    let filter = match log_level.as_str() {
        "trace" => "trace",
        "debug" => "debug",
        "warn" | "warning" => "warn",
        "error" => "error",
        _ => {
            eprintln!(
                "Warning: unknown log level '{}', defaulting to 'info'. Valid levels: trace, debug, info, warn, error",
                log_level
            );
            "info"
        }
    };

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(filter))
        .format_timestamp_millis()
        .init();

    info!(
        "WebsocketServer v{} starting with log level '{}'",
        env!("CARGO_PKG_VERSION"),
        filter
    );

    let config = Arc::new(config);

    let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
    rt.block_on(server::run_server(config));
}
