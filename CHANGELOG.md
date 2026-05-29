# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.3] - 2026-05-29

This update introduces new build variants


## [1.0.2] - 2026-05-28

This update introduces improvements to logging


## [1.0.1] - 2026-05-27

This update introduces improvements

### Changed
 - CloseReason enum - each `tokio::select!` branch now returns a typed reason instead of silently failing
 - `forward_ws_to_tcp` Logs the specific Websocket error type and close frame details
 - `forward_tcp_to_ws` Logs clean EOF vs read errors, and WS write failures
 - `child_monitor` Logs the PHP process exit code or (killed-by-signal) reason
 - `cleanup_child` Logs the final exit status after cleaning


## [1.0.0] - 2026-05-26

Initial release of WebsocketServer