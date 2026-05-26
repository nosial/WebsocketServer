# WebSocket Server

A reliable WebSocket-to-TCP bridge for PHP applications, written in Rust. Each WebSocket connection spawns a
dedicated PHP process that communicates via TCP, with the server acting as a transparent pipeline between the WebSocket
client and the PHP process.

## Table of contents

<!-- TOC -->
* [WebSocket Server](#websocket-server)
  * [Table of contents](#table-of-contents)
  * [Features](#features)
  * [Architecture](#architecture)
  * [Usage](#usage)
    * [Core Options](#core-options)
    * [WebSocket Tuning Options](#websocket-tuning-options)
    * [TLS / WSS Options](#tls--wss-options)
    * [Help and Version](#help-and-version)
  * [TLS / SSL Configuration](#tls--ssl-configuration)
    * [1. Self-Signed (`internal`)](#1-self-signed-internal)
    * [2. Manual Certificates (`manual`)](#2-manual-certificates-manual)
    * [3. ACME / Let's Encrypt (`automate`)](#3-acme--lets-encrypt-automate)
    * [Client Certificate Authentication](#client-certificate-authentication)
  * [PHP Environment Variables](#php-environment-variables)
    * [Server Identification](#server-identification)
    * [Client Information](#client-information)
    * [Request Information](#request-information)
    * [WebSocket Headers (extracted individually)](#websocket-headers-extracted-individually)
    * [TCP Back-Connection](#tcp-back-connection)
  * [PHP Handler Protocol](#php-handler-protocol)
    * [Example PHP Handler](#example-php-handler)
    * [Using the PHP Library](#using-the-php-library)
  * [Resource Management](#resource-management)
    * [Connection Lifecycle](#connection-lifecycle)
    * [Limits and Protections](#limits-and-protections)
    * [Cleanup on Disconnect](#cleanup-on-disconnect)
  * [Nginx Reverse Proxy](#nginx-reverse-proxy)
  * [Makefile Commands](#makefile-commands)
  * [Building from Source](#building-from-source)
    * [Prerequisites](#prerequisites)
    * [Build](#build)
    * [Installation](#installation)
  * [Testing](#testing)
  * [Performance Notes](#performance-notes)
  * [License](#license)
<!-- TOC -->

## Features

- **Per-connection PHP processes** — each WebSocket client gets an isolated PHP process
- **Bidirectional message bridging** — WebSocket messages forwarded to PHP via TCP and vice versa
- **TLS/SSL support** — three modes: self-signed, manual certificates, and automatic Let's Encrypt (ACME) with hot-swappable renewal
- **Resource governance** — configurable limits on connections, processes, timeouts, and buffer sizes
- **Graceful shutdown** — drains active connections on SIGINT/SIGTERM with configurable timeout
- **Connection metadata via environment variables** — client IP, headers, request URI, and more passed to PHP
- **No OpenSSL dependency** — pure Rust TLS via `rustls`

---

## Architecture

```
Client (WebSocket)  <-->  WebSocket Server  <-->  PHP Process (TCP)
```

1. A client establishes a WebSocket connection to the server
2. The server performs the WebSocket handshake, captures request metadata (URI, headers), and generates a unique connection ID
3. The server registers a pending bridge entry keyed by the connection ID, then spawns a dedicated PHP process
4. The PHP process receives connection details via environment variables, including `WSS_TCP_HOST` and `WSS_TCP_PORT` — the address it must connect back to
5. The PHP process connects back to the server's TCP bridge listener and sends its connection ID followed by a newline
6. The server reads the connection ID, pairs the TCP stream with the pending WebSocket via the bridge, and begins forwarding data bidirectionally
7. The connection remains alive for the lifetime of the PHP process
8. When the PHP process exits, the WebSocket client disconnects, or a timeout is reached, the connection is torn down and all resources are cleaned up

---

## Usage

```bash
websocket-server --php-executable /usr/bin/php --script /path/to/script.php
```

### Core Options

All options can be set via CLI flags or the corresponding `WSS_CONFIG_*` environment variable (CLI flags take precedence).

| Option                  | Short | Default     | Environment Variable                        | Description                                        |
|-------------------------|-------|-------------|---------------------------------------------|----------------------------------------------------|
| `--ws-host`             | `-H`  | `0.0.0.0`   | `WSS_CONFIG_WS_HOST`                        | WebSocket server bind address                      |
| `--ws-port`             | `-P`  | `8080`      | `WSS_CONFIG_WS_PORT`                        | WebSocket server port                              |
| `--tcp-bind`            | `-B`  | `127.0.0.1` | `WSS_CONFIG_TCP_BIND`                       | TCP bind address for PHP back-connections          |
| `--tcp-port`            |       | `0`         | `WSS_CONFIG_TCP_PORT`                       | TCP port for PHP back-connections (0 = ephemeral)  |
| `--php-executable`      | `-e`  | (required)  | `WSS_CONFIG_PHP_EXECUTABLE`                 | Path to the PHP executable                         |
| `--script`              | `-s`  | (required)  | `WSS_CONFIG_SCRIPT`                         | PHP script to execute per WebSocket connection     |
| `--php-arg`             | `-a`  | (none)      | `WSS_CONFIG_PHP_ARGS`                       | Additional argument passed to PHP (repeatable)     |
| `--max-connections`     | `-M`  | `256`       | `WSS_CONFIG_MAX_CONNECTIONS`                | Maximum simultaneous WebSocket connections         |
| `--max-processes`       | `-m`  | `64`        | `WSS_CONFIG_MAX_PROCESSES`                  | Maximum simultaneous PHP processes                 |
| `--connection-timeout`  | `-T`  | `0`         | `WSS_CONFIG_CONNECTION_TIMEOUT`             | Max connection lifetime in seconds (0 = no limit)  |
| `--php-timeout`         | `-t`  | `0`         | `WSS_CONFIG_PHP_TIMEOUT`                    | Max PHP process runtime in seconds (0 = no limit)  |
| `--buffer-size`         | `-b`  | `65536`     | `WSS_CONFIG_BUFFER_SIZE`                    | TCP read buffer size in bytes                      |
| `--log-level`           | `-l`  | `info`      | `WSS_CONFIG_LOG_LEVEL`                      | Log level: trace, debug, info, warn, error         |
| `--php-connect-timeout` |       | `30`        | `WSS_CONFIG_PHP_CONNECT_TIMEOUT`            | Timeout in seconds waiting for PHP to connect back |
| `--php-connect-retries` |       | `3`         | `WSS_CONFIG_PHP_CONNECT_RETRIES`            | Number of retries when spawning PHP fails          |

### WebSocket Tuning Options

| Option                    | Default    | Environment Variable                         | Description                                          |
|---------------------------|------------|----------------------------------------------|------------------------------------------------------|
| `--max-payload-size`      | `16777216` | `WSS_CONFIG_MAX_PAYLOAD_SIZE`                | Maximum WebSocket payload size in bytes (16 MB)      |
| `--write-buffer-size`     | `131072`   | `WSS_CONFIG_WRITE_BUFFER_SIZE`               | WebSocket write buffer size in bytes (128 KB)        |
| `--max-write-buffer-size` | `16777216` | `WSS_CONFIG_MAX_WRITE_BUFFER`                | Maximum WebSocket write buffer size in bytes (16 MB) |

### TLS / WSS Options

| Option                       | Default        | Environment Variable                              | Description                                                                               |
|------------------------------|----------------|---------------------------------------------------|-------------------------------------------------------------------------------------------|
| `--tls-mode`                 | (none)         | `WSS_CONFIG_TLS_MODE`                             | TLS mode: `manual`, `internal`, or `automate`                                             |
| `--tls-cert`                 | (none)         | `WSS_CONFIG_TLS_CERT`                             | Path to TLS certificate file (PEM) for `manual` mode                                      |
| `--tls-key`                  | (none)         | `WSS_CONFIG_TLS_KEY`                              | Path to TLS private key file (PEM) for `manual` mode                                      |
| `--tls-domain`               | (none)         | (not available)                                   | Domain name(s) for certificate (repeatable, used by `internal` and `automate`)            |
| `--tls-email`                | (none)         | `WSS_CONFIG_TLS_EMAIL`                            | Email for ACME registration (`automate` mode)                                             |
| `--tls-acme-state-dir`       | `./acme-state` | `WSS_CONFIG_TLS_ACME_DIR`                         | Directory to store ACME account and certificate data                                      |
| `--tls-force-acme`           | `false`        | `WSS_CONFIG_TLS_FORCE_AUTOMATE`                   | Force re-obtaining certificate even if cached                                             |
| `--tls-renewal-window-ratio` | `0.33`         | `WSS_CONFIG_TLS_RENEWAL_WINDOW_RATIO`             | Renew certificate when < this fraction of lifetime remains                                |
| `--tls-dns-provider`         | (none)         | `WSS_CONFIG_TLS_DNS_PROVIDER`                     | DNS provider for ACME DNS-01 challenges                                                   |
| `--tls-dns-param`            | (none)         | `WSS_CONFIG_TLS_DNS_PARAMS`                       | DNS provider parameters (repeatable, key=value format)                                    |
| `--tls-client-auth`          | (none)         | `WSS_CONFIG_TLS_CLIENT_AUTH_MODE`                 | Client authentication mode: `request`, `require`, `verify-if-given`, `require-and-verify` |
| `--tls-client-auth-ca`       | (none)         | `WSS_CONFIG_TLS_CLIENT_AUTH_CA`                   | CA certificate file for client certificate verification                                   |
| `--tls-ciphers`              | (none)         | `WSS_CONFIG_TLS_CIPHERS`                          | Allowed TLS cipher suites (repeatable)                                                    |
| `--tls-curves`               | (none)         | `WSS_CONFIG_TLS_CURVES`                           | Allowed TLS key exchange groups (repeatable)                                              |
| `--tls-alpn`                 | (none)         | `WSS_CONFIG_TLS_ALPN`                             | ALPN protocol list (comma-separated, e.g. `http/1.1,h2`)                                  |
| `--tls-key-type`             | `ed25519`      | `WSS_CONFIG_TLS_KEY_TYPE`                         | Key type for self-signed/acme certs: `ed25519`, `p256`, `p384`, `rsa2048`, `rsa4096`      |
| `--tls-secrets-log`          | (none)         | `WSS_CONFIG_TLS_INSECURE_SECRETS_LOG`             | File path to log TLS session secrets (debugging only)                                     |

### Help and Version

| Option      | Short | Description               |
|-------------|-------|---------------------------|
| `--help`    | `-h`  | Print help information    |
| `--version` | `-V`  | Print version information |

---

## TLS / SSL Configuration

Three mutually exclusive TLS modes are supported via `--tls-mode`:

### 1. Self-Signed (`internal`)

Generates a self-signed certificate at startup using `--tls-domain` (defaults to `localhost`). Useful for development
and internal networks.

```bash
websocket-server --php-executable /usr/bin/php --script ./handler.php \
  --tls-mode internal \
  --tls-domain example.com \
  --tls-domain "*.example.com"
```

### 2. Manual Certificates (`manual`)

Loads PEM-encoded certificate and private key files from disk.

```bash
websocket-server --php-executable /usr/bin/php --script ./handler.php \
  --tls-mode manual \
  --tls-cert /etc/ssl/certs/server.crt \
  --tls-key /etc/ssl/private/server.key
```

### 3. ACME / Let's Encrypt (`automate`)

Automatically obtains and renews certificates from Let's Encrypt via HTTP-01 challenges (requires port 80). Certificates are cached in the ACME state directory and renewed automatically in the background.

```bash
websocket-server --php-executable /usr/bin/php --script ./handler.php \
  --tls-mode automate \
  --tls-domain example.com \
  --tls-email admin@example.com \
  --tls-acme-state-dir /var/lib/websocket-server/acme
```

The renewal background task runs daily and checks whether the certificate lifetime remaining is below `--tls-renewal-window-ratio` (default 0.33). On renewal, the `TlsAcceptor` is hot-swapped without restarting the server.

### Client Certificate Authentication

```bash
websocket-server --php-executable /usr/bin/php --script ./handler.php \
  --tls-mode manual \
  --tls-cert /etc/ssl/certs/server.crt \
  --tls-key /etc/ssl/private/server.key \
  --tls-client-auth require-and-verify \
  --tls-client-auth-ca /etc/ssl/ca.crt
```

---

## PHP Environment Variables

The following environment variables are passed to the PHP process for each connection:

### Server Identification

| Variable            | Description                                                                            |
|---------------------|----------------------------------------------------------------------------------------|
| `WSS_ENABLED`       | Always set to `1`. Used by client libraries to detect the WebSocket Server environment |
| `WSS_CONNECTION_ID` | Unique UUID v4 identifier for this connection                                          |

### Client Information

| Variable          | Description                         |
|-------------------|-------------------------------------|
| `WSS_CLIENT_IP`   | IP address of the WebSocket client  |
| `WSS_CLIENT_PORT` | Port of the WebSocket client        |
| `WSS_SERVER_HOST` | Server host the client connected to |
| `WSS_SERVER_PORT` | Server port the client connected to |

### Request Information

| Variable              | Description                             |
|-----------------------|-----------------------------------------|
| `WSS_REQUEST_URI`     | Full request URI (path + query string)  |
| `WSS_REQUEST_PATH`    | Path component of the URI               |
| `WSS_REQUEST_QUERY`   | Query string component of the URI       |
| `WSS_REQUEST_HEADERS` | JSON object of all HTTP request headers |

### WebSocket Headers (extracted individually)

| Variable                     | Description                           |
|------------------------------|---------------------------------------|
| `WSS_SEC_WEBSOCKET_PROTOCOL` | `Sec-WebSocket-Protocol` header value |
| `WSS_SEC_WEBSOCKET_VERSION`  | `Sec-WebSocket-Version` header value  |
| `WSS_ORIGIN`                 | `Origin` header value                 |
| `WSS_USER_AGENT`             | `User-Agent` header value             |
| `WSS_HOST`                   | `Host` header value                   |
| `WSS_X_FORWARDED_FOR`        | `X-Forwarded-For` header value        |
| `WSS_X_REAL_IP`              | `X-Real-IP` header value              |

### TCP Back-Connection

| Variable       | Description                                         |
|----------------|-----------------------------------------------------|
| `WSS_TCP_HOST` | Host address for the PHP process to connect back to |
| `WSS_TCP_PORT` | TCP port for the PHP process to connect back to     |

---

## PHP Handler Protocol

The PHP script must:

1. Read the `WSS_TCP_HOST` and `WSS_TCP_PORT` environment variables
2. Establish a TCP connection to that address
3. Send the connection ID (`WSS_CONNECTION_ID`) followed by a newline to identify itself
4. Read data from the TCP socket (incoming WebSocket messages forwarded as raw bytes)
5. Write response data to the TCP socket (sent to the WebSocket client as binary messages)
6. Continue until the script exits (closing the WebSocket connection)

### Example PHP Handler

```php
<?php
$host = getenv('WSS_TCP_HOST');
$port = getenv('WSS_TCP_PORT');
$connId = getenv('WSS_CONNECTION_ID');

$fp = fsockopen($host, $port, $errno, $errstr, 30);
if (!$fp) {
    fwrite(STDERR, "Failed to connect: $errstr ($errno)\n");
    exit(1);
}

// Send connection ID to identify this PHP process
fwrite($fp, $connId . "\n");
fflush($fp);

// Read and respond to messages
while (!feof($fp)) {
    $data = fread($fp, 8192);
    if ($data === false) {
        break;
    }
    if ($data === '') {
        usleep(10000);
        continue;
    }

    // Process the message (echo uppercase example)
    $response = strtoupper($data);
    fwrite($fp, $response);
    fflush($fp);
}

fclose($fp);
```

### Using the PHP Library

The [WebsocketLib](https://github.com/nosial/websocketlib) library handles all of this automatically:

```php
<?php
use WebsocketLib\Websocket;

$ws = new Websocket();
$conn = $ws->getConnection();

fwrite(STDERR, "Connected: {$conn->getConnectionId()}\n");

while ($ws->isConnected()) {
    $data = $ws->read(8192);
    if ($data === null) break;

    $ws->send(strtoupper($data));
}
```

---

## Resource Management

WebsocketServer is designed to be efficient and to run for long-term deployments.

### Connection Lifecycle

1. WebSocket client connects -> server accepts, performs WebSocket handshake, and captures request metadata
2. A unique connection ID (UUID v4) is generated; a pending bridge is registered for it
3. PHP process is spawned with the configured script and environment variables containing all connection details — including the TCP address (`WSS_TCP_HOST`/`WSS_TCP_PORT`) to connect back to
4. PHP must connect back to the server's TCP bridge listener and send its connection ID followed by a newline to identify itself
5. Server resolves the bridge, pairing the TCP stream with the WebSocket connection
6. Bidirectional forwarding begins: WebSocket messages are forwarded as raw bytes to TCP, and TCP data is forwarded as binary WebSocket messages
7. Connection persists until PHP exits, client disconnects, or a timeout is reached; the PHP process's stderr is captured and relayed to the server log
8. All resources (PHP process, TCP sockets, memory) are cleaned up

### Limits and Protections

- **Max Connections**: Prevents resource exhaustion from too many concurrent WebSocket connections
- **Max Processes**: Limits the number of concurrent PHP processes
- **Connection Timeout**: Automatically closes stale connections after the specified duration
- **PHP Timeout**: Kills PHP processes that run beyond their allowed time
- **PHP Connect Timeout**: Detects PHP processes that fail to connect back within the timeout
- **Connect Retries**: Automatically retries spawning PHP if the initial attempt fails
- **Graceful Shutdown**: On SIGINT/SIGTERM, waits up to 30 seconds for active connections to drain before exiting

### Cleanup on Disconnect

When any part of the connection pipeline terminates:
- The remaining forwarder tasks are immediately cancelled
- The PHP process is killed (SIGKILL) if still running
- TCP sockets are closed
- Memory is freed
- Semaphore permits are released (allowing new connections)

---

## Nginx Reverse Proxy

An example `nginx.config` is included in the repository. It uses a **front-controller pattern**: all HTTP requests are
forwarded to PHP-FPM via `index.php`, while any WebSocket connection — regardless of path — is proxied to the Rust
WebSocket server.

This allows you to run both your regular web application and WebSocket server on the same domain and port, with nginx
handling the routing based on the presence of the `Upgrade: websocket` header. The WebSocket server captures the full
request URI (including query string) in the `Host` header, which it parses and exposes as `WSS_REQUEST_URI` for your
PHP scripts.

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

upstream websocket_backend {
    server 127.0.0.1:8080;
}

upstream php_fpm_backend {
    server unix:/var/run/php/php8.2-fpm.sock;
}

server {
    listen 80;
    server_name example.com;

    root /var/www/html;
    index index.php;

    charset utf-8;

    # WebSocket connections are proxied to the Rust WebSocket server.
    # All other requests are forwarded to index.php via PHP-FPM.
    location / {
        if ($http_upgrade != "websocket") {
            rewrite ^ /index.php last;
        }
    }

    location /index.php {
        if ($http_upgrade = "websocket") {
            proxy_pass http://websocket_backend;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-Host $host;
            proxy_set_header X-Forwarded-Port $server_port;
            proxy_read_timeout 86400s;
            proxy_send_timeout 86400s;
            break;
        }

        include fastcgi_params;
        fastcgi_pass php_fpm_backend;
        fastcgi_param SCRIPT_FILENAME $document_root/index.php;
        fastcgi_param QUERY_STRING $query_string;
        fastcgi_index index.php;
    }
}
```

How it works:

- **Every request** arrives at `/`. If it's not a WebSocket upgrade, nginx internally rewrites to `/index.php` and serves it via PHP-FPM — no `.php$` regex location needed.
- **If the request has `Upgrade: websocket`**, the `/index.php` location detects it and proxies to the WebSocket server instead. The full request URI (path + query) is preserved in the `Host` header, which the server captures as `WSS_REQUEST_URI`.
- The `proxy_set_header` directives pass the real client IP, protocol, host, and port so the server can populate `WSS_CLIENT_IP`, `WSS_X_FORWARDED_FOR`, `WSS_X_REAL_IP`, `WSS_SERVER_HOST`, `WSS_SERVER_PORT`, and the `WSS_REQUEST_*` environment variables correctly.

See `nginx.config` in the repository for the complete configuration.

---

## Makefile Commands

| Command                                | Description                                 |
|----------------------------------------|---------------------------------------------|
| `make` / `make build` / `make release` | Build in release mode                       |
| `make debug`                           | Build in debug mode                         |
| `make test`                            | Run integration tests                       |
| `make test-all`                        | Run all tests (including unit tests)        |
| `make check`                           | Run clippy with warnings denied             |
| `make fmt`                             | Format code with `cargo fmt`                |
| `make fmt-check`                       | Check formatting without changes            |
| `make clean`                           | Clean build artifacts                       |
| `make install`                         | Install binary via `cargo install --path .` |

---

## Building from Source

### Prerequisites

- Rust 1.75 or later (edition 2021)
- Cargo

### Build

```bash
cargo build --release
```

The compiled binary will be at `target/release/websocket-server`.

### Installation

```bash
cargo install --path .
```

Or copy the binary directly:

```bash
cp target/release/websocket-server /usr/local/bin/
```

---

## Testing

Integration tests are written in Rust using `#[tokio::test]`. They test plain WebSocket echo, WSS with self-signed and manual certificates, concurrent connections, clean close, and invalid request handling.

**Prerequisite:** PHP must be installed and on `PATH`.

```bash
make test        # runs integration tests only
make test-all    # runs all tests with output
```

Or directly with Cargo:

```bash
cargo test --test integration_test -- --nocapture
```

## Performance Notes

WebsocketServer is designed for simplicity and reliability rather than raw performance. Each WebSocket connection spawns
a separate PHP process which costs more resources than an in-process handler. However, this isolation provides a layer
of reliability as you avoid running into memory leaks if you were to run the WebsocketServer purely implemented in PHP.

Approximately ~100-500 concurrent connections can be handled on a typical server where's ~1,000-5,000 concurrent
connections leads into a territory of ram usage accumulating up to 2GB or more depending on the PHP script being executed.

It would be more reliable to treat WebsocketServer as a means to extend your web application/service's capabilities or
features by providing short-lived or moderately long-lived WebSocket connections to run PHP scripts that can perform
tasks asynchronously or outside the request-response lifecycle of your main web application. For example, you can use
WebsocketServer to run PHP scripts that perform background processing, long-running tasks, or real-time communication
without blocking your main web server.


## License

The project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.