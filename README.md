This is a Rust implementation of a SOCKS5 server, similar to [socksyproxy](https://github.com/easypost/socksyproxy).

![CI](https://github.com/EasyPost/ferrous-socks/workflows/CI/badge.svg?branch=master)

Features:

 - High concurrency via [tokio](https://tokio.rs/)
 - IPv4 and IPv6 support
 - Server-side DNS resolution
 - ACL functionality
 - Specifying bind addresses for outgoing IPv4 and IPv6 sessions
 - Operational statistics via a domain socket or TCP socket
 - basic SOCKS4 and SOCKS4a support (username parameter is ignored)
 - will accept any username+password authentication (and log the username)

Check out [example.toml](example.toml) for an example of what the config file looks like. You can generate the default config by running `ferrous-socks --dump-config default.toml`
