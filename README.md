This is a Rust implementation of a SOCKS5 server, similar to [socksyproxy](https://github.com/easypost/socksyproxy).

[![Build Status](https://travis-ci.com/EasyPost/ferrous-socks.svg?branch=master)](https://travis-ci.com/EasyPost/ferrous-socks)

Features:

 - High concurrency via [tokio](https://tokio.rs/)
 - IPv4 and IPv6 support
 - Server-side DNS resolution
 - ACL functionality
 - Specifying bind addresses for outgoing IPv4 and IPv6 sessions
 - Operational statistics via a domain socket or TCP socket
 - basic SOCKS4 and SOCKS4a support (username parameter is ignored)
 - will accept any username+password authentication (and log the username)

Check out [example.toml](example.toml) for an example of what the config file looks like.
