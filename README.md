This is a Rust implementation of a SOCKS5 server, similar to [socksyproxy](https://github.com/easypost/socksyproxy).

Features:

 - High concurrency via [tokio](https://tokio.rs/)
 - IPv4 and IPv6 support
 - Server-side DNS resolution
 - ACL functionality

Coming soon:

 - Operational statistics via a domain socket

Not implemented:

 - Authentication

Check out [example.toml](example.toml) for an example of what the config file looks like.
