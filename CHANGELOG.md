1.0.8
-----
- Bump `regex` crate for [RUSTSEC-2022-0013](https://rustsec.org/advisories/RUSTSEC-2022-0013.html)

1.0.7
-----
- Switch to `syslog` 6 and `env_logger` 0.9 to fix RUSTSEC advisories

1.0.6
-----
- Bump dependencies
- Improve graceful shutdowns
- Add `--dump-config` to generate a config
- Clean up stats server
- fix PROXY protocol implementation
- Bump edition to 2021 (MRSV is therefore 1.56.0)

1.0.5
-----
- Minor dependency bumps

1.0.4
-----
- Include local and peer address in in-flight connections on the control socket
- Bump to Tokio 1.x
- Add some more metrics
- Fatal if config includes invalid fields

1.0.3
----
- You can now pass a list of addresses to listen on
- When SIGTERM or SIGINT is received, shut down gracefully (unbind listening sockets but wait for in-flight sessions to end) for up to `shutdown-timeout-ms` milliseconds
- Add `-C` flag to check config and exit
- Added `stats-socket-mode` configuration parameter to set the permissions on a domain stats socket

1.0.2
-----
- `RSV` should always be set to 0x00
- Send response for unsupported commands after we finish reading the whole request
- Add some more metrics

1.0.1
-----
- Fix bug with unix domain stats sockets

1.0.0
-----
- Initial release
