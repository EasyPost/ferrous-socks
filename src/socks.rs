use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::Context;
use byteorder::{ByteOrder, NetworkEndian};
use futures_util::future::FutureExt;
use futures_util::stream::StreamExt;
use log::{debug, error, info, warn};
use permit::Permit;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::config::Config;
use crate::reply::Reply;
use crate::request::{Address, Connection, Request, Version};
use crate::stats::Stats;

const LISTEN_BACKLOG: u32 = 128;

#[derive(Debug, PartialEq, Eq)]
enum HandshakeResult {
    Okay,
    AuthenticatedAs(String),
    Failed,
    Version4([u8; 2]),
}

async fn authenticate_rfc1929<S>(socket: &mut S) -> Result<Option<String>, tokio::io::Error>
where
    S: AsyncRead + AsyncWrite + Unpin + 'static,
{
    let mut buf = [0u8; 2];
    socket.read_exact(&mut buf).await?;
    // VER = 0x01
    if buf[0] != 0x01 {
        return Ok(None);
    }
    let mut username = vec![0u8; buf[1] as usize];
    socket.read_exact(&mut username).await?;
    let mut password_len = [0u8; 1];
    socket.read_exact(&mut password_len).await?;
    let mut password = vec![0u8; password_len[0] as usize];
    socket.read_exact(&mut password).await?;
    socket.write_all(&[0x1u8, 0x0u8]).await?;
    Ok(Some(String::from_utf8_lossy(&username).into_owned()))
}

/// Perform the RFC1928 authentication handshake
///
/// Prerequisite: Nothing has been read from the socket yet
///
/// If returns HandshakeResult::Failed, the stream should be closed. Otherwise,
/// we are (to some degree) authenticated.
async fn handshake_auth<S>(socket: &mut S) -> Result<HandshakeResult, tokio::io::Error>
where
    S: AsyncRead + AsyncWrite + Unpin + 'static,
{
    // If this is SOCKS4, the first byte is 0x04 and the second byte is actually not part of the
    // handshake. Oops!
    let mut init_buf = [0u8; 2];
    socket.read_exact(&mut init_buf).await?;
    if init_buf[0] == 0x04 {
        return Ok(HandshakeResult::Version4(init_buf));
    }
    // If this is SOCKS5, the first byte is 0x05 and the second byte is the number of auth
    // mechanisms supported
    if init_buf[0] != 0x05 {
        socket.write_all(&[0x05u8, 0xff]).await?;
        return Ok(HandshakeResult::Failed);
    }
    let num_auths = init_buf[1];
    if num_auths > 0xfe {
        socket.write_all(&[0x05u8, 0xff]).await?;
        return Ok(HandshakeResult::Failed);
    }
    // Each auth mechanism is a single byte
    let mut auths = vec![0u8; num_auths as usize];
    socket.read_exact(&mut auths).await?;
    // Try more sophisticated (higher-valued) auth mechanisms first
    auths.sort_by(|a, b| b.cmp(a));
    for auth in auths {
        if auth == 0u8 {
            // 0x00 == unauthenticated. great
            socket.write_all(&[0x5u8, 0x00u8]).await?;
            return Ok(HandshakeResult::Okay);
        } else if auth == 0x02u8 {
            // 0x02 = username+password auth as per RFC1929
            socket.write_all(&[0x5u8, 0x2u8]).await?;
            if let Some(username) = authenticate_rfc1929(socket).await? {
                return Ok(HandshakeResult::AuthenticatedAs(username));
            } else {
                warn!("1929 authentication failed; aborting");
                socket.write_all(&[0x1u8, 0xffu8]).await?;
            }
        }
    }
    // if we get here, we didn't have any supported auth mechainisms. oops.
    socket.write_all(&[0x5u8, 0xffu8]).await?;
    Ok(HandshakeResult::Failed)
}

#[derive(Debug, Error)]
enum RequestError {
    #[error("Bad address type")]
    BadAddressType,
    #[error("I/O Error: {0}")]
    Io(#[from] tokio::io::Error),
}

/// Read a SOCKSv4 or SOCKSv5 request from the stream
async fn read_request<S>(
    socket: &mut S,
    already_read: Option<[u8; 2]>,
    username: Option<String>,
) -> Result<Option<Request>, RequestError>
where
    S: AsyncRead + AsyncWrite + Unpin + 'static,
{
    let (ver, cmd, addr_type) = if let Some(already_read) = already_read {
        (already_read[0], already_read[1], 0x01u8)
    } else {
        let mut fixed_buf = [0u8; 4];
        socket.read_exact(&mut fixed_buf).await?;
        let ver = fixed_buf[0];
        let cmd = fixed_buf[1];
        let addr_type = fixed_buf[3];
        (ver, cmd, addr_type)
    };
    let version = match ver {
        4 => Version::Four,
        5 => Version::Five,
        _ => {
            Reply::SocksFailure
                .write_error(socket, Version::Five)
                .await?;
            return Ok(None);
        }
    };
    let request = match version {
        Version::Four => {
            let mut buf = [0u8; 6];
            socket.read_exact(&mut buf).await?;
            let mut ip_buf = [0u8; 4];
            ip_buf.copy_from_slice(&buf[2..6]);
            let dport = NetworkEndian::read_u16(&buf[0..2]);
            let ip_addr: Ipv4Addr = ip_buf.into();
            let mut username = Vec::new();
            let mut buf = [0u8; 1];
            loop {
                socket.read_exact(&mut buf).await?;
                if buf[0] == 0x0 {
                    break;
                }
                username.push(buf[0]);
            }
            let address = if ip_addr.octets()[0..3] == [0, 0, 0] {
                let mut addr_buf = Vec::new();
                loop {
                    socket.read_exact(&mut buf).await?;
                    if buf[0] == 0x0 {
                        break;
                    }
                    addr_buf.push(buf[0]);
                }
                Address::DomainName(String::from_utf8_lossy(&addr_buf).into_owned())
            } else {
                Address::IpAddr(IpAddr::V4(ip_addr))
            };
            Request::new(
                address,
                dport,
                version,
                Some(String::from_utf8_lossy(&username).into_owned()),
            )
        }
        Version::Five => {
            let address = match addr_type {
                0x01 => {
                    let mut buf = [0u8; 4];
                    socket.read_exact(&mut buf).await?;
                    Address::IpAddr(IpAddr::V4(buf.into()))
                }
                0x03 => {
                    let mut len_buf = [0u8; 1];
                    socket.read_exact(&mut len_buf).await?;
                    let mut name = vec![0u8; len_buf[0] as usize];
                    socket.read_exact(&mut name).await?;
                    Address::DomainName(String::from_utf8_lossy(&name).into_owned())
                }
                0x04 => {
                    let mut buf = [0u8; 16];
                    socket.read_exact(&mut buf).await?;
                    Address::IpAddr(IpAddr::V6(buf.into()))
                }
                _ => return Err(RequestError::BadAddressType),
            };
            let mut port_buf = [0u8; 2];
            socket.read_exact(&mut port_buf).await?;
            let dport = NetworkEndian::read_u16(&port_buf);
            Request::new(address, dport, version, username)
        }
    };
    if cmd != 0x01 {
        Reply::CommandNotSupported
            .write_error(socket, Version::Five)
            .await?;
        return Ok(None);
    }
    Ok(Some(request))
}

async fn handle_one_connection<S>(
    mut socket: S,
    address: SocketAddr,
    config: Arc<Config>,
    stats: &Stats,
    conn_id: u64,
) -> Result<bool, anyhow::Error>
where
    S: AsyncRead + AsyncWrite + Unpin + 'static,
{
    let address = if config.expect_proxy {
        let header = match tokio::time::timeout(
            config.proxy_protocol_timeout,
            crate::proxy::read_proxy_header(&mut socket, address),
        )
        .await
        {
            Ok(h) => h.context("error reading PROXY protocol")?,
            Err(e) => {
                warn!("{}: timeout reading PROXY header: {:?}", conn_id, e);
                stats.proxy_protocol_timeout();
                return Ok(false);
            }
        };
        if header.transport != crate::proxy::Transport::Stream {
            anyhow::bail!("Invalid PROXY transport in header {:?}", header);
        }
        log::trace!("PROXY request {:?}", header);
        header.source_address
    } else {
        address
    };
    debug!("{}: accepted connection from {:?}", conn_id, address);
    let mut username = None;
    let already_read = match handshake_auth(&mut socket)
        .await
        .context("error handshaking auth")?
    {
        HandshakeResult::Okay => None,
        HandshakeResult::AuthenticatedAs(u) => {
            stats.handshake_authenticated();
            username = Some(u);
            None
        }
        HandshakeResult::Failed => {
            stats.handshake_failed();
            debug!("{}: handshake failed", conn_id);
            return Ok(false);
        }
        HandshakeResult::Version4(bytes) => Some(bytes),
    };
    stats.handshake_success();
    debug!("{}: handshake succeeded", conn_id);
    let request = read_request(&mut socket, already_read, username)
        .await
        .context("error reading request")?;
    if let Some(request) = request {
        if let Some(ref u) = request.username {
            debug!("{}: authenticated as {:?}", conn_id, u);
        } else {
            debug!("{}: unauthenticated", conn_id);
        }
        let version = request.ver;
        stats.set_request(conn_id, &request).await;
        let mut conn =
            match tokio::time::timeout(config.connect_timeout, request.clone().connect(&config))
                .await
            {
                Ok(c) => {
                    stats.record_connection(&c);
                    match c {
                        Ok(Connection::Connected(c)) => c,
                        Ok(Connection::NotAllowed) => {
                            warn!("{}: denying connection to {:?}", conn_id, request);
                            Reply::ConnectionNotAllowed
                                .write_error(&mut socket, version)
                                .await?;
                            return Ok(false);
                        }
                        Ok(Connection::AddressNotSupported) => {
                            warn!("{}: bad address family to {:?}", conn_id, request);
                            Reply::AddressNotSupported
                                .write_error(&mut socket, version)
                                .await?;
                            return Ok(false);
                        }
                        Ok(Connection::SocksFailure) => {
                            warn!("{}: failure (resolution?) to {:?}", conn_id, request);
                            Reply::SocksFailure
                                .write_error(&mut socket, version)
                                .await?;
                            return Ok(false);
                        }
                        Err(e) => {
                            Reply::NetworkUnreachable
                                .write_error(&mut socket, version)
                                .await?;
                            warn!("error connecting: {:?}", e);
                            return Ok(false);
                        }
                    }
                }
                Err(e) => {
                    warn!("{}: timeout connecting: {:?}", conn_id, e);
                    Reply::TtlExpired.write_error(&mut socket, version).await?;
                    stats.handshake_timeout();
                    return Ok(false);
                }
            };
        let remote_end = conn.peer_addr().context("error getting peer address")?;
        let local_end = conn.local_addr().context("error getting local address")?;
        stats.set_connection(conn_id, local_end, remote_end).await;
        info!(
            "{}: connected to {:?} from {:?}",
            conn_id, remote_end, local_end
        );
        match version {
            Version::Five => {
                socket
                    .write_all(&[
                        0x05,
                        0x00,
                        0x00,
                        match local_end {
                            SocketAddr::V4(_) => 0x01,
                            SocketAddr::V6(_) => 0x04,
                        },
                    ])
                    .await?;
                match local_end.ip() {
                    IpAddr::V4(i) => socket.write_all(&i.octets()).await?,
                    IpAddr::V6(i) => socket.write_all(&i.octets()).await?,
                };
                let mut buf = [0u8; 2];
                NetworkEndian::write_u16(&mut buf, local_end.port());
                socket
                    .write_all(&buf)
                    .await
                    .context("error writing v5 response header")?;
            }
            Version::Four => {
                socket
                    .write_all(&[0x00, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                    .await
                    .context("error writing v4 response header")?;
            }
        }
        let (stoc, ctos) = tokio::io::copy_bidirectional(&mut conn, &mut socket)
            .await
            .context("error copying body")?;
        stats.record_traffic(stoc, ctos);
        Ok(true)
    } else {
        Ok(false)
    }
}

async fn handle_one_connection_wrapper(
    socket: TcpStream,
    address: SocketAddr,
    config: Arc<Config>,
    stats: Arc<Stats>,
    permit: Permit,
) {
    let conn_id = stats.start_request(address).await;
    if let Some(timeout) = config.total_timeout {
        match tokio::time::timeout(
            timeout,
            handle_one_connection(socket, address, config, &stats, conn_id),
        )
        .await
        {
            Ok(Ok(_)) => {
                stats.session_success();
            }
            Ok(Err(e)) => {
                stats.session_error();
                error!("error handling session {}: {:?}", conn_id, e);
            }
            Err(_) => {
                warn!("session {} timed out!", conn_id);
                stats.session_timeout();
            }
        }
    } else {
        match handle_one_connection(socket, address, config, &stats, conn_id).await {
            Ok(_) => {
                stats.session_success();
            }
            Err(e) => {
                stats.session_error();
                error!("error handling session {}: {:?}", conn_id, e);
            }
        }
    }
    info!("{}: finishing request", conn_id);
    stats.finish_request(conn_id).await;
    drop(permit);
}

async fn handle_connections(
    listener: TcpListener,
    conf: Arc<Config>,
    stats: Arc<Stats>,
    permit: Permit,
) -> Result<(), tokio::io::Error> {
    let outstanding = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let listen_permit = permit.new_sub();

    let handled = tokio_stream::wrappers::TcpListenerStream::new(listener)
        .take_until(listen_permit)
        .filter_map(|socket| async { socket.ok().and_then(|s| s.peer_addr().ok().map(|p| (s, p))) })
        .map(|(socket, address)| {
            let my_config = Arc::clone(&conf);
            let my_stats = Arc::clone(&stats);
            let my_outstanding = Arc::clone(&outstanding);

            my_outstanding.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(
                handle_one_connection_wrapper(socket, address, my_config, my_stats, permit.clone())
                    .map(move |r| {
                        my_outstanding.fetch_sub(1, Ordering::SeqCst);
                        r
                    }),
            );
        })
        .fold(0usize, |acc, _| async move { acc.wrapping_add(1) })
        .await;
    debug!("handled {} connections before getting shut down", handled);
    Ok(())
}

// you have to be inside an async fn to call tokio::spawn, but actually this is entirely
// synchronous
pub async fn run(
    conf: Arc<Config>,
    stats: Arc<Stats>,
    permit: Permit,
) -> anyhow::Result<(Vec<tokio::task::JoinHandle<std::io::Result<()>>>, Permit)> {
    let handles = conf
        .listen_address
        .iter()
        .map(|addr| {
            let listener = if addr.is_ipv6() {
                tokio::net::TcpSocket::new_v6().expect("failed to create IPv6 socket")
            } else {
                tokio::net::TcpSocket::new_v4().expect("failed to create IPv4 socket")
            };

            listener
                .set_reuseaddr(true)
                .context("failed to set SO_REUSEADDR")?;

            #[cfg(all(unix, not(any(target_os = "solaris"))))]
            listener
                .set_reuseport(conf.reuse_port)
                .context("failed to set SO_REUSEPORT")?;

            listener
                .bind(*addr)
                .with_context(|| format!("failed to bind to {:?}", addr))?;
            info!("Listening on: {}", addr);

            listener
                .listen(LISTEN_BACKLOG)
                .context("failed to listen on socket")
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|listener| {
            tokio::spawn(handle_connections(
                listener,
                Arc::clone(&conf),
                Arc::clone(&stats),
                permit.new_sub(),
            ))
        })
        .collect::<Vec<tokio::task::JoinHandle<_>>>();
    Ok((handles, permit))
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::{authenticate_rfc1929, handshake_auth, read_request, HandshakeResult};
    use crate::request::{Address, Request, Version};

    #[tokio::test]
    async fn test_authenticate_rfc1929() {
        let (mut lhs, mut rhs) = tokio::net::UnixStream::pair().unwrap();

        let h = tokio::spawn(async move {
            lhs.write_all(&hex!("01 04 75736572 07 68756e74657232"))
                .await?;
            let mut buf = [0xffu8; 2];
            lhs.read_exact(&mut buf).await?;
            Ok::<_, tokio::io::Error>(buf)
        });
        assert_eq!(
            authenticate_rfc1929(&mut rhs).await.unwrap(),
            Some("user".to_string())
        );
        let buf = h.await.unwrap().unwrap();
        assert_eq!(buf, hex!("0100"));
    }

    #[tokio::test]
    async fn test_handshake_auth_no_methods() {
        let (mut lhs, mut rhs) = tokio::net::UnixStream::pair().unwrap();

        let h = tokio::spawn(async move {
            lhs.write_all(&hex!("05 00")).await?;
            let mut buf = [0xffu8; 2];
            lhs.read_exact(&mut buf).await?;
            Ok::<_, tokio::io::Error>(buf)
        });
        let result = handshake_auth(&mut rhs).await.unwrap();
        assert_eq!(result, HandshakeResult::Failed);
        let buf = h.await.unwrap().unwrap();
        assert_eq!(buf, hex!("05ff"));
    }

    #[tokio::test]
    async fn test_handshake_auth_prefers_auth() {
        let (mut lhs, mut rhs) = tokio::net::UnixStream::pair().unwrap();

        let h = tokio::spawn(async move {
            lhs.write_all(&hex!("05 02 00 02")).await?;
            let mut buf = [0xffu8; 2];
            lhs.read_exact(&mut buf).await?;
            assert!(&buf == &[0x05u8, 0x02u8]);
            lhs.write_all(&hex!("01 04 75736572 07 68756e74657232"))
                .await?;
            lhs.read_exact(&mut buf).await?;
            Ok::<_, tokio::io::Error>(buf)
        });
        let result = handshake_auth(&mut rhs).await.unwrap();
        assert_eq!(result, HandshakeResult::AuthenticatedAs("user".to_string()));
        let buf = h.await.unwrap().unwrap();
        assert_eq!(buf, hex!("0100"));
    }

    #[tokio::test]
    async fn test_handshake_auth_accepts_no_auth() {
        let (mut lhs, mut rhs) = tokio::net::UnixStream::pair().unwrap();

        let h = tokio::spawn(async move {
            lhs.write_all(&hex!("05 02 00 7f")).await?;
            let mut buf = [0xffu8; 2];
            lhs.read_exact(&mut buf).await?;
            assert!(&buf == &[0x05u8, 0x00u8]);
            Ok::<_, tokio::io::Error>(buf)
        });
        let result = handshake_auth(&mut rhs).await.unwrap();
        assert_eq!(result, HandshakeResult::Okay);
        let buf = h.await.unwrap().unwrap();
        assert_eq!(buf, hex!("0500"));
    }

    #[tokio::test]
    async fn test_read_request_v4() {
        let (mut lhs, mut rhs) = tokio::net::UnixStream::pair().unwrap();

        let h = tokio::spawn(async move {
            let req = hex!("0050 08080404 62617a00");
            lhs.write_all(&req).await?;
            Ok::<_, tokio::io::Error>(())
        });

        let req = read_request(&mut rhs, Some(hex!("0401")), None)
            .await
            .unwrap();
        assert_eq!(
            req,
            Some(Request {
                address: Address::IpAddr("8.8.4.4".parse().unwrap()),
                dport: 80,
                ver: Version::Four,
                username: Some("baz".to_owned()),
            })
        );
        h.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_read_request_v5_ipv4() {
        let (mut lhs, mut rhs) = tokio::net::UnixStream::pair().unwrap();

        let h = tokio::spawn(async move {
            let req = hex!("05 01 00 01 08080404 0050");
            lhs.write_all(&req).await?;
            Ok::<_, tokio::io::Error>(())
        });

        let req = read_request(&mut rhs, None, Some("foo".to_owned()))
            .await
            .unwrap();
        assert_eq!(
            req,
            Some(Request {
                address: Address::IpAddr("8.8.4.4".parse().unwrap()),
                dport: 80,
                ver: Version::Five,
                username: Some("foo".to_owned()),
            })
        );
        h.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_read_request_v5_address() {
        let (mut lhs, mut rhs) = tokio::net::UnixStream::pair().unwrap();

        let h = tokio::spawn(async move {
            let req = hex!("05 01 00 03 0f 7777772e6578616d706c652e636f6d 0050");
            lhs.write_all(&req).await?;
            Ok::<_, tokio::io::Error>(())
        });

        let req = read_request(&mut rhs, None, None).await.unwrap();
        assert_eq!(
            req,
            Some(Request {
                address: Address::DomainName("www.example.com".to_owned()),
                dport: 80,
                ver: Version::Five,
                username: None,
            })
        );
        h.await.unwrap().unwrap();
    }
}
