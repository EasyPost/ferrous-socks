use std::env;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use byteorder::{ByteOrder, NetworkEndian};
use clap::{self, Arg};
use derive_more::Display;
use futures::future::FutureExt;
use log::{debug, error, info, warn};
use net2::unix::UnixTcpBuilderExt;
use net2::TcpBuilder;
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;
use tokio::signal::unix::SignalKind;
use tokio::stream::StreamExt;

mod acl;
mod config;
mod proxy;
mod reply;
mod request;
mod stats;
mod stats_socket;
mod util;

use config::Config;
use reply::Reply;
use request::{Address, Connection, Request, Version};

const LISTEN_BACKLOG: i32 = 128;

enum HandshakeResult {
    Okay,
    AuthenticatedAs(String),
    Failed,
    Version4([u8; 2]),
}

async fn authenticate_rfc1929(socket: &mut TcpStream) -> Result<Option<String>, tokio::io::Error> {
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
async fn handshake_auth(socket: &mut TcpStream) -> Result<HandshakeResult, tokio::io::Error> {
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

#[derive(Debug, Display)]
enum RequestError {
    BadAddressType,
    IoError(tokio::io::Error),
}

impl Error for RequestError {}

impl From<tokio::io::Error> for RequestError {
    fn from(t: tokio::io::Error) -> Self {
        RequestError::IoError(t)
    }
}

/// Read a SOCKSv4 or SOCKSv5 request from the stream
async fn read_request(
    socket: &mut TcpStream,
    already_read: Option<[u8; 2]>,
) -> Result<Option<Request>, RequestError> {
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
            Request::new(address, dport, version, None)
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

async fn handle_one_connection(
    mut socket: TcpStream,
    address: SocketAddr,
    config: Arc<Config>,
    stats: &stats::Stats,
    conn_id: u64,
) -> Result<bool, Box<dyn Error>> {
    let address = if config.expect_proxy {
        let header = proxy::read_proxy_header(&mut socket, address).await?;
        header.source_address
    } else {
        address
    };
    debug!("{}: accepted connection from {:?}", conn_id, address);
    let mut username = None;
    let already_read = match handshake_auth(&mut socket).await? {
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
    let request = read_request(&mut socket, already_read).await?;
    if let Some(mut request) = request {
        request.set_username(username);
        if let Some(ref u) = request.username {
            debug!("{}: authenticated as {:?}", conn_id, u);
        } else {
            debug!("{}: unauthenticated", conn_id);
        }
        let version = request.ver;
        stats.set_request(conn_id, &request).await;
        let mut conn = match tokio::time::timeout(
            Duration::from_millis(config.connect_timeout_ms.into()),
            request.clone().connect(&config),
        )
        .await
        {
            Ok(c) => match c {
                Ok(Connection::Connected(c)) => c,
                Ok(Connection::ConnectionNotAllowed) => {
                    warn!("{}: denying connection to {:?}", conn_id, request);
                    Reply::ConnectionNotAllowed
                        .write_error(&mut socket, version)
                        .await?;
                    return Ok(false);
                }
                Ok(Connection::AddressNotSupported) => {
                    warn!("{}: bad address family to to {:?}", conn_id, request);
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
            },
            Err(e) => {
                warn!("{}: timeout connecting: {:?}", conn_id, e);
                Reply::TtlExpired.write_error(&mut socket, version).await?;
                stats.handshake_timeout();
                return Ok(false);
            }
        };
        let remote_end = conn.peer_addr()?;
        let local_end = conn.local_addr()?;
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
                socket.write_all(&buf).await?;
            }
            Version::Four => {
                socket
                    .write_all(&[0x00, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                    .await?;
            }
        }
        let (mut conn_r, mut conn_w) = conn.split();
        let (mut socket_r, mut socket_w) = socket.split();
        let (first, second) = tokio::join!(
            util::copy_then_shutdown(&mut conn_r, &mut socket_w),
            util::copy_then_shutdown(&mut socket_r, &mut conn_w)
        );
        first?;
        second?;
        Ok(true)
    } else {
        Ok(false)
    }
}

async fn handle_one_connection_wrapper(
    socket: TcpStream,
    address: SocketAddr,
    config: Arc<Config>,
    stats: Arc<stats::Stats>,
) {
    let conn_id = stats.start_request(address).await;
    if let Some(total_timeout_ms) = config.total_timeout_ms {
        let timeout = Duration::from_millis(total_timeout_ms.into());
        match tokio::time::timeout(
            timeout,
            handle_one_connection(socket, address, config, &stats, conn_id),
        )
        .await
        {
            Ok(Ok(_)) => {
                stats.session_success();
            }
            Ok(Err(e)) => error!("error handling session {}: {:?}", conn_id, e),
            Err(_) => {
                warn!("session {} timed out!", conn_id);
                stats.session_timeout();
            }
        }
    } else {
        match handle_one_connection(socket, address, config, &stats, conn_id).await {
            Ok(_) => (),
            Err(e) => error!("error handling session {}: {:?}", conn_id, e),
        }
    }
    info!("{}: finishing request", conn_id);
    stats.finish_request(conn_id).await;
}

enum StreamResult {
    Stream(TcpStream),
    Signal,
}

async fn handle_connections(
    mut listener: TcpListener,
    conf: Arc<Config>,
    stats: Arc<stats::Stats>,
) -> Result<(), tokio::io::Error> {
    let interrupt_signal_stream =
        tokio::signal::unix::signal(SignalKind::interrupt())?.map(|_| StreamResult::Signal);
    let term_signal_stream =
        tokio::signal::unix::signal(SignalKind::terminate())?.map(|_| StreamResult::Signal);

    let mut stream = listener
        .incoming()
        .filter_map(|s| s.ok().map(|os| StreamResult::Stream(os)))
        .merge(interrupt_signal_stream)
        .merge(term_signal_stream);

    let outstanding = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    while let Some(result) = stream.next().await {
        match result {
            StreamResult::Stream(socket) => {
                let address = socket.peer_addr()?;

                let my_config = Arc::clone(&conf);
                let my_stats = Arc::clone(&stats);
                let my_outstanding = Arc::clone(&outstanding);

                my_outstanding.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(
                    handle_one_connection_wrapper(socket, address, my_config, my_stats).map(
                        move |r| {
                            my_outstanding.fetch_sub(1, Ordering::SeqCst);
                            r
                        },
                    ),
                );
            }
            StreamResult::Signal => {
                info!("got signal in listener");
                break;
            }
        }
    }
    // eagerly drop the stream to shut down the listening socket
    drop(stream);
    drop(listener);
    // this is cheesy. we should probably have something other than time-based
    // polling here.
    let start_poll = Instant::now();
    let expiration = Duration::from_millis(conf.shutdown_timeout_ms);
    while outstanding.load(Ordering::Relaxed) != 0 {
        if start_poll.elapsed() > expiration {
            warn!("giving up on outstanding sockets and exiting anyway!");
            break;
        }
        debug!("waiting for outstanding tasks to exit");
        tokio::time::delay_for(Duration::from_millis(500)).await;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let matches = clap::App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author("EasyPost <oss@easypost.com>")
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .value_name("PATH")
                .help("Path to configuration TOML file")
                .takes_value(true)
                .required(true),
        )
        .get_matches();

    let conf = Arc::new(Config::from_path(matches.value_of("config").unwrap())?);

    conf.initialize_logging();

    let stats = Arc::new(stats::Stats::new());

    if let Some(ref stats_socket_listen_address) = conf.stats_socket_listen_address {
        if stats_socket_listen_address.starts_with('/')
            || stats_socket_listen_address.starts_with('.')
        {
            let listener = stats_socket::bind_unix_listener(stats_socket_listen_address).expect(
                format!(
                    "failed to bind to domain socket {:?}",
                    stats_socket_listen_address
                )
                .as_str(),
            );
            tokio::spawn(stats_socket::stats_main_unix(listener, Arc::clone(&stats)));
        } else {
            let listener = tokio::net::TcpListener::bind(stats_socket_listen_address)
                .await
                .expect(
                    format!(
                        "failed to bind to TCP socket {:?}",
                        stats_socket_listen_address
                    )
                    .as_str(),
                );
            tokio::spawn(stats_socket::stats_main_tcp(listener, Arc::clone(&stats)));
        }
    }

    let listen_results = conf
        .listen_address
        .iter()
        .map(|addr| {
            let listener = if addr.is_ipv6() {
                TcpBuilder::new_v6().expect("failed to create IPv6 socket")
            } else {
                TcpBuilder::new_v4().expect("failed to create IPv4 socket")
            };
            let listener = listener
                .reuse_address(true)
                .expect("failed to set SO_REUSEADDR");

            let listener = if addr.is_ipv6() {
                listener.only_v6(false).expect("failed to set IPV6_V6ONLY")
            } else {
                listener
            };

            #[cfg(all(unix, not(any(target_os = "solaris"))))]
            let listener = listener
                .reuse_port(conf.reuse_port)
                .expect("failed to set SO_REUSEPORT")
                .bind(addr)
                .expect(format!("failed to bind to {:?}", addr).as_str());
            info!("Listening on: {}", addr);

            TcpListener::from_std(
                listener
                    .listen(LISTEN_BACKLOG)
                    .expect("failed to listen on socket"),
            )
            .expect("failed to map sync socket to async socket")
        })
        .map(|listener| {
            tokio::spawn(handle_connections(
                listener,
                Arc::clone(&conf),
                Arc::clone(&stats),
            ))
        })
        .collect::<futures::stream::FuturesUnordered<_>>()
        .collect::<Vec<_>>()
        .await;
    info!("listen results: {:?}", listen_results);
    Ok(())
}
