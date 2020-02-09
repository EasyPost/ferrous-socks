use std::error::Error;
use std::env;
use std::net::{SocketAddr, IpAddr};
use std::time::Duration;

use byteorder::{NetworkEndian, ByteOrder};
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;
use derive_more::Display;
use log::{info, warn, error};
use clap::{self, Arg};

mod proxy;
mod config;

async fn handshake_auth(socket: &mut TcpStream) -> Result<bool, tokio::io::Error> {
    let mut init_buf = [0u8; 2];
    socket.read_exact(&mut init_buf).await?;
    if init_buf[0] != 0x05 {
        socket.write_all(&[0x05u8, 0xff]).await?;
        return Ok(false);
    }
    let num_auths = init_buf[1];
    if num_auths > 0xfe {
        socket.write_all(&[0x05u8, 0xff]).await?;
        return Ok(false);
    }
    let mut auths = vec![0u8; num_auths as usize];
    socket.read_exact(&mut auths).await?;
    if auths.iter().any(|&i| i == 0u8) {
        socket.write_all(&[0x5u8, 0x00u8]).await?;
        Ok(true)
    } else {
        socket.write_all(&[05u8, 0xffu8]).await?;
        Ok(false)
    }
}

#[derive(Debug)]
enum Address {
    IpAddr(IpAddr),
    DomainName(String)
}

#[derive(Debug)]
struct Request {
    address: Address,
    dport: u16,
}

impl Request {
    async fn connect(self) -> Result<TcpStream, tokio::io::Error> {
        let conn = match self.address {
            Address::IpAddr(i) => TcpStream::connect((i, self.dport)).await?,
            Address::DomainName(d) => TcpStream::connect((d.as_str(), self.dport)).await?,
        };
        Ok(conn)
    }
}


#[derive(Debug, Display)]
enum RequestError {
    BadAddressType,
    IoError(tokio::io::Error),
}

impl Error for RequestError { }

impl From<tokio::io::Error> for RequestError {
    fn from(t: tokio::io::Error) -> Self {
        RequestError::IoError(t)
    }
}

enum Reply {
    Success,
    SocksFailure,
    ConnectionNotAllowed,
    NetworkUnreachable,
    ConnectionRefused,
    TtlExpired,
    CommandNotSupported,
    AddressNotSupported
}

impl Reply {
    fn as_u8(&self) -> u8 {
        use Reply::*;

        match self {
            Success => 0x00,
            SocksFailure => 0x01,
            ConnectionNotAllowed => 0x02,
            NetworkUnreachable => 0x03,
            ConnectionRefused => 0x04,
            TtlExpired => 0x05,
            CommandNotSupported => 0x07,
            AddressNotSupported => 0x08,
        }
    }

    async fn write_error<A: AsyncWrite + Unpin>(&self, into: &mut A) -> Result<(), tokio::io::Error> {
        into.write_all(&[0x05, self.as_u8(), 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await
    }
}

async fn read_request(socket: &mut TcpStream, address: SocketAddr) -> Result<Option<Request>, RequestError> {
    let mut fixed_buf = [0u8; 4];
    socket.read_exact(&mut fixed_buf).await?;
    let ver = fixed_buf[0];
    let cmd = fixed_buf[1];
    if ver != 0x05 {
        Reply::SocksFailure.write_error(socket).await?;
        return Ok(None);
    }
    if cmd != 0x01 {
        Reply::CommandNotSupported.write_error(socket).await?;
        return Ok(None);
    }
    let address = match fixed_buf[3] {
        0x01 => {
            let mut buf = [0u8; 4];
            socket.read_exact(&mut buf).await?;
            Address::IpAddr(IpAddr::V4(buf.into()))
        },
        0x03 => {
            let mut len_buf = [0u8; 1];
            socket.read_exact(&mut len_buf).await?;
            let mut name = vec![0u8; len_buf[0] as usize];
            socket.read_exact(&mut name).await?;
            Address::DomainName(String::from_utf8(name).unwrap())
        },
        0x04 => {
            let mut buf = [0u8; 16];
            socket.read_exact(&mut buf).await?;
            Address::IpAddr(IpAddr::V6(buf.into()))
        }
        _ => return Err(RequestError::BadAddressType)
    };
    let mut port_buf = [0u8; 2];
    socket.read_exact(&mut port_buf).await?;
    let dport = NetworkEndian::read_u16(&port_buf);
    Ok(Some(Request {
        address,
        dport
    }))
}

async fn handle_one_connection(mut socket: TcpStream, address: SocketAddr) -> Result<bool, Box<dyn Error>> {
    if ! handshake_auth(&mut socket).await? {
        return Ok(false);
    }
    let request = read_request(&mut socket, address).await?;
    if let Some(request) = request {
        let mut conn = match tokio::time::timeout(
                Duration::from_millis(3000),
                request.connect()
            ).await {
            Ok(c) => match c {
                Ok(c) => c,
                Err(e) => {
                    Reply::NetworkUnreachable.write_error(&mut socket).await?;
                    return Ok(false);
                }
            }
            Err(e) => {
                warn!("timeout connecting: {:?}", e);
                Reply::TtlExpired.write_error(&mut socket).await?;
                return Ok(false);
            }
        };
        let local_end = conn.local_addr()?;
        socket.write_all(&[0x05, 0x00, 0x01, match local_end {
            SocketAddr::V4(_) => 0x01,
            SocketAddr::V6(_) => 0x04
        }]).await?;
        match local_end.ip() {
            IpAddr::V4(i) => socket.write_all(&i.octets()).await?,
            IpAddr::V6(i) => socket.write_all(&i.octets()).await?,
        };
        let mut buf = [0u8; 2];
        NetworkEndian::write_u16(&mut buf, local_end.port());
        socket.write_all(&buf).await?;
        let (mut conn_r, mut conn_w) = conn.split();
        let (mut socket_r,  mut socket_w) = socket.split();
        let (first, second) = tokio::join!(
            tokio::io::copy(&mut conn_r, &mut socket_w),
            tokio::io::copy(&mut socket_r, &mut conn_w)
        );
        first?;
        second?;
        Ok(true)
    } else {
        Ok(false)
    }
}

async fn handle_one_connection_wrapper(socket: TcpStream, address: SocketAddr) {
    match tokio::time::timeout(Duration::from_secs(300000), handle_one_connection(socket, address)).await {
        Ok(Ok(_)) => (),
        Ok(Err(e)) => error!("error handling session: {:?}", e),
        Err(_) => eprintln!("session timed out!"),
    }
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let matches = clap::App::new(env!("CARGO_PKG_NAME"))
                            .version(env!("CARGO_PKG_VERSION"))
                            .author("EasyPost <oss@easypost.com>")
                            .about(env!("CARGO_PKG_DESCRIPTION"))
                            .arg(Arg::with_name("config")
                                     .short("c")
                                     .long("config")
                                     .value_name("PATH")
                                     .help("Path to configuration TOML file")
                                     .takes_value(true)
                                     .required(true))
                            .get_matches();

    let conf = config::Config::from_path(matches.value_of("config").unwrap())?;

    // Next up we create a TCP listener which will listen for incoming
    // connections. This TCP listener is bound to the address we determined
    // above and must be associated with an event loop.
    let mut listener = TcpListener::bind(&conf.bind_address).await?;
    info!("Listening on: {}", conf.bind_address);

    loop {
        // Asynchronously wait for an inbound socket.
        let (socket, address) = listener.accept().await?;

        // And this is where much of the magic of this server happens. We
        // crucially want all clients to make progress concurrently, rather than
        // blocking one on completion of another. To achieve this we use the
        // `tokio::spawn` function to execute the work in the background.
        //
        // Essentially here we're executing a new task to run concurrently,
        // which will allow all of our clients to be processed concurrently.

        tokio::spawn(handle_one_connection_wrapper(socket, address));
    }
}
