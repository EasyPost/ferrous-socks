use std::error::Error;
use std::io::Cursor;
use std::net::{IpAddr, SocketAddr};

use byteorder::NetworkEndian;
use derive_more::Display;
use tokio::net::TcpStream;
use tokio::prelude::*;

#[derive(Debug)]
pub(crate) enum Mode {
    Local,
    Proxy,
}

#[derive(Debug)]
pub(crate) enum Family {
    Unspec,
    Inet,
    Inet6,
    Unix,
}

#[derive(Debug)]
pub(crate) enum Transport {
    Empty,
    Stream,
    Dgram,
}

#[derive(Debug)]
pub(crate) struct ProxyHeader {
    pub mode: Mode,
    pub family: Family,
    pub transport: Transport,
    pub source_address: SocketAddr,
}

#[derive(Debug, Display)]
pub(crate) enum HeaderError {
    InvalidMagicBytes,
    InvalidVersion(u8),
    InvalidMode(u8),
    InvalidFamily(u8),
    InvalidTransport(u8),
    InvalidVarData(u16),
    IoError(tokio::io::Error),
    UnsupportedFamilyOrAddress,
}

impl Error for HeaderError {}

impl From<tokio::io::Error> for HeaderError {
    fn from(e: tokio::io::Error) -> HeaderError {
        HeaderError::IoError(e)
    }
}

pub(crate) async fn read_proxy_header(
    socket: &mut TcpStream,
    address: SocketAddr,
) -> Result<ProxyHeader, HeaderError> {
    println!("about to read header");
    let mut fixed_header = [0u8; 16];
    println!("read header: {:?}", fixed_header);
    socket.read_exact(&mut fixed_header).await?;
    if fixed_header[..12] != *b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A" {
        return Err(HeaderError::InvalidMagicBytes);
    }
    let version_command = fixed_header[13];
    let family_address = fixed_header[14];
    let remaining_len =
        byteorder::ReadBytesExt::read_u16::<NetworkEndian>(&mut &fixed_header[15..16])?;
    dbg!(&remaining_len);
    let version = version_command >> 4;
    if version != 0x02 {
        return Err(HeaderError::InvalidVersion(version));
    }
    dbg!(&version);
    let mode = match version_command & 0x0f {
        0x00 => Mode::Local,
        0x01 => Mode::Proxy,
        other => return Err(HeaderError::InvalidMode(other)),
    };
    dbg!(&mode);
    let family = match family_address >> 4 {
        0x00 => Family::Unspec,
        0x01 => Family::Inet,
        0x02 => Family::Inet6,
        0x03 => Family::Unix,
        other => return Err(HeaderError::InvalidFamily(other)),
    };
    dbg!(&family);
    let transport = match family_address & 0x0f {
        0x00 => Transport::Empty,
        0x01 => Transport::Stream,
        0x02 => Transport::Dgram,
        other => return Err(HeaderError::InvalidTransport(other)),
    };
    dbg!(&transport);
    let source_address = match family {
        Family::Unix => {
            eprintln!("remaining data is {}", remaining_len);
            address
        }
        Family::Inet => {
            if remaining_len != 12 {
                eprintln!("expected 96 bytes of address; got {:?}", remaining_len);
                return Err(HeaderError::InvalidVarData(remaining_len));
            }
            let mut buf = [0u8; 12];
            socket.read_exact(&mut buf).await?;
            let mut cursor = Cursor::new(buf);
            let source_addr = byteorder::ReadBytesExt::read_u32::<NetworkEndian>(&mut cursor)?;
            let source_addr = IpAddr::V4(source_addr.into());
            let _ = byteorder::ReadBytesExt::read_u32::<NetworkEndian>(&mut cursor);
            let source_port = byteorder::ReadBytesExt::read_u16::<NetworkEndian>(&mut cursor)?;
            SocketAddr::new(source_addr, source_port)
        }
        Family::Inet6 => {
            let mut buf = [0u8; 36];
            let mut ip_buf = [0u8; 16];
            ip_buf.copy_from_slice(&buf[0..16]);
            socket.read_exact(&mut buf).await?;
            let source_addr = IpAddr::V6(ip_buf.into());
            let source_port =
                byteorder::ReadBytesExt::read_u16::<NetworkEndian>(&mut &buf[32..34])?;
            SocketAddr::new(source_addr, source_port)
        }
        Family::Unspec => return Err(HeaderError::UnsupportedFamilyOrAddress),
    };
    Ok(ProxyHeader {
        mode: mode,
        family: family,
        transport: transport,
        source_address: source_address,
    })
}
