use log::error;
use std::io::Cursor;
use std::net::{IpAddr, SocketAddr};

use byteorder::NetworkEndian;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    Local,
    Proxy,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Family {
    Unspec,
    Inet,
    Inet6,
    Unix,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Transport {
    Empty,
    Stream,
    Dgram,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ProxyHeader {
    pub mode: Mode,
    pub family: Family,
    pub transport: Transport,
    pub source_address: SocketAddr,
}

#[derive(Debug, Error)]
pub(crate) enum HeaderError {
    #[error("Invalid magic bytes in PROXY protocol")]
    InvalidMagicBytes,
    #[error("Invalid PROXY version {0}")]
    InvalidVersion(u8),
    #[error("Invalid mode byte {0}")]
    InvalidMode(u8),
    #[error("Invalid family byte {0}")]
    InvalidFamily(u8),
    #[error("Invalid transport byte {0}")]
    InvalidTransport(u8),
    #[error("Invalid variable data of length {0}")]
    InvalidVarData(u16),
    #[error("I/O Error: {0}")]
    Io(#[from] tokio::io::Error),
    #[error("Unsupported family/address")]
    UnsupportedFamilyOrAddress,
}

/// Read the PROXY(v2) protocol
pub(crate) async fn read_proxy_header<S>(
    socket: &mut S,
    address: SocketAddr,
) -> Result<ProxyHeader, HeaderError>
where
    S: AsyncRead + Unpin + 'static,
{
    let mut fixed_header = [0u8; 16];
    socket.read_exact(&mut fixed_header).await?;
    if fixed_header[..12] != *b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A" {
        return Err(HeaderError::InvalidMagicBytes);
    }
    let version_command = fixed_header[12];
    let family_address = fixed_header[13];
    let remaining_len =
        byteorder::ReadBytesExt::read_u16::<NetworkEndian>(&mut &fixed_header[14..16])?;
    let version = version_command >> 4;
    if version != 0x02 {
        return Err(HeaderError::InvalidVersion(version));
    }
    let mode = match version_command & 0x0f {
        0x00 => Mode::Local,
        0x01 => Mode::Proxy,
        other => return Err(HeaderError::InvalidMode(other)),
    };
    let family = match family_address >> 4 {
        0x00 => Family::Unspec,
        0x01 => Family::Inet,
        0x02 => Family::Inet6,
        0x03 => Family::Unix,
        other => return Err(HeaderError::InvalidFamily(other)),
    };
    let transport = match family_address & 0x0f {
        0x00 => Transport::Empty,
        0x01 => Transport::Stream,
        0x02 => Transport::Dgram,
        other => return Err(HeaderError::InvalidTransport(other)),
    };
    let source_address = match family {
        Family::Unix => {
            error!("remaining data is {}", remaining_len);
            address
        }
        Family::Inet => {
            if remaining_len != 12 {
                error!("expected 12 bytes of address; got {:?}", remaining_len);
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
            socket.read_exact(&mut buf).await?;
            ip_buf.copy_from_slice(&buf[0..16]);
            let source_addr = IpAddr::V6(ip_buf.into());
            let source_port =
                byteorder::ReadBytesExt::read_u16::<NetworkEndian>(&mut &buf[32..34])?;
            SocketAddr::new(source_addr, source_port)
        }
        Family::Unspec => return Err(HeaderError::UnsupportedFamilyOrAddress),
    };
    Ok(ProxyHeader {
        mode,
        family,
        transport,
        source_address,
    })
}

#[cfg(test)]
mod tests {
    use super::read_proxy_header;
    use super::{Family, Mode, ProxyHeader, Transport};
    use hex_literal::hex;

    macro_rules! proxy_header_tests {
        ($($label: ident: $value: expr, )*) => {
            $(
            #[tokio::test]
            async fn $label() {
                let (input, expected) = $value;
                let raw = "0.0.0.1:1".parse().unwrap();
                let mut r = std::io::Cursor::new(input);
                let found = read_proxy_header(&mut r, raw).await.expect("should parse");
                assert_eq!(expected, found);
            }
            )*
        }
    }

    proxy_header_tests! {
        ipv4_stream: (
            hex!("0d0a0d0a000d0a515549540a 21 11 000c 08080808 0a0a0a0a 846c 0050"),
            ProxyHeader {
                mode: Mode::Proxy,
                family: Family::Inet,
                transport: Transport::Stream,
                source_address: "8.8.8.8:33900".parse().unwrap()
            }
        ),
        ipv4_dgram: (
            hex!("0d0a0d0a000d0a515549540a 21 12 000c 08080808 0a0a0a0a 846c 0050"),
            ProxyHeader {
                mode: Mode::Proxy,
                family: Family::Inet,
                transport: Transport::Dgram,
                source_address: "8.8.8.8:33900".parse().unwrap()
            }
        ),
        ipv6_stream: (
            hex!("0d0a0d0a000d0a515549540a 20 21 0024 2607f0d02901007e0000000000000003 fd00eaea000000000000000000000001 846c 0050"),
            ProxyHeader {
                mode: Mode::Local,
                family: Family::Inet6,
                transport: Transport::Stream,
                source_address: "[2607:f0d0:2901:7e::3]:33900".parse().unwrap()
            }
        ),
        ipv6_dgram: (
            hex!("0d0a0d0a000d0a515549540a 20 22 0024 2607f0d02901007e0000000000000003 fd00eaea000000000000000000000001 ffff 0050"),
            ProxyHeader {
                mode: Mode::Local,
                family: Family::Inet6,
                transport: Transport::Dgram,
                source_address: "[2607:f0d0:2901:7e::3]:65535".parse().unwrap()
            }
        ),
    }
}
