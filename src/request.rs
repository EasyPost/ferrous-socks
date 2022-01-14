use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use log::debug;
use serde::Serialize;
use tokio::net::{TcpSocket, TcpStream};

use crate::config::Config;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Address {
    IpAddr(IpAddr),
    DomainName(String),
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum Version {
    #[serde(rename = "4")]
    Four,
    #[serde(rename = "5")]
    Five,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Request {
    pub address: Address,
    pub dport: u16,
    pub ver: Version,
    pub username: Option<String>,
}

impl Request {
    pub fn new(address: Address, dport: u16, ver: Version, username: Option<String>) -> Self {
        Request {
            address,
            dport,
            ver,
            username,
        }
    }
}

pub enum Connection {
    Connected(TcpStream),
    NotAllowed,
    AddressNotSupported,
    SocksFailure,
}

async fn connect_bind(
    bind_addr: IpAddr,
    connect_addr: IpAddr,
    connect_port: u16,
) -> Result<TcpStream, tokio::io::Error> {
    debug!("connecting with explicit bind of {:?}", bind_addr);
    let connect = SocketAddr::new(connect_addr, connect_port);
    let bind = SocketAddr::new(bind_addr, 0);
    let socket = if bind_addr.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }?;
    socket.bind(bind)?;
    socket.connect(connect).await
}

async fn connect_one(
    username: Option<&str>,
    addr: IpAddr,
    port: u16,
    config: &Config,
) -> Result<Connection, tokio::io::Error> {
    let conn = if config.acl.is_permitted(username, addr, port) {
        if config.bind_addresses.is_empty() {
            Connection::Connected(TcpStream::connect((addr, port)).await?)
        } else {
            for item in config.bind_addresses.iter() {
                match (item.is_ipv4(), addr.is_ipv4()) {
                    (true, true) => {
                        if *item == IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)) {
                            return Ok(Connection::Connected(
                                TcpStream::connect((addr, port)).await?,
                            ));
                        } else {
                            return Ok(Connection::Connected(
                                connect_bind(*item, addr, port).await?,
                            ));
                        }
                    }
                    (false, false) => {
                        if *item == IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)) {
                            return Ok(Connection::Connected(
                                TcpStream::connect((addr, port)).await?,
                            ));
                        } else {
                            return Ok(Connection::Connected(
                                connect_bind(*item, addr, port).await?,
                            ));
                        }
                    }
                    (_, _) => continue,
                }
            }
            Connection::AddressNotSupported
        }
    } else {
        Connection::NotAllowed
    };
    Ok(conn)
}

impl Request {
    pub async fn connect(self, config: &Config) -> Result<Connection, tokio::io::Error> {
        let conn = match self.address {
            Address::IpAddr(i) => {
                connect_one(self.username.as_deref(), i, self.dport, config).await?
            }
            Address::DomainName(d) => {
                let mut saw_not_allowed = false;
                let mut saw_not_supported = false;
                let lookup = format!("{}:{}", d.as_str(), self.dport);
                for addr in tokio::net::lookup_host(lookup.as_str()).await? {
                    match connect_one(self.username.as_deref(), addr.ip(), self.dport, config)
                        .await?
                    {
                        Connection::Connected(c) => return Ok(Connection::Connected(c)),
                        Connection::AddressNotSupported => {
                            saw_not_supported = true;
                        }
                        Connection::NotAllowed => {
                            saw_not_allowed = true;
                        }
                        _ => {}
                    }
                }
                if saw_not_allowed {
                    Connection::NotAllowed
                } else if saw_not_supported {
                    Connection::AddressNotSupported
                } else {
                    Connection::SocksFailure
                }
            }
        };
        Ok(conn)
    }
}
