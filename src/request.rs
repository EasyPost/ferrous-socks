use std::net::{SocketAddr, IpAddr};

use tokio::net::TcpStream;

use crate::config::Config;

#[derive(Debug, Clone)]
pub enum Address {
    IpAddr(IpAddr),
    DomainName(String)
}

#[derive(Debug, Clone)]
pub struct Request {
    pub address: Address,
    pub dport: u16,
}

impl Request {
    pub async fn connect(self, config: &Config) -> Result<Option<TcpStream>, tokio::io::Error> {
        let conn = match self.address {
            Address::IpAddr(i) => {
                if config.is_permitted(i, self.dport) {
                    Some(TcpStream::connect((i, self.dport)).await?)
                } else {
                    None
                }
            }
            Address::DomainName(d) => {
                for addr in tokio::net::lookup_host(d.as_str()).await? {
                    let addr = SocketAddr::new(addr.ip(), self.dport);
                    if config.is_permitted(addr.ip(), self.dport) {
                        return Ok(Some(TcpStream::connect(addr).await?));
                    }
                }
                None
            }
        };
        Ok(conn)
    }
}
