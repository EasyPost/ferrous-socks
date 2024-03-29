use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::request::Version;

#[derive(Debug)]
pub enum Reply {
    SocksFailure,
    ConnectionNotAllowed,
    NetworkUnreachable,
    #[allow(dead_code)]
    ConnectionRefused,
    TtlExpired,
    CommandNotSupported,
    AddressNotSupported,
}

impl Reply {
    fn as_u8(&self) -> u8 {
        use Reply::*;

        match self {
            SocksFailure => 0x01,
            ConnectionNotAllowed => 0x02,
            NetworkUnreachable => 0x03,
            ConnectionRefused => 0x04,
            TtlExpired => 0x05,
            CommandNotSupported => 0x07,
            AddressNotSupported => 0x08,
        }
    }

    pub async fn write_error<A>(
        &self,
        into: &mut A,
        version: Version,
    ) -> Result<(), tokio::io::Error>
    where
        A: AsyncWrite + Unpin + 'static,
    {
        match version {
            Version::Four => {
                into.write_all(&[0x00, 0x5b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                    .await
            }
            Version::Five => {
                into.write_all(&[
                    0x05,
                    self.as_u8(),
                    0x00,
                    0x01,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                ])
                .await
            }
        }
    }
}
