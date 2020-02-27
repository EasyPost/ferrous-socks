use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use serde::ser::SerializeStruct;

static ZERO_SECONDS: Duration = Duration::from_secs(0);

pub fn serialize_system_time<S>(ts: &SystemTime, ser: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let elapsed = ts.elapsed().unwrap_or(ZERO_SECONDS);
    if let Ok(dur) = ts.duration_since(UNIX_EPOCH) {
        let mut f = ser.serialize_struct("time", 2)?;
        f.serialize_field("ts", &dur.as_secs_f64())?;
        f.serialize_field("ago", &elapsed.as_secs_f64())?;
        f.end()
    } else {
        ser.serialize_str("unknown")
    }
}

pub async fn copy_then_shutdown<S, D>(src: &mut S, dest: &mut D) -> Result<(), tokio::io::Error>
where
    S: AsyncRead + Unpin,
    D: AsRef<TcpStream> + AsyncWrite + Unpin,
{
    tokio::io::copy(src, dest).await?;
    dest.as_ref().shutdown(std::net::Shutdown::Write)?;
    Ok(())
}
