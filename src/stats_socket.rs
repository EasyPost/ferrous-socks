use std::fs::Permissions;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use log::{debug, warn};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::UnixListener;

use crate::stats::Stats;

/// Bind a listening UNIX domain socket at /foo/bar by first
/// binding to /foo/bar.pid and atomically renaming to /foo/bar
pub fn bind_unix_listener<P: AsRef<Path>>(
    path: P,
    mode: Permissions,
) -> tokio::io::Result<UnixListener> {
    let mut path_buf = path.as_ref().to_owned();
    let orig_path_buf = path_buf.clone();
    if let Ok(metadata) = std::fs::metadata(&path_buf) {
        if !metadata.file_type().is_socket() {
            panic!("pre-existing non-socket file at {:?}", path_buf);
        }
    }
    let mut target_file_name = path_buf.file_name().unwrap().to_owned();
    target_file_name.push(format!(".{}", std::process::id()));
    path_buf.set_file_name(target_file_name);
    let listener = UnixListener::bind(&path_buf)?;
    std::fs::set_permissions(&path_buf, mode)?;
    std::fs::rename(path_buf, orig_path_buf)?;
    Ok(listener)
}

async fn handle_stats_connection<S>(
    mut socket: S,
    stats: Arc<Stats>,
) -> Result<(), tokio::io::Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let dumped = stats.serialize_to_vec().await;
    match dumped {
        Ok(dumped) => {
            socket.write_all(&dumped).await?;
        }
        Err(e) => {
            warn!("error dumping stats: {:?}", e);
        }
    }
    Ok(())
}

async fn handle_stats_connection_wrapper<S>(socket: S, stats: Arc<Stats>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let timeout = Duration::from_secs(10);
    match tokio::time::timeout(timeout, handle_stats_connection(socket, stats)).await {
        Ok(Ok(_)) => (),
        Ok(Err(e)) => {
            warn!("error handling stats connection: {:?}", e);
        }
        Err(_) => {}
    }
}

/* This is gross.
 *
 * async functions in traits isn't stable, so there's no trait that both
 * TcpListener and UnixListener implement. Therefore, if we want to be able
 * to do both, we have to copy-pasta the code. At least do it with a macro!
 *
 * In some better universe there'd be something like
 *
 * trait StreamListener {
 *   type StreamType: AsyncRead + AsyncWrite + Unpin;
 *   type AddressType;
 *
 *   async fn accept() -> (Self::StreamType, Self::AddressType);
 * }
 */

macro_rules! generate_stats_main {
    ($name:ident, $listener_type:ty) => {
        pub async fn $name(mut listener: $listener_type, stats: Arc<Stats>) {
            loop {
                let (socket, address) = match listener.accept().await {
                    Ok(o) => o,
                    Err(e) => {
                        warn!("error accepting on stats socket: {:?}", e);
                        return;
                    }
                };
                debug!("stats conn from {:?}", address);
                let my_stats = Arc::clone(&stats);
                tokio::spawn(handle_stats_connection_wrapper(socket, my_stats));
            }
        }
    };
}

generate_stats_main!(stats_main_tcp, TcpListener);
generate_stats_main!(stats_main_unix, UnixListener);
