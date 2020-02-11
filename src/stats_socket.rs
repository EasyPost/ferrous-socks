use std::sync::Arc;
use std::time::Duration;

use log::{debug, warn};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::UnixListener;

use crate::stats::Stats;

async fn handle_stats_connection<S>(
    mut socket: S,
    stats: Arc<Stats>,
) -> Result<(), tokio::io::Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let dumped = stats.serialize_to_vec().await;
    if let Ok(dumped) = dumped {
        socket.write_all(&dumped).await?;
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

pub async fn stats_main_tcp(mut listener: TcpListener, stats: Arc<Stats>) {
    loop {
        let (socket, address) = match listener.accept().await {
            Ok(o) => o,
            Err(e) => {
                warn!("error accepting on stats socket: {:?}", e);
                return;
            }
        };
        debug!("conn from {:?}", address);
        let my_stats = Arc::clone(&stats);
        tokio::spawn(handle_stats_connection_wrapper(socket, my_stats));
    }
}

pub async fn stats_main_unix(mut listener: UnixListener, stats: Arc<Stats>) {
    loop {
        let (socket, address) = match listener.accept().await {
            Ok(o) => o,
            Err(e) => {
                warn!("error accepting on stats socket: {:?}", e);
                return;
            }
        };
        debug!("conn from {:?}", address);
        let my_stats = Arc::clone(&stats);
        tokio::spawn(handle_stats_connection_wrapper(socket, my_stats));
    }
}
