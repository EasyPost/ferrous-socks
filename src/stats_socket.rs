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
