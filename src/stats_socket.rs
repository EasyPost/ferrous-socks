use std::fs::Permissions;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures_core::stream::Stream;
use futures_util::stream::StreamExt;
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
    S: AsyncRead + AsyncWrite + Unpin + 'static,
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
    S: AsyncRead + AsyncWrite + Unpin + 'static,
{
    let timeout = Duration::from_secs(3);
    match tokio::time::timeout(timeout, handle_stats_connection(socket, stats)).await {
        Ok(Ok(_)) => (),
        Ok(Err(e)) => {
            warn!("error handling stats connection: {:?}", e);
        }
        Err(_) => {}
    }
}

pub struct StatsServer {
    stats: Arc<Stats>,
    permit: permit::Permit,
}

impl StatsServer {
    pub fn new(stats: Arc<Stats>, permit: permit::Permit) -> Self {
        Self { stats, permit }
    }

    pub async fn run<S, ST>(self, stream: S)
    where
        S: Stream<Item = std::io::Result<ST>> + Unpin,
        ST: Send + AsyncRead + AsyncWrite + Unpin + 'static,
    {
        let stats = self.stats;
        let permit_listen = self.permit.new_sub();
        futures_util::future::select(
            self.permit,
            stream
                .take_until(permit_listen)
                .for_each_concurrent(5, move |conn| {
                    let my_stats = Arc::clone(&stats);
                    async {
                        if let Ok(conn) = conn {
                            handle_stats_connection_wrapper(conn, my_stats).await;
                        }
                    }
                }),
        )
        .await;
        debug!("stats server shut down");
    }

    pub async fn run_tcp(self, listener: TcpListener) {
        self.run(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await;
    }

    pub async fn run_unix(self, listener: UnixListener) {
        self.run(tokio_stream::wrappers::UnixListenerStream::new(listener))
            .await;
    }
}
