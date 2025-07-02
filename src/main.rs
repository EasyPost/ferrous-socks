use std::env;
use std::sync::Arc;

use anyhow::Context;
use clap::Arg;
use futures_util::future::FutureExt;
use log::{debug, info, warn};
use tokio::signal::unix::{signal, SignalKind};

mod acl;
mod config;
mod proxy;
mod reply;
mod request;
mod socks;
mod stats;
mod stats_socket;
mod util;

use config::Config;

fn cli() -> clap::Command<'static> {
    clap::Command::new(clap::crate_name!())
        .version(clap::crate_version!())
        .author(clap::crate_authors!())
        .about(clap::crate_description!())
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("PATH")
                .help("Path to configuration TOML file")
                .takes_value(true)
                .required_unless_present("dump-config"),
        )
        .arg(
            Arg::new("check-config")
                .short('C')
                .long("check-config")
                .help("Only check config syntax and exit")
                .conflicts_with("dump-config")
        )
        .arg(
            Arg::new("dump-config")
                .long("dump-config")
                .value_name("PATH")
                .takes_value(true)
                .help("Dump out config (with all defaults interpolated) to the given path (- meaning stdout)"),
        )
        .next_help_heading("LOGGING OPTIONS")
        .arg(
            Arg::new("log_level")
                .short('L')
                .long("log-level")
                .takes_value(true)
                .default_value("warn")
                .possible_values(&["error", "warn", "info", "debug", "trace"])
                .help("Log level (only used if log level not set for syslog in config)"),
        )
        .arg(
            Arg::new("stderr")
                .short('E')
                .long("stderr")
                .help("Force logging to stderr"),
        )
}

async fn any_shutdown_signal() {
    debug!("Will shut down on HUP, QUIT, INT, or TERM");
    futures_util::future::select_all(
        vec![
            signal(SignalKind::hangup()).unwrap().recv().boxed(),
            signal(SignalKind::quit()).unwrap().recv().boxed(),
            signal(SignalKind::interrupt()).unwrap().recv().boxed(),
            signal(SignalKind::terminate()).unwrap().recv().boxed(),
        ]
        .into_iter(),
    )
    .await;
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let matches = cli().get_matches();

    let conf = if let Some(config_path) = matches.value_of("config") {
        Config::from_path(config_path)?
    } else {
        Config::default()
    };

    if let Some(dump_path) = matches.value_of("dump-config") {
        let dump_path = if dump_path == "-" {
            None
        } else {
            Some(dump_path)
        };
        conf.dump(dump_path)?;
        if let Some(path) = dump_path {
            println!("Config dumped to {:?}", path);
        }
        return Ok(());
    };

    let conf = Arc::new(conf);

    if matches.is_present("check-config") {
        println!("Config loaded successfully");
        return Ok(());
    }

    conf.initialize_logging(&matches);

    let stats = Arc::new(stats::Stats::new());

    if conf.expect_proxy {
        info!("NOTE: Expecting PROXY protocol on streams");
    }

    let p = permit::Permit::new();

    // Set up the stats server
    if let Some(ref stats_socket_listen_address) = conf.stats_socket_listen_address {
        let server = stats_socket::StatsServer::new(Arc::clone(&stats), p.new_sub());
        if stats_socket_listen_address.starts_with('/')
            || stats_socket_listen_address.starts_with('.')
        {
            info!(
                "Stats socket listening on {:?}",
                stats_socket_listen_address
            );
            let listener = stats_socket::bind_unix_listener(
                stats_socket_listen_address,
                conf.stats_socket_mode.clone(),
            )
            .with_context(|| {
                format!(
                    "failed to bind to domain socket {:?}",
                    stats_socket_listen_address,
                )
            })?;
            tokio::spawn(server.run_unix(listener));
        } else {
            info!(
                "Stats socket listening on {:?}",
                stats_socket_listen_address
            );
            let listener = tokio::net::TcpListener::bind(stats_socket_listen_address)
                .await
                .with_context(|| {
                    format!(
                        "failed to bind to TCP socket {:?}",
                        stats_socket_listen_address
                    )
                })?;
            tokio::spawn(server.run_tcp(listener));
        }
    }

    // Set up the main SOCKS server
    let (_, p) = socks::run(Arc::clone(&conf), stats, p).await?;

    // Shut down on signal (TODO: or if the socks server dies?)
    any_shutdown_signal().await;
    info!("got shutdown signal; attempting graceful shutdown");
    let shutdown_start = std::time::Instant::now();
    match p.revoke().wait_subs_timeout(conf.shutdown_timeout) {
        Ok(_) => debug!("shutdown finished in {:?}", shutdown_start.elapsed()),
        Err(e) => warn!(
            "shutdown timed out after {:?}: {:?}",
            shutdown_start.elapsed(),
            e
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::cli;

    #[test]
    fn test_debug_assert_cli() {
        cli().debug_assert();
    }
}
