use clap::{Parser, Subcommand};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
use syslog_agent_core::{Config, Relay};
use syslog_agent_dtls_openssl::OpenSslConnector;

#[derive(Parser)]
#[command(
    name = "syslog-dtls-agent",
    version,
    about = "A bounded UDP syslog relay over certificate-verified DTLS 1.2"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Print an example TOML configuration (does not create files).
    Config,
    /// Validate configuration, client identity and CA files without sending traffic.
    Check {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Run in the foreground until Ctrl-C / SIGTERM.
    Run {
        #[arg(short, long)]
        config: PathBuf,
        #[arg(long,default_value_t=5,value_parser=clap::value_parser!(u64).range(1..=3600))]
        status_interval: u64,
    },
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
fn run() -> Result<(), String> {
    match Args::parse().command {
        Command::Config => print!("{}", Config::default().to_toml()?),
        Command::Check { config } => {
            let cfg = Config::load(&config)?;
            OpenSslConnector::new(&cfg).map_err(|e| e.to_string())?;
            println!("Configuration and credentials are valid. Collector connectivity has not been tested.");
        }
        Command::Run {
            config,
            status_interval,
        } => {
            let cfg = Config::load(&config)?;
            let backend = Arc::new(OpenSslConnector::new(&cfg).map_err(|e| e.to_string())?);
            let stopping = Arc::new(AtomicBool::new(false));
            let flag = stopping.clone();
            ctrlc::set_handler(move || flag.store(true, Ordering::Relaxed))
                .map_err(|e| e.to_string())?;
            let mut relay = Relay::start(cfg, backend)?;
            let mut last = std::time::Instant::now() - Duration::from_secs(status_interval);
            while !stopping.load(Ordering::Relaxed) && relay.status().running {
                if last.elapsed() >= Duration::from_secs(status_interval) {
                    println!(
                        "{}",
                        serde_json::to_string(&relay.status()).map_err(|e| e.to_string())?
                    );
                    last = std::time::Instant::now();
                }
                thread::sleep(Duration::from_millis(100));
            }
            println!(
                "{}",
                serde_json::to_string(&relay.stop()).map_err(|e| e.to_string())?
            );
        }
    }
    Ok(())
}
