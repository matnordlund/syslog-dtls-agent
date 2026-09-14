mod auth;
mod web;
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
    /// Configuration file (defaults to agent.toml beside the executable).
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}
#[derive(Subcommand)]
enum Command {
    /// Print an example TOML configuration (does not create files).
    Config,
    /// Validate configuration, client identity and CA files without sending traffic.
    Check,
    /// Run in the foreground until Ctrl-C / SIGTERM.
    Run {
        #[arg(long,default_value_t=5,value_parser=clap::value_parser!(u64).range(1..=3600))]
        status_interval: u64,
        /// Override the HTTP management address configured in TOML.
        #[arg(long)]
        http_listen: Option<std::net::SocketAddr>,
        /// Disable the embedded browser UI.
        #[arg(long)]
        no_http: bool,
    },
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
fn run() -> Result<(), String> {
    let args = Args::parse();
    match args.command.unwrap_or(Command::Run {
        status_interval: 5,
        http_listen: None,
        no_http: false,
    }) {
        Command::Config => print!("{}", Config::default().to_toml()?),
        Command::Check => {
            let cfg = Config::load(&configuration_path(args.config)?)?;
            OpenSslConnector::new(&cfg).map_err(|e| e.to_string())?;
            println!("Configuration and credentials are valid. Collector connectivity has not been tested.");
        }
        Command::Run {
            status_interval,
            http_listen,
            no_http,
        } => {
            let config = configuration_path(args.config)?;
            let cfg = Config::load(&config)?;
            let http_listen = http_listen
                .unwrap_or_else(|| std::net::SocketAddr::new(cfg.http.address, cfg.http.port));
            let mut auth = if no_http {
                None
            } else {
                auth::Auth::new(&cfg.http.oidc)?
            };
            let http = if no_http {
                None
            } else {
                Some(web::bind(http_listen)?)
            };
            let backend = Arc::new(OpenSslConnector::new(&cfg).map_err(|e| e.to_string())?);
            let stopping = Arc::new(AtomicBool::new(false));
            let flag = stopping.clone();
            ctrlc::set_handler(move || flag.store(true, Ordering::Relaxed))
                .map_err(|e| e.to_string())?;
            let relay = Relay::start(cfg.clone(), backend)?;
            let mut agent = web::Agent {
                config: cfg,
                path: config,
                relay: Some(relay),
                last: Default::default(),
            };
            if http.is_some() {
                eprintln!(
                    "HTTP UI: {}",
                    auth.as_ref()
                        .map(|a| a.origin().to_owned())
                        .unwrap_or_else(|| format!("http://{http_listen}"))
                );
            }
            let mut last = std::time::Instant::now() - Duration::from_secs(status_interval);
            while !stopping.load(Ordering::Relaxed) && (http.is_some() || agent.status().running) {
                if last.elapsed() >= Duration::from_secs(status_interval) {
                    println!(
                        "{}",
                        serde_json::to_string(&agent.status()).map_err(|e| e.to_string())?
                    );
                    last = std::time::Instant::now();
                }
                if let Some(server) = &http {
                    if let Some(request) = server
                        .recv_timeout(Duration::from_millis(100))
                        .map_err(|e| e.to_string())?
                    {
                        web::handle(request, http_listen, &mut agent, &mut auth);
                    }
                } else {
                    thread::sleep(Duration::from_millis(100));
                }
            }
            println!(
                "{}",
                serde_json::to_string(&agent.stop()).map_err(|e| e.to_string())?
            );
        }
    }
    Ok(())
}

fn configuration_path(config: Option<PathBuf>) -> Result<PathBuf, String> {
    if let Some(path) = config {
        return std::path::absolute(path).map_err(|e| e.to_string());
    }
    let executable = std::env::current_exe()
        .map_err(|e| format!("Cannot locate executable: {e}. Specify --config."))?;
    Ok(executable.with_file_name("agent.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_next_to_executable_and_explicit_path_wins() {
        assert_eq!(
            configuration_path(None).unwrap(),
            std::env::current_exe()
                .unwrap()
                .with_file_name("agent.toml")
        );
        let custom = PathBuf::from("custom.toml");
        assert_eq!(
            configuration_path(Some(custom.clone())).unwrap(),
            std::path::absolute(custom).unwrap()
        );
    }

    #[test]
    fn run_and_check_accept_omitted_config() {
        assert!(Args::try_parse_from(["agent"]).unwrap().command.is_none());
        assert!(matches!(
            Args::try_parse_from(["agent", "run"]).unwrap().command,
            Some(Command::Run { .. })
        ));
        assert!(matches!(
            Args::try_parse_from(["agent", "check"]).unwrap().command,
            Some(Command::Check)
        ));
    }

    #[test]
    fn config_is_accepted_without_a_command_and_on_either_side_of_subcommands() {
        for arguments in [
            vec!["agent", "--config", "./agent.toml"],
            vec!["agent", "-c", "./agent.toml"],
            vec!["agent", "--config", "./agent.toml", "run"],
            vec!["agent", "run", "--config", "./agent.toml"],
            vec!["agent", "--config", "./agent.toml", "check"],
            vec!["agent", "check", "--config", "./agent.toml"],
        ] {
            let args = Args::try_parse_from(arguments).unwrap();
            assert_eq!(args.config, Some(PathBuf::from("./agent.toml")));
        }
        assert!(Args::try_parse_from(["agent", "--config", "./agent.toml"])
            .unwrap()
            .command
            .is_none());
    }
}
