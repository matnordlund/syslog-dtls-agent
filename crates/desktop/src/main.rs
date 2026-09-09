#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};
use syslog_agent_core::{Config, Relay, Status};
use syslog_agent_dtls_openssl::OpenSslConnector;
use tauri::Manager;
use tauri_plugin_dialog::DialogExt;

#[derive(Default)]
struct AppState {
    relay: Option<Relay>,
    last: Status,
}
type Shared = Arc<Mutex<AppState>>;

#[tauri::command]
fn default_config() -> Config {
    Config::default()
}
#[tauri::command]
fn normalize_source_ip(ip: String) -> Result<String, String> {
    ip.parse::<std::net::IpAddr>()
        .map(syslog_agent_core::config::canonical_ip)
        .map(|ip| ip.to_string())
        .map_err(|_| {
            "Enter an exact IPv4 or IPv6 address (no hostname, port, or CIDR range)".into()
        })
}
#[tauri::command]
fn status(state: tauri::State<'_, Shared>) -> Status {
    let s = state.lock().unwrap();
    s.relay
        .as_ref()
        .map(Relay::status)
        .unwrap_or_else(|| s.last.clone())
}

#[tauri::command]
async fn start(config: Config, state: tauri::State<'_, Shared>) -> Result<Status, String> {
    let shared = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let mut s = shared.lock().unwrap();
        if s.relay.as_ref().is_some_and(|relay| relay.status().running) {
            return Err("Stop the relay before applying new settings".into());
        }
        if let Some(mut relay) = s.relay.take() {
            s.last = relay.stop();
        }
        let mut config = config;
        config.resolve_paths(&std::env::current_dir().map_err(|e| e.to_string())?);
        let connector = OpenSslConnector::new(&config).map_err(|e| e.to_string())?;
        let relay = Relay::start(config, Arc::new(connector))?;
        let status = relay.status();
        s.relay = Some(relay);
        Ok(status)
    })
    .await
    .map_err(|_| "Relay worker failed".to_string())?
}
#[tauri::command]
async fn stop(state: tauri::State<'_, Shared>) -> Result<Status, String> {
    let shared = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let mut s = shared.lock().unwrap();
        if let Some(mut relay) = s.relay.take() {
            s.last = relay.stop();
        }
        s.last.clone()
    })
    .await
    .map_err(|_| "Relay worker failed".into())
}
#[tauri::command]
async fn validate(config: Config) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        OpenSslConnector::new(&config).map_err(|e| e.to_string())?;
        Ok(
            "Configuration and credentials valid. Connectivity is checked when the relay starts."
                .into(),
        )
    })
    .await
    .map_err(|_| "Validation worker failed".to_string())?
}
#[tauri::command]
async fn pick_file(app: tauri::AppHandle) -> Result<Option<String>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        app.dialog()
            .file()
            .blocking_pick_file()
            .map(|p| p.to_string())
    })
    .await
    .map_err(|_| "File dialog failed".into())
}
#[tauri::command]
async fn load_config(app: tauri::AppHandle) -> Result<Option<Config>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let Some(path) = app
            .dialog()
            .file()
            .add_filter("TOML configuration", &["toml"])
            .blocking_pick_file()
        else {
            return Ok(None);
        };
        Config::load(&PathBuf::from(path.to_string())).map(Some)
    })
    .await
    .map_err(|_| "Load dialog failed".to_string())?
}
#[tauri::command]
async fn save_config(app: tauri::AppHandle, config: Config) -> Result<bool, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let mut config = config;
        config.resolve_paths(&std::env::current_dir().map_err(|e| e.to_string())?);
        config.validate()?;
        let Some(path) = app
            .dialog()
            .file()
            .add_filter("TOML configuration", &["toml"])
            .set_file_name("agent.toml")
            .blocking_save_file()
        else {
            return Ok(false);
        };
        std::fs::write(PathBuf::from(path.to_string()), config.to_toml()?)
            .map_err(|e| format!("Cannot save configuration: {e}"))?;
        Ok(true)
    })
    .await
    .map_err(|_| "Save dialog failed".to_string())?
}
fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(Shared::default())
        .invoke_handler(tauri::generate_handler![
            default_config,
            normalize_source_ip,
            status,
            start,
            stop,
            validate,
            pick_file,
            load_config,
            save_config
        ])
        .build(tauri::generate_context!())
        .expect("Cannot initialize desktop application")
        .run(|app, event| {
            if let tauri::RunEvent::Exit = event {
                let state = app.state::<Shared>();
                let mut s = state.lock().unwrap();
                if let Some(mut relay) = s.relay.take() {
                    relay.stop();
                }
            }
        });
}
