use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Parser;

use erbridge::cli::{Cli, Command};
use erbridge::config::{
    self, ConnectConfig, ConnectTunnel, FileConfig, ForwardRule, ServeConfig, ServeTunnel,
};
use erbridge::stats::Registry;
use erbridge::{forward, reverse, tui};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let file_cfg = match &cli.config {
        Some(path) => FileConfig::load(path)?,
        None => FileConfig::default(),
    };

    let registry = Registry::new();
    if cli.headless {
        let log_path = cli
            .log_file
            .clone()
            .unwrap_or_else(|| PathBuf::from("erbridge.log"));
        registry
            .set_log_file(log_path.clone())
            .with_context(|| format!("opening log file {}", log_path.display()))?;
        eprintln!("erbridge: headless mode, logging to {}", log_path.display());
    }

    let headless = cli.headless;
    let work_registry = registry.clone();
    let work = run_command(cli.command, file_cfg, work_registry);

    if headless {
        work.await
    } else {
        tokio::select! {
            result = work => result,
            result = tui::run(registry) => result,
        }
    }
}

async fn run_command(command: Command, file_cfg: FileConfig, registry: Registry) -> Result<()> {
    match command {
        Command::Forward { maps } => {
            let rules = resolve_forward(&file_cfg, &maps)?;
            forward::run_forward(rules, registry).await
        }
        Command::Serve {
            listen,
            token,
            tunnels,
        } => {
            let cfg = resolve_serve(&file_cfg, listen, token, &tunnels)?;
            reverse::serve::run_serve(cfg, registry).await
        }
        Command::Connect {
            server,
            token,
            tunnels,
        } => {
            let cfg = resolve_connect(&file_cfg, server, token, &tunnels)?;
            reverse::connect::run_connect(cfg, registry).await
        }
    }
}

fn resolve_forward(file_cfg: &FileConfig, cli_maps: &[String]) -> Result<Vec<ForwardRule>> {
    let mut rules = file_cfg.forward.clone();
    for raw in cli_maps {
        rules.push(config::parse_map_flag(raw)?);
    }
    Ok(rules)
}

fn resolve_serve(
    file_cfg: &FileConfig,
    listen: Option<String>,
    token: Option<String>,
    cli_tunnels: &[String],
) -> Result<ServeConfig> {
    let mut cfg = file_cfg.serve.clone().unwrap_or(ServeConfig {
        listen: String::new(),
        token: String::new(),
        tunnel: Vec::new(),
    });
    if let Some(l) = listen {
        cfg.listen = l;
    }
    if let Some(t) = token {
        cfg.token = t;
    }
    for raw in cli_tunnels {
        let (name, external) = parse_name_value(raw)?;
        cfg.tunnel.push(ServeTunnel { name, external });
    }
    if cfg.listen.is_empty() {
        bail!("serve: missing control listen address (config `serve.listen` or --listen)");
    }
    if cfg.token.is_empty() {
        bail!("serve: missing token (config `serve.token` or --token)");
    }
    Ok(cfg)
}

fn resolve_connect(
    file_cfg: &FileConfig,
    server: Option<String>,
    token: Option<String>,
    cli_tunnels: &[String],
) -> Result<ConnectConfig> {
    let mut cfg = file_cfg.connect.clone().unwrap_or(ConnectConfig {
        server: String::new(),
        token: String::new(),
        tunnel: Vec::new(),
        reconnect_min_secs: 1,
        reconnect_max_secs: 30,
    });
    if let Some(s) = server {
        cfg.server = s;
    }
    if let Some(t) = token {
        cfg.token = t;
    }
    for raw in cli_tunnels {
        let (name, target) = parse_name_value(raw)?;
        cfg.tunnel.push(ConnectTunnel { name, target });
    }
    if cfg.server.is_empty() {
        bail!("connect: missing server address (config `connect.server` or --server)");
    }
    if cfg.token.is_empty() {
        bail!("connect: missing token (config `connect.token` or --token)");
    }
    Ok(cfg)
}

fn parse_name_value(raw: &str) -> Result<(String, String)> {
    let (name, value) = raw
        .split_once('=')
        .with_context(|| format!("expected NAME=VALUE, got: {raw}"))?;
    Ok((name.trim().to_string(), value.trim().to_string()))
}
