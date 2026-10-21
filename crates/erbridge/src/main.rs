use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Parser;

mod admin;
mod cli;
mod tui;

use cli::{Cli, Command};
use erbridge_core::config::{
    self, ClientRule, ConnectConfig, ConnectTunnel, FileConfig, ForwardRule, ServeConfig,
    ServeTunnel,
};
use erbridge_core::reverse::enroll::{Credentials, enroll};
use erbridge_core::stats::Registry;
use erbridge_core::{client, forward, reverse};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let file_cfg = match &cli.config {
        Some(path) => FileConfig::load(path)?,
        None => FileConfig::default(),
    };

    // One-shot commands print their result and exit; they have no use for the
    // live view or a log file.
    match &cli.command {
        Command::Enroll { server, code, out } => {
            return run_enroll(server, code, out.as_deref()).await;
        }
        Command::ServeAdmin { tenants, action } => {
            let path = tenants_path(tenants.clone(), &file_cfg)?;
            print!("{}", admin::run(&path, action)?);
            return Ok(());
        }
        _ => {}
    }

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
        Command::Forward { maps, token } => {
            let rules = resolve_forward(&file_cfg, &maps, token)?;
            forward::run_forward(rules, registry).await
        }
        Command::Client { maps, token } => {
            let rules = resolve_client(&file_cfg, &maps, token)?;
            client::run_client(rules, registry).await
        }
        Command::Serve {
            listen,
            token,
            tunnels,
            tenants,
            sni_listen,
        } => {
            let cfg = resolve_serve(&file_cfg, listen, token, &tunnels, tenants, sni_listen)?;
            reverse::serve::run_serve(cfg, registry).await
        }
        Command::Connect {
            server,
            token,
            tunnels,
            credentials,
            target,
        } => {
            let cfg = resolve_connect(&file_cfg, server, token, &tunnels, credentials, target)?;
            reverse::connect::run_connect(cfg, registry).await
        }
        Command::Enroll { .. } | Command::ServeAdmin { .. } => {
            unreachable!("one-shot commands are handled before run_command")
        }
    }
}

fn resolve_forward(
    file_cfg: &FileConfig,
    cli_maps: &[String],
    cli_token: Option<String>,
) -> Result<Vec<ForwardRule>> {
    let mut rules = file_cfg.forward.clone();
    for raw in cli_maps {
        rules.push(config::parse_map_flag(raw)?);
    }
    // `--token` applies to every mapping with a `transport` from this
    // invocation that doesn't already carry its own token from the config
    // file.
    if let Some(token) = cli_token {
        for rule in &mut rules {
            if rule.transport.is_some() && rule.token.is_none() {
                rule.token = Some(token.clone());
            }
        }
    }
    Ok(rules)
}

fn resolve_client(
    file_cfg: &FileConfig,
    cli_maps: &[String],
    cli_token: Option<String>,
) -> Result<Vec<ClientRule>> {
    let mut rules = file_cfg.client.clone();
    for raw in cli_maps {
        rules.push(config::parse_client_map_flag(raw)?);
    }
    if let Some(token) = cli_token {
        for rule in &mut rules {
            if rule.token.is_none() {
                rule.token = Some(token.clone());
            }
        }
    }
    Ok(rules)
}

fn resolve_serve(
    file_cfg: &FileConfig,
    listen: Option<String>,
    token: Option<String>,
    cli_tunnels: &[String],
    tenants: Option<PathBuf>,
    sni_listen: Option<String>,
) -> Result<ServeConfig> {
    let mut cfg = file_cfg.serve.clone().unwrap_or_default();
    if let Some(l) = listen {
        cfg.listen = l;
    }
    if let Some(path) = tenants {
        cfg.tenants_file = Some(path.display().to_string());
    }
    if let Some(addr) = sni_listen {
        cfg.sni_listen = Some(addr);
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
    // Also rejects mixing the two modes' options.
    if !cfg.is_multi_tenant()? && cfg.token.is_empty() {
        bail!("serve: missing token (config `serve.token` or --token)");
    }
    Ok(cfg)
}

fn resolve_connect(
    file_cfg: &FileConfig,
    server: Option<String>,
    token: Option<String>,
    cli_tunnels: &[String],
    credentials: Option<PathBuf>,
    target: Option<String>,
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
    if let Some(path) = credentials {
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading credentials {}", path.display()))?;
        let creds = Credentials::from_toml(&text)
            .with_context(|| format!("loading credentials {}", path.display()))?;
        let target = target.context("connect: --credentials needs --target")?;
        if cfg.token.is_empty() {
            cfg.token = creds.token;
        }
        cfg.tunnel.push(ConnectTunnel {
            name: creds.name,
            target,
        });
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

/// The tenant file for `serve-admin`: the flag, else the config's
/// `serve.tenants_file`.
fn tenants_path(flag: Option<PathBuf>, file_cfg: &FileConfig) -> Result<PathBuf> {
    flag.or_else(|| {
        file_cfg
            .serve
            .as_ref()
            .and_then(|s| s.tenants_file.as_deref().map(PathBuf::from))
    })
    .context("serve-admin: no tenant file (--tenants or config `serve.tenants_file`)")
}

async fn run_enroll(server: &str, code: &str, out: Option<&std::path::Path>) -> Result<()> {
    let credentials = enroll(server, code).await?;
    let text = credentials.to_toml()?;
    match out {
        Some(path) => {
            write_new_private(path, text.as_bytes())?;
            eprintln!("enrolled as '{}' ({})", credentials.name, credentials.sni);
            eprintln!("credentials written to {}", path.display());
            eprintln!(
                "next: erbridge connect --server {server} --credentials {} --target <LOCAL_ADDR>",
                path.display()
            );
        }
        None => print!("{text}"),
    }
    Ok(())
}

/// Creates `path` readable by its owner only, refusing to overwrite: the file
/// holds a secret that cannot be fetched again.
fn write_new_private(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("creating {} (it must not already exist)", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn serve_cfg() -> FileConfig {
        FileConfig::default()
    }

    #[test]
    fn serve_in_multi_tenant_mode_needs_no_token() {
        let cfg = resolve_serve(
            &serve_cfg(),
            Some("0.0.0.0:9000".into()),
            None,
            &[],
            Some("t.toml".into()),
            Some("0.0.0.0:443".into()),
        )
        .unwrap();
        assert_eq!(cfg.tenants_file.as_deref(), Some("t.toml"));
        assert!(cfg.is_multi_tenant().unwrap());
    }

    #[test]
    fn serve_still_requires_a_token_without_tenants() {
        let err = resolve_serve(
            &serve_cfg(),
            Some("0.0.0.0:9000".into()),
            None,
            &[],
            None,
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("missing token"), "{err:#}");
    }

    #[test]
    fn mixing_token_and_tenants_is_rejected() {
        let mixed = resolve_serve(
            &serve_cfg(),
            Some("0.0.0.0:9000".into()),
            Some("t".into()),
            &[],
            Some("t.toml".into()),
            Some("0.0.0.0:443".into()),
        );
        assert!(mixed.is_err());
        let no_sni = resolve_serve(
            &serve_cfg(),
            Some("0.0.0.0:9000".into()),
            None,
            &[],
            Some("t.toml".into()),
            None,
        );
        assert!(no_sni.is_err());
    }

    #[test]
    fn connect_builds_its_tunnel_from_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.toml");
        let creds = Credentials {
            name: "t-abc".into(),
            token: "secret".into(),
            sni: "a.example.com".into(),
        };
        std::fs::write(&path, creds.to_toml().unwrap()).unwrap();

        let cfg = resolve_connect(
            &FileConfig::default(),
            Some("h:9000".into()),
            None,
            &[],
            Some(path.clone()),
            Some("127.0.0.1:8080".into()),
        )
        .unwrap();
        assert_eq!(cfg.token, "secret");
        assert_eq!(cfg.tunnel.len(), 1);
        assert_eq!(
            (cfg.tunnel[0].name.as_str(), cfg.tunnel[0].target.as_str()),
            ("t-abc", "127.0.0.1:8080")
        );

        // An explicit token wins over the file's; a missing target is an error.
        let explicit = resolve_connect(
            &FileConfig::default(),
            Some("h:9000".into()),
            Some("mine".into()),
            &[],
            Some(path.clone()),
            Some("127.0.0.1:8080".into()),
        )
        .unwrap();
        assert_eq!(explicit.token, "mine");
        assert!(
            resolve_connect(
                &FileConfig::default(),
                Some("h:9000".into()),
                None,
                &[],
                Some(path),
                None
            )
            .is_err()
        );
    }

    #[test]
    fn tenants_path_prefers_the_flag_over_the_config() {
        let file_cfg = FileConfig {
            serve: Some(ServeConfig {
                tenants_file: Some("from-config.toml".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            tenants_path(Some("flag.toml".into()), &file_cfg).unwrap(),
            PathBuf::from("flag.toml")
        );
        assert_eq!(
            tenants_path(None, &file_cfg).unwrap(),
            PathBuf::from("from-config.toml")
        );
        assert!(tenants_path(None, &FileConfig::default()).is_err());
    }

    #[test]
    fn credentials_are_written_privately_and_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.toml");
        write_new_private(&path, b"secret").unwrap();
        assert!(write_new_private(&path, b"other").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"secret");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
