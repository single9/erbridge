//! Same ping-pong methodology as `benches/latency.rs`, but against external
//! NAT-traversal tunnels (frp, rathole, bore) instead of just erbridge, so
//! the numbers are comparable apples-to-apples: reverse tunnel vs reverse
//! tunnel, not erbridge's direct `forward` mode against tools that don't
//! have an equivalent (frp/rathole/bore only do the dial-out/reverse case).
//!
//! External binaries are optional — a tool missing from PATH is skipped
//! with a note rather than failing the run. Override locations with
//! `FRPC_BIN` / `FRPS_BIN` / `RATHOLE_BIN` / `BORE_BIN` env vars.
//!
//! Run with: `cargo run --release --example compare_tunnels`

use std::io::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use erbridge::config::{ConnectConfig, ConnectTunnel, ServeConfig, ServeTunnel};
use erbridge::reverse::connect::run_connect;
use erbridge::reverse::serve::run_serve;
use erbridge::stats::Registry;

const PAYLOAD: &[u8; 64] = &[0x42; 64];
const WARMUP: usize = 200;
const ITERS: usize = 5000;
const READY_TIMEOUT: Duration = Duration::from_secs(8);
const TOKEN: &str = "erbridge-compare-bench";

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn bin(env_var: &str, default: &str) -> String {
    std::env::var(env_var).unwrap_or_else(|_| default.to_string())
}

/// Kills its child process (and, best-effort, waits on it) when dropped, so
/// an early `return` on a failed scenario never leaks a server/client alive.
struct ChildGuard {
    child: Child,
    label: &'static str,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        eprintln!("stopped {}", self.label);
    }
}

fn spawn_logged(
    cmd: &mut Command,
    label: &'static str,
    log_dir: &std::path::Path,
) -> Result<ChildGuard, String> {
    let out = std::fs::File::create(log_dir.join(format!("{label}.log")))
        .map_err(|e| format!("creating log file for {label}: {e}"))?;
    let err = out.try_clone().map_err(|e| e.to_string())?;
    cmd.stdout(Stdio::from(out)).stderr(Stdio::from(err));
    match cmd.spawn() {
        Ok(child) => Ok(ChildGuard { child, label }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(format!(
            "binary not found for {label} ({:?})",
            cmd.get_program()
        )),
        Err(e) => Err(format!("failed to spawn {label}: {e}")),
    }
}

async fn wait_ready(addr: SocketAddr, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect(addr).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    false
}

async fn run_echo_server(addr: SocketAddr) {
    let listener = TcpListener::bind(addr).await.expect("bind echo server");
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => continue,
        };
        let _ = stream.set_nodelay(true);
        tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(stream);
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });
    }
}

async fn measure(addr: SocketAddr) -> Result<Vec<Duration>, String> {
    let mut stream = TcpStream::connect(addr)
        .await
        .map_err(|e| format!("connect to {addr}: {e}"))?;
    stream.set_nodelay(true).map_err(|e| e.to_string())?;
    let mut buf = [0u8; PAYLOAD.len()];

    for _ in 0..WARMUP {
        stream.write_all(PAYLOAD).await.map_err(|e| e.to_string())?;
        stream
            .read_exact(&mut buf)
            .await
            .map_err(|e| e.to_string())?;
    }

    let mut samples = Vec::with_capacity(ITERS);
    for _ in 0..ITERS {
        let t0 = Instant::now();
        stream.write_all(PAYLOAD).await.map_err(|e| e.to_string())?;
        stream
            .read_exact(&mut buf)
            .await
            .map_err(|e| e.to_string())?;
        samples.push(t0.elapsed());
    }
    Ok(samples)
}

struct Stats {
    min: f64,
    p50: f64,
    p95: f64,
    p99: f64,
    max: f64,
}

fn percentiles(mut samples: Vec<Duration>) -> Stats {
    samples.sort();
    let us = |d: Duration| d.as_secs_f64() * 1e6;
    let n = samples.len();
    let at = |q: f64| us(samples[(((n - 1) as f64) * q).round() as usize]);
    Stats {
        min: us(samples[0]),
        p50: at(0.50),
        p95: at(0.95),
        p99: at(0.99),
        max: us(samples[n - 1]),
    }
}

enum Outcome {
    Ok(Stats),
    Skipped(String),
}

async fn scenario_baseline(target: SocketAddr) -> Outcome {
    match measure(target).await {
        Ok(s) => Outcome::Ok(percentiles(s)),
        Err(e) => Outcome::Skipped(e),
    }
}

async fn scenario_erbridge_reverse(target: SocketAddr) -> Outcome {
    let control_port = free_port();
    let external_port = free_port();
    let external_addr: SocketAddr = format!("127.0.0.1:{external_port}").parse().unwrap();

    let serve_cfg = ServeConfig {
        listen: format!("127.0.0.1:{control_port}"),
        token: TOKEN.into(),
        tunnel: vec![ServeTunnel {
            name: "bench".into(),
            external: format!("127.0.0.1:{external_port}"),
        }],
    };
    let connect_cfg = ConnectConfig {
        server: format!("127.0.0.1:{control_port}"),
        token: TOKEN.into(),
        tunnel: vec![ConnectTunnel {
            name: "bench".into(),
            target: target.to_string(),
        }],
        reconnect_min_secs: 1,
        reconnect_max_secs: 2,
    };

    tokio::spawn(run_serve(serve_cfg, Registry::new()));
    tokio::time::sleep(Duration::from_millis(80)).await;
    tokio::spawn(run_connect(connect_cfg, Registry::new()));

    if !wait_ready(external_addr, READY_TIMEOUT).await {
        return Outcome::Skipped("reverse tunnel never became ready".into());
    }
    match measure(external_addr).await {
        Ok(s) => Outcome::Ok(percentiles(s)),
        Err(e) => Outcome::Skipped(e),
    }
}

async fn scenario_frp(target: SocketAddr, log_dir: &std::path::Path) -> Outcome {
    let control_port = free_port();
    let external_port = free_port();
    let external_addr: SocketAddr = format!("127.0.0.1:{external_port}").parse().unwrap();

    let frps_toml = log_dir.join("frps.toml");
    let frpc_toml = log_dir.join("frpc.toml");
    if let Err(e) = std::fs::write(
        &frps_toml,
        format!("bindAddr = \"127.0.0.1\"\nbindPort = {control_port}\nauth.token = \"{TOKEN}\"\n"),
    ) {
        return Outcome::Skipped(format!("writing frps.toml: {e}"));
    }
    if let Err(e) = std::fs::write(
        &frpc_toml,
        format!(
            "serverAddr = \"127.0.0.1\"\nserverPort = {control_port}\nauth.token = \"{TOKEN}\"\n\n\
             [[proxies]]\nname = \"bench\"\ntype = \"tcp\"\nlocalIP = \"{}\"\nlocalPort = {}\nremotePort = {external_port}\n",
            target.ip(),
            target.port()
        ),
    ) {
        return Outcome::Skipped(format!("writing frpc.toml: {e}"));
    }

    let _server = match spawn_logged(
        Command::new(bin("FRPS_BIN", "frps"))
            .arg("-c")
            .arg(&frps_toml),
        "frps",
        log_dir,
    ) {
        Ok(g) => g,
        Err(e) => return Outcome::Skipped(e),
    };
    tokio::time::sleep(Duration::from_millis(400)).await;
    let _client = match spawn_logged(
        Command::new(bin("FRPC_BIN", "frpc"))
            .arg("-c")
            .arg(&frpc_toml),
        "frpc",
        log_dir,
    ) {
        Ok(g) => g,
        Err(e) => return Outcome::Skipped(e),
    };

    if !wait_ready(external_addr, READY_TIMEOUT).await {
        return Outcome::Skipped("frp proxy never became ready (see frps.log/frpc.log)".into());
    }
    match measure(external_addr).await {
        Ok(s) => Outcome::Ok(percentiles(s)),
        Err(e) => Outcome::Skipped(e),
    }
}

async fn scenario_rathole(target: SocketAddr, log_dir: &std::path::Path) -> Outcome {
    let control_port = free_port();
    let external_port = free_port();
    let external_addr: SocketAddr = format!("127.0.0.1:{external_port}").parse().unwrap();

    let server_toml = log_dir.join("rathole_server.toml");
    let client_toml = log_dir.join("rathole_client.toml");
    if let Err(e) = std::fs::write(
        &server_toml,
        format!(
            "[server]\nbind_addr = \"127.0.0.1:{control_port}\"\ndefault_token = \"{TOKEN}\"\n\n\
             [server.services.bench]\nbind_addr = \"127.0.0.1:{external_port}\"\n"
        ),
    ) {
        return Outcome::Skipped(format!("writing server.toml: {e}"));
    }
    if let Err(e) = std::fs::write(
        &client_toml,
        format!(
            "[client]\nremote_addr = \"127.0.0.1:{control_port}\"\ndefault_token = \"{TOKEN}\"\n\n\
             [client.services.bench]\nlocal_addr = \"{target}\"\n"
        ),
    ) {
        return Outcome::Skipped(format!("writing client.toml: {e}"));
    }

    let _server = match spawn_logged(
        Command::new(bin("RATHOLE_BIN", "rathole"))
            .arg(&server_toml)
            .arg("-s"),
        "rathole_server",
        log_dir,
    ) {
        Ok(g) => g,
        Err(e) => return Outcome::Skipped(e),
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    let _client = match spawn_logged(
        Command::new(bin("RATHOLE_BIN", "rathole"))
            .arg(&client_toml)
            .arg("-c"),
        "rathole_client",
        log_dir,
    ) {
        Ok(g) => g,
        Err(e) => return Outcome::Skipped(e),
    };

    if !wait_ready(external_addr, READY_TIMEOUT).await {
        return Outcome::Skipped(
            "rathole tunnel never became ready (see rathole_server.log/rathole_client.log)".into(),
        );
    }
    match measure(external_addr).await {
        Ok(s) => Outcome::Ok(percentiles(s)),
        Err(e) => Outcome::Skipped(e),
    }
}

async fn scenario_bore(target: SocketAddr, log_dir: &std::path::Path) -> Outcome {
    // bore's control port is fixed (not configurable via CLI), so only one
    // bore scenario may run at a time within a process — fine here since
    // scenarios run sequentially and the guards kill the pair before we move on.
    let external_port = free_port();
    let external_addr: SocketAddr = format!("127.0.0.1:{external_port}").parse().unwrap();

    let _server = match spawn_logged(
        Command::new(bin("BORE_BIN", "bore")).args([
            "server",
            "--bind-addr",
            "127.0.0.1",
            "--secret",
            TOKEN,
        ]),
        "bore_server",
        log_dir,
    ) {
        Ok(g) => g,
        Err(e) => return Outcome::Skipped(e),
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    let _client = match spawn_logged(
        Command::new(bin("BORE_BIN", "bore")).args([
            "local",
            &target.port().to_string(),
            "--to",
            "127.0.0.1",
            "--port",
            &external_port.to_string(),
            "--secret",
            TOKEN,
        ]),
        "bore_client",
        log_dir,
    ) {
        Ok(g) => g,
        Err(e) => return Outcome::Skipped(e),
    };

    if !wait_ready(external_addr, READY_TIMEOUT).await {
        return Outcome::Skipped(
            "bore tunnel never became ready (see bore_server.log/bore_client.log)".into(),
        );
    }
    match measure(external_addr).await {
        Ok(s) => Outcome::Ok(percentiles(s)),
        Err(e) => Outcome::Skipped(e),
    }
}

#[tokio::main]
async fn main() {
    let log_dir: PathBuf =
        std::env::temp_dir().join(format!("erbridge-compare-{}", std::process::id()));
    std::fs::create_dir_all(&log_dir).expect("create log dir");
    println!("logs: {}", log_dir.display());

    let target_port = free_port();
    let target: SocketAddr = format!("127.0.0.1:{target_port}").parse().unwrap();
    tokio::spawn(run_echo_server(target));
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut results: Vec<(&str, Outcome)> = Vec::new();

    results.push(("baseline (direct)", scenario_baseline(target).await));
    results.push((
        "erbridge (serve/connect)",
        scenario_erbridge_reverse(target).await,
    ));
    results.push(("frp", scenario_frp(target, &log_dir).await));
    results.push(("rathole", scenario_rathole(target, &log_dir).await));
    results.push(("bore", scenario_bore(target, &log_dir).await));

    let baseline_p50 = results
        .iter()
        .find(|(name, _)| *name == "baseline (direct)")
        .and_then(|(_, o)| match o {
            Outcome::Ok(s) => Some(s.p50),
            Outcome::Skipped(_) => None,
        });

    println!();
    println!(
        "{:<26} {:>9} {:>9} {:>9} {:>9} {:>9} {:>12}",
        "path", "min", "p50", "p95", "p99", "max", "Δp50 vs base"
    );
    println!("{}", "-".repeat(26 + 9 * 5 + 12 + 6));
    for (name, outcome) in &results {
        match outcome {
            Outcome::Ok(s) => {
                let delta = match baseline_p50 {
                    Some(b) if *name != "baseline (direct)" => format!("{:+.1} µs", s.p50 - b),
                    _ => "—".to_string(),
                };
                println!(
                    "{name:<26} {:>6.1}µs {:>6.1}µs {:>6.1}µs {:>6.1}µs {:>6.1}µs {:>12}",
                    s.min, s.p50, s.p95, s.p99, s.max, delta
                );
            }
            Outcome::Skipped(reason) => {
                println!("{name:<26} skipped — {reason}");
            }
        }
    }
    let _ = std::io::stdout().flush();
}
