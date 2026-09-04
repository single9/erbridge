use std::collections::VecDeque;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;

pub type ConnId = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
        }
    }
}

/// Live view of one active (or just-closed) connection, cheap to clone since the
/// byte counters are shared atomics updated by the pump loop as data flows.
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub id: ConnId,
    pub label: String,
    pub protocol: Protocol,
    pub source: String,
    pub destination: String,
    pub started_at: Instant,
    pub bytes_in: Arc<AtomicU64>,
    pub bytes_out: Arc<AtomicU64>,
}

impl ConnectionInfo {
    pub fn duration(&self) -> Duration {
        self.started_at.elapsed()
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    ConnectionOpened {
        id: ConnId,
        label: String,
        protocol: Protocol,
        source: String,
        destination: String,
    },
    ConnectionClosed {
        id: ConnId,
        label: String,
        protocol: Protocol,
        source: String,
        destination: String,
        bytes_in: u64,
        bytes_out: u64,
        duration_ms: u128,
    },
    Info {
        message: String,
    },
    Error {
        message: String,
    },
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Event::ConnectionOpened {
                label,
                protocol,
                source,
                destination,
                ..
            } => write!(f, "[open] {label} {protocol} {source} -> {destination}"),
            Event::ConnectionClosed {
                label,
                protocol,
                source,
                destination,
                bytes_in,
                bytes_out,
                duration_ms,
                ..
            } => write!(
                f,
                "[close] {label} {protocol} {source} -> {destination} in={bytes_in}B out={bytes_out}B dur={duration_ms}ms"
            ),
            Event::Info { message } => write!(f, "[info] {message}"),
            Event::Error { message } => write!(f, "[error] {message}"),
        }
    }
}

#[derive(Serialize)]
struct JsonLogLine<'a> {
    ts_unix_ms: u128,
    #[serde(flatten)]
    event: &'a Event,
}

const MAX_LOG_LINES: usize = 500;

struct Inner {
    next_id: AtomicU64,
    total_bytes_in: AtomicU64,
    total_bytes_out: AtomicU64,
    total_connections: AtomicU64,
    live: Mutex<Vec<ConnectionInfo>>,
    log: Mutex<VecDeque<String>>,
    log_file: Mutex<Option<File>>,
}

/// Shared registry of live connections and recent events, read by the TUI and,
/// when a log file is configured, mirrored to disk as JSON lines for headless use.
#[derive(Clone)]
pub struct Registry(Arc<Inner>);

impl Registry {
    pub fn new() -> Self {
        Registry(Arc::new(Inner {
            next_id: AtomicU64::new(1),
            total_bytes_in: AtomicU64::new(0),
            total_bytes_out: AtomicU64::new(0),
            total_connections: AtomicU64::new(0),
            live: Mutex::new(Vec::new()),
            log: Mutex::new(VecDeque::with_capacity(MAX_LOG_LINES)),
            log_file: Mutex::new(None),
        }))
    }

    pub fn set_log_file(&self, path: PathBuf) -> anyhow::Result<()> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        *self.0.log_file.lock().unwrap() = Some(file);
        Ok(())
    }

    fn next_id(&self) -> ConnId {
        self.0.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Register a new connection and emit its `ConnectionOpened` event. Returns a
    /// handle whose `bytes_in`/`bytes_out` counters the caller should update live.
    pub fn open(
        &self,
        label: impl Into<String>,
        protocol: Protocol,
        source: impl Into<String>,
        destination: impl Into<String>,
    ) -> ConnectionInfo {
        let info = ConnectionInfo {
            id: self.next_id(),
            label: label.into(),
            protocol,
            source: source.into(),
            destination: destination.into(),
            started_at: Instant::now(),
            bytes_in: Arc::new(AtomicU64::new(0)),
            bytes_out: Arc::new(AtomicU64::new(0)),
        };
        self.0.total_connections.fetch_add(1, Ordering::Relaxed);
        self.0.live.lock().unwrap().push(info.clone());
        self.push_event(Event::ConnectionOpened {
            id: info.id,
            label: info.label.clone(),
            protocol: info.protocol,
            source: info.source.clone(),
            destination: info.destination.clone(),
        });
        info
    }

    pub fn close(&self, info: &ConnectionInfo) {
        let bytes_in = info.bytes_in.load(Ordering::Relaxed);
        let bytes_out = info.bytes_out.load(Ordering::Relaxed);
        self.0.total_bytes_in.fetch_add(bytes_in, Ordering::Relaxed);
        self.0
            .total_bytes_out
            .fetch_add(bytes_out, Ordering::Relaxed);
        self.0.live.lock().unwrap().retain(|c| c.id != info.id);
        self.push_event(Event::ConnectionClosed {
            id: info.id,
            label: info.label.clone(),
            protocol: info.protocol,
            source: info.source.clone(),
            destination: info.destination.clone(),
            bytes_in,
            bytes_out,
            duration_ms: info.duration().as_millis(),
        });
    }

    pub fn info(&self, message: impl Into<String>) {
        self.push_event(Event::Info {
            message: message.into(),
        });
    }

    pub fn error(&self, message: impl Into<String>) {
        self.push_event(Event::Error {
            message: message.into(),
        });
    }

    fn push_event(&self, event: Event) {
        let line = event.to_string();
        {
            let mut log = self.0.log.lock().unwrap();
            if log.len() >= MAX_LOG_LINES {
                log.pop_front();
            }
            log.push_back(line);
        }
        if let Some(file) = self.0.log_file.lock().unwrap().as_mut() {
            let ts_unix_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis();
            let json = JsonLogLine {
                ts_unix_ms,
                event: &event,
            };
            if let Ok(mut s) = serde_json::to_string(&json) {
                s.push('\n');
                let _ = file.write_all(s.as_bytes());
            }
        }
    }

    pub fn live_connections(&self) -> Vec<ConnectionInfo> {
        self.0.live.lock().unwrap().clone()
    }

    pub fn recent_log(&self) -> Vec<String> {
        self.0.log.lock().unwrap().iter().cloned().collect()
    }

    pub fn totals(&self) -> Totals {
        let live = self.0.live.lock().unwrap();
        let live_bytes_in: u64 = live
            .iter()
            .map(|c| c.bytes_in.load(Ordering::Relaxed))
            .sum();
        let live_bytes_out: u64 = live
            .iter()
            .map(|c| c.bytes_out.load(Ordering::Relaxed))
            .sum();
        Totals {
            live_connections: live.len(),
            total_connections: self.0.total_connections.load(Ordering::Relaxed),
            bytes_in: self.0.total_bytes_in.load(Ordering::Relaxed) + live_bytes_in,
            bytes_out: self.0.total_bytes_out.load(Ordering::Relaxed) + live_bytes_out,
        }
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Totals {
    pub live_connections: usize,
    pub total_connections: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}
