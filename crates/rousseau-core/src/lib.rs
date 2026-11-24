//! Core of Rousseau: the normalized event model, the agent process-tree tracker,
//! the correlation engine that ties OS activity back to tool calls, the
//! detection rule engine, incident grouping, SQLite storage and the portable
//! `.rousseau` bundle format.
//!
//! Everything in this crate is platform independent so that it can be unit
//! tested anywhere and so the same semantics can be mirrored by the Python
//! `rousseau-lab` package.

pub mod bundle;
pub mod config;
pub mod correlate;
pub mod event;
pub mod hash;
pub mod incident;
pub mod paths;
pub mod pipeline;
pub mod rules;
pub mod storage;
pub mod time;
pub mod tree;

pub use event::{Event, EventKind, Severity};

/// Version string embedded into bundles and API responses.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Anything that accepts events produced by a sensor, proxy or adapter.
///
/// Implementations must never block for long: sensors call this from hot
/// paths. Bounded channels with `try_send` are the expected implementation.
pub trait EventSink: Send + Sync {
    /// Hands one event to the sink. Returns `false` if the event was dropped
    /// (for example because a bounded queue was full).
    fn emit(&self, event: Event) -> bool;
}

/// An [`EventSink`] backed by a bounded tokio channel. Dropped events are
/// counted so that sensor health can report them.
#[derive(Clone)]
pub struct ChannelSink {
    tx: tokio::sync::mpsc::Sender<Event>,
    dropped: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl ChannelSink {
    /// Wraps a bounded sender.
    pub fn new(tx: tokio::sync::mpsc::Sender<Event>) -> Self {
        Self { tx, dropped: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)) }
    }

    /// Number of events dropped because the channel was full or closed.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl EventSink for ChannelSink {
    fn emit(&self, event: Event) -> bool {
        match self.tx.try_send(event) {
            Ok(()) => true,
            Err(_) => {
                self.dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                false
            }
        }
    }
}
