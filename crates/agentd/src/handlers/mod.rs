//! Task handlers and the bounded registry used by the polling loop.

mod fetch;
mod handler;
mod mod_handler;
mod ping;
mod shell;

pub use fetch::FetchHandler;
pub use handler::{Handler, HandlerOutcome};
pub use mod_handler::ModHandler;
pub use ping::PingHandler;
pub use shell::{run_shell, ShellHandler};

use serde_cbor::Value;
use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, OnceLock,
    },
};
use thiserror::Error;
use tokio::sync::Semaphore;

/// Bounded pending-task capacity.
pub const QUEUE_CAPACITY: usize = 32;

fn active_groups() -> &'static Mutex<HashSet<u32>> {
    static GROUPS: OnceLock<Mutex<HashSet<u32>>> = OnceLock::new();
    GROUPS.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Records a child process group owned by a running handler.
pub fn register_process_group(pgid: u32) {
    if let Ok(mut groups) = active_groups().lock() {
        groups.insert(pgid);
    }
}

/// Forgets a child process group after its child has been reaped.
pub fn unregister_process_group(pgid: u32) {
    if let Ok(mut groups) = active_groups().lock() {
        groups.remove(&pgid);
    }
}

/// Terminates every child process group still running during a drain timeout.
pub fn kill_active_process_groups() {
    let groups = active_groups()
        .lock()
        .map(|groups| groups.iter().copied().collect::<Vec<_>>())
        .unwrap_or_default();
    for pgid in groups {
        crate::limits::kill_process_group(pgid);
    }
}

/// Registry errors.
#[derive(Debug, Error)]
pub enum HandlerError {
    /// A handler with this name is already registered.
    #[error("handler already registered: {0}")]
    Duplicate(String),
    /// No handler exists for this name.
    #[error("unknown handler: {0}")]
    Unknown(String),
}

/// The only dispatch surface used by the polling loop.
pub struct HandlerRegistry {
    semaphore: Arc<Semaphore>,
    limit: usize,
    handlers: BTreeMap<String, Arc<dyn Handler>>,
    queue: Mutex<VecDeque<(String, Value)>>,
    dropped: AtomicU64,
}

impl HandlerRegistry {
    /// Creates a registry with a bounded execution semaphore.
    pub fn new(limit: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(limit.max(1))),
            limit: limit.max(1),
            handlers: BTreeMap::new(),
            queue: Mutex::new(VecDeque::new()),
            dropped: AtomicU64::new(0),
        }
    }

    /// Waits until no handler invocation is in flight.
    pub async fn wait_idle(&self) {
        let Ok(permits) = u32::try_from(self.limit) else {
            return;
        };
        if let Ok(_permits) = self.semaphore.acquire_many(permits).await {
            // Permits are released when this future completes.
        }
    }

    /// Registers one handler by its stable name.
    pub fn register(&mut self, handler: Arc<dyn Handler>) -> Result<(), HandlerError> {
        let name = handler.name().to_owned();
        if self.handlers.contains_key(&name) {
            return Err(HandlerError::Duplicate(name));
        }
        self.handlers.insert(name, handler);
        Ok(())
    }

    /// Registers the built-in ping, shell, and fetch handlers.
    pub fn register_all(&mut self) -> Result<(), HandlerError> {
        self.register(Arc::new(PingHandler::default()))?;
        self.register(Arc::new(ShellHandler::default()))?;
        self.register(Arc::new(FetchHandler::default()))?;
        Ok(())
    }

    /// Returns the names currently registered.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.handlers.keys().map(String::as_str)
    }

    /// Returns how many queued tasks have been dropped by overflow.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Returns the current pending queue length.
    pub fn queue_len(&self) -> usize {
        self.queue.lock().map_or(0, |queue| queue.len())
    }

    /// Enqueues a call, dropping the oldest entry on overflow.
    ///
    /// Returns a failed outcome for the dropped task when the queue was full.
    pub fn submit(&self, name: &str, args: &Value) -> Result<Option<HandlerOutcome>, HandlerError> {
        if !self.handlers.contains_key(name) {
            return Err(HandlerError::Unknown(name.to_owned()));
        }
        let mut queue = self
            .queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let dropped = if queue.len() >= QUEUE_CAPACITY {
            queue.pop_front();
            self.dropped.fetch_add(1, Ordering::Relaxed);
            Some(HandlerOutcome::failed("queue full"))
        } else {
            None
        };
        queue.push_back((name.to_owned(), args.clone()));
        Ok(dropped)
    }

    /// Runs a handler under the registry semaphore and bounded queue.
    pub async fn handle(&self, name: &str, args: &Value) -> Result<HandlerOutcome, HandlerError> {
        self.submit(name, args)?;
        let (name, args) = self
            .queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pop_front()
            .ok_or_else(|| HandlerError::Unknown(name.to_owned()))?;
        let handler = self
            .handlers
            .get(&name)
            .cloned()
            .ok_or_else(|| HandlerError::Unknown(name.clone()))?;
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| HandlerError::Unknown(name))?;
        let args = args.clone();
        let outcome = tokio::spawn(async move { handler.handle(&args).await })
            .await
            .unwrap_or_else(|error| HandlerOutcome::failed(format!("handler panic: {error}")));
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_registration_is_rejected() {
        let mut registry = HandlerRegistry::new(4);
        registry.register_all().expect("built-ins register");
        assert!(matches!(
            registry.register(Arc::new(PingHandler::default())),
            Err(HandlerError::Duplicate(name)) if name == "ping"
        ));
    }

    #[test]
    fn queue_overflow_drops_the_oldest_and_counts_it() {
        let mut registry = HandlerRegistry::new(4);
        registry.register_all().expect("built-ins register");
        let args = Value::Map(Default::default());
        for _ in 0..QUEUE_CAPACITY {
            assert!(registry.submit("ping", &args).expect("submit").is_none());
        }
        let dropped = registry.submit("ping", &args).expect("submit");
        assert!(dropped.is_some_and(|outcome| outcome.code == -1));
        assert_eq!(registry.queue_len(), QUEUE_CAPACITY);
        assert_eq!(registry.dropped(), 1);
    }

    #[test]
    fn unknown_handler_is_rejected_before_enqueue() {
        let registry = HandlerRegistry::new(4);
        assert!(matches!(
            registry.submit("nope", &Value::Null),
            Err(HandlerError::Unknown(name)) if name == "nope"
        ));
    }

    struct PanicHandler;

    #[async_trait::async_trait]
    impl Handler for PanicHandler {
        fn name(&self) -> &str {
            "panic"
        }
        fn capabilities(&self) -> &[String] {
            &[]
        }
        async fn handle(&self, _args: &Value) -> HandlerOutcome {
            panic!("deliberate handler panic");
        }
    }

    #[tokio::test]
    async fn handler_panic_becomes_a_failed_result() {
        let mut registry = HandlerRegistry::new(2);
        registry.register(Arc::new(PanicHandler)).expect("register");
        let outcome = registry
            .handle("panic", &Value::Null)
            .await
            .expect("panic is contained");
        assert!(!outcome.ok);
        assert_eq!(outcome.code, -1);
        assert!(outcome.stderr.contains("handler panic"), "{outcome:?}");
    }
}
