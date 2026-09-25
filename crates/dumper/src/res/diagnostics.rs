use anyhow::{Context, Result};
use std::{
    cell::RefCell,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
thread_local! {
    static ACTIVE: RefCell<Option<Arc<Mutex<State>>>> = const { RefCell::new(None) };
}

struct State {
    id: u64,
    current: String,
    since: Instant,
    files: usize,
    memory: Arc<super::memory::Monitor>,
}

pub(super) struct Session {
    state: Arc<Mutex<State>>,
    started: Instant,
    stop: mpsc::Sender<()>,
}

impl Session {
    pub(super) fn start() -> Result<Self> {
        let root = std::env::current_dir().context("resolve Resources output directory")?;
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        if let Some(value) = std::env::var_os("GC_DONT_GC") {
            log::warn!(
                "[Resources #{id}] GC_DONT_GC={value:?}; environment requests disabled collection; actual runtime GC state is unverified, managed temporary objects may accumulate"
            );
        }
        let memory = Arc::new(super::memory::Monitor::new()?);
        let state = Arc::new(Mutex::new(State {
            id,
            current: "starting".into(),
            since: Instant::now(),
            files: 0,
            memory: memory.clone(),
        }));
        let (stop, rx) = mpsc::channel();
        let watched = state.clone();
        std::thread::Builder::new().name(format!("resources-watch-{id}")).spawn(move || {
            let mut ticks = 0;
            while matches!(rx.recv_timeout(Duration::from_millis(250)), Err(mpsc::RecvTimeoutError::Timeout)) {
                let _ = memory.check();
                ticks += 1;
                if ticks % 40 != 0 { continue; }
                let state = watched.lock().unwrap_or_else(|e| e.into_inner());
                log::info!("[Resources #{id}] heartbeat operation={} operation_elapsed_ms={} files_written={} {} {}",
                    state.current, state.since.elapsed().as_millis(), state.files, memory.summary(), native_history_summary());
            }
        }).context("start Resources diagnostics")?;
        ACTIVE.with(|active| *active.borrow_mut() = Some(state.clone()));
        log::info!(
            "[Resources #{id}] start unix_ms={} output={} log={} package_version={}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
            root.join("DUMP/Resources").display(),
            root.join("hsr-owner.log").display(),
            env!("CARGO_PKG_VERSION")
        );
        Ok(Self {
            state,
            started: Instant::now(),
            stop,
        })
    }

    pub(super) fn current(&self) -> String {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .current
            .clone()
    }

    pub(super) fn finish(&self, result: &Result<()>) {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let _ = state.memory.sample(true);
        log::info!(
            "[Resources #{}] final memory {} {}",
            state.id,
            state.memory.summary(),
            native_history_summary()
        );
        match result {
            Ok(()) => log::info!(
                "[Resources #{}] finished elapsed_ms={} files_written={}",
                state.id,
                self.started.elapsed().as_millis(),
                state.files
            ),
            Err(error) => log::error!(
                "[Resources #{}] failed operation={} elapsed_ms={} files_written={} (partial output retained): {error:#}",
                state.id,
                state.current,
                self.started.elapsed().as_millis(),
                state.files
            ),
        }
    }
}

fn native_history_summary() -> String {
    let stats = il2cpp::native_call_history_stats();
    format!(
        "native_calls={} history_entries={} history_reserved_bytes={}",
        stats.calls, stats.retained, stats.reserved_bytes
    )
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        ACTIVE.with(|active| *active.borrow_mut() = None);
    }
}

fn update(label: String, emit: bool) {
    ACTIVE.with(|active| {
        if let Some(state) = active.borrow().as_ref() {
            let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
            state.current = label;
            state.since = Instant::now();
            if emit {
                log::info!("[Resources #{}] {}", state.id, state.current);
            }
        }
    });
}

pub(super) fn checkpoint(label: impl Into<String>) {
    update(label.into(), true);
}

pub(super) fn row_checkpoint(table: &str, row: usize, operation: &str) {
    // Record every call in memory, but only emit periodic progress to disk/UI.
    update(
        format!("{table} row={row} operation={operation}"),
        row % 1000 == 0 && operation == "MoveNext",
    );
}

pub(super) fn file_written() {
    ACTIVE.with(|active| {
        if let Some(state) = active.borrow().as_ref() {
            state.lock().unwrap_or_else(|e| e.into_inner()).files += 1;
        }
    });
}

pub(super) fn check_memory() -> Result<()> {
    ACTIVE.with(|active| {
        if let Some(state) = active.borrow().as_ref() {
            state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .memory
                .check()?;
        }
        Ok(())
    })
}

pub(super) fn operation<T>(label: impl Into<String>, run: impl FnOnce() -> Result<T>) -> Result<T> {
    let label = label.into();
    checkpoint(format!("begin {label}"));
    let before = sample_memory().with_context(|| label.clone())?;
    let start = Instant::now();
    let result = run().with_context(|| label.clone());
    let after = sample_memory();
    if result.is_ok() {
        let after = after.with_context(|| format!("after {label}"))?;
        let memory = before
            .zip(after)
            .map(|(before, after)| {
                format!(
                    " private_delta_mib={} {}",
                    (after.private_bytes as i64 - before.private_bytes as i64) / (1024 * 1024),
                    after.summary()
                )
            })
            .unwrap_or_default();
        checkpoint(format!(
            "end {label} elapsed_ms={}{memory}",
            start.elapsed().as_millis()
        ));
    }
    result
}

fn sample_memory() -> Result<Option<super::memory::Snapshot>> {
    ACTIVE.with(|active| {
        active
            .borrow()
            .as_ref()
            .map(|state| {
                state
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .memory
                    .sample(true)
            })
            .transpose()
    })
}
