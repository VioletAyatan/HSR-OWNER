use anyhow::{Context, Result};
use std::{
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant},
};

struct State {
    stage: &'static str,
    index: usize,
    total: usize,
    address: usize,
    operation: &'static str,
    since: Instant,
}

/// Only update the current operation in memory. The separate watcher can report
/// a native call that never returns, without logging/flushing every table row.
pub(crate) struct Progress {
    name: &'static str,
    state: Arc<Mutex<State>>,
    started: Instant,
    stop: mpsc::Sender<()>,
}

impl Progress {
    pub(crate) fn start(name: &'static str) -> Result<Self> {
        let state = Arc::new(Mutex::new(State {
            stage: "starting",
            index: 0,
            total: 0,
            address: 0,
            operation: "starting",
            since: Instant::now(),
        }));
        let watched = state.clone();
        let started = Instant::now();
        let (stop, rx) = mpsc::channel();
        std::thread::Builder::new()
            .name(format!("{name}-progress"))
            .spawn(move || {
                while matches!(
                    rx.recv_timeout(Duration::from_secs(10)),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ) {
                    // Never hold the progress lock while writing to the logger.
                    let summary = describe(&watched);
                    log::info!(
                        "[{name} Dumper] heartbeat elapsed_ms={} {summary}",
                        started.elapsed().as_millis()
                    );
                }
            })
            .context("start dump progress watcher")?;
        log::info!("[{name} Dumper] start");
        Ok(Self {
            name,
            state,
            started,
            stop,
        })
    }

    pub(crate) fn stage(&self, stage: &'static str, total: usize) {
        *self.state.lock().unwrap_or_else(|e| e.into_inner()) = State {
            stage,
            index: 0,
            total,
            address: 0,
            operation: "begin",
            since: Instant::now(),
        };
        log::info!("[{} Dumper] stage={stage} total={total}", self.name);
    }

    pub(crate) fn step(&self, index: usize, address: usize, operation: &'static str) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.index = index;
        state.address = address;
        state.operation = operation;
        state.since = Instant::now();
    }

    pub(crate) fn summary(&self) -> String {
        describe(&self.state)
    }

    pub(crate) fn finish<T, E: std::fmt::Display>(&self, result: &std::result::Result<T, E>) {
        match result {
            Ok(_) => log::info!(
                "[{} Dumper] finished elapsed_ms={}",
                self.name,
                self.started.elapsed().as_millis()
            ),
            Err(error) => log::error!(
                "[{} Dumper] failed elapsed_ms={} {}: {error:#}",
                self.name,
                self.started.elapsed().as_millis(),
                self.summary()
            ),
        }
    }
}

fn describe(state: &Mutex<State>) -> String {
    let state = state.lock().unwrap_or_else(|e| e.into_inner());
    format!(
        "stage={} index={} total={} address=0x{:X} operation={} operation_elapsed_ms={}",
        state.stage,
        state.index,
        state.total,
        state.address,
        state.operation,
        state.since.elapsed().as_millis()
    )
}

impl Drop for Progress {
    fn drop(&mut self) {
        let _ = self.stop.send(());
    }
}
