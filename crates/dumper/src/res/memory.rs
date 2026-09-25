use anyhow::{Context, Result, bail};
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};
use windows::Win32::System::{
    ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX},
    SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX},
    Threading::GetCurrentProcess,
};

const MIB: u64 = 1024 * 1024;
const PRIVATE_LIMIT: u64 = 16 * 1024 * MIB;
const COMMIT_RESERVE: u64 = 2 * 1024 * MIB;
const MIN_PHYSICAL_RESERVE: u64 = 1024 * MIB;

#[derive(Clone, Copy, Debug)]
pub(super) struct Snapshot {
    pub private_bytes: u64,
    pub working_set: u64,
    pub available_commit: u64,
    pub available_physical: u64,
    pub total_physical: u64,
}

impl Snapshot {
    pub(super) fn read() -> Result<Self> {
        let mut process = PROCESS_MEMORY_COUNTERS_EX::default();
        process.cb = std::mem::size_of_val(&process) as u32;
        let mut system = MEMORYSTATUSEX::default();
        system.dwLength = std::mem::size_of_val(&system) as u32;
        unsafe {
            GetProcessMemoryInfo(
                GetCurrentProcess(),
                (&mut process as *mut PROCESS_MEMORY_COUNTERS_EX).cast::<PROCESS_MEMORY_COUNTERS>(),
                process.cb,
            )
            .context("GetProcessMemoryInfo")?;
            GlobalMemoryStatusEx(&mut system).context("GlobalMemoryStatusEx")?;
        }
        Ok(Self {
            private_bytes: process.PrivateUsage as u64,
            working_set: process.WorkingSetSize as u64,
            available_commit: system.ullAvailPageFile,
            available_physical: system.ullAvailPhys,
            total_physical: system.ullTotalPhys,
        })
    }

    pub(super) fn summary(self) -> String {
        format!(
            "private_mib={} working_set_mib={} available_commit_mib={} available_physical_mib={} total_physical_mib={}",
            self.private_bytes / MIB,
            self.working_set / MIB,
            self.available_commit / MIB,
            self.available_physical / MIB,
            self.total_physical / MIB
        )
    }

    fn check(self) -> Result<()> {
        let physical_reserve = MIN_PHYSICAL_RESERVE.max(self.total_physical / 20);
        if self.private_bytes >= PRIVATE_LIMIT
            || self.available_commit <= COMMIT_RESERVE
            || self.available_physical <= physical_reserve
        {
            bail!(
                "Resources memory limit reached; cooperative stop requested: {} (private_limit_mib={}, commit_reserve_mib={}, physical_reserve_mib={}); partial output retained; game memory is not forcibly collected",
                self.summary(),
                PRIVATE_LIMIT / MIB,
                COMMIT_RESERVE / MIB,
                physical_reserve / MIB
            );
        }
        Ok(())
    }
}

struct State {
    sampled: Instant,
    snapshot: Snapshot,
    failure: Option<String>,
}

pub(super) struct Monitor(Mutex<State>);

impl Monitor {
    pub(super) fn new() -> Result<Self> {
        let snapshot = Snapshot::read()?;
        log::info!(
            "[Resources memory] start {} private_limit_mib={} commit_reserve_mib={}",
            snapshot.summary(),
            PRIVATE_LIMIT / MIB,
            COMMIT_RESERVE / MIB
        );
        snapshot.check()?;
        Ok(Self(Mutex::new(State {
            sampled: Instant::now(),
            snapshot,
            failure: None,
        })))
    }

    pub(super) fn check(&self) -> Result<()> {
        self.sample(false).map(|_| ())
    }

    pub(super) fn sample(&self, force: bool) -> Result<Snapshot> {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if force
            || (state.failure.is_none() && state.sampled.elapsed() >= Duration::from_millis(100))
        {
            let result = Snapshot::read().and_then(|snapshot| {
                state.snapshot = snapshot;
                snapshot.check()
            });
            state.sampled = Instant::now();
            if let Err(error) = result {
                let message = format!("{error:#}");
                if state.failure.is_none() {
                    log::error!("[Resources memory] {message}");
                    state.failure = Some(message);
                }
            }
        }
        if let Some(error) = &state.failure {
            bail!("{error}");
        }
        Ok(state.snapshot)
    }

    pub(super) fn summary(&self) -> String {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .snapshot
            .summary()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_checks_process_and_system_commit_independently() {
        let healthy = Snapshot {
            private_bytes: PRIVATE_LIMIT - 1,
            working_set: 0,
            available_commit: COMMIT_RESERVE + 1,
            available_physical: 4 * 1024 * MIB,
            total_physical: 16 * 1024 * MIB,
        };
        assert!(healthy.check().is_ok());
        assert!(
            Snapshot {
                private_bytes: PRIVATE_LIMIT,
                ..healthy
            }
            .check()
            .is_err()
        );
        assert!(
            Snapshot {
                available_commit: COMMIT_RESERVE,
                ..healthy
            }
            .check()
            .is_err()
        );
    }

    #[test]
    fn memory_snapshot_works_without_game() {
        let snapshot = Snapshot::read().unwrap();
        assert!(snapshot.private_bytes > 0);
        assert!(snapshot.working_set > 0);
        assert!(snapshot.total_physical > 0);
        assert!(snapshot.available_physical <= snapshot.total_physical);
    }

    #[test]
    fn physical_pressure_stops_even_with_plenty_of_commit() {
        let mut snapshot = Snapshot {
            private_bytes: 10 * 1024 * MIB,
            working_set: 9 * 1024 * MIB,
            available_commit: 24 * 1024 * MIB,
            available_physical: MIN_PHYSICAL_RESERVE,
            total_physical: 16 * 1024 * MIB,
        };
        assert!(
            snapshot
                .check()
                .unwrap_err()
                .to_string()
                .contains("physical_reserve_mib=1024")
        );
        snapshot.available_physical += 1;
        assert!(snapshot.check().is_ok());
        snapshot.total_physical = 64 * 1024 * MIB;
        snapshot.available_physical = snapshot.total_physical / 20;
        assert!(snapshot.check().is_err());
        snapshot.available_physical += 1;
        assert!(snapshot.check().is_ok());
    }
}
