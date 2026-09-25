use std::sync::atomic::{AtomicBool, Ordering};

/// The guard must outlive panic handling and delivery of the terminal event.
pub(super) struct TaskGate(AtomicBool);

impl TaskGate {
    pub(super) const fn new() -> Self {
        Self(AtomicBool::new(false))
    }

    pub(super) fn try_enter(&self) -> Option<TaskGuard<'_>> {
        self.0
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| TaskGuard(self))
    }
}

pub(super) struct TaskGuard<'a>(&'a TaskGate);

impl Drop for TaskGuard<'_> {
    fn drop(&mut self) {
        self.0.0.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::TaskGate;

    #[test]
    fn rejects_concurrent_task_and_allows_retry() {
        let gate = TaskGate::new();
        let guard = gate.try_enter().unwrap();
        std::thread::scope(|scope| {
            scope
                .spawn(|| assert!(gate.try_enter().is_none()))
                .join()
                .unwrap();
        });
        drop(guard);
        assert!(gate.try_enter().is_some());
    }

    #[test]
    fn releases_during_unwind() {
        let gate = TaskGate::new();
        let _ = std::panic::catch_unwind(|| {
            let _guard = gate.try_enter().unwrap();
            panic!("simulated export failure");
        });
        assert!(gate.try_enter().is_some());
    }
}
