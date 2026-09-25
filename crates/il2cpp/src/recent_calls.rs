use std::{collections::VecDeque, sync::Mutex};

const MAX_ENTRIES: usize = 256;
const MAX_SIGNATURE_BYTES: usize = 1024;
static HISTORY: Mutex<History> = Mutex::new(History::new());

/// Diagnostic history must not retain one heap allocation per reflection call.
struct History {
    entries: VecDeque<String>,
    calls: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct NativeCallHistoryStats {
    pub calls: u64,
    pub retained: usize,
    pub reserved_bytes: usize,
}

impl History {
    const fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            calls: 0,
        }
    }

    fn record(&mut self, signature: &str) {
        self.calls = self.calls.saturating_add(1);
        // Reuse the evicted string allocation after the ring fills up.
        let mut entry = if self.entries.len() == MAX_ENTRIES {
            self.entries.pop_front().unwrap()
        } else {
            String::with_capacity(MAX_SIGNATURE_BYTES)
        };
        entry.clear();
        if signature.len() > MAX_SIGNATURE_BYTES {
            let mut end = MAX_SIGNATURE_BYTES - 3;
            while !signature.is_char_boundary(end) {
                end -= 1;
            }
            entry.push_str(&signature[..end]);
            entry.push_str("...");
        } else {
            entry.push_str(signature);
        }
        self.entries.push_back(entry);
    }

    fn stats(&self) -> NativeCallHistoryStats {
        NativeCallHistoryStats {
            calls: self.calls,
            retained: self.entries.len(),
            reserved_bytes: self.entries.capacity() * std::mem::size_of::<String>()
                + self.entries.iter().map(String::capacity).sum::<usize>(),
        }
    }
}

pub(super) fn record(signature: &str) {
    HISTORY
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .record(signature);
}

/// Oldest to newest; only the diagnostic copy is truncated, never method lookup.
pub fn recent_native_sigs() -> Vec<String> {
    HISTORY
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entries
        .iter()
        .cloned()
        .collect()
}

pub fn clear_native_sigs() {
    *HISTORY.lock().unwrap_or_else(|e| e.into_inner()) = History::new();
}

pub fn native_call_history_stats() -> NativeCallHistoryStats {
    HISTORY.lock().unwrap_or_else(|e| e.into_inner()).stats()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn million_reflection_calls_keep_storage_bounded_and_reuse_allocations() {
        let mut history = History::new();
        for _ in 0..MAX_ENTRIES {
            history.record("System.Reflection.MonoField::GetValue14");
        }
        let reserved = history.stats().reserved_bytes;
        for _ in MAX_ENTRIES..1_000_000 {
            history.record("System.RuntimeType::GetTypeFromHandle201");
        }
        let stats = history.stats();
        assert_eq!(stats.calls, 1_000_000);
        assert_eq!(stats.retained, MAX_ENTRIES);
        assert_eq!(stats.reserved_bytes, reserved);
        assert!(reserved <= MAX_ENTRIES * (MAX_SIGNATURE_BYTES + std::mem::size_of::<String>()));
    }

    #[test]
    fn retains_recent_order_and_truncates_utf8_without_changing_input() {
        let mut history = History::new();
        for index in 0..300 {
            history.record(&format!("method-{index}"));
        }
        assert_eq!(history.entries.front().unwrap(), "method-44");
        assert_eq!(history.entries.back().unwrap(), "method-299");
        let signature = "方法".repeat(600);
        history.record(&signature);
        let retained = history.entries.back().unwrap();
        assert!(retained.len() <= MAX_SIGNATURE_BYTES);
        assert!(retained.ends_with("..."));
        assert_eq!(signature.len(), 3600);
    }
}
