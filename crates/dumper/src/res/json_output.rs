use anyhow::{Context, Result};
use std::{
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_FILE: AtomicU64 = AtomicU64::new(1);

struct PendingFile(PathBuf);
impl Drop for PendingFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Keep the old destination intact unless serialization and flush both succeed.
fn write_file<T>(path: &Path, write: impl FnOnce(&mut BufWriter<File>) -> Result<T>) -> Result<T> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temporary_path = path.with_extension(format!(
        "json.resources-part-{}-{}",
        std::process::id(),
        NEXT_FILE.fetch_add(1, Ordering::Relaxed)
    ));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary_path)
        .with_context(|| format!("create temporary output {}", temporary_path.display()))?;
    let pending = PendingFile(temporary_path);
    let mut writer = BufWriter::with_capacity(64 * 1024, file);
    let result = write(&mut writer)?;
    writer
        .flush()
        .with_context(|| format!("flush {}", pending.0.display()))?;
    drop(writer);
    std::fs::rename(&pending.0, path).with_context(|| format!("publish {}", path.display()))?;
    Ok(result)
}

pub(super) fn value(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    write_file(path, |writer| {
        serde_json::to_writer_pretty(writer, value).context("stream JSON to file")
    })
}

pub(super) fn rows(
    path: &Path,
    enumerate: impl FnOnce(&mut dyn FnMut(serde_json::Value) -> Result<()>) -> Result<usize>,
) -> Result<usize> {
    write_file(path, |writer| {
        writer.write_all(b"[\n")?;
        let mut first = true;
        let count = enumerate(&mut |row| {
            if !first {
                writer.write_all(b",\n")?;
            }
            first = false;
            serde_json::to_writer_pretty(&mut *writer, &row).context("stream JSON row")
        })?;
        writer.write_all(b"\n]")?;
        Ok(count)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streaming_failure_preserves_old_file_and_removes_partial_output() {
        let root = std::env::temp_dir().join(format!("resources-json-test-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("table.json");
        std::fs::write(&path, b"[42]").unwrap();
        assert!(
            rows(&path, |emit| {
                emit(serde_json::json!({"row": 1}))?;
                anyhow::bail!("simulated memory stop")
            })
            .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"[42]");
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
        rows(&path, |emit| {
            emit(serde_json::json!({"row": 1}))?;
            emit(serde_json::json!({"row": 2}))?;
            Ok(2)
        })
        .unwrap();
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(value, serde_json::json!([{"row": 1}, {"row": 2}]));
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
}
