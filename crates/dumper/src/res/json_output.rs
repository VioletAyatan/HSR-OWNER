use anyhow::{Context, Result};
use std::{
    collections::HashSet,
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

static NEXT_FILE: AtomicU64 = AtomicU64::new(1);

/// Destinations published by the current Resources session (normalized keys).
static PUBLISHED: Mutex<Option<HashSet<String>>> = Mutex::new(None);

/// Key a destination the way Win32 names it on disk: `/` separators, ASCII
/// case-insensitive, and trailing dots/spaces stripped from every component
/// (`CreateFileW` drops them, so `Act1.json ` and `Act1.json` are one file).
fn publish_key(path: &Path) -> String {
    let text = path.to_string_lossy().replace('\\', "/");
    text.trim_start_matches("./")
        .split('/')
        .map(|component| component.trim_end_matches([' ', '.']))
        .collect::<Vec<_>>()
        .join("/")
        .to_ascii_lowercase()
}

/// Start a fresh registry; called once per Resources session.
pub(super) fn reset_published() {
    *PUBLISHED.lock().unwrap_or_else(|e| e.into_inner()) = Some(HashSet::new());
}

pub(super) fn is_published(path: &Path) -> bool {
    PUBLISHED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .is_some_and(|set| set.contains(&publish_key(path)))
}

fn record_published(path: &Path) {
    if let Some(set) = PUBLISHED.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
        set.insert(publish_key(path));
    }
}

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
    record_published(path);
    Ok(result)
}

/// Publish raw bytes (undecoded DesignData entries).
pub(super) fn bytes(path: &Path, data: &[u8]) -> Result<()> {
    write_file(path, |writer| {
        writer.write_all(data).context("write raw bytes")
    })
}

pub(super) fn value(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    write_file(path, |writer| {
        serde_json::to_writer_pretty(writer, value).context("stream JSON to file")
    })
}

/// Publish another path for the same runtime table without allocating or
/// serializing its managed rows a second time.
pub(super) fn copy(source: &Path, destination: &Path) -> Result<()> {
    write_file(destination, |writer| {
        let mut reader = File::open(source)
            .with_context(|| format!("open table snapshot {}", source.display()))?;
        // Explicit bounded chunks keep memory checks active during large copies.
        let mut buffer = [0u8; 64 * 1024];
        loop {
            super::diagnostics::check_memory()?;
            let count = std::io::Read::read(&mut reader, &mut buffer)?;
            if count == 0 {
                break;
            }
            writer.write_all(&buffer[..count])?;
        }
        Ok(())
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
    fn publish_keys_follow_win32_trailing_space_and_dot_stripping() {
        // The runtime catalog names some Rogue dialogue acts with a trailing
        // space; Win32 writes them to the stripped name, so the DesignData
        // step must see the stripped name as already published.
        let runtime = Path::new("./DUMP/Resources/Config/Level/Rogue/Event1/Act1.json ");
        let index = Path::new("./DUMP/Resources/Config/Level/Rogue/Event1/Act1.json");
        assert_eq!(publish_key(runtime), publish_key(index));
        assert_eq!(
            publish_key(Path::new("A/dir. /b.json")),
            publish_key(Path::new("a/DIR/b.json"))
        );
        assert_ne!(
            publish_key(Path::new("a/b.json")),
            publish_key(Path::new("a/b_json"))
        );
    }

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
        let copied = root.join("copy.json");
        copy(&path, &copied).unwrap();
        assert_eq!(
            std::fs::read(&copied).unwrap(),
            std::fs::read(&path).unwrap()
        );
        assert!(copy(&root.join("missing.json"), &copied).is_err());
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 2);
        assert_eq!(
            std::fs::read(&copied).unwrap(),
            std::fs::read(&path).unwrap()
        );
        std::fs::remove_file(copied).unwrap();
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
}
