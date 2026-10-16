//! Read-only access to the installed DesignData v4 package.
//!
//! `M_DesignV.bytes` names the index `DesignV_<md5>.bytes`. The index lists
//! chunk files (`<md5>.bytes`; language chunks live under `<tag>/`) and, per
//! chunk, entries keyed by xxHash64 (seed 0) of the logical path, for example
//! `BakedConfig/Config/Level/Mission/1000101/MissionInfo_1000101.bytes`.
//! Persistent and StreamingAssets are separate snapshots; lookups prefer the
//! highest revision. The index stores no names, only hashes.
use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::HashMap,
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::Mutex,
};

pub fn path_hash(logical_path: &str) -> u64 {
    xxhash_rust::xxh64::xxh64(logical_path.as_bytes(), 0)
}

#[derive(Clone, Copy, Debug)]
pub struct Entry {
    pub chunk: usize,
    pub offset: u64,
    pub size: u64,
}

pub struct Chunk {
    pub digest: String,
    pub tag: Option<String>,
    pub size: u64,
    pub path: Option<PathBuf>,
}

pub struct Snapshot {
    pub name: &'static str,
    pub revision: u32,
    pub index_digest: String,
    pub chunks: Vec<Chunk>,
    pub entries: HashMap<u64, Entry>,
    handles: Mutex<HashMap<usize, File>>,
}

pub struct DesignData {
    /// Highest revision first.
    pub snapshots: Vec<Snapshot>,
}

/// `StarRail_Data` next to the game executable (the dumper runs in-process).
pub fn game_data_dir() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("resolve game executable")?;
    let candidate = exe
        .parent()
        .context("game executable has no parent directory")?
        .join("StarRail_Data");
    if candidate.is_dir() {
        return Ok(candidate);
    }
    let fallback = std::env::current_dir()?.join("StarRail_Data");
    ensure!(
        fallback.is_dir(),
        "StarRail_Data not found next to {} or in the working directory",
        exe.display()
    );
    Ok(fallback)
}

impl DesignData {
    pub fn open(data_dir: &Path) -> Result<Self> {
        let roots = [
            ("Persistent", data_dir.join("Persistent/DesignData/Windows")),
            (
                "StreamingAssets",
                data_dir.join("StreamingAssets/DesignData/Windows"),
            ),
        ];
        let mut snapshots = Vec::new();
        for (name, root) in &roots {
            if !root.join("M_DesignV.bytes").is_file() {
                continue;
            }
            let fallback: Vec<&Path> = roots
                .iter()
                .filter(|(other, _)| other != name)
                .map(|(_, root)| root.as_path())
                .collect();
            snapshots.push(
                Snapshot::open(name, root, &fallback)
                    .with_context(|| format!("open DesignData {name} at {}", root.display()))?,
            );
        }
        ensure!(
            !snapshots.is_empty(),
            "no DesignData index under {}",
            data_dir.display()
        );
        snapshots.sort_by(|a, b| b.revision.cmp(&a.revision));
        Ok(Self { snapshots })
    }

    pub fn contains(&self, hash: u64) -> bool {
        self.snapshots.iter().any(|s| s.entries.contains_key(&hash))
    }

    pub fn lookup(&self, hash: u64) -> Option<(&Snapshot, Entry)> {
        self.snapshots
            .iter()
            .find_map(|s| s.entries.get(&hash).map(|entry| (s, *entry)))
    }

    /// Every entry once, from the highest revision that lists it.
    pub fn all_entries(&self) -> Vec<(u64, &Snapshot, Entry)> {
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for snapshot in &self.snapshots {
            for (hash, entry) in &snapshot.entries {
                if seen.insert(*hash) {
                    out.push((*hash, snapshot, *entry));
                }
            }
        }
        out
    }

    /// One log line per snapshot.
    pub fn describe(&self) -> Vec<String> {
        self.snapshots
            .iter()
            .map(|s| {
                let missing: Vec<String> = s
                    .chunks
                    .iter()
                    .filter(|c| c.path.is_none())
                    .map(|c| format!("{}({})", c.digest, c.tag.as_deref().unwrap_or("core")))
                    .collect();
                format!(
                    "{} revision={} index=DesignV_{}.bytes chunks={} entries={} missing_chunks={missing:?}",
                    s.name,
                    s.revision,
                    s.index_digest,
                    s.chunks.len(),
                    s.entries.len()
                )
            })
            .collect()
    }
}

impl Snapshot {
    fn open(name: &'static str, root: &Path, fallback_roots: &[&Path]) -> Result<Self> {
        let mini = std::fs::read(root.join("M_DesignV.bytes")).context("read M_DesignV.bytes")?;
        ensure!(
            mini.len() >= 52 && &mini[..4] == b"SRMI",
            "M_DesignV.bytes is not an SRMI header ({} bytes)",
            mini.len()
        );
        let revision = u32::from_le_bytes(mini[24..28].try_into()?);
        let mut digest = [0u8; 16];
        digest.copy_from_slice(&mini[28..44]);
        for word in digest.chunks_exact_mut(4) {
            word.reverse();
        }
        let index_digest = hex(&digest);
        let index_size = u64::from_le_bytes(mini[44..52].try_into()?);
        let index_path = root.join(format!("DesignV_{index_digest}.bytes"));
        let index =
            std::fs::read(&index_path).with_context(|| format!("read {}", index_path.display()))?;
        ensure!(
            index.len() as u64 == index_size,
            "{} has {} bytes, mini header declares {index_size}",
            index_path.display(),
            index.len()
        );
        let (mut chunks, entries) = parse_index(&index)?;
        for chunk in &mut chunks {
            // A locale chunk only ever comes from its own tag directory.
            let relative = match &chunk.tag {
                Some(tag) => PathBuf::from(tag).join(format!("{}.bytes", chunk.digest)),
                None => PathBuf::from(format!("{}.bytes", chunk.digest)),
            };
            chunk.path = std::iter::once(root)
                .chain(fallback_roots.iter().copied())
                .map(|base| base.join(&relative))
                .find(|path| {
                    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.len() == chunk.size)
                });
        }
        Ok(Self {
            name,
            revision,
            index_digest,
            chunks,
            entries,
            handles: Mutex::new(HashMap::new()),
        })
    }

    pub fn read(&self, entry: Entry) -> Result<Vec<u8>> {
        let chunk = self
            .chunks
            .get(entry.chunk)
            .context("entry references a chunk outside the index")?;
        let path = chunk.path.as_ref().with_context(|| {
            format!(
                "chunk {} (tag {:?}) is not installed",
                chunk.digest, chunk.tag
            )
        })?;
        let size = usize::try_from(entry.size).context("entry size")?;
        let mut handles = self.handles.lock().unwrap_or_else(|e| e.into_inner());
        if !handles.contains_key(&entry.chunk) {
            let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
            handles.insert(entry.chunk, file);
        }
        let file = handles.get_mut(&entry.chunk).expect("inserted above");
        file.seek(SeekFrom::Start(entry.offset))?;
        let mut buffer = vec![0u8; size];
        file.read_exact(&mut buffer).with_context(|| {
            format!(
                "read {size} bytes at {} from {}",
                entry.offset,
                path.display()
            )
        })?;
        Ok(buffer)
    }

    pub fn chunk_installed(&self, entry: Entry) -> bool {
        self.chunks
            .get(entry.chunk)
            .is_some_and(|chunk| chunk.path.is_some())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .filter(|end| *end <= self.data.len())
            .with_context(|| format!("index truncated at {} (need {len})", self.pos))?;
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into()?))
    }
    fn i32(&mut self) -> Result<i32> {
        Ok(i32::from_be_bytes(self.take(4)?.try_into()?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into()?))
    }
}

/// Strict DesignData v4 index parser (big-endian).
pub(crate) fn parse_index(data: &[u8]) -> Result<(Vec<Chunk>, HashMap<u64, Entry>)> {
    let mut r = Cursor { data, pos: 0 };
    let magic = r.u32()?;
    let version = r.u32()?;
    ensure!(
        (magic, version) == (255, 4),
        "unsupported DesignData index magic={magic} version={version}"
    );
    let file_count = r.u32()? as usize;
    let entry_count = r.u32()? as usize;
    ensure!(
        file_count
            .saturating_mul(37)
            .saturating_add(entry_count.saturating_mul(16))
            <= data.len() - r.pos,
        "index counts exceed its size"
    );
    let mut chunks = Vec::with_capacity(file_count);
    let mut entries = HashMap::with_capacity(entry_count);
    for chunk_index in 0..file_count {
        let _path_hash = r.u64()?;
        let digest = hex(r.take(16)?);
        let size = r.u64()?;
        let count = r.i32()?;
        ensure!(
            count >= 0 && entries.len() + count as usize <= entry_count,
            "chunk {chunk_index}: invalid entry count {count}"
        );
        for _ in 0..count {
            let hash = r.u64()?;
            let entry_size = u64::from(r.u32()?);
            let offset = u64::from(r.u32()?);
            ensure!(
                offset + entry_size <= size,
                "chunk {chunk_index}: entry {hash:016x} exceeds chunk size"
            );
            let previous = entries.insert(
                hash,
                Entry {
                    chunk: chunk_index,
                    offset,
                    size: entry_size,
                },
            );
            ensure!(previous.is_none(), "duplicate entry hash {hash:016x}");
        }
        let tag = match r.u8()? {
            0x80 => None,
            0 => {
                let len = r.u8()? as usize;
                let tag = std::str::from_utf8(r.take(len)?)
                    .context("chunk tag is not UTF-8")?
                    .to_string();
                ensure!(r.u8()? == 0x80, "chunk {chunk_index}: bad tag terminator");
                ensure!(
                    tag.chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
                    "chunk {chunk_index}: unsafe tag {tag:?}"
                );
                // An explicitly encoded empty tag marks a core chunk.
                (!tag.is_empty()).then_some(tag)
            }
            other => bail!("chunk {chunk_index}: bad tag marker {other:#x}"),
        };
        chunks.push(Chunk {
            digest,
            tag,
            size,
            path: None,
        });
    }
    ensure!(
        entries.len() == entry_count,
        "index lists {} entries, header declares {entry_count}",
        entries.len()
    );
    ensure!(
        r.pos == data.len(),
        "{} trailing index bytes",
        data.len() - r.pos
    );
    Ok((chunks, entries))
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    fn index(tag: Option<&str>) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend(255u32.to_be_bytes());
        d.extend(4u32.to_be_bytes());
        d.extend(1u32.to_be_bytes());
        d.extend(2u32.to_be_bytes());
        d.extend(7u64.to_be_bytes());
        d.extend([0xab; 16]);
        d.extend(100u64.to_be_bytes());
        d.extend(2i32.to_be_bytes());
        for (hash, size, offset) in [(1u64, 10u32, 0u32), (2, 20, 10)] {
            d.extend(hash.to_be_bytes());
            d.extend(size.to_be_bytes());
            d.extend(offset.to_be_bytes());
        }
        match tag {
            None => d.push(0x80),
            Some(tag) => {
                d.push(0);
                d.push(tag.len() as u8);
                d.extend(tag.as_bytes());
                d.push(0x80);
            }
        }
        d
    }

    #[test]
    fn parses_v4_index() {
        let (chunks, entries) = parse_index(&index(Some("cn"))).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].tag.as_deref(), Some("cn"));
        assert_eq!(chunks[0].digest, "ab".repeat(16));
        assert_eq!(entries[&2].offset, 10);
        assert_eq!(entries[&2].size, 20);
        // Core chunks may carry an explicitly encoded empty tag.
        let (chunks, _) = parse_index(&index(Some(""))).unwrap();
        assert_eq!(chunks[0].tag, None);
        let (chunks, _) = parse_index(&index(None)).unwrap();
        assert_eq!(chunks[0].tag, None);
    }

    #[test]
    fn rejects_truncation_trailing_bytes_and_unsafe_tags() {
        let good = index(None);
        assert!(parse_index(&good[..good.len() - 1]).is_err());
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(parse_index(&trailing).is_err());
        assert!(parse_index(&index(Some("../x"))).is_err());
    }

    #[test]
    fn path_hash_matches_client_index() {
        // Pair taken from the revision 16706787 Persistent index.
        assert_eq!(
            path_hash("BakedConfig/ExcelOutput/TextmapMain_jp.bytes"),
            0x58421c81a556484d
        );
    }

    pub(crate) fn installed_client() -> Option<DesignData> {
        let data_dir = Path::new("D:/StarRail_Beta/StarRail_Data");
        if !data_dir
            .join("Persistent/DesignData/Windows/M_DesignV.bytes")
            .is_file()
        {
            eprintln!("skipped: no installed client at {}", data_dir.display());
            return None;
        }
        Some(DesignData::open(data_dir).unwrap())
    }

    /// Read-only check against the installed client; skipped when it is absent.
    #[test]
    fn opens_installed_client_index() {
        let Some(design) = installed_client() else {
            return;
        };
        let top = &design.snapshots[0];
        assert_eq!(top.name, "Persistent");
        assert!(top.entries.len() >= 143_000, "{}", top.entries.len());
        assert!(design.all_entries().len() >= top.entries.len());
        // Locale chunks resolve only from their own tag directory.
        for chunk in top.chunks.iter().filter(|c| c.path.is_some()) {
            let path = chunk.path.as_ref().unwrap();
            match &chunk.tag {
                Some(tag) => assert_eq!(
                    path.parent().unwrap().file_name().unwrap().to_str(),
                    Some(tag.as_str())
                ),
                None => assert_ne!(
                    path.parent().unwrap().file_name().unwrap().to_str(),
                    Some("cn")
                ),
            }
        }
        let (snapshot, entry) = design
            .lookup(path_hash("BakedConfig/ConfigManifest.json"))
            .unwrap();
        let bytes = snapshot.read(entry).unwrap();
        assert_eq!(bytes.len() as u64, entry.size);
        let manifest: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(manifest.get("AdventureAbilityConfig").is_some());
    }
}
