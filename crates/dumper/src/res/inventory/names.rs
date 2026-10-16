//! Logical names for DesignData entries (the index stores only xxHash64).
//!
//! Sources, each accepted only on an exact hash hit against the installed index:
//! - the embedded table recovered offline for revision 16706787
//!   (front-coded `<shared>\t<suffix>` lines, LZ4 with size prefix);
//! - path strings inside every installed chunk (configs reference each other
//!   by `Config/...json` paths), so later client versions still resolve;
//! - the client's own path transforms (`.layout.`, `.partial.`).
use super::super::design_data::{DesignData, path_hash};
use anyhow::{Context, Result};
use std::{collections::HashMap, io::Read};

static EMBEDDED: &[u8] = include_bytes!("../../../resources/designdata/names.lz4");

/// Longest path token considered; also the scan window overlap.
const MAX_TOKEN: usize = 400;
const WINDOW: usize = 16 << 20;

pub struct Names {
    pub by_hash: HashMap<u64, String>,
    pub embedded_hits: usize,
    pub discovered: usize,
}

fn embedded() -> Result<Vec<String>> {
    let text = lz4_flex::decompress_size_prepended(EMBEDDED).context("decompress name table")?;
    let text = String::from_utf8(text).context("name table is not UTF-8")?;
    let mut names = Vec::new();
    let mut previous = String::new();
    for line in text.lines() {
        let (shared, suffix) = line.split_once('\t').context("malformed name table line")?;
        let shared: usize = shared.parse().context("malformed shared prefix")?;
        // The generator counts characters, not bytes.
        let mut name: String = previous.chars().take(shared).collect();
        name.push_str(suffix);
        names.push(name.clone());
        previous = name;
    }
    Ok(names)
}

/// Client transforms: insert `.layout.` / `.partial.` before the extension.
fn variants(logical: &str) -> Vec<String> {
    let Some(stem) = logical.strip_suffix(".bytes") else {
        return Vec::new();
    };
    ["layout", "partial", "partial.layout"]
        .iter()
        .map(|tag| format!("{stem}.{tag}.bytes"))
        .collect()
}

fn is_path_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'/' | b'-')
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Candidate logical paths from path strings embedded in `data`.
fn scan(data: &[u8], emit: &mut dyn FnMut(String)) {
    const MARKERS: [&[u8]; 4] = [b"BakedConfig/", b"Config/", b"Story/", b"Stages/"];
    let mut i = 0;
    while i < data.len() {
        if !matches!(data[i], b'B' | b'C' | b'S') {
            i += 1;
            continue;
        }
        let Some(marker) = MARKERS.iter().find(|m| data[i..].starts_with(m)) else {
            i += 1;
            continue;
        };
        let mut end = i;
        while end < data.len() && end - i < MAX_TOKEN && is_path_byte(data[end]) {
            end += 1;
        }
        let token = &data[i..end];
        // A following field can append path-like bytes; cut at every extension.
        for ext in [&b".json"[..], b".bytes"] {
            let mut from = 0;
            while let Some(pos) = find(&token[from..], ext) {
                let cut = from + pos + ext.len();
                if let Ok(text) = std::str::from_utf8(&token[..cut]) {
                    let stem = text
                        .strip_suffix(".json")
                        .or_else(|| text.strip_suffix(".bytes"))
                        .unwrap_or(text);
                    if *marker == b"BakedConfig/" {
                        emit(format!("{stem}.bytes"));
                    } else {
                        emit(format!("BakedConfig/{stem}.bytes"));
                    }
                }
                from = cut;
            }
        }
        i = end.max(i + marker.len());
    }
}

/// Scan a chunk file in bounded windows; tokens never exceed the overlap.
fn scan_file(path: &std::path::Path, emit: &mut dyn FnMut(String)) -> Result<()> {
    let mut file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut buffer = vec![0u8; WINDOW + MAX_TOKEN];
    let mut kept = 0;
    loop {
        let mut filled = kept;
        while filled < buffer.len() {
            let read = file
                .read(&mut buffer[filled..])
                .with_context(|| format!("read {}", path.display()))?;
            if read == 0 {
                break;
            }
            filled += read;
        }
        if filled == kept {
            return Ok(());
        }
        scan(&buffer[..filled], emit);
        if filled < buffer.len() {
            return Ok(());
        }
        buffer.copy_within(filled - MAX_TOKEN..filled, 0);
        kept = MAX_TOKEN;
        super::super::diagnostics::check_memory()?;
    }
}

pub fn resolve(design: &DesignData) -> Result<Names> {
    let mut by_hash = HashMap::new();
    let mut embedded_hits = 0;
    for name in embedded()? {
        let hash = path_hash(&name);
        if design.contains(hash) && by_hash.insert(hash, name).is_none() {
            embedded_hits += 1;
        }
    }
    // Discovery: strings inside every installed chunk.
    let mut pending: Vec<String> = Vec::new();
    for snapshot in &design.snapshots {
        for chunk in &snapshot.chunks {
            let Some(path) = &chunk.path else { continue };
            scan_file(path, &mut |candidate| {
                let hash = path_hash(&candidate);
                if !by_hash.contains_key(&hash) && design.contains(hash) {
                    pending.push(candidate);
                }
            })?;
        }
    }
    // Client transforms on everything named so far, to a fixed point.
    pending.extend(by_hash.values().flat_map(|name| variants(name)));
    let mut discovered = 0;
    while !pending.is_empty() {
        let mut next = Vec::new();
        for name in pending {
            let hash = path_hash(&name);
            if !by_hash.contains_key(&hash) && design.contains(hash) {
                next.extend(variants(&name));
                by_hash.insert(hash, name);
                discovered += 1;
            }
        }
        pending = next;
    }
    Ok(Names {
        by_hash,
        embedded_hits,
        discovered,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_table_decodes() {
        let names = embedded().unwrap();
        assert_eq!(names.len(), 136_836);
        assert!(names.windows(2).all(|w| w[0] < w[1]));
        assert!(names.contains(&"BakedConfig/ExcelOutput/TextmapMain_jp.bytes".to_string()));
        assert!(
            names.contains(
                &"BakedConfig/Config/Level/Mission/1000101/MissionInfo_1000101.partial.bytes"
                    .to_string()
            )
        );
    }

    #[test]
    fn scan_extracts_json_and_baked_paths() {
        let mut out = Vec::new();
        scan(
            b"\x2dConfig/Level/Mission/1/Act/Act1.json\x01xBakedConfig/ExcelOutput/A.bytes\x00Story/Discussion/X.jsonZZ",
            &mut |s| out.push(s),
        );
        assert!(out.contains(&"BakedConfig/Config/Level/Mission/1/Act/Act1.bytes".to_string()));
        assert!(out.contains(&"BakedConfig/ExcelOutput/A.bytes".to_string()));
        assert!(out.contains(&"BakedConfig/Story/Discussion/X.bytes".to_string()));
    }

    #[test]
    fn scan_file_finds_tokens_across_window_boundaries() {
        let dir = std::env::temp_dir().join(format!("designdata-scan-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("chunk.bytes");
        let token = b"Config/Level/Boundary/Graph_1.json";
        // Starts 10 bytes before the first window ends, so only the overlap sees it whole.
        let mut data = vec![0u8; WINDOW + MAX_TOKEN - 10];
        data.extend_from_slice(token);
        data.extend_from_slice(&[0u8; 32]);
        std::fs::write(&path, &data).unwrap();
        let mut out = Vec::new();
        scan_file(&path, &mut |s| out.push(s)).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(out.contains(&"BakedConfig/Config/Level/Boundary/Graph_1.bytes".to_string()));
    }

    #[test]
    fn variants_follow_client_transforms() {
        assert_eq!(
            variants("BakedConfig/Config/A/MissionInfo_1.bytes"),
            [
                "BakedConfig/Config/A/MissionInfo_1.layout.bytes",
                "BakedConfig/Config/A/MissionInfo_1.partial.bytes",
                "BakedConfig/Config/A/MissionInfo_1.partial.layout.bytes",
            ]
        );
    }
}
