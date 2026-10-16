//! TextMap: every installed language, decoded straight from DesignData.
//!
//! `BakedConfig/ExcelOutput/Textmap_<lang>.bytes` and `TextmapMain_<lang>.bytes`
//! are `TextmapExcelTable` row files: a zigzag varint row count, then per row a
//! varint field mask (1 = ID, 2 = Text, 4 = HasParam) followed by the present
//! fields (`ID.Hash` zigzag int32, `ID.Hash64` varint uint64, `Text` varint
//! length + UTF-8, `HasParam` varint 0/1). Rows keep file order and the runtime
//! serializer's shape; on this client the decoded `Textmap_cn` equals the
//! runtime `TextmapExcelTable` dump row for row (397,428 rows).
//!
//! Output follows the per-language convention `TextMap/TextMap<LANG>.json` and
//! `TextMap/TextMapMain<LANG>.json`. Only when no `Textmap_*` file decodes does
//! the step fall back to the runtime table, which holds the active language
//! only and keeps its legacy name `TextMapEN.json`.
use super::design_data::{DesignData, path_hash};
use super::{checkpoint, diagnostics, json_output, operation};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

const LANGUAGES: [&str; 14] = [
    "cn", "en", "jp", "kr", "chs", "cht", "de", "es", "fr", "ru", "th", "vi", "pt", "id",
];
const TABLES: [(&str, &str); 2] = [("Textmap", "TextMap"), ("TextmapMain", "TextMapMain")];

/// `Textmap_cn` -> `TextMapCN.json`, `TextmapMain_jp` -> `TextMapMainJP.json`.
pub(super) fn output_name(stem: &str) -> Option<String> {
    let (input, language) = stem.split_once('_')?;
    let (_, output) = TABLES.iter().find(|(name, _)| *name == input)?;
    (!language.is_empty()
        && language.len() <= 8
        && language.bytes().all(|b| b.is_ascii_alphanumeric()))
    .then(|| format!("{output}{}.json", language.to_ascii_uppercase()))
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn varint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = *self
                .data
                .get(self.pos)
                .with_context(|| format!("varint truncated at {}", self.pos))?;
            self.pos += 1;
            value |= u64::from(byte & 0x7f) << shift;
            if byte < 0x80 {
                return Ok(value);
            }
        }
        bail!("varint longer than 10 bytes ending at {}", self.pos)
    }

    fn bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .filter(|end| *end <= self.data.len())
            .with_context(|| format!("{len} bytes at {} exceed the entry", self.pos))?;
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }
}

fn zigzag(value: u64) -> i64 {
    ((value >> 1) as i64) ^ -((value & 1) as i64)
}

/// Decode a baked TextMap file; fails on unknown fields, truncation or trailing bytes.
pub(super) fn decode_rows(data: &[u8], emit: &mut dyn FnMut(Value) -> Result<()>) -> Result<usize> {
    let mut cursor = Cursor { data, pos: 0 };
    let count = zigzag(cursor.varint().context("row count")?);
    ensure!(
        count >= 0 && count as u64 <= data.len() as u64,
        "invalid row count {count}"
    );
    for index in 0..count as usize {
        let flags = cursor
            .varint()
            .with_context(|| format!("row {index} mask"))?;
        ensure!(
            flags & !7 == 0,
            "row {index}: unknown field mask {flags:#x}"
        );
        let (mut hash, mut hash64, mut text, mut has_param) = (0i64, 0u64, Value::Null, false);
        if flags & 1 != 0 {
            hash = zigzag(
                cursor
                    .varint()
                    .with_context(|| format!("row {index} ID.Hash"))?,
            );
            ensure!(
                i32::try_from(hash).is_ok(),
                "row {index}: ID.Hash {hash} is not an int32"
            );
            hash64 = cursor
                .varint()
                .with_context(|| format!("row {index} ID.Hash64"))?;
        }
        if flags & 2 != 0 {
            let len = usize::try_from(cursor.varint()?)?;
            let bytes = cursor
                .bytes(len)
                .with_context(|| format!("row {index} Text"))?;
            text = Value::String(
                std::str::from_utf8(bytes)
                    .with_context(|| format!("row {index}: Text is not UTF-8"))?
                    .to_owned(),
            );
        }
        if flags & 4 != 0 {
            let value = cursor.varint()?;
            ensure!(value <= 1, "row {index}: HasParam {value}");
            has_param = value == 1;
        }
        emit(json!({
            "Text": text,
            "ID": {"Hash": hash, "Hash64": hash64},
            "HasParam": has_param,
        }))?;
    }
    ensure!(
        cursor.pos == data.len(),
        "{} trailing bytes after {count} rows",
        data.len() - cursor.pos
    );
    Ok(count as usize)
}

pub fn dump(design: &DesignData) -> Result<()> {
    let mut decoded_textmaps = 0;
    for language in LANGUAGES {
        for (input, _) in TABLES {
            let logical = format!("BakedConfig/ExcelOutput/{input}_{language}.bytes");
            let Some((snapshot, entry)) = design.lookup(path_hash(&logical)) else {
                continue;
            };
            if !snapshot.chunk_installed(entry) {
                let tag = snapshot.chunks[entry.chunk]
                    .tag
                    .as_deref()
                    .unwrap_or("core");
                checkpoint(format!(
                    "TextMap: {logical} is listed but its '{tag}' chunk is not installed"
                ));
                continue;
            }
            let name = output_name(&format!("{input}_{language}")).context("TextMap name")?;
            let output = PathBuf::from(format!("./DUMP/Resources/TextMap/{name}"));
            let data = snapshot.read(entry)?;
            let result = operation(
                format!("TextMap: decode {logical} -> {}", output.display()),
                || {
                    let rows = json_output::rows(&output, |emit| decode_rows(&data, emit))?;
                    diagnostics::file_written();
                    Ok(rows)
                },
            );
            match result {
                Ok(rows) => {
                    checkpoint(format!("TextMap: {name} rows={rows}"));
                    if input == "Textmap" {
                        decoded_textmaps += 1;
                    }
                }
                // Left unpublished; the DesignData step keeps the raw bytes.
                Err(error) => log::warn!("[Resources] TextMap: {logical} not decoded: {error:#}"),
            }
        }
    }
    if decoded_textmaps == 0 {
        log::warn!(
            "[Resources] TextMap: no Textmap_<lang> decoded; using the runtime table (active language, legacy name TextMapEN.json)"
        );
        let name = "RPG.GameCore.TextmapExcelTable";
        super::write_table(
            super::runtime_type(name)?,
            name,
            Path::new("./DUMP/Resources/TextMap/TextMapEN.json"),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn varint(mut value: u64, out: &mut Vec<u8>) {
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                return;
            }
            out.push(byte | 0x80);
        }
    }

    fn zz(value: i64) -> u64 {
        ((value << 1) ^ (value >> 63)) as u64
    }

    fn sample() -> Vec<u8> {
        let mut d = Vec::new();
        varint(zz(2), &mut d);
        // full row
        varint(7, &mut d);
        varint(zz(-1_793_724_068), &mut d);
        varint(9_946_548_085_294_031_227, &mut d);
        varint(6, &mut d);
        d.extend_from_slice("哀丽".as_bytes());
        varint(1, &mut d);
        // ID + Text only
        varint(3, &mut d);
        varint(zz(2_036_795_812), &mut d);
        varint(12_518_437_936_274_253_375, &mut d);
        varint(0, &mut d);
        d
    }

    fn decode(data: &[u8]) -> Result<Vec<Value>> {
        let mut rows = Vec::new();
        decode_rows(data, &mut |row| {
            rows.push(row);
            Ok(())
        })?;
        Ok(rows)
    }

    #[test]
    fn decodes_rows_in_runtime_shape() {
        let rows = decode(&sample()).unwrap();
        assert_eq!(
            serde_json::to_string(&rows[0]).unwrap(),
            r#"{"Text":"哀丽","ID":{"Hash":-1793724068,"Hash64":9946548085294031227},"HasParam":true}"#
        );
        assert_eq!(
            rows[1],
            json!({"Text": "", "ID": {"Hash": 2036795812u32, "Hash64": 12518437936274253375u64}, "HasParam": false})
        );
    }

    #[test]
    fn rejects_truncation_trailing_bytes_and_unknown_fields() {
        let data = sample();
        assert!(decode(&data[..data.len() - 1]).is_err());
        let mut trailing = data.clone();
        trailing.push(0);
        assert!(decode(&trailing).is_err());
        let mut unknown = Vec::new();
        varint(zz(1), &mut unknown);
        varint(8, &mut unknown);
        assert!(decode(&unknown).is_err());
    }

    #[test]
    fn output_names_follow_language_convention() {
        assert_eq!(output_name("Textmap_cn").as_deref(), Some("TextMapCN.json"));
        assert_eq!(
            output_name("TextmapMain_jp").as_deref(),
            Some("TextMapMainJP.json")
        );
        assert_eq!(output_name("DrinkMakerCheersTypeTextmap"), None);
        assert_eq!(output_name("Textmap_a_b"), None);
        assert_eq!(output_name("Textmap_"), None);
    }

    /// Offline check against the installed client; skipped when it is absent.
    #[test]
    fn decodes_installed_textmaps_exactly() {
        let Some(design) = super::super::design_data::tests::installed_client() else {
            return;
        };
        let pinned = design.snapshots[0].revision == 16_706_787;
        for (logical, expected) in [
            ("BakedConfig/ExcelOutput/Textmap_cn.bytes", 397_428usize),
            ("BakedConfig/ExcelOutput/Textmap_en.bytes", 393_961),
            ("BakedConfig/ExcelOutput/TextmapMain_kr.bytes", 1_128),
        ] {
            let (snapshot, entry) = design.lookup(path_hash(logical)).unwrap();
            let data = snapshot.read(entry).unwrap();
            let mut first = None;
            let count = decode_rows(&data, &mut |row| {
                first.get_or_insert(row);
                Ok(())
            })
            .unwrap();
            if pinned {
                assert_eq!(count, expected, "{logical}");
            }
            if pinned && logical.ends_with("Textmap_cn.bytes") {
                // Same first row as the runtime TextmapExcelTable dump of this client.
                assert_eq!(
                    serde_json::to_string(&first.unwrap()).unwrap(),
                    r#"{"Text":"拍摄「巨树」","ID":{"Hash":2036795812,"Hash64":12518437936274253375},"HasParam":false}"#
                );
            }
        }
    }
}
