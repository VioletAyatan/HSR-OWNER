//! Offline evidence for the same XLua enum scanner used by the runtime dumper.
use super::{
    names::identifier,
    output::{ProtoItem, TypeToItemMap, short_name},
    rsp_scan::{self, FunctionTable},
};
use anyhow::{Context, Result, ensure};
use serde::{
    Deserialize,
    de::{MapAccess, Visitor},
};
use serde_json::json;
use std::{
    collections::{HashMap, HashSet},
    fmt,
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom},
    path::Path,
};

struct Method {
    name: String,
    rva: usize,
}
#[derive(Default)]
struct Methods {
    total: usize,
    candidates: Vec<Method>,
}

fn recovered_name(signature: &str) -> Option<&str> {
    let name = signature
        .strip_prefix("XLua.StaticLuaCallbacks::Proto")?
        .strip_suffix("Get(System.IntPtr,XLua.ObjectTranslator,System.Object,System.Int32)")?;
    identifier(name).then_some(name)
}

impl<'de> Deserialize<'de> for Methods {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct MethodVisitor;
        impl<'de> Visitor<'de> for MethodVisitor {
            type Value = Methods;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("method signature/RVA object")
            }
            fn visit_map<M: MapAccess<'de>>(
                self,
                mut map: M,
            ) -> std::result::Result<Methods, M::Error> {
                let mut result = Methods::default();
                while let Some((signature, address)) = map.next_entry::<String, String>()? {
                    result.total += 1;
                    if let Some(name) = recovered_name(&signature) {
                        let rva = usize::from_str_radix(
                            address.strip_prefix("0x").unwrap_or(&address),
                            16,
                        )
                        .map_err(serde::de::Error::custom)?;
                        result.candidates.push(Method {
                            name: name.to_owned(),
                            rva,
                        });
                    }
                }
                Ok(result)
            }
        }
        deserializer.deserialize_map(MethodVisitor)
    }
}

#[derive(Deserialize)]
struct Metadata {
    #[serde(rename = "Address")]
    slot: usize,
    #[serde(rename = "Name")]
    name: String,
}
#[derive(Deserialize)]
struct Script {
    #[serde(rename = "ScriptMetadata")]
    metadata: Vec<Metadata>,
}

struct Section {
    rva: usize,
    raw_offset: u64,
    raw_size: usize,
}
struct Pe {
    file: File,
    file_len: u64,
    base: usize,
    image_len: usize,
    sections: Vec<Section>,
    records: Vec<u8>,
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<usize> {
    let end = offset.checked_add(2).context("PE word offset overflow")?;
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..end)
            .context("truncated PE word")?
            .try_into()?,
    ) as usize)
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<usize> {
    let end = offset.checked_add(4).context("PE dword offset overflow")?;
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..end)
            .context("truncated PE dword")?
            .try_into()?,
    ) as usize)
}

impl Pe {
    fn read_file(&mut self, offset: u64, length: usize) -> Result<Vec<u8>> {
        let end = offset
            .checked_add(u64::try_from(length)?)
            .context("PE file range overflow")?;
        ensure!(
            end <= self.file_len,
            "PE file range 0x{offset:X}..0x{end:X} exceeds file length"
        );
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .context("allocate PE read buffer")?;
        bytes.resize(length, 0);
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.read_exact(&mut bytes)?;
        Ok(bytes)
    }
    fn read_rva(&mut self, rva: usize, length: usize) -> Result<Vec<u8>> {
        let end = rva.checked_add(length).context("PE RVA range overflow")?;
        ensure!(end <= self.image_len, "PE RVA range exceeds SizeOfImage");
        let offsets = self
            .sections
            .iter()
            .filter_map(|section| {
                let section_end = section.rva.checked_add(section.raw_size)?;
                (rva >= section.rva && end <= section_end)
                    .then(|| {
                        section
                            .raw_offset
                            .checked_add(u64::try_from(rva - section.rva).ok()?)
                    })
                    .flatten()
            })
            .collect::<Vec<_>>();
        ensure!(
            offsets.len() == 1,
            "PE RVA 0x{rva:X} length 0x{length:X} has {} file-backed sections",
            offsets.len()
        );
        self.read_file(offsets[0], length)
    }
    fn open(path: &Path) -> Result<Self> {
        let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
        let file_len = file.metadata()?.len();
        let mut pe = Self {
            file,
            file_len,
            base: 0,
            image_len: 0,
            sections: vec![],
            records: vec![],
        };
        let dos = pe.read_file(0, 64)?;
        ensure!(dos.starts_with(b"MZ"), "missing DOS header");
        let header_offset = u32_at(&dos, 0x3c)?;
        let header = pe.read_file(u64::try_from(header_offset)?, 24)?;
        ensure!(
            header.starts_with(b"PE\0\0") && u16_at(&header, 4)? == 0x8664,
            "expected x64 PE header"
        );
        let section_count = u16_at(&header, 6)?;
        let optional_size = u16_at(&header, 20)?;
        let optional_offset = header_offset
            .checked_add(24)
            .context("PE optional-header offset overflow")?;
        let optional = pe.read_file(u64::try_from(optional_offset)?, optional_size)?;
        ensure!(
            u16_at(&optional, 0)? == 0x20b,
            "expected PE32+ optional header"
        );
        ensure!(
            u32_at(&optional, 108)? >= 4,
            "PE has no exception directory"
        );
        let base_end = 24usize.checked_add(8).context("PE base offset overflow")?;
        pe.base = usize::try_from(u64::from_le_bytes(
            optional
                .get(24..base_end)
                .context("truncated image base")?
                .try_into()?,
        ))?;
        pe.image_len = u32_at(&optional, 56)?;
        ensure!(
            pe.image_len != 0 && pe.base.checked_add(pe.image_len).is_some(),
            "invalid PE image address range"
        );
        let table_rva = u32_at(&optional, 0x88)?;
        let table_size = u32_at(&optional, 0x8c)?;
        ensure!(
            table_rva != 0 && table_size != 0 && table_size % 12 == 0,
            "invalid exception directory"
        );
        let section_offset = optional_offset
            .checked_add(optional_size)
            .context("PE section-table offset overflow")?;
        let section_size = section_count
            .checked_mul(40)
            .context("PE section-table length overflow")?;
        let sections = pe.read_file(u64::try_from(section_offset)?, section_size)?;
        for entry in sections.chunks_exact(40) {
            let virtual_size = u32_at(entry, 8)?;
            let rva = u32_at(entry, 12)?;
            let raw_size = u32_at(entry, 16)?;
            let raw_offset = u64::try_from(u32_at(entry, 20)?)?;
            ensure!(
                rva.checked_add(virtual_size.max(raw_size))
                    .is_some_and(|end| end <= pe.image_len),
                "PE section exceeds image"
            );
            ensure!(
                raw_offset
                    .checked_add(u64::try_from(raw_size)?)
                    .is_some_and(|end| end <= file_len),
                "PE section exceeds file"
            );
            pe.sections.push(Section {
                rva,
                raw_offset,
                raw_size,
            });
        }
        pe.records = pe.read_rva(table_rva, table_size)?;
        Ok(pe)
    }
}

fn add_alias(aliases: &mut HashMap<String, Option<String>>, alias: &str, original: &str) {
    let entry = aliases
        .entry(alias.to_owned())
        .or_insert_with(|| Some(original.to_owned()));
    if entry.as_deref() != Some(original) {
        *entry = None;
    }
}

pub(super) fn recover(directory: &Path, items: &TypeToItemMap) -> Result<HashMap<String, String>> {
    let methods: Methods =
        serde_json::from_reader(BufReader::new(File::open(directory.join("methods2.json"))?))
            .context("read XLua method signatures")?;
    // serde ignores the three large, unrelated arrays without allocating them.
    let script: Script = serde_json::from_reader(BufReader::new(File::open(
        directory.join("script-mini.json"),
    )?))
    .context("read declared XLua array TypeInfo metadata")?;
    let mut aliases = HashMap::new();
    for item in items.values() {
        if let ProtoItem::Enum(enumeration) = &*item.borrow() {
            let original = &enumeration.name;
            let short = short_name(original);
            if short.len() == 11 && short.bytes().all(|byte| byte.is_ascii_uppercase()) {
                add_alias(
                    &mut aliases,
                    original.strip_prefix("Proto.").unwrap_or(original),
                    original,
                );
                add_alias(&mut aliases, short, original);
            }
        }
    }
    let parent = directory.parent().context("dump directory has no parent")?;
    let mut pe = Pe::open(&parent.join("GameAssembly.dll"))?;
    let function_records = std::mem::take(&mut pe.records);
    let functions = FunctionTable::from_records(&function_records, pe.image_len)?;
    let mut slots = HashMap::<usize, Option<String>>::new();
    for entry in &script.metadata {
        let Some(array) = entry.name.strip_suffix("[]_TypeInfo") else {
            continue;
        };
        let array = array.strip_prefix("Proto.").unwrap_or(array);
        let Some(original) = aliases
            .get(array)
            .or_else(|| aliases.get(short_name(array)))
            .and_then(Option::as_ref)
        else {
            continue;
        };
        ensure!(
            entry
                .slot
                .checked_add(size_of::<usize>())
                .is_some_and(|end| end <= pe.image_len),
            "array TypeInfo slot outside image: 0x{:X}",
            entry.slot
        );
        let previous = slots
            .entry(entry.slot)
            .or_insert_with(|| Some(original.clone()));
        if previous.as_ref() != Some(original) {
            *previous = None;
        }
    }
    let declared_slots: HashSet<_> = slots
        .iter()
        .filter_map(|(&slot, owner)| owner.as_ref().map(|_| slot))
        .collect();
    let mut evidence = vec![];
    let mut proposals = vec![];
    let mut by_raw = HashMap::<String, HashSet<String>>::new();
    let mut by_name = HashMap::<String, HashSet<String>>::new();
    let (mut scanned, mut bound, mut decoded, mut missing_range) = (0, 0, 0, 0);
    for method in &methods.candidates {
        let range = functions.containing(method.rva);
        let Some(range) = range else {
            missing_range += 1;
            continue;
        };
        let code = pe
            .read_rva(range.start, range.end - range.start)
            .with_context(|| format!("read XLua enum getter RVA 0x{:X}", method.rva))?;
        let ip = pe
            .base
            .checked_add(range.start)
            .context("XLua getter address overflow")?;
        let result = rsp_scan::scan_unique(
            &code,
            u64::try_from(ip)?,
            pe.base,
            pe.image_len,
            &declared_slots,
        );
        scanned += 1;
        decoded += result.decoded;
        let Some(slot) = result.slot else { continue };
        let Some(original) = slots.get(&slot).and_then(Option::as_ref) else {
            continue;
        };
        bound += 1;
        by_raw
            .entry(original.clone())
            .or_default()
            .insert(method.name.clone());
        by_name
            .entry(method.name.clone())
            .or_default()
            .insert(original.clone());
        proposals.push((original.clone(), method.name.clone()));
        evidence.push(json!({ "method_rva": format!("0x{:X}", method.rva), "slot": format!("0x{slot:X}"), "raw_name": original, "candidate_name": method.name }));
    }
    let recovered: HashMap<_, _> = proposals
        .into_iter()
        .filter(|(raw, name)| by_raw[raw].len() == 1 && by_name[name].len() == 1)
        .collect();
    for row in &mut evidence {
        row["accepted_candidate"] = json!(
            row["raw_name"]
                .as_str()
                .is_some_and(|raw| recovered.contains_key(raw))
        );
    }
    let report = json!({
        "validation": "offline production scanner; candidate mappings may still be rejected by final apply_type_names",
        "method_signatures": methods.total, "candidate_methods": methods.candidates.len(),
        "declared_metadata_records": script.metadata.len(), "declared_array_slots": declared_slots.len(),
        "runtime_function_records": function_records.len() / 12, "scanned": scanned, "bound": bound,
        "accepted": recovered.len(), "decoded_instructions": decoded, "missing_function_range": missing_range,
        "conflicting_raw_names": by_raw.values().filter(|names| names.len() > 1).count(),
        "conflicting_candidates": by_name.values().filter(|names| names.len() > 1).count(), "evidence": evidence
    });
    serde_json::to_writer_pretty(
        File::create(directory.join("proto-xlua-enum-validation.json"))?,
        &report,
    )?;
    log::info!(
        "[XLua Enum Replay] candidates={} scanned={scanned} bound={bound} accepted={} missing_range={missing_range}",
        methods.candidates.len(),
        recovered.len()
    );
    Ok(recovered)
}

#[test]
fn exact_getter_signature_is_required() {
    assert_eq!(
        recovered_name(
            "XLua.StaticLuaCallbacks::ProtoCmdAdventureTypeGet(System.IntPtr,XLua.ObjectTranslator,System.Object,System.Int32)"
        ),
        Some("CmdAdventureType")
    );
    assert_eq!(
        recovered_name(
            "Other::ProtoCmdAdventureTypeGet(System.IntPtr,XLua.ObjectTranslator,System.Object,System.Int32)"
        ),
        None
    );
    assert_eq!(
        recovered_name("XLua.StaticLuaCallbacks::ProtoCmdAdventureTypeGet(System.IntPtr)"),
        None
    );
    assert_eq!(
        recovered_name(
            "XLua.StaticLuaCallbacks::Proto1_InvalidGet(System.IntPtr,XLua.ObjectTranslator,System.Object,System.Int32)"
        ),
        None
    );
}

#[test]
fn ambiguous_short_enum_alias_remains_rejected() {
    let mut aliases = HashMap::new();
    add_alias(&mut aliases, "AAAAAAAAAAA", "Outer.AAAAAAAAAAA");
    add_alias(&mut aliases, "AAAAAAAAAAA", "Other.AAAAAAAAAAA");
    add_alias(&mut aliases, "AAAAAAAAAAA", "Outer.AAAAAAAAAAA");
    assert_eq!(aliases["AAAAAAAAAAA"], None);
}
