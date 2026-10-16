//! Offline root-type sniffing for DesignData blobs.
//!
//! For each named entry, try every candidate root type with the strict
//! schema parser and record which types decode the blob exactly.
use anyhow::{Context, Result};
use rayon::prelude::*;
use resource_data::{DataDefine, DynamicParser, ValueKind, offline::index::Snapshot};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{BufRead, Write};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

const GAME: &str = "D:/StarRail_Beta";
const INVENTORY: &str = "D:/StarRail_Beta/HSR-OWNER/designdata-inventory/designdata_inventory.csv";

#[derive(Serialize)]
struct Out<'a> {
    path: &'a str,
    json: &'a str,
    kind: &'a str,
    size: u64,
    covered: bool,
    truth: Option<&'a str>,
    truth_type: Option<&'a str>,
    truth_error: Option<String>,
    exact: Vec<u16>,
    gap: Vec<(u16, u64)>,
}

struct Row {
    hash: u64,
    path: String,
    json: String,
    kind: String,
    size: u64,
    covered: bool,
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--decode") {
        // --decode <logical BakedConfig path> <full type name>
        let types: HashMap<String, DataDefine> =
            resource_data::load_types(Path::new(&format!("{GAME}/DUMP/data.json")))?;
        let snapshot = Snapshot::open(Path::new(&format!(
            "{GAME}/StarRail_Data/Persistent/DesignData/Windows"
        )))?;
        let bytes = snapshot.read(&args[2])?.context("entry not in index")?;
        let kind = ValueKind::Class(args[3].clone());
        let mut parser = DynamicParser::new_trusted(&types, &bytes);
        match parser.parse_exact(&kind, false) {
            Ok(value) => println!("{}", serde_json::to_string_pretty(&value)?),
            Err(e) => println!("ERROR {e:#}"),
        }
        return Ok(());
    }
    let out_path = args.get(1).cloned().unwrap_or("sniff.jsonl".into());
    let filter = args.get(2).cloned();
    let types: HashMap<String, DataDefine> =
        resource_data::load_types(Path::new(&format!("{GAME}/DUMP/data.json")))?;
    eprintln!("types {}", types.len());

    // loader -> return type
    let mut by_short: HashMap<String, Vec<String>> = HashMap::new();
    for key in types.keys() {
        let short = key.rsplit(['.', '/', '+']).next().unwrap_or(key);
        by_short.entry(short.to_string()).or_default().push(key.clone());
    }
    let loaders_txt = std::fs::read_to_string("../loaders.txt").context("loaders.txt")?;
    let mut loader_type: HashMap<String, String> = HashMap::new();
    let mut unresolved = Vec::new();
    for line in loaders_txt.lines() {
        // "RetType LoadName(string ) 0xRVA"
        let mut parts = line.split_whitespace();
        let (Some(ret), Some(call)) = (parts.next(), parts.next()) else { continue };
        let name = call.split('(').next().unwrap_or(call).to_string();
        let full = if types.contains_key(ret) {
            Some(ret.to_string())
        } else {
            match by_short.get(ret).map(Vec::as_slice) {
                Some([one]) => Some(one.clone()),
                Some(many) => {
                    // prefer RPG.GameCore / RPG.Client namespaces
                    many.iter()
                        .find(|k| k.starts_with("RPG.GameCore."))
                        .or_else(|| many.first())
                        .cloned()
                }
                None => None,
            }
        };
        match full {
            Some(full) => {
                loader_type.insert(name, full);
            }
            None => unresolved.push(format!("{name}:{ret}")),
        }
    }
    eprintln!("loaders resolved {} unresolved {}", loader_type.len(), unresolved.len());
    for u in &unresolved {
        eprintln!("  unresolved {u}");
    }
    let mut extra_loaders: Vec<(String, String)> = Vec::new();
    // Loaders outside GameCoreConfigLoader used by HSR-OWNER.
    for (name, ty) in [
        ("LoadRogueDialogueEventConfig", "RogueDialogueEventConfig"),
        ("LoadRogueNPCConfig", "RogueNPCConfig"),
        ("LoadRogueChestMapConfig", "RogueChestMapConfig"),
        ("LoadSummonUnitConfig", "SummonUnitConfig"),
        ("LoadLevelGraphConfig", "LevelGraphConfig"),
        ("LoadTurnBasedAbilityConfigList", "TurnBasedAbilityConfigList"),
        ("LoadMainMissionInfoConfig", "MainMissionInfoConfig"),
        ("LoadManikinMonsterConfig", "ManikinMonsterConfig"),
        ("LoadManikinCharacterConfig", "ManikinCharacterConfig"),
        ("LoadManikinPetConfig", "ManikinPetConfig"),
        ("LoadManikinServantConfig", "ManikinServantConfig"),
        ("LoadGlobalModifierConfig", "GlobalModifierConfig"),
        ("LoadSkillTreePointPresetConfig", "SkillTreePointPresetConfig"),
        ("LoadGlobalTaskListTemplateConfig", "GlobalTaskListTemplateConfig"),
        ("LoadAdventureModifierLookupTable", "AdventureModifierLookupTable"),
        ("LoadVideoCaptionConfig", "VideoCaptionConfig"),
    ] {
        if !loader_type.contains_key(name) {
            extra_loaders.push((name.into(), ty.into()));
        }
    }
    for (name, short) in extra_loaders {
        if let Some(keys) = by_short.get(&short) {
            let full = keys
                .iter()
                .find(|k| k.starts_with("RPG."))
                .or_else(|| keys.first())
                .unwrap()
                .clone();
            eprintln!("  extra loader {name} -> {full}");
            loader_type.insert(name, full);
        } else {
            eprintln!("  extra loader {name}: type {short} not in schema");
        }
    }

    // candidate roots: every loader return type with a valid schema
    let mut roots: BTreeSet<String> = loader_type.values().cloned().collect();
    if let Ok(extra) = std::fs::read_to_string("../extra_roots.txt") {
        for line in extra.lines().map(str::trim).filter(|l| !l.is_empty()) {
            if types.contains_key(line) {
                roots.insert(line.to_string());
            }
        }
    }
    let mut valid_roots = Vec::new();
    for root in &roots {
        if types.contains_key(root) {
            valid_roots.push(root.clone());
        } else {
            eprintln!("  root missing from schema {root}");
        }
    }
    eprintln!("roots {} valid {}", roots.len(), valid_roots.len());

    // ground truth from the last Resources log
    let mut truth: HashMap<String, String> = HashMap::new();
    let log = std::fs::File::open(format!("{GAME}/hsr-owner.log"))?;
    for line in std::io::BufReader::new(log).lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };
        if let Some(pos) = line.find("begin Config: load ") {
            let rest = &line[pos + "begin Config: load ".len()..];
            if let Some((loader, path)) = rest.split_once(" path=") {
                truth.insert(path.trim().to_string(), loader.to_string());
            }
        }
    }
    eprintln!("truth paths {}", truth.len());

    // inventory
    let text = std::fs::read_to_string(INVENTORY)?;
    let mut rows = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if i == 0 {
            continue;
        }
        let cols: Vec<&str> = line.split(',').collect();
        if cols.len() < 15 || cols[0] != "Persistent" || cols[8].is_empty() {
            continue;
        }
        let kind = cols[10];
        let path = cols[8];
        if path.starts_with("BakedConfig/ExcelOutput") || kind == "binary-header" {
            continue;
        }
        if let Some(f) = &filter {
            if !path.contains(f.as_str()) {
                continue;
            }
        }
        rows.push(Row {
            hash: u64::from_str_radix(cols[2], 16)?,
            path: path.to_string(),
            json: cols[9].to_string(),
            kind: kind.to_string(),
            size: cols[7].parse()?,
            covered: cols[14] == "yes",
        });
    }
    eprintln!("rows {}", rows.len());

    let snapshot = Snapshot::open(Path::new(&format!(
        "{GAME}/StarRail_Data/Persistent/DesignData/Windows"
    )))?;
    let done = AtomicUsize::new(0);
    let kinds: Vec<ValueKind> = valid_roots.iter().map(|r| ValueKind::Class(r.clone())).collect();
    let results: Vec<String> = rows
        .par_iter()
        .map(|row| {
            let bytes = match snapshot.read_hash(row.hash) {
                Ok(Some(b)) => b,
                _ => return String::new(),
            };
            let mut exact = Vec::new();
            let mut gap = Vec::new();
            for (i, kind) in kinds.iter().enumerate() {
                match DynamicParser::new_trusted(&types, &bytes).parse_exact(kind, false) {
                    Ok(_) => exact.push(i as u16),
                    Err(e) => {
                        let text = format!("{e:#}");
                        if is_gap(&text) {
                            gap.push((i as u16, deepest_offset(&text)));
                        }
                    }
                }
            }
            let matches: Vec<&str> = exact.iter().map(|&i| valid_roots[i as usize].as_str()).collect();
            let truth_loader = truth.get(&row.json).map(String::as_str);
            let truth_type = truth_loader.and_then(|l| loader_type.get(l)).map(String::as_str);
            let truth_error = truth_type.and_then(|t| {
                if matches.contains(&t) {
                    None
                } else {
                    let kind = ValueKind::Class(t.to_string());
                    DynamicParser::new_trusted(&types, &bytes)
                        .parse_exact(&kind, false)
                        .err()
                        .map(|e| format!("{e:#}").chars().take(400).collect())
                }
            });
            let n = done.fetch_add(1, Ordering::Relaxed);
            if n % 10000 == 0 {
                eprintln!("progress {n}");
            }
            serde_json::to_string(&Out {
                path: &row.path,
                json: &row.json,
                kind: &row.kind,
                size: row.size,
                covered: row.covered,
                truth: truth_loader,
                truth_type,
                truth_error,
                exact,
                gap,
            })
            .unwrap()
        })
        .collect();
    let mut file = std::io::BufWriter::new(std::fs::File::create(&out_path)?);
    for line in results.iter().filter(|l| !l.is_empty()) {
        writeln!(file, "{line}")?;
    }
    let mut lt: BTreeMap<&String, &String> = BTreeMap::new();
    for (k, v) in &loader_type {
        lt.insert(k, v);
    }
    std::fs::write("loader_types.json", serde_json::to_string_pretty(&lt)?)?;
    std::fs::write("roots.json", serde_json::to_string_pretty(&valid_roots)?)?;
    eprintln!("wrote {out_path}");
    Ok(())
}


fn is_gap(text: &str) -> bool {
    const GAPS: &[&str] = &[
        "not present for",
        "unsupported custom class format",
        "unhandled type",
        "missing its zero descendant",
        "missing schema type",
        "unhandled primitive",
        "unsupported schema kind",
        "recursive struct has no finite",
    ];
    GAPS.iter().any(|g| text.contains(g))
}

fn deepest_offset(text: &str) -> u64 {
    let mut best = 0;
    for part in text.split("at offset ").skip(1) {
        let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(v) = digits.parse::<u64>() {
            best = best.max(v);
        }
    }
    best
}
