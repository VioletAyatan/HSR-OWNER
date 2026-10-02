//! Explicit disk-only regression of captured native methods; never run by default.
use super::super::sync_scan::{self, Mode, ScanResult};
use super::{Binding, Pe, Resolver};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::BTreeMap, collections::BTreeSet, fs, path::PathBuf, time::Instant};

type Key = (usize, String, String);
type Pair = (u32, u32);

#[derive(Deserialize)]
struct Input {
    image_size: usize,
    scanner_sha256: String,
    methods: Vec<Method>,
}
#[derive(Deserialize)]
struct Method {
    owner: String,
    signature: String,
    rva: usize,
    mode: String,
    code: String,
    body_end: usize,
    body_bytes: usize,
    function_bounds: Option<[usize; 2]>,
    next_metadata_entry: usize,
    #[serde(default = "default_scalar_bytes")]
    scalar_bytes: usize,
}
fn default_scalar_bytes() -> usize {
    4
}
#[derive(Deserialize)]
struct Baseline {
    methods: Vec<Previous>,
}
#[derive(Deserialize)]
struct Previous {
    owner: String,
    signature: String,
    rva: usize,
    mode: String,
    body_end: usize,
    body_bytes: usize,
    copies: Vec<PreviousCopy>,
    accessor_offset: Option<u32>,
    accessor_sites: Vec<usize>,
}
#[derive(Deserialize)]
struct PreviousCopy {
    proto_offset: u32,
    business_offset: u32,
}

fn key(rva: usize, owner: &str, signature: &str) -> Key {
    (rva, owner.to_owned(), signature.to_owned())
}
fn code(hex: &str) -> Result<Vec<u8>> {
    ensure!(
        hex.len() % 2 == 0 && hex.is_ascii(),
        "invalid native hex length/encoding"
    );
    (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).context("invalid native hex byte"))
        .collect()
}
fn pairs(scan: &ScanResult) -> BTreeSet<Pair> {
    scan.copies
        .iter()
        .map(|c| (c.proto_offset, c.business_offset))
        .collect()
}
fn scan_json(scan: &ScanResult) -> Value {
    json!({
        "copies": scan.copies.iter().map(|c| json!({
            "proto_offset": c.proto_offset, "business_offset": c.business_offset,
            "load_rva": c.load_rva, "store_rva": c.store_rva,
        })).collect::<Vec<_>>(),
        "accessor_offset": scan.accessor_offset, "accessor_sites": scan.accessor_sites,
        "decoded": scan.decoded, "rejected_paths": scan.rejected_paths,
        "ambiguous": scan.ambiguous,
    })
}

fn mapped_disk(file: &[u8], expected_image_size: usize) -> Result<Vec<u8>> {
    let bytes = |at: usize, len: usize| -> Result<&[u8]> {
        file.get(at..at.checked_add(len).context("disk offset overflow")?)
            .context("truncated disk PE")
    };
    let u16_at =
        |at| -> Result<usize> { Ok(u16::from_le_bytes(bytes(at, 2)?.try_into()?) as usize) };
    let u32_at =
        |at| -> Result<usize> { Ok(u32::from_le_bytes(bytes(at, 4)?.try_into()?) as usize) };
    ensure!(bytes(0, 2)? == b"MZ", "disk DOS signature mismatch");
    let pe = u32_at(0x3c)?;
    ensure!(bytes(pe, 4)? == b"PE\0\0", "disk PE signature mismatch");
    let coff = pe.checked_add(4).context("COFF offset overflow")?;
    bytes(coff, 20)?;
    ensure!(u16_at(coff)? == 0x8664, "disk image is not AMD64");
    let count = u16_at(coff + 2)?;
    let optional_size = u16_at(coff + 16)?;
    let opt = coff.checked_add(20).context("optional-header overflow")?;
    bytes(opt, optional_size)?;
    ensure!(
        optional_size >= 112 && u16_at(opt)? == 0x20b,
        "disk image is not PE32+"
    );
    let image_size = u32_at(opt + 56)?;
    let headers = u32_at(opt + 60)?;
    ensure!(
        image_size == expected_image_size && headers > 0 && headers <= image_size,
        "disk/captured image size mismatch or invalid headers"
    );
    let table = opt
        .checked_add(optional_size)
        .context("section table overflow")?;
    let section_bytes = count
        .checked_mul(40)
        .context("section table length overflow")?;
    ensure!(
        table
            .checked_add(section_bytes)
            .is_some_and(|end| end <= headers),
        "section table outside headers"
    );
    bytes(table, section_bytes)?;
    let mut image = Vec::new();
    image
        .try_reserve_exact(image_size)
        .context("mapped image allocation failed")?;
    image.resize(image_size, 0);
    image[..headers].copy_from_slice(bytes(0, headers)?);
    for n in 0..count {
        let at = table + n * 40;
        let rva = u32_at(at + 12)?;
        let raw_size = u32_at(at + 16)?;
        let raw = u32_at(at + 20)?;
        let end = rva
            .checked_add(raw_size)
            .context("section mapped range overflow")?;
        image
            .get_mut(rva..end)
            .context("section outside mapped image")?
            .copy_from_slice(bytes(raw, raw_size)?);
    }
    Ok(image)
}

fn validate_method(pe: &Pe<'_>, method: &Method) -> Result<Vec<u8>> {
    let bytes = code(&method.code)?;
    ensure!(
        !bytes.is_empty() && bytes.len() == method.body_bytes,
        "captured body length mismatch"
    );
    ensure!(
        method.rva.checked_add(bytes.len()) == Some(method.body_end),
        "captured body end mismatch"
    );
    ensure!(
        method.next_metadata_entry > method.rva && method.body_end <= method.next_metadata_entry,
        "captured metadata next entry does not bound body"
    );
    ensure!(
        pe.executable(method.rva, bytes.len()),
        "method outside executable PE section"
    );
    let current = pe.containing_function(method.rva);
    match (method.function_bounds, current) {
        (Some([start, end]), Some(current)) => {
            ensure!(
                start == current.start && end == current.end,
                "captured/current PE function bounds differ"
            );
            ensure!(
                method.body_end == end.min(method.next_metadata_entry),
                "captured body does not use PE/metadata intersection"
            );
        }
        (None, None) => {
            ensure!(
                method.body_end == method.next_metadata_entry,
                "leaf body does not reach supplied metadata next entry"
            );
        }
        _ => anyhow::bail!("captured/current pdata ownership differs"),
    }
    ensure!(
        pe.bytes(method.rva, bytes.len())? == bytes,
        "captured native bytes differ from current DLL"
    );
    Ok(bytes)
}

#[test]
#[ignore = "requires explicit current DLL and candidate native capture; disk evidence, not naming acceptance"]
fn replay_candidate_native_methods() -> Result<()> {
    let total = Instant::now();
    let path = |name| -> Result<PathBuf> {
        Ok(PathBuf::from(
            std::env::var(name).with_context(|| format!("missing {name}"))?,
        ))
    };
    let dll_path = path("HSR_PROTO_FLOW_DLL")?;
    let input_path = path("HSR_PROTO_FLOW_INPUT")?;
    let output = path("HSR_PROTO_FLOW_OUT")?;
    let input: Input = serde_json::from_slice(&fs::read(&input_path)?)?;
    ensure!(!input.methods.is_empty(), "empty candidate capture");
    let image = mapped_disk(&fs::read(&dll_path)?, input.image_size)?;
    let pe = Pe::new(&image, |_, _| Ok(()))?;
    let mut resolver = Resolver::new(pe, Binding::DeclaredDisk);
    let mut rows = Vec::new();
    let mut identities = BTreeSet::new();
    let mut failures = 0;
    let mut heartbeat = Instant::now();
    for (index, method) in input.methods.iter().enumerate() {
        ensure!(
            identities.insert((
                key(method.rva, &method.owner, &method.signature),
                method.scalar_bytes
            )),
            "duplicate native identity"
        );
        let mut row = json!({"owner":method.owner,"signature":method.signature,"rva":method.rva,
            "mode":method.mode,"body_bytes":method.body_bytes,"body_end":method.body_end,"scalar_bytes":method.scalar_bytes});
        let result = (|| -> Result<()> {
            let mode = match method.mode.as_str() {
                "Sync" => Mode::Sync,
                "Getter" => Mode::Getter,
                "Setter" => Mode::Setter,
                _ => anyhow::bail!("unsupported candidate scan mode"),
            };
            let bytes = validate_method(&resolver.pe, method)?;
            let before = sync_scan::scan_typed(&bytes, method.rva, mode, method.scalar_bytes);
            row["ordinary_scan"] = scan_json(&before);
            let mut after = None;
            if mode == Mode::Sync {
                match resolver.plan(method.rva, &bytes) {
                    Ok(plan) => {
                        after = Some(sync_scan::scan_planned_typed(
                            &bytes,
                            method.rva,
                            mode,
                            &plan.terminal_calls,
                            &plan.exceptional_edges,
                            &plan.switch_edges,
                            plan.code_bytes,
                            method.scalar_bytes,
                        ));
                        row["plan"] = serde_json::to_value(plan)?;
                    }
                    Err(error) => row["plan_error"] = json!(format!("{error:#}")),
                }
            }
            row["scan"] = scan_json(after.as_ref().unwrap_or(&before));
            Ok(())
        })();
        if let Err(error) = result {
            failures += 1;
            row["error"] = json!(format!("{error:#}"));
        }
        rows.push(row);
        if heartbeat.elapsed().as_secs() >= 1 {
            eprintln!(
                "[Native Candidates] scanned={}/{} failures={failures}",
                index + 1,
                input.methods.len()
            );
            heartbeat = Instant::now();
        }
    }
    let report = json!({"validation":if failures == 0 {"success"} else {"failed"},
        "input":input_path,"source_dll":dll_path,"binding":"declared-disk-only","methods":rows,
        "statistics":resolver.stats,"failures":failures,"total_ms":total.elapsed().as_secs_f64()*1000.0,
        "boundary":"Complete current disk bodies bounded by captured PE/metadata; scanner assumes instance RCX=this/RDX=Proto. Method instance, actual return ABI and declared typed property require runtime verification before any naming acceptance."});
    fs::create_dir_all(&output)?;
    fs::write(
        output.join("candidate-native-output.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    ensure!(failures == 0, "{failures} invalid native captures");
    Ok(())
}

#[test]
#[ignore = "requires explicit current DLL, captured native input/baseline and output directory; disk-only"]
fn replay_existing_native_methods() -> Result<()> {
    let total = Instant::now();
    let path = |name| -> Result<PathBuf> {
        Ok(PathBuf::from(
            std::env::var(name).with_context(|| format!("missing {name}"))?,
        ))
    };
    let dll_path = path("HSR_PROTO_FLOW_DLL")?;
    let input_path = path("HSR_PROTO_FLOW_INPUT")?;
    let baseline_path = path("HSR_PROTO_FLOW_BASELINE")?;
    let output = path("HSR_PROTO_FLOW_OUT")?;
    let input: Input = serde_json::from_slice(&fs::read(&input_path)?)?;
    let baseline: Baseline = serde_json::from_slice(&fs::read(&baseline_path)?)?;
    ensure!(!input.methods.is_empty(), "empty native regression input");
    let mut previous = BTreeMap::new();
    for item in baseline.methods {
        let id = key(item.rva, &item.owner, &item.signature);
        ensure!(
            previous.insert(id.clone(), item).is_none(),
            "duplicate baseline identity {id:?}"
        );
    }
    let mut identities = BTreeSet::new();
    for method in &input.methods {
        let id = key(method.rva, &method.owner, &method.signature);
        ensure!(
            identities.insert(id.clone()),
            "duplicate input identity {id:?}"
        );
    }
    ensure!(
        identities == previous.keys().cloned().collect(),
        "input/baseline identities differ"
    );
    let disk = fs::read(&dll_path)?;
    let image = mapped_disk(&disk, input.image_size)?;
    drop(disk);
    fn readable(_: usize, _: usize) -> Result<()> {
        Ok(())
    }
    let pe = Pe::new(&image, readable)?;
    let function_count = pe.function_count();
    let setup_ms = total.elapsed().as_secs_f64() * 1000.0;
    let mut resolver = Resolver::new(pe, Binding::DeclaredDisk);
    let mut rows = Vec::with_capacity(input.methods.len());
    let mut failures = 0usize;
    let mut plan_errors = 0usize;
    let mut added_pairs = 0usize;
    let mut removed_pairs = 0usize;
    let mut baseline_errors = 0usize;
    let mut sync_methods = 0usize;
    let mut planned_methods = 0usize;
    let mut changed_methods = 0usize;
    let mut heartbeat = Instant::now();
    for (index, method) in input.methods.iter().enumerate() {
        let timer = Instant::now();
        let old = &previous[&key(method.rva, &method.owner, &method.signature)];
        let mut row = json!({"owner":method.owner,"signature":method.signature,"rva":method.rva,
            "mode":method.mode,"body_bytes":method.body_bytes,"body_end":method.body_end,"pass":false});
        let result = (|| -> Result<()> {
            ensure!(
                method.mode == old.mode
                    && method.body_end == old.body_end
                    && method.body_bytes == old.body_bytes,
                "input/baseline method metadata differs"
            );
            let mode = match method.mode.as_str() {
                "Sync" => Mode::Sync,
                "Getter" => Mode::Getter,
                "Setter" => Mode::Setter,
                _ => anyhow::bail!("unsupported captured scanner mode"),
            };
            let bytes = validate_method(&resolver.pe, method)?;
            row["native_bytes_match"] = json!(true);
            let before = sync_scan::scan(&bytes, method.rva, mode);
            let before_pairs = pairs(&before);
            let expected: BTreeSet<_> = old
                .copies
                .iter()
                .map(|c| (c.proto_offset, c.business_offset))
                .collect();
            let old_sites: BTreeSet<_> = old.accessor_sites.iter().copied().collect();
            let baseline_matches = before_pairs == expected
                && before.accessor_offset == old.accessor_offset
                && before
                    .accessor_sites
                    .iter()
                    .copied()
                    .collect::<BTreeSet<_>>()
                    == old_sites;
            baseline_errors += usize::from(!baseline_matches);
            row["baseline_matches"] = json!(baseline_matches);
            row["baseline_pairs"] = json!(expected);
            row["old_scan"] = scan_json(&before);
            let mut after = None;
            if mode == Mode::Sync {
                sync_methods += 1;
                row["plan_attempted"] = json!(true);
                match resolver.plan(method.rva, &bytes) {
                    Ok(plan) => {
                        planned_methods += usize::from(!plan.terminal_calls.is_empty());
                        after = Some(sync_scan::scan_planned_typed(
                            &bytes,
                            method.rva,
                            mode,
                            &plan.terminal_calls,
                            &plan.exceptional_edges,
                            &plan.switch_edges,
                            plan.code_bytes,
                            4,
                        ));
                        row["plan"] = serde_json::to_value(plan)?;
                        row["fallback_to_old"] = json!(false);
                    }
                    Err(error) => {
                        plan_errors += 1;
                        row["plan_error"] = json!(format!("{error:#}"));
                        row["fallback_to_old"] = json!(true);
                    }
                }
            } else {
                row["plan_attempted"] = json!(false);
            }
            let after = after.as_ref().unwrap_or(&before);
            let after_pairs = pairs(after);
            let added: Vec<_> = after_pairs.difference(&before_pairs).copied().collect();
            let removed: Vec<_> = before_pairs.difference(&after_pairs).copied().collect();
            added_pairs += added.len();
            removed_pairs += removed.len();
            changed_methods += usize::from(!added.is_empty() || !removed.is_empty());
            let accessor_unchanged = after.accessor_offset == before.accessor_offset
                && after.accessor_sites == before.accessor_sites;
            row["added_pairs"] = json!(added);
            row["removed_pairs"] = json!(removed);
            row["accessor_unchanged"] = json!(accessor_unchanged);
            row["new_scan"] = scan_json(after);
            ensure!(
                baseline_matches,
                "ordinary scanner differs from captured baseline"
            );
            ensure!(
                removed.is_empty(),
                "controlled CFG loses previously witnessed copy pairs"
            );
            ensure!(
                accessor_unchanged,
                "controlled CFG changes accessor evidence"
            );
            Ok(())
        })();
        match result {
            Ok(()) => row["pass"] = json!(true),
            Err(error) => {
                failures += 1;
                row["error"] = json!(format!("{error:#}"));
            }
        }
        row["elapsed_ms"] = json!(timer.elapsed().as_secs_f64() * 1000.0);
        rows.push(row);
        if heartbeat.elapsed().as_secs() >= 1 {
            eprintln!(
                "[Sync Flow Replay] methods={}/{} failures={} plan_errors={}",
                index + 1,
                input.methods.len(),
                failures,
                plan_errors
            );
            heartbeat = Instant::now();
        }
    }
    ensure!(
        resolver.cache.len() <= function_count,
        "proof cache exceeds actual PE function count"
    );
    let report = json!({
        "validation": if failures == 0 { "success" } else { "failed" },
        "source_dll":dll_path,"input":input_path,"baseline":baseline_path,
        "binding":"declared-disk-only","baseline_scanner_sha256":input.scanner_sha256,
        "methods":rows,"summary":{"methods":input.methods.len(),"sync_methods":sync_methods,
            "planned_methods":planned_methods,"changed_methods":changed_methods,
            "added_copy_pairs":added_pairs,"removed_copy_pairs":removed_pairs,
            "baseline_errors":baseline_errors,"plan_errors":plan_errors,"failures":failures,
            "runtime_functions":function_count,"cache_entries":resolver.cache.len(),
            "setup_ms":setup_ms,"total_ms":total.elapsed().as_secs_f64()*1000.0},
        "statistics":resolver.stats,
        "boundary":"Disk PE/native-byte and copy/accessor regression only. Leaf ranges use supplied captured metadata bounds. No current runtime reflection, original field-name, live IAT or in-game validation.",
    });
    fs::create_dir_all(&output)?;
    fs::write(
        output.join("batch-flow-replay.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    ensure!(
        failures == 0,
        "{failures} native regression failures; inspect batch-flow-replay.json"
    );
    Ok(())
}
