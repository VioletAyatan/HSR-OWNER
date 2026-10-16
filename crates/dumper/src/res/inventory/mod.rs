//! Complete the Resources export from the DesignData index itself.
//!
//! The earlier steps discover resources by reference (manifest, Excel fields,
//! templates, callbacks) and cannot see files nothing points to. This step
//! walks every entry of the installed index once:
//!
//! - already published earlier in this session: recorded only;
//! - named config/story/stage entry: decoded with the client's deserializer
//!   picked by `rules`, accepted only on exact consumption, and written as
//!   JSON at its JSON-domain path under `DUMP/Resources`;
//! - anything else (no rule, every candidate rejected, Excel binary headers,
//!   tables the runtime does not expose, unnamed hashes): raw bytes under
//!   `DUMP/ResourcesRaw`.
//!
//! `DUMP/ResourcesInventory.csv` lists every index entry with its outcome and
//! `DUMP/ResourcesInventory.json` summarizes the run.
mod decode;
mod names;
pub(super) mod rules;

use super::design_data::{DesignData, Entry, Snapshot};
use super::{checkpoint, diagnostics, json_output, operation};
use anyhow::{Context, Result};
use reflection::serializer::BoxedSerializer;
use serde_json::json;
use std::{
    collections::BTreeMap,
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

const RESOURCES: &str = "./DUMP/Resources";
const RAW: &str = "./DUMP/ResourcesRaw";
const REPORT: &str = "./DUMP/ResourcesInventory.csv";
const SUMMARY: &str = "./DUMP/ResourcesInventory.json";

#[derive(Debug)]
enum Kind {
    TextMap(String),
    Excel(String),
    ExcelHeader,
    RawJson(String),
    Config(String),
    Other,
}

fn classify(logical: &str) -> Kind {
    let Some(rest) = logical.strip_prefix("BakedConfig/") else {
        return Kind::Other;
    };
    let file = rest.rsplit('/').next().unwrap_or(rest);
    let root = rest.split('/').next().unwrap_or("");
    if root.starts_with("ExcelOutput") {
        if file.contains(".binary_header.") {
            return Kind::ExcelHeader;
        }
        let stem = file.strip_suffix(".bytes").unwrap_or(file);
        if let Some(output) = super::textmap::output_name(stem) {
            return Kind::TextMap(format!("TextMap/{output}"));
        }
        // The runtime ExcelOutput step names every root's table by file stem.
        return Kind::Excel(format!("ExcelOutput/{stem}.json"));
    }
    if file.ends_with(".json") {
        return Kind::RawJson(rest.to_string());
    }
    match rules::json_path(logical) {
        Some(json) => Kind::Config(json),
        None => Kind::Other,
    }
}

/// Logical names come from hash hits, but must still stay inside the output root.
fn safe_relative(path: &str) -> bool {
    const RESERVED: [&str; 4] = ["CON", "PRN", "AUX", "NUL"];
    !path.is_empty()
        && path.split('/').all(|part| {
            let base = part.split('.').next().unwrap_or(part).to_ascii_uppercase();
            let device = RESERVED.contains(&base.as_str())
                || ((base.starts_with("COM") || base.starts_with("LPT"))
                    && base.len() == 4
                    && base.as_bytes()[3].is_ascii_digit());
            !part.is_empty()
                && part != "."
                && part != ".."
                && !device
                && !part.ends_with(['.', ' '])
                && !part
                    .chars()
                    .any(|c| c.is_control() || "<>:\"\\|?*".contains(c))
        })
}

fn csv(field: &str) -> String {
    if field.contains([',', '"', '\n', '\r']) {
        format!(
            "\"{}\"",
            field.replace('"', "\"\"").replace(['\n', '\r'], " ")
        )
    } else {
        field.to_string()
    }
}

fn write_raw(relative: &str, data: &[u8]) -> Result<()> {
    json_output::bytes(&PathBuf::from(format!("{RAW}/{relative}")), data)?;
    diagnostics::file_written();
    Ok(())
}

#[derive(Default)]
struct Stats {
    status: BTreeMap<String, usize>,
    bytes: BTreeMap<String, u64>,
    decoded: BTreeMap<String, usize>,
    rejected: BTreeMap<String, usize>,
    raw_reasons: BTreeMap<String, usize>,
    missing_chunks: BTreeMap<String, usize>,
}

/// A failed decode that grows the process by this much disables its rule at
/// once: a wrong root type reads garbage lengths and allocates accordingly.
const SPIKE_BYTES: u64 = 256 * 1024 * 1024;
/// Growth over the step's starting private bytes after which no further
/// entry is decoded; the rest is kept raw so the step still completes.
const STEP_BUDGET_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Failed decodes a rule may accumulate, without any success, before it is
/// disabled for the rest of the run. Calibrated on a full run: the latest
/// first success in a mixed family came after 27 failures, so only rules with
/// weak evidence are cut early; proven rules stop only on allocation spikes.
fn failure_budget(strength: rules::Strength) -> usize {
    match strength {
        rules::Strength::Guessed => 5,
        rules::Strength::Inferred => 50,
        rules::Strength::Sniffed => 100,
        rules::Strength::Proven => usize::MAX,
    }
}

/// Decode record of one (rule, loader) pair.
#[derive(Default)]
struct Health {
    successes: usize,
    failures: usize,
    disabled: Option<String>,
}

impl Health {
    /// Record a failure; returns the reason when this disables the pair.
    fn fail(&mut self, strength: rules::Strength, grown: u64, error: &str) -> Option<String> {
        self.failures += 1;
        if self.disabled.is_some() {
            return None;
        }
        let reason = if grown >= SPIKE_BYTES {
            format!(
                "a failed decode grew the process by {} MiB",
                grown / (1024 * 1024)
            )
        } else if self.successes == 0 && self.failures >= failure_budget(strength) {
            format!("{} failures without a success", self.failures)
        } else {
            return None;
        };
        let reason = format!(
            "{reason}; first error: {}",
            error.chars().take(120).collect::<String>()
        );
        self.disabled = Some(reason.clone());
        Some(reason)
    }
}

fn private_bytes() -> Option<u64> {
    super::memory::Snapshot::read()
        .ok()
        .map(|snapshot| snapshot.private_bytes)
}

struct Exporter {
    rules: rules::Rules,
    decoders: decode::Decoders,
    serializer: BoxedSerializer,
    stats: Stats,
    health: BTreeMap<(String, String), (rules::Strength, Health)>,
    /// Set once decoding stops for the rest of the step.
    raw_only: Option<String>,
}

type Outcome = (&'static str, String);

impl Exporter {
    fn raw(&mut self, logical: &str, data: &[u8], reason: &str) -> Result<Outcome> {
        write_raw(logical, data)?;
        *self
            .stats
            .raw_reasons
            .entry(reason.to_string())
            .or_default() += 1;
        Ok(("raw", reason.to_string()))
    }

    fn export(
        &mut self,
        hash: u64,
        snapshot: &Snapshot,
        entry: Entry,
        name: Option<&str>,
    ) -> Result<Outcome> {
        if !snapshot.chunk_installed(entry) {
            let tag = snapshot.chunks[entry.chunk]
                .tag
                .clone()
                .unwrap_or_else(|| "core".into());
            *self.stats.missing_chunks.entry(tag.clone()).or_default() += 1;
            return Ok(("chunk-missing", tag));
        }
        let Some(logical) = name.filter(|n| safe_relative(n)) else {
            let data = snapshot.read(entry)?;
            write_raw(&format!("_Unnamed/{hash:016x}.bytes"), &data)?;
            let detail = name.map(|n| format!("unsafe name {n}")).unwrap_or_default();
            return Ok(("raw-unnamed", detail));
        };
        let published = |relative: &str| {
            json_output::is_published(&PathBuf::from(format!("{RESOURCES}/{relative}")))
        };
        match classify(logical) {
            Kind::TextMap(output) | Kind::Excel(output) if published(&output) => {
                Ok(("exported", output))
            }
            Kind::TextMap(_) => {
                let data = snapshot.read(entry)?;
                self.raw(logical, &data, "TextMap not decoded")
            }
            Kind::Excel(_) => {
                let data = snapshot.read(entry)?;
                self.raw(logical, &data, "Excel table not exposed by the runtime")
            }
            Kind::ExcelHeader => {
                let data = snapshot.read(entry)?;
                self.raw(logical, &data, "Excel binary header")
            }
            Kind::RawJson(output) => {
                if published(&output) {
                    return Ok(("exported", output));
                }
                let data = snapshot.read(entry)?;
                json_output::bytes(&PathBuf::from(format!("{RESOURCES}/{output}")), &data)?;
                diagnostics::file_written();
                Ok(("copied", output))
            }
            Kind::Config(json_path) => {
                if published(&json_path) {
                    return Ok(("exported", String::new()));
                }
                let data = snapshot.read(entry)?;
                self.config(logical, &json_path, &data)
            }
            Kind::Other => {
                let data = snapshot.read(entry)?;
                self.raw(logical, &data, "not a config path")
            }
        }
    }

    fn config(&mut self, logical: &str, json_path: &str, data: &[u8]) -> Result<Outcome> {
        let Some(selection) = self.rules.candidates(logical) else {
            return self.raw(logical, data, "no type rule");
        };
        let (tier, key, strength) = (selection.tier, selection.key, selection.strength);
        let loaders: Vec<String> = selection.loaders.into_iter().map(str::to_string).collect();
        if let Some(stop) = &self.raw_only {
            let detail = format!("decoding stopped ({tier}): {stop}");
            write_raw(logical, data)?;
            *self
                .stats
                .raw_reasons
                .entry("decoding stopped".to_string())
                .or_default() += 1;
            return Ok(("raw", detail));
        }
        let output = PathBuf::from(format!("{RESOURCES}/{json_path}"));
        let mut errors = Vec::new();
        let mut attempted = false;
        for loader in &loaders {
            let pair = (key.clone(), loader.clone());
            if let Some(reason) = self
                .health
                .get(&pair)
                .and_then(|(_, health)| health.disabled.as_ref())
            {
                errors.push(format!("{loader}: rule disabled ({reason})"));
                continue;
            }
            if !self.decoders.prepare(loader) {
                errors.push(format!("{loader}: decoder unavailable"));
                continue;
            }
            attempted = true;
            diagnostics::quiet(format!("DesignData: decode {json_path} with {loader}"));
            let decoder = self.decoders.decoder(loader).expect("prepared above");
            let checked = decoder.checked();
            let before = private_bytes();
            let result = self
                .decoders
                .decode(decoder, json_path, data, &mut self.serializer);
            let (_, health) = self
                .health
                .entry(pair)
                .or_insert_with(|| (strength, Health::default()));
            match result {
                Ok((value, actual)) => {
                    health.successes += 1;
                    json_output::value(&output, &value)?;
                    diagnostics::file_written();
                    *self.stats.decoded.entry(loader.clone()).or_default() += 1;
                    let mut detail = format!("{loader} ({tier})");
                    if let Some(actual) = actual {
                        detail.push_str(&format!(" actual={actual}"));
                    }
                    let status = if checked {
                        "decoded"
                    } else {
                        "decoded-unchecked"
                    };
                    return Ok((status, detail));
                }
                Err(error) => {
                    let text = format!("{error:#}");
                    let grown = private_bytes()
                        .zip(before)
                        .map_or(0, |(after, before)| after.saturating_sub(before));
                    if let Some(reason) = health.fail(strength, grown, &text) {
                        log::warn!(
                            "[Resources] DesignData: disabled {loader} for {key} ({strength:?}): {reason}"
                        );
                    }
                    *self.stats.rejected.entry(loader.clone()).or_default() += 1;
                    errors.push(format!(
                        "{loader}: {}",
                        text.chars().take(160).collect::<String>()
                    ));
                }
            }
        }
        let reason = if attempted {
            "every candidate type rejected"
        } else if errors.iter().all(|e| e.ends_with("decoder unavailable")) {
            "decoder unavailable"
        } else {
            "rule disabled"
        };
        write_raw(logical, data)?;
        *self
            .stats
            .raw_reasons
            .entry(reason.to_string())
            .or_default() += 1;
        Ok(("raw", format!("{reason} ({tier}): {}", errors.join(" | "))))
    }

    /// Stop decoding for the rest of the step once memory grows past the
    /// step budget or the session's global limit; returns true when stopped.
    fn check_budget(&mut self, baseline: Option<u64>) -> bool {
        if self.raw_only.is_some() {
            return true;
        }
        let now = private_bytes();
        let stop = match (now, baseline) {
            (Some(now), Some(base)) if now > base + STEP_BUDGET_BYTES => Some(format!(
                "private memory grew from {} MiB to {} MiB",
                base / (1024 * 1024),
                now / (1024 * 1024)
            )),
            _ => diagnostics::check_memory().err().map(|e| format!("{e:#}")),
        };
        if let Some(stop) = stop {
            log::warn!(
                "[Resources] DesignData: decoding stopped, remaining entries are kept raw: {stop}"
            );
            self.raw_only = Some(stop);
            return true;
        }
        false
    }
}

pub fn dump(design: &DesignData) -> Result<()> {
    let names = operation("DesignData: resolve names", || names::resolve(design))?;
    checkpoint(format!(
        "DesignData: named={} (embedded={} discovered={}) of {} entries",
        names.by_hash.len(),
        names.embedded_hits,
        names.discovered,
        design.all_entries().len()
    ));
    let rules = rules::Rules::embedded();
    let loader_names = rules.loader_names();
    let decoders = operation("DesignData: index deserializers", || {
        decode::Decoders::new(&loader_names)
    })?;
    let mut exporter = Exporter {
        rules,
        decoders,
        serializer: super::new_serializer(),
        stats: Stats::default(),
        health: BTreeMap::new(),
        raw_only: None,
    };
    let baseline = private_bytes();
    checkpoint(format!(
        "DesignData: {} loaders={} family_rules={}",
        exporter.decoders.describe(),
        loader_names.len(),
        exporter.rules.family_count()
    ));

    let mut entries = design.all_entries();
    // Deterministic order: named entries by path, then unnamed by hash.
    entries.sort_by(
        |a, b| match (names.by_hash.get(&a.0), names.by_hash.get(&b.0)) {
            (Some(x), Some(y)) => x.cmp(y),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.0.cmp(&b.0),
        },
    );
    if let Some(parent) = Path::new(REPORT).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut report =
        BufWriter::new(std::fs::File::create(REPORT).with_context(|| format!("create {REPORT}"))?);
    writeln!(
        report,
        "snapshot,revision,path_hash,chunk,tag,offset,size,logical_path,status,detail"
    )?;
    let total = entries.len();
    for (index, (hash, snapshot, entry)) in entries.into_iter().enumerate() {
        // Past the budget the remaining entries are kept raw; the step must
        // still finish with a complete report instead of failing the dump.
        exporter.check_budget(baseline);
        if index % 5000 == 0 {
            checkpoint(format!(
                "DesignData: progress {index}/{total} status={:?} private_mib={}",
                exporter.stats.status,
                private_bytes().unwrap_or(0) / (1024 * 1024)
            ));
        }
        let name = names.by_hash.get(&hash).map(String::as_str);
        let (status, detail) = exporter
            .export(hash, snapshot, entry, name)
            .with_context(|| {
                format!(
                    "DesignData entry {hash:016x} {}",
                    name.unwrap_or("<unnamed>")
                )
            })?;
        *exporter.stats.status.entry(status.to_string()).or_default() += 1;
        *exporter.stats.bytes.entry(status.to_string()).or_default() += entry.size;
        let chunk = &snapshot.chunks[entry.chunk];
        writeln!(
            report,
            "{},{},{hash:016x},{},{},{},{},{},{},{}",
            snapshot.name,
            snapshot.revision,
            chunk.digest,
            chunk.tag.as_deref().unwrap_or(""),
            entry.offset,
            entry.size,
            csv(name.unwrap_or("")),
            status,
            csv(&detail)
        )?;
        // Keep the report current on disk: after a hard crash the first entry
        // missing from it (in this deterministic order) is the culprit.
        report.flush()?;
    }
    report.flush()?;
    let stats = &exporter.stats;
    let summary = json!({
        "snapshots": design.snapshots.iter().map(|s| json!({
            "name": s.name,
            "revision": s.revision,
            "index": format!("DesignV_{}.bytes", s.index_digest),
            "chunks": s.chunks.len(),
            "entries": s.entries.len(),
            "missing_chunks": s.chunks.iter().filter(|c| c.path.is_none())
                .map(|c| json!({"digest": c.digest, "tag": c.tag})).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "entries": total,
        "named": names.by_hash.len(),
        "named_embedded": names.embedded_hits,
        "named_discovered": names.discovered,
        "status": stats.status,
        "bytes_by_status": stats.bytes,
        "decoded_by_loader": stats.decoded,
        "rejected_attempts_by_loader": stats.rejected,
        "raw_reasons": stats.raw_reasons,
        "missing_chunk_entries_by_tag": stats.missing_chunks,
        "unavailable_decoders": exporter.decoders.unavailable,
        "serializer_max_depth": exporter.serializer.max_depth(),
        "decoding_stopped": exporter.raw_only,
        "disabled_rules": exporter.health.iter()
            .filter_map(|((key, loader), (strength, health))| health.disabled.as_ref().map(|reason| json!({
                "rule": key,
                "loader": loader,
                "strength": format!("{strength:?}"),
                "successes": health.successes,
                "failures": health.failures,
                "reason": reason,
            })))
            .collect::<Vec<_>>(),
    });
    std::fs::write(SUMMARY, serde_json::to_string_pretty(&summary)?)
        .with_context(|| format!("write {SUMMARY}"))?;
    let disabled = exporter
        .health
        .values()
        .filter(|(_, health)| health.disabled.is_some())
        .count();
    checkpoint(format!(
        "DesignData: done entries={total} status={:?} raw_reasons={:?} disabled_rules={disabled} decoding_stopped={:?} serializer_max_depth={}",
        stats.status,
        stats.raw_reasons,
        exporter.raw_only,
        exporter.serializer.max_depth()
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_index_paths() {
        assert!(matches!(
            classify("BakedConfig/ExcelOutputGameCore/AvatarConfig.bytes"),
            Kind::Excel(o) if o == "ExcelOutput/AvatarConfig.json"
        ));
        assert!(matches!(
            classify("BakedConfig/ExcelOutput/AvatarConfigExcelTable.binary_header.bytes"),
            Kind::ExcelHeader
        ));
        assert!(matches!(
            classify("BakedConfig/ExcelOutput/Textmap_cn.bytes"),
            Kind::TextMap(o) if o == "TextMap/TextMapCN.json"
        ));
        assert!(matches!(
            classify("BakedConfig/ExcelOutput/TextmapMain_jp.bytes"),
            Kind::TextMap(o) if o == "TextMap/TextMapMainJP.json"
        ));
        assert!(matches!(
            classify("BakedConfig/ExcelOutput/DrinkMakerCheersTypeTextmap.bytes"),
            Kind::Excel(o) if o == "ExcelOutput/DrinkMakerCheersTypeTextmap.json"
        ));
        assert!(matches!(
            classify("BakedConfig/ConfigManifest.json"),
            Kind::RawJson(o) if o == "ConfigManifest.json"
        ));
        assert!(matches!(
            classify("BakedConfig/Config/Level/Mission/1/Act/Act1.bytes"),
            Kind::Config(o) if o == "Config/Level/Mission/1/Act/Act1.json"
        ));
        assert!(matches!(
            classify("BakedConfig/Stages/Outputs/A/B.volume.bytes"),
            Kind::Config(o) if o == "Stages/Outputs/A/B.volume.json"
        ));
        assert!(matches!(classify("Other/X.bytes"), Kind::Other));
    }

    #[test]
    fn rejects_unsafe_relative_paths() {
        assert!(safe_relative("BakedConfig/Config/A.bytes"));
        assert!(safe_relative("BakedConfig/Config/CONFIG/Comet.bytes"));
        for bad in [
            "",
            "/a",
            "a//b",
            "a/../b",
            "a/./b",
            "a:b",
            "a\\b",
            "a/b.",
            "a/b ",
            "a/NUL.bytes",
            "a/com1.bytes",
            "a/Lpt9",
            "a/\u{1}b",
        ] {
            assert!(!safe_relative(bad), "{bad:?}");
        }
    }

    #[test]
    fn csv_quotes_when_needed() {
        assert_eq!(csv("a"), "a");
        assert_eq!(csv("a,b"), "\"a,b\"");
        assert_eq!(csv("a\"b"), "\"a\"\"b\"");
        assert_eq!(csv("a\nb"), "\"a b\"");
    }

    #[test]
    fn failing_rules_are_disabled_by_strength_and_allocation_spikes() {
        use rules::Strength::{Guessed, Inferred, Proven};
        let fail_until_disabled = |strength| {
            let mut health = Health::default();
            (1..=1000)
                .find(|_| health.fail(strength, 0, "consumed 1 of 9 bytes").is_some())
                .unwrap_or(0)
        };
        assert_eq!(fail_until_disabled(Guessed), 5);
        assert_eq!(fail_until_disabled(Inferred), 50);
        assert_eq!(fail_until_disabled(Proven), 0);
        let mut inferred = Health::default();
        let reason = (0..50)
            .find_map(|_| inferred.fail(Inferred, 0, "OverflowException"))
            .unwrap();
        assert!(reason.contains("50 failures") && reason.contains("OverflowException"));
        // A rule that has decoded something is never disabled by count...
        let mut proven = Health {
            successes: 1,
            ..Health::default()
        };
        for _ in 0..200 {
            assert!(proven.fail(Proven, SPIKE_BYTES - 1, "x").is_none());
        }
        // ...but a failed decode that allocates a spike disables it at once.
        let reason = proven.fail(Proven, SPIKE_BYTES, "x").unwrap();
        assert!(reason.contains("grew the process by 256 MiB"), "{reason}");
        assert!(proven.fail(Proven, SPIKE_BYTES, "x").is_none());
        assert_eq!(proven.failures, 202);
    }

    /// Offline check against the installed client; skipped when it is absent.
    #[test]
    fn installed_index_is_named_and_typed() {
        let Some(design) = super::super::design_data::tests::installed_client() else {
            return;
        };
        let names = names::resolve(&design).unwrap();
        let rules = rules::Rules::embedded();
        let (mut configs, mut ruled, mut unsafe_names) = (0usize, 0usize, 0usize);
        let mut kinds = BTreeMap::<&str, usize>::new();
        for name in names.by_hash.values() {
            unsafe_names += usize::from(!safe_relative(name));
            let kind = classify(name);
            *kinds
                .entry(match kind {
                    Kind::TextMap(_) => "textmap",
                    Kind::Excel(_) => "excel",
                    Kind::ExcelHeader => "excel-header",
                    Kind::RawJson(_) => "json",
                    Kind::Config(_) => "config",
                    Kind::Other => "other",
                })
                .or_default() += 1;
            if let Kind::Config(_) = kind {
                configs += 1;
                ruled += usize::from(rules.candidates(name).is_some());
            }
        }
        eprintln!(
            "named={} embedded={} discovered={} kinds={kinds:?} configs={configs} ruled={ruled}",
            names.by_hash.len(),
            names.embedded_hits,
            names.discovered
        );
        assert!(names.by_hash.len() >= 136_836);
        assert_eq!(unsafe_names, 0);
        assert!(ruled * 1000 >= configs * 995, "{ruled}/{configs}");
    }
}
