//! Re-apply the proto naming passes to an existing dump, without the game.
//!
//! Usage: `hsr-proto-rename <DUMP_DIR> <OUT_DIR>`
//!
//! Reads `StarRail.proto` and `packetIds.json` (plus `cs-type-infos.json` and
//! `sc-packet-handlers.json` when present) from `DUMP_DIR` and writes renamed
//! copies and `proto-offline-name-evidence.json` to `OUT_DIR`. The input is
//! never modified; `OUT_DIR` must not exist yet.
use std::{fs, path::Path, process::ExitCode};

use version::proto_offline;

const HANDLER_FILES: [&str; 2] = ["cs-type-infos.json", "sc-packet-handlers.json"];

fn run(dump: &Path, out: &Path) -> Result<(), String> {
    if out.exists() {
        return Err(format!(
            "output directory already exists: {}",
            out.display()
        ));
    }
    let read = |name: &str| {
        fs::read_to_string(dump.join(name))
            .map_err(|error| format!("cannot read {}: {error}", dump.join(name).display()))
    };
    let proto = read("StarRail.proto")?;
    let packet_ids = read("packetIds.json")?;
    let renamed = proto_offline::rename(&proto, &packet_ids)?;

    fs::create_dir_all(out).map_err(|error| format!("cannot create {}: {error}", out.display()))?;
    let write = |name: &str, contents: &str| {
        fs::write(out.join(name), contents)
            .map_err(|error| format!("cannot write {}: {error}", out.join(name).display()))
    };
    write("StarRail.proto", &renamed.proto)?;
    write("packetIds.json", &renamed.packet_ids)?;
    for name in HANDLER_FILES {
        if dump.join(name).exists() {
            write(
                name,
                &proto_offline::rename_handlers(&read(name)?, &renamed.type_aliases)?,
            )?;
        }
    }
    let mut evidence = serde_json::to_string_pretty(&renamed.evidence)
        .map_err(|error| format!("cannot write evidence: {error}"))?;
    evidence.push('\n');
    write("proto-offline-name-evidence.json", &evidence)?;

    let summary = &renamed.summary;
    println!(
        "obfuscated types {} -> {}, obfuscated fields {} -> {}, packet names changed {}",
        summary.obfuscated_types_before,
        summary.obfuscated_types_after,
        summary.obfuscated_fields_before,
        summary.obfuscated_fields_after,
        summary.packet_names_changed
    );
    println!("written to {}", out.display());
    Ok(())
}

fn main() -> ExitCode {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let [dump, out] = args.as_slice() else {
        eprintln!("usage: hsr-proto-rename <DUMP_DIR> <OUT_DIR>");
        return ExitCode::from(2);
    };
    match run(Path::new(dump), Path::new(out)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
