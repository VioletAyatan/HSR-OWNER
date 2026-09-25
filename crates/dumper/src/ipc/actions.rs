use std::path::Path;

use anyhow::Context;
use hsr_ipc::{DumperAction, ProtoDumpMode};

use crate::{csharp, parser_data, proto, res, runtime, script, script_v2};

pub fn run(action: DumperAction) -> anyhow::Result<()> {
    ensure_dump_folder()?;
    if action == DumperAction::Resources {
        return res::dump();
    }
    runtime::init_default();
    runtime::attach_current_thread_to_il2cpp();

    match action {
        DumperAction::Proto { mode } => dump_proto(mode)?,
        DumperAction::CSharp => {
            prepare_script_metadata("C#")?;
            csharp::dump(false)?;
        }
        DumperAction::ParserData => parser_data::dump(),
        DumperAction::Script => script::dump()?,
        DumperAction::ScriptV2 => script_v2::dump(),
        DumperAction::Resources => unreachable!("Resources has its own diagnostic boundary"),
    }

    Ok(())
}

pub fn ensure_dump_folder() -> std::io::Result<()> {
    let folder = Path::new("./DUMP");
    if !folder.is_dir() {
        std::fs::create_dir_all(folder)?;
    }
    Ok(())
}

fn prepare_script_metadata(consumer: &str) -> anyhow::Result<()> {
    if !script::is_ready() {
        log::info!("[{consumer} Dumper] preparing Script metadata prerequisite...");
        script::dump().context("Script metadata prerequisite")?;
    }
    anyhow::ensure!(
        script::is_ready(),
        "Script metadata prerequisite did not publish all caches"
    );
    Ok(())
}

fn dump_proto(mode: ProtoDumpMode) -> anyhow::Result<()> {
    prepare_script_metadata("Proto")?;
    log::info!("[Proto Dumper] starting mode {mode:?}");
    proto::dump(
        &mut std::fs::File::create("./DUMP/StarRail.proto")?,
        &mut std::fs::File::create("./DUMP/packetIds.json")?,
        map_proto_mode(mode),
        false,
    )?;
    Ok(())
}

fn map_proto_mode(mode: ProtoDumpMode) -> proto::ProtoDumpMode {
    match mode {
        ProtoDumpMode::ClassFieldNumber => proto::ProtoDumpMode::ClassFieldNumber,
        ProtoDumpMode::MergeFrom => proto::ProtoDumpMode::MergeFrom,
        ProtoDumpMode::WriteTo => proto::ProtoDumpMode::WriteTo,
        ProtoDumpMode::Asm => proto::ProtoDumpMode::Asm,
    }
}
