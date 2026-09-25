use std::{cell::RefCell, rc::Rc};

use anyhow::{Context, Result};
use reflection::serializer::BoxedSerializer;
use serde_json::Value;

fn extract_npc_json_paths(name: &str) -> Result<Vec<String>> {
    let json = super::read_excel(name)?;
    json.iter()
        .enumerate()
        .map(|(index, item)| {
            item.get("NPCJsonPath")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .with_context(|| format!("{name} row {index} has invalid NPCJsonPath"))
        })
        .collect()
}

pub fn dump(serializer: &mut BoxedSerializer) -> Result<()> {
    let mut rogue_npc_paths = Vec::new();
    for name in ["RogueNPC", "RogueTournNPC", "RogueMagicNPC"] {
        rogue_npc_paths
            .extend(extract_npc_json_paths(name).with_context(|| format!("reading {name}"))?);
    }

    let dialogue_paths = Rc::new(RefCell::new(Vec::<String>::new()));
    let dialogue_paths_clone = dialogue_paths.clone();
    serializer.add_callback(
        String::from("DialoguePath"),
        Rc::new(move |value| {
            if let Value::String(value) = value {
                dialogue_paths_clone.borrow_mut().push(value.to_string());
            }
        }),
    );

    let option_paths = Rc::new(RefCell::new(Vec::<String>::new()));
    let option_paths_clone = option_paths.clone();
    serializer.add_callback(
        String::from("OptionPath"),
        Rc::new(move |value| {
            if let Value::String(value) = value {
                option_paths_clone.borrow_mut().push(value.to_string());
            }
        }),
    );

    super::dump_from_config_list("LoadRogueNPCConfig", rogue_npc_paths, serializer)?;

    super::dump_from_config_list("LoadLevelGraphConfig", dialogue_paths.take(), serializer)?;
    serializer.remove_callback("DialoguePath");

    super::dump_from_config_list(
        "LoadRogueDialogueEventConfig",
        option_paths.take(),
        serializer,
    )?;
    serializer.remove_callback("OptionPath");
    Ok(())
}
