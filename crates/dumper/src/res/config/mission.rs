use std::{cell::RefCell, collections::HashSet, rc::Rc};

use anyhow::{Context, Result};
use reflection::serializer::BoxedSerializer;
use serde_json::Value;

fn read_performance(name: &str, out: &mut HashSet<String>) -> Result<()> {
    let entries = super::read_excel(name)?;

    for (index, item) in entries.iter().enumerate() {
        let path = item
            .get("PerformancePath")
            .or_else(|| item.get("ActPath"))
            .and_then(Value::as_str)
            .with_context(|| {
                format!("{name} row {index} has neither a valid PerformancePath nor ActPath")
            })?;
        out.insert(path.to_owned());
    }
    Ok(())
}

fn dump_level_graphs(serializer: &mut BoxedSerializer) -> Result<()> {
    let mut performances = HashSet::new();
    for name in [
        "PerformanceA",
        "PerformanceC",
        "PerformanceCG",
        "PerformanceD",
        "PerformanceDS",
        "PerformanceE",
        "PerformanceVideo",
        "DialogueNPC",
    ] {
        read_performance(name, &mut performances).with_context(|| format!("reading {name}"))?;
    }
    super::dump_from_config_list(
        "LoadLevelGraphConfig",
        performances.into_iter().collect(),
        serializer,
    )?;
    Ok(())
}

fn dump_mission_info(serializer: &mut BoxedSerializer) -> Result<()> {
    let chess_board_data = super::read_excel("MainMission")?;

    let main_mission_paths = chess_board_data
        .iter()
        .enumerate()
        .map(|(index, data)| {
            let mission_id = data
                .get("MainMissionID")
                .and_then(Value::as_u64)
                .with_context(|| format!("MainMission row {index} has invalid MainMissionID"))?;
            Ok(format!(
                "Config/Level/Mission/{mission_id}/MissionInfo_{mission_id}.json"
            ))
        })
        .collect::<Result<HashSet<_>>>()?;

    let sub_mission_paths = Rc::new(RefCell::new(Vec::<String>::new()));
    let sub_mission_paths_clone = sub_mission_paths.clone();

    serializer.add_callback(
        String::from("MissionJsonPath"),
        Rc::new(move |value| {
            if let Value::String(value) = value {
                sub_mission_paths_clone.borrow_mut().push(value.to_string());
            }
        }),
    );

    super::dump_from_config_list(
        "LoadMainMissionInfoConfig",
        main_mission_paths.into_iter().collect(),
        serializer,
    )?;

    serializer.remove_callback("MissionJsonPath");

    super::dump_from_config_list("LoadLevelGraphConfig", sub_mission_paths.take(), serializer)?;
    Ok(())
}

pub fn dump(serializer: &mut BoxedSerializer) -> Result<()> {
    dump_mission_info(serializer)?;
    dump_level_graphs(serializer)?;
    Ok(())
}
