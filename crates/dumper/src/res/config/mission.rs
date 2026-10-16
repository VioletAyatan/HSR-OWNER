use std::{cell::RefCell, collections::HashSet, path::PathBuf, rc::Rc};

use anyhow::{Context, Result};
use reflection::serializer::BoxedSerializer;
use serde_json::Value;

use super::checkpoint;

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

/// `MissionInfo_<id>.json` -> `MissionInfo_<id>.partial.json`
/// (`GameCoreConfigLoader.BinaryMainMissionPartialPath` inserts `.partial.`).
fn partial_path(path: &str) -> Option<String> {
    let stem = path.strip_suffix(".json")?;
    (!stem.is_empty()).then(|| format!("{stem}.partial.json"))
}

/// Mirrors the client's MissionInfo load (`CLPPAMNDKIM.EMKCDCFEMIP`): read
/// `MissionInfo_<id>`, then its `.partial` file, and set the main config's
/// `SubMissionList` to the partial's. The main file no longer carries the
/// sub-missions, so the merged object is what the game actually uses. The
/// partial is published as well, unmodified.
fn dump_main_missions(paths: Vec<String>, serializer: &mut BoxedSerializer) -> Result<()> {
    let func_name = "LoadMainMissionInfoConfig";
    let paths = super::prepare_config_paths(func_name, paths);
    checkpoint(format!("Config: {func_name} paths={}", paths.len()));
    let main = super::ConfigLoader::new(func_name)?;
    let partial = super::ConfigLoader::new("LoadMainMissionPartialInfoConfig")?;
    let (mut skipped, mut merged) = (0, 0);
    for path in paths {
        let Some(mut info) = main.load(&path, serializer)? else {
            skipped += 1;
            continue;
        };
        if let Some(partial_path) = partial_path(&path)
            && let Some(partial_info) = partial.load(&partial_path, serializer)?
        {
            let list = partial_info
                .get("SubMissionList")
                .cloned()
                .unwrap_or(Value::Null);
            info.as_object_mut()
                .with_context(|| format!("{path}: MainMissionInfoConfig is not an object"))?
                .insert("SubMissionList".to_string(), list);
            super::super::write_json(
                &PathBuf::from(format!("./DUMP/Resources/{partial_path}")),
                &partial_info,
            )?;
            merged += 1;
        }
        super::super::write_json(&PathBuf::from(format!("./DUMP/Resources/{path}")), &info)?;
    }
    checkpoint(format!(
        "Config: completed {func_name} skipped_absent={skipped} merged_partial={merged}"
    ));
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

    let result = dump_main_missions(main_mission_paths.into_iter().collect(), serializer);
    serializer.remove_callback("MissionJsonPath");
    result?;

    super::dump_from_config_list("LoadLevelGraphConfig", sub_mission_paths.take(), serializer)?;
    Ok(())
}

pub fn dump(serializer: &mut BoxedSerializer) -> Result<()> {
    dump_mission_info(serializer)?;
    dump_level_graphs(serializer)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::partial_path;

    #[test]
    fn partial_path_matches_client_transform() {
        assert_eq!(
            partial_path("Config/Level/Mission/1000101/MissionInfo_1000101.json").as_deref(),
            Some("Config/Level/Mission/1000101/MissionInfo_1000101.partial.json")
        );
        assert_eq!(partial_path("Config/X.bytes"), None);
        assert_eq!(partial_path(".json"), None);
    }
}
