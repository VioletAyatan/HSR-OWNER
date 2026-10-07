//! `Config/ConfigCharacter`: character, NPC, Manikin and FreeStyle configs.
//!
//! These files are not listed in the client's ConfigManifest. They are found
//! through every `Config/ConfigCharacter/*.json` string (value or object key)
//! in ExcelOutput and in the Config files exported before this step (field
//! names vary and some are obfuscated), then through references inside the
//! exported character configs (FreeStyle configs, override parents, ...)
//! until no new path appears. Absent paths are skipped by
//! `dump_from_config_list`.
use anyhow::{Context, Result};
use reflection::serializer::BoxedSerializer;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

const PREFIX: &str = "Config/ConfigCharacter/";
const RESOURCES: &str = "./DUMP/Resources";
const SCAN_DIRS: &[&str] = &["./DUMP/Resources/ExcelOutput", "./DUMP/Resources/Config"];
/// Output of this step; scanned through the fixpoint instead.
const OWN_DIR: &str = "ConfigCharacter";

/// Fixed top-level files loaded by name in client code.
const FIXED: &[(&str, &str)] = &[
    (
        "LoadCharacterAtlasFaceMappingConfig",
        "CharacterAtlasFaceMappingConfig.json",
    ),
    (
        "LoadCharacterEyeBloomMappingConfig",
        "CharacterEyeBloomMappingConfig.json",
    ),
    (
        "LoadCharacterEyeCtrlMappingConfig",
        "CharacterEyeCtrlMappingConfig.json",
    ),
    (
        "LoadCharacterFaceExpressionMappingConfig",
        "CharacterFaceExpressionMappingConfig.json",
    ),
    (
        "LoadCharacterPhaseSkillInfoMappingConfig",
        "CharacterPhaseSkillInfoMappingConfig.json",
    ),
    (
        "LoadCharacterReplaceMaterialConfig",
        "CharacterReplaceMaterialConfig.json",
    ),
    (
        "LoadCharacterScaleDataConfig",
        "CharacterScaleDataConfig.json",
    ),
    (
        "LoadCharacterSkillCustomStatisticConfig",
        "CharacterSkillCustomStatisticConfig.json",
    ),
    (
        "LoadCharacterSkillStatisticConfig",
        "CharacterSkillStatisticConfig.json",
    ),
    (
        "LoadCharacterSomatoCommonConfig",
        "CharacterSomatoCommonConfig.json",
    ),
    ("LoadEntityColliderConfig", "EntityColliderConfig.json"),
    (
        "LoadProjectileTemplateConfig",
        "ProjectileTemplateConfig.json",
    ),
    ("LoadNPCAppearancePresetList", "NPCAppearancePresets.json"),
    (
        "LoadRuanMadeCakeFeatureMap",
        "RuanMadeCakeFeatureConfig.json",
    ),
];

/// Loader for a character config path, chosen by directory.
fn loader_for(path: &str) -> &'static str {
    let rest = path.strip_prefix(PREFIX).unwrap_or(path);
    let dir = |name: &str| rest.starts_with(name) || rest.contains(&format!("/{name}"));
    if rest.ends_with("_ElationConfig.json") {
        // Referenced by `ElationConfigPath` inside character configs.
        "LoadElationConfigList"
    } else if rest.ends_with("_AnimEvent.json") {
        // Referenced by `AnimEventConfigList` inside character configs.
        "LoadCharacterAnimEventConfig"
    } else if dir("Manikin/") {
        // `LoadManikinAvatarConfig` is an area-level type: avatar configs are
        // full Manikin character configs and would load as empty objects.
        if dir("Manikin/Monster/") {
            "LoadManikinMonsterConfig"
        } else if dir("Manikin/Pet/") {
            "LoadManikinPetConfig"
        } else if dir("Manikin/Servant/") {
            "LoadManikinServantConfig"
        } else {
            "LoadManikinCharacterConfig"
        }
    } else if dir("FreeStyle/") {
        "LoadFreeStyleCharacterConfig"
    } else if dir("LocalPlayer/") || dir("NPC/") || dir("NPCMonster/") || dir("FakePlayer/") {
        "LoadAdventureCharacterConfig"
    } else {
        // Battle characters; subclasses (BattleEvent, override, servant)
        // are resolved by the client from `$type`.
        "LoadCharacterConfig"
    }
}

fn is_character_path(value: &str) -> bool {
    value.starts_with(PREFIX)
        && value.ends_with(".json")
        && !value.ends_with(".layout.json")
        && !value[PREFIX.len()..].trim().is_empty()
}

fn collect_paths(value: &Value, out: &mut BTreeSet<String>) {
    match value {
        Value::String(value) if is_character_path(value) => {
            out.insert(value.clone());
        }
        Value::Array(values) => values.iter().for_each(|value| collect_paths(value, out)),
        Value::Object(map) => {
            // Some tables are keyed by config path (e.g. skill statistics).
            for (key, value) in map {
                if is_character_path(key) {
                    out.insert(key.clone());
                }
                collect_paths(value, out);
            }
        }
        _ => {}
    }
}

fn scan_file(path: &Path, out: &mut BTreeSet<String>) -> Result<()> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    // Cheap prefilter: most Config files never mention a character config.
    if !std::str::from_utf8(&bytes).is_ok_and(|text| text.contains(PREFIX)) {
        return Ok(());
    }
    let value: Value =
        serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?;
    collect_paths(&value, out);
    Ok(())
}

fn scan_tree(dir: &Path, out: &mut BTreeSet<String>) -> Result<usize> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("read {}", dir.display()))?
        .collect::<std::io::Result<_>>()?;
    entries.sort_by_key(|entry| entry.path());
    let mut files = 0;
    for entry in entries {
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            if path.file_name().is_some_and(|name| name != OWN_DIR) {
                files += scan_tree(&path, out)?;
            }
        } else if path.extension().is_some_and(|ext| ext == "json") {
            scan_file(&path, out)?;
            files += 1;
        }
    }
    Ok(files)
}

fn exported_references() -> Result<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    for dir in SCAN_DIRS {
        let files = scan_tree(Path::new(dir), &mut out)?;
        super::checkpoint(format!(
            "Config/ConfigCharacter: scanned {dir} files={files} references={}",
            out.len()
        ));
    }
    Ok(out)
}

fn output_path(path: &str) -> PathBuf {
    PathBuf::from(format!("{RESOURCES}/{path}"))
}

fn layout_path(path: &str) -> Option<String> {
    path.strip_suffix(".json")
        .map(|stem| format!("{stem}.layout.json"))
}

pub fn dump(serializer: &mut BoxedSerializer) -> Result<()> {
    let mut written = BTreeSet::new();
    let mut pending = exported_references()?;
    // Fixed files first: they may reference character configs as well.
    for (loader, name) in FIXED {
        let path = format!("{PREFIX}{name}");
        super::dump_from_config_list(loader, vec![path.clone()], serializer)?;
        let file = output_path(&path);
        if file.is_file() {
            scan_file(&file, &mut pending)?;
            written.insert(path);
        }
    }
    let mut seen: BTreeSet<String> = written.clone();
    pending.retain(|path| !seen.contains(path));
    let mut round = 0;
    while !pending.is_empty() {
        round += 1;
        let mut groups = BTreeMap::<&str, Vec<String>>::new();
        for path in &pending {
            groups
                .entry(loader_for(path))
                .or_default()
                .push(path.clone());
        }
        seen.extend(pending.iter().cloned());
        for (loader, paths) in groups {
            super::dump_from_config_list(loader, paths, serializer)?;
        }
        let mut found = BTreeSet::new();
        for path in std::mem::take(&mut pending) {
            let file = output_path(&path);
            if file.is_file() {
                scan_file(&file, &mut found)?;
                written.insert(path);
            }
        }
        pending = found.difference(&seen).cloned().collect();
        super::checkpoint(format!(
            "Config/ConfigCharacter: round={round} written={} new_references={}",
            written.len(),
            pending.len()
        ));
    }

    let layouts = written
        .iter()
        .filter_map(|path| layout_path(path))
        .collect();
    super::dump_from_config_list("LoadConfigBakeLayoutInfoList", layouts, serializer)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn loader_is_chosen_by_directory() {
        let cases = [
            (
                "Config/ConfigCharacter/LocalPlayer/LocalPlayer_Pearl_00_Config.json",
                "LoadAdventureCharacterConfig",
            ),
            (
                "Config/ConfigCharacter/Activity/LocalPlayer/LocalPlayer_AetherDivide_PlayerBoy_00_Config.json",
                "LoadAdventureCharacterConfig",
            ),
            (
                "Config/ConfigCharacter/NPC/Avatar/NPC_Avatar_Pearl_00_Config.json",
                "LoadAdventureCharacterConfig",
            ),
            (
                "Config/ConfigCharacter/NPCMonster/X_Config.json",
                "LoadAdventureCharacterConfig",
            ),
            (
                "Config/ConfigCharacter/Manikin/Avatar/Manikin_Avatar_Acheron_00_Config.json",
                "LoadManikinCharacterConfig",
            ),
            (
                "Config/ConfigCharacter/Manikin/Pet/Manikin_Pet_Complainer_00_Config.json",
                "LoadManikinPetConfig",
            ),
            (
                "Config/ConfigCharacter/Manikin/Special/X_Config.json",
                "LoadManikinCharacterConfig",
            ),
            (
                "Config/ConfigCharacter/FreeStyle/Avatar/Avatar_Maid_Pearl_00_FreeStyle_Config.json",
                "LoadFreeStyleCharacterConfig",
            ),
            (
                "Config/ConfigCharacter/Avatar/Avatar_Acheron_00_Config.json",
                "LoadCharacterConfig",
            ),
            (
                "Config/ConfigCharacter/GridFight/3.5/Avatar_GridFight_Acheron_00_Config.json",
                "LoadCharacterConfig",
            ),
            (
                "Config/ConfigCharacter/Avatar/Avatar_Pearl_00_ElationConfig.json",
                "LoadElationConfigList",
            ),
            (
                "Config/ConfigCharacter/ElationBattle/Avatar_ElationBattle_Feixiao_00_Designer_AnimEvent.json",
                "LoadCharacterAnimEventConfig",
            ),
        ];
        for (path, loader) in cases {
            assert_eq!(loader_for(path), loader, "{path}");
        }
    }

    #[test]
    fn references_are_collected_from_any_field_and_depth() {
        let mut out = BTreeSet::new();
        collect_paths(
            &json!([
                {"PlayerJsonPath": "Config/ConfigCharacter/LocalPlayer/A_Config.json"},
                {"OLJDOBFJLOM": {"x": ["Config/ConfigCharacter/Manikin/Pet/B_Config.json"]}},
                {"Other": "Config/ConfigAI/C.json"},
                {"Layout": "Config/ConfigCharacter/A_Config.layout.json"},
                {"Blank": "Config/ConfigCharacter/"},
                {"Stats": {"Config/ConfigCharacter/GridFight/C_Config.json": {"N": 1}}},
            ]),
            &mut out,
        );
        assert_eq!(
            out.into_iter().collect::<Vec<_>>(),
            [
                "Config/ConfigCharacter/GridFight/C_Config.json",
                "Config/ConfigCharacter/LocalPlayer/A_Config.json",
                "Config/ConfigCharacter/Manikin/Pet/B_Config.json",
            ]
        );
    }

    #[test]
    fn layout_path_replaces_extension() {
        assert_eq!(
            layout_path("Config/ConfigCharacter/Avatar/A_Config.json").as_deref(),
            Some("Config/ConfigCharacter/Avatar/A_Config.layout.json")
        );
    }
}
