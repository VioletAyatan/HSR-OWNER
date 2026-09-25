use super::{checkpoint, invoke_error, operation};
use anyhow::{Context, Result, ensure};
use il2cpp::{
    get_native_method,
    vm::{boxed_value::BoxedBool, object::Il2CppObject, string::Il2CppString, value::Void},
};
use reflection::{method_info::MethodInfo, serializer::BoxedSerializer};
use std::{collections::BTreeMap, path::PathBuf};

mod level_output_floor;
mod mission;
mod rogue_chest_map;
mod rogue_npc;
mod summon_unit;
mod video_caption;

pub fn dump() -> Result<()> {
    let (type_field, path_field) = super::manifest_fields()?;
    let manifest = config_manifest(&type_field, &path_field)?;
    let mut serializer = super::new_serializer();
    for (name, paths) in manifest {
        let loader = match name.as_str() {
            "AdventureAbilityConfig" => "LoadAdventureAbilityConfigList",
            "TurnBasedAbilityConfig" => "LoadTurnBasedAbilityConfigList",
            "BattleLineupSkillTreePresetConfig" => "LoadSkillTreePointPresetConfig",
            "GlobalModifierConfig" => "LoadGlobalModifierConfig",
            "AdventureModifierConfig" => "LoadAdventureModifierLookupTable",
            "ComplexSkillAIGlobalGroupConfig" => "LoadComplexSkillAIGlobalGroupLookup",
            "GlobalTaskTemplate" => "LoadGlobalTaskListTemplateConfig",
            _ => {
                checkpoint(format!(
                    "Config: skip unsupported manifest type {name} paths={}",
                    paths.len()
                ));
                continue;
            }
        };
        dump_from_config_list(loader, paths, &mut serializer)?;
    }
    operation("Config/SummonUnit", || summon_unit::dump(&mut serializer))?;
    operation("Config/LevelOutput", || {
        level_output_floor::dump(&mut serializer)
    })?;
    operation("Config/VideoCaption", || {
        video_caption::dump(&mut serializer)
    })?;
    operation("Config/RogueNPC", || rogue_npc::dump(&mut serializer))?;
    operation("Config/RogueChestMap", || {
        rogue_chest_map::dump(&mut serializer)
    })?;
    operation("Config/Mission", || mission::dump(&mut serializer))?;
    Ok(())
}

fn config_manifest(type_field: &str, path_field: &str) -> Result<BTreeMap<String, Vec<String>>> {
    operation("Config: LoadConfigManifest", || {
        get_native_method("RPG.GameCore.GameCoreConfigManager::LoadConfigManifest()")
            .context("missing LoadConfigManifest")?
            .invoke::<Void>(Il2CppObject::NULL, &[])
            .map_err(invoke_error)?;
        Ok(())
    })?;
    let getter = get_native_method("RPG.GameCore.ConfigManifest::get_ManifestItems()")
        .context("missing ConfigManifest.get_ManifestItems")?;
    let info = MethodInfo::from_handle(getter)?;
    let items = operation("Config: get_ManifestItems", || {
        getter
            .invoke::<Il2CppObject>(Il2CppObject::NULL, &[])
            .map_err(invoke_error)
    })?;
    ensure!(
        items.0 != 0,
        "ConfigManifest.get_ManifestItems returned null"
    );
    let serialized = operation("Config: serialize manifest", || {
        super::new_serializer().serialize(info.get_return_type()?, items)
    })?;
    parse_manifest(serialized, type_field, path_field)
}

fn parse_manifest(
    value: serde_json::Value,
    type_field: &str,
    path_field: &str,
) -> Result<BTreeMap<String, Vec<String>>> {
    let items = value
        .as_array()
        .context("Config manifest: expected array")?;
    let mut out = BTreeMap::<String, Vec<String>>::new();
    for (index, item) in items.iter().enumerate() {
        let name = item
            .get(type_field)
            .and_then(|value| value.as_str())
            .with_context(|| {
                format!("Config manifest item {index}: missing/string field {type_field}")
            })?;
        let paths: Vec<String> = serde_json::from_value(
            item.get(path_field)
                .with_context(|| {
                    format!("Config manifest item {index}: missing field {path_field}")
                })?
                .clone(),
        )
        .with_context(|| {
            format!("Config manifest item {index}: expected string array {path_field}")
        })?;
        // A manifest may contain several entries of the same type.
        out.entry(name.to_string()).or_default().extend(paths);
    }
    Ok(out)
}

fn read_excel(name: &str) -> Result<Vec<serde_json::Value>> {
    let path = PathBuf::from(format!("./DUMP/Resources/ExcelOutput/{name}.json"));
    operation(format!("read dependency {}", path.display()), || {
        let bytes = std::fs::read(&path)
            .with_context(|| format!("read Excel dependency {}", path.display()))?;
        serde_json::from_slice(&bytes)
            .with_context(|| format!("parse Excel dependency {} as an array", path.display()))
    })
}

fn dump_from_config_list(
    func_name: &str,
    mut paths: Vec<String>,
    serializer: &mut BoxedSerializer,
) -> Result<()> {
    paths.sort();
    paths.dedup();
    checkpoint(format!("Config: {func_name} paths={}", paths.len()));
    if paths.is_empty() {
        return Ok(());
    }
    let loader = get_native_method(&format!(
        "RPG.GameCore.GameCoreConfigLoader::{func_name}(System.String)"
    ))
    .with_context(|| format!("missing GameCoreConfigLoader::{func_name}(System.String)"))?;
    let return_type = MethodInfo::from_handle(loader)?.get_return_type()?;
    let exists = get_native_method("RPG.Client.AssetLoader::ExistsDesignData(System.String)")
        .context("missing AssetLoader::ExistsDesignData(System.String)")?;
    let mut skipped = 0;
    for path in paths {
        let argument = Il2CppString::from(path.as_str());
        let present = operation(format!("Config: exists {path}"), || {
            exists
                .invoke::<BoxedBool>(Il2CppObject::NULL, &[&argument])
                .map(|value| value.unbox())
                .map_err(invoke_error)
        })?;
        if !present {
            skipped += 1;
            checkpoint(format!("Config: skip absent path {path}"));
            continue;
        }
        // Propagate existing SEH protection as a task failure, never a false success.
        microseh::try_seh(|| {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
                let data = operation(format!("Config: load {func_name} path={path}"), || {
                    loader
                        .invoke::<Il2CppObject>(Il2CppObject::NULL, &[&argument])
                        .map_err(invoke_error)
                })?;
                ensure!(data.0 != 0, "{func_name} path={path}: loader returned null");
                let serialized =
                    operation(format!("Config: serialize {func_name} path={path}"), || {
                        serializer.serialize(return_type, data)
                    })?;
                super::write_json(
                    &PathBuf::from(format!("./DUMP/Resources/{path}")),
                    &serialized,
                )
            }))
        })
        .map_err(|error| {
            anyhow::anyhow!("Config {func_name} path={path}: native exception {error:?}")
        })?
        .map_err(|payload| {
            let message = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("unknown panic payload");
            anyhow::anyhow!("Config {func_name} path={path}: Rust panic: {message}")
        })??;
    }
    checkpoint(format!(
        "Config: completed {func_name} skipped_absent={skipped}"
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_manifest;
    use serde_json::json;

    #[test]
    fn manifest_merges_repeated_types() {
        let parsed = parse_manifest(
            json!([
                {"type": "A", "paths": ["one"]},
                {"type": "A", "paths": ["two"]}
            ]),
            "type",
            "paths",
        )
        .unwrap();
        assert_eq!(parsed["A"], ["one", "two"]);
    }

    #[test]
    fn manifest_reports_incompatible_fields() {
        let error =
            parse_manifest(json!([{"type": "A", "paths": 42}]), "type", "paths").unwrap_err();
        assert!(format!("{error:#}").contains("item 0"));
        assert!(format!("{error:#}").contains("paths"));
    }
}
