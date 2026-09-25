use anyhow::{Context, Result};
use reflection::serializer::BoxedSerializer;
use serde_json::Value;
use std::{cell::RefCell, rc::Rc};

pub fn dump(serializer: &mut BoxedSerializer) -> Result<()> {
    let maze_plane = super::read_excel("MazePlane")?;

    let paths: Result<Vec<_>> = maze_plane
        .iter()
        .enumerate()
        .map(|(index, p)| {
            let plane_id = p.get("PlaneID").and_then(Value::as_u64)
                .and_then(|id| u32::try_from(id).ok())
                .with_context(|| format!("MazePlane row {index} has invalid PlaneID"))?;
            let floor_ids = p.get("FloorIDList").and_then(Value::as_array)
                .with_context(|| format!("MazePlane row {index} has invalid FloorIDList"))?;
            floor_ids.iter().enumerate().map(|(floor_index, value)| {
                value.as_u64().and_then(|id| u32::try_from(id).ok())
                    .map(|floor_id| (plane_id, floor_id))
                    .with_context(|| format!("MazePlane row {index} FloorIDList[{floor_index}] is not a valid u32 ID"))
            }).collect::<Result<Vec<_>>>()
        })
        .collect::<Result<Vec<_>>>()
        .map(|rows| rows.into_iter().flatten().collect());
    let paths = paths?;

    let group_paths = Rc::new(RefCell::new(Vec::<String>::new()));
    let group_paths_clone = group_paths.clone();

    serializer.add_callback(
        String::from("GroupPath"),
        Rc::new(move |value| {
            if let Value::String(value) = value
                && value.starts_with("Config/LevelOutput/")
            {
                group_paths_clone.borrow_mut().push(value.clone());
            }
        }),
    );

    let mut rt_level_floor_paths = Vec::with_capacity(paths.len());
    let mut baked_floor_paths = Vec::with_capacity(paths.len());
    let mut cross_map_brief_paths = Vec::with_capacity(paths.len());
    let mut region_paths = Vec::with_capacity(paths.len());
    let mut rotation_paths = Vec::with_capacity(paths.len());
    let mut era_flipper_paths = Vec::with_capacity(paths.len());
    let mut navmap_paths = Vec::with_capacity(paths.len());

    for (plane_id, floor_id) in paths {
        let name = format!("P{plane_id}_F{floor_id}");
        rt_level_floor_paths.push(format!("Config/LevelOutput/RuntimeFloor/{name}.json"));
        baked_floor_paths.push(format!("Config/LevelOutput_Baked/Floor/{name}_Baked.json"));
        cross_map_brief_paths.push(format!(
            "Config/LevelOutput_Baked/FloorCrossMapBriefInfo/CrossMapBriefInfo_{name}.json"
        ));
        region_paths.push(format!("Config/LevelOutput/Region/FloorRegion_{name}.json"));
        rotation_paths.push(format!(
            "Config/LevelOutput/RotatableRegion/RotatableRegion_Floor_{floor_id}.json"
        ));
        era_flipper_paths.push(format!(
            "Config/LevelOutput/EraFlipper/EraFlipper_Floor_{floor_id}.json"
        ));
        navmap_paths.push(format!("Config/LevelOutput/Map/MapInfo_{name}.json"));
    }

    super::dump_from_config_list("LoadRtLevelFloorInfo", rt_level_floor_paths, serializer)?;
    super::dump_from_config_list("LoadLevelFloorBakedInfo", baked_floor_paths, serializer)?;
    super::dump_from_config_list(
        "LoadLevelFloorCrossMapBriefInfo",
        cross_map_brief_paths,
        serializer,
    )?;
    super::dump_from_config_list("LoadLevelRegionInfos", region_paths, serializer)?;
    super::dump_from_config_list("LoadMapRotationConfig", rotation_paths, serializer)?;
    super::dump_from_config_list("LoadEraFlipperConfig", era_flipper_paths, serializer)?;
    super::dump_from_config_list("LoadLevelNavmapConfig", navmap_paths, serializer)?;
    super::dump_from_config_list("LoadRtLevelGroupInfo", group_paths.take(), serializer)?;

    serializer.remove_callback("GroupPath");
    Ok(())
}
