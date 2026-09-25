use anyhow::{Context, Result};
use reflection::serializer::BoxedSerializer;
use serde_json::Value;

fn extract_caption_paths(name: &str) -> Result<Vec<String>> {
    let json = super::read_excel(name)?;
    json.iter()
        .enumerate()
        .map(|(index, item)| {
            item.get("CaptionPath")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .with_context(|| format!("{name} row {index} has invalid CaptionPath"))
        })
        .collect()
}

pub fn dump(serializer: &mut BoxedSerializer) -> Result<()> {
    let mut paths = Vec::new();
    for name in ["VideoConfig", "CutSceneConfig", "LoopCGConfig"] {
        paths.extend(extract_caption_paths(name).with_context(|| format!("reading {name}"))?);
    }

    super::dump_from_config_list("LoadVideoCaptionConfig", paths, serializer)?;
    Ok(())
}
