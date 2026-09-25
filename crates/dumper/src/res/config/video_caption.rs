use anyhow::{Context, Result};
use reflection::serializer::BoxedSerializer;
use serde_json::Value;

fn extract_caption_paths(name: &str) -> Result<Vec<String>> {
    let json = super::read_excel(name)?;
    collect_caption_paths(name, &json)
}

fn collect_caption_paths(name: &str, rows: &[Value]) -> Result<Vec<String>> {
    let mut paths = Vec::new();
    let mut skipped_blank = 0;
    for (index, item) in rows.iter().enumerate() {
        let path = item
            .get("CaptionPath")
            .and_then(Value::as_str)
            .with_context(|| {
                format!("{name} row {index} has invalid CaptionPath (expected string)")
            })?;
        // A video/cutscene can have no caption resource. Empty references are
        // not valid inputs to the game's ExistsDesignData API.
        if path.trim().is_empty() {
            skipped_blank += 1;
            super::checkpoint(format!(
                "Config/VideoCaption: skip {name} row={index} CaptionPath={path:?} reason=no caption reference"
            ));
            continue;
        }
        paths.push(path.to_owned());
    }
    super::checkpoint(format!(
        "Config/VideoCaption: {name} rows={} caption_paths={} skipped_blank={skipped_blank}",
        rows.len(),
        paths.len()
    ));
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn optional_blank_captions_are_skipped_without_losing_valid_paths() {
        let paths = collect_caption_paths(
            "VideoConfig",
            &[
                json!({"CaptionPath": ""}),
                json!({"CaptionPath": "Config/VideoCaption/example.json"}),
                json!({"CaptionPath": " \t\r\n"}),
                json!({"CaptionPath": " Config/VideoCaption/unchanged.json "}),
            ],
        )
        .unwrap();
        assert_eq!(
            paths,
            [
                "Config/VideoCaption/example.json",
                " Config/VideoCaption/unchanged.json "
            ]
        );
        assert!(
            collect_caption_paths("LoopCGConfig", &[json!({"CaptionPath": ""})])
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn malformed_caption_fields_still_report_source_table_and_row() {
        for invalid in [
            json!({}),
            json!({"CaptionPath": null}),
            json!({"CaptionPath": 42}),
        ] {
            let error =
                collect_caption_paths("CutSceneConfig", &[json!({"CaptionPath": ""}), invalid])
                    .unwrap_err()
                    .to_string();
            assert!(error.contains("CutSceneConfig row 1"));
            assert!(error.contains("CaptionPath"));
        }
    }
}

pub fn dump(serializer: &mut BoxedSerializer) -> Result<()> {
    let mut paths = Vec::new();
    for name in ["VideoConfig", "CutSceneConfig", "LoopCGConfig"] {
        paths.extend(extract_caption_paths(name).with_context(|| format!("reading {name}"))?);
    }

    super::dump_from_config_list("LoadVideoCaptionConfig", paths, serializer)?;
    Ok(())
}
