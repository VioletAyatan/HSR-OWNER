use anyhow::{Context, Result};
use reflection::serializer::BoxedSerializer;
use serde_json::Value;

pub fn dump(serializer: &mut BoxedSerializer) -> Result<()> {
    let chess_board_data = super::read_excel("RogueDLCChessBoard")?;

    let paths: Result<Vec<_>> = chess_board_data
        .iter()
        .enumerate()
        .map(|(index, data)| {
            data.get("ChessBoardConfiguration")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .with_context(|| {
                    format!("RogueDLCChessBoard row {index} has invalid ChessBoardConfiguration")
                })
        })
        .collect();

    super::dump_from_config_list("LoadRogueChestMapConfig", paths?, serializer)?;
    Ok(())
}
