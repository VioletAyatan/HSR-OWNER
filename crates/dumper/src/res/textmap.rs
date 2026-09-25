use anyhow::Result;
use std::path::Path;

pub fn dump() -> Result<()> {
    let name = "RPG.GameCore.TextmapExcelTable";
    // The legacy filename does not imply the game's current language is English.
    super::write_table(
        super::runtime_type(name)?,
        name,
        Path::new("./DUMP/Resources/TextMap/TextMapEN.json"),
    )
}
