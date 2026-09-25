use anyhow::{Context, Result};
use reflection::serializer::BoxedSerializer;
use serde_json::Value;

pub fn dump(serializer: &mut BoxedSerializer) -> Result<()> {
    let summon_unit_data = super::read_excel("SummonUnitData")?;

    let paths: Result<Vec<_>> = summon_unit_data
        .iter()
        .enumerate()
        .map(|(index, data)| {
            data.get("JsonPath")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .with_context(|| format!("SummonUnitData row {index} has invalid JsonPath"))
        })
        .collect();

    super::dump_from_config_list("LoadSummonUnitConfig", paths?, serializer)?;
    Ok(())
}
