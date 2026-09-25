use anyhow::{Context, Result, ensure};
use il2cpp::vm::{array::Il2CppArray, object::Il2CppObject, string::Il2CppString};
use reflection::{assembly, runtime_type::RuntimeType};
use std::path::PathBuf;

pub fn dump() -> Result<()> {
    let assemblies = assembly::get_assemblies();
    let assembly = assemblies
        .iter()
        .find(|a| a.get_name() == "RPG.GameCore.Config")
        .context("missing RPG.GameCore.Config assembly")?;
    let types = assembly.get_types();
    super::checkpoint(format!("ExcelOutput: scan {} types", types.len()));
    for ty in types {
        dump_table(ty).with_context(|| format!("ExcelOutput type {}", ty.il_name()))?;
    }
    Ok(())
}

fn dump_table(table: RuntimeType) -> Result<()> {
    let mut paths_field = None;
    let mut has_index = false;
    for field in table.get_fields_il2cpp() {
        let name = field.get_field_type()?.format_type_name(true);
        if name == "string[]" {
            paths_field = Some(field);
        } else if name.contains("Dictionary")
            && (name.contains("Row") || name.contains("CommonIndexKey"))
        {
            has_index = true;
        }
    }
    let Some(paths_field) = paths_field.filter(|_| has_index) else {
        return Ok(());
    };
    let name = table.il_name();
    super::checkpoint(format!("ExcelOutput: read paths for {name}"));
    let value = paths_field.get_value(Il2CppObject::NULL)?;
    ensure!(value.0 != 0, "{name}: null path list");
    let paths = Il2CppArray(value.0).to_vec::<Il2CppString>();
    for path in paths {
        ensure!(path.0 != 0, "{name}: null path in path list");
        let path = path.as_str();
        // Preserve runtime-table semantics. Do not unload/reload shared game tables.
        let output_name = path.rsplit('/').next().unwrap_or(&path);
        let output_name = output_name.strip_suffix(".bytes").unwrap_or(output_name);
        let output = PathBuf::from(format!("./DUMP/Resources/ExcelOutput/{output_name}.json"));
        super::write_table(table, &format!("{name} path={path}"), &output)?;
    }
    Ok(())
}
