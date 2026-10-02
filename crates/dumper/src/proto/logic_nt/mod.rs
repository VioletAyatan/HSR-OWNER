use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

pub mod field;
pub mod message;

use super::output::ProtoItem;

pub struct LogicNames {
    pub types: HashMap<String, String>,
    pub fields: HashMap<String, String>,
}

pub fn run_logic_nt(
    items: &[Rc<RefCell<ProtoItem>>],
    message_nt_map: &HashMap<String, String>,
    predeobf_map: &HashMap<String, String>,
) -> std::io::Result<LogicNames> {
    let mut nt_map: indexmap::IndexMap<String, String> = indexmap::IndexMap::new();
    let mut global_field_map: HashMap<String, String> = predeobf_map.clone();

    for (k, v) in predeobf_map {
        nt_map.entry(k.clone()).or_insert(v.clone());
    }

    for (obf_name, deobf_name) in message_nt_map {
        nt_map.insert(obf_name.clone(), deobf_name.clone());
    }

    message::deobf_messages(items, message_nt_map, &mut nt_map);
    // Keep type and field namespaces separate, and return both to the writer.
    let types = items
        .iter()
        .filter_map(|item| {
            let item = item.borrow();
            let name = match &*item {
                ProtoItem::Message(m) => &m.name,
                ProtoItem::Enum(e) => &e.name,
            };
            nt_map.get(name).map(|deobf| (name.clone(), deobf.clone()))
        })
        .collect::<HashMap<_, _>>();
    field::deobf_fields(items, &mut nt_map, &mut global_field_map);

    let output_content: String = nt_map
        .iter()
        .filter(|(original, recovered)| original != recovered)
        .map(|(k, v)| format!("{k} {v}"))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write("./DUMP/nt.txt", output_content)?;
    log::info!(
        "[Logic NT] complete: type_names={} field_names={} new_fields={}",
        types.len(),
        global_field_map.len(),
        global_field_map.len().saturating_sub(predeobf_map.len())
    );
    Ok(LogicNames {
        types,
        fields: global_field_map,
    })
}
