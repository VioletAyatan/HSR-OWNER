mod allocator;
pub mod decode_gateway;
pub mod decoder;
pub mod dispatch;
pub mod parse_gate_server;
pub mod region;
pub mod stop_info;

use std::collections::HashMap;

use iced_x86::Register;

use crate::proto::{
    names::ScopedFieldNames,
    output::{ProtoItem, TypeToItemMap, snake_field},
};
use serde_json::{Value, json};

#[derive(Default)]
pub(in crate::proto) struct GateNames {
    pub global: HashMap<String, String>,
    pub scoped: ScopedFieldNames,
    evidence: Vec<Value>,
    native: Value,
}

impl GateNames {
    pub(in crate::proto) fn retain_unresolved(&mut self, baseline: &TypeToItemMap) {
        for item in baseline.values() {
            let item = item.borrow();
            let ProtoItem::Message(message) = &*item else {
                continue;
            };
            let Some(names) = self.scoped.get_mut(&message.name) else {
                continue;
            };
            for field in &message.fields {
                if !crate::proto::util::is_obf(&field.name)
                    && names
                        .get(&field.number)
                        .is_some_and(|name| snake_field(name) != snake_field(&field.name))
                {
                    names.remove(&field.number);
                    for row in &mut self.evidence {
                        if row["message"].as_str() == Some(message.name.as_str())
                            && row["tag"].as_u64() == Some(u64::from(field.number))
                        {
                            row["status"] = json!("preserved-existing-name");
                        }
                    }
                }
            }
        }
    }

    pub(in crate::proto) fn write(&mut self, final_items: &TypeToItemMap) -> std::io::Result<()> {
        for row in &mut self.evidence {
            let final_name = final_items.values().find_map(|item| {
                let item = item.borrow();
                let ProtoItem::Message(message) = &*item else {
                    return None;
                };
                if Some(message.name.as_str()) != row["message"].as_str() {
                    return None;
                }
                message
                    .fields
                    .iter()
                    .find(|field| Some(u64::from(field.number)) == row["tag"].as_u64())
                    .map(|field| snake_field(&field.name))
            });
            if row["status"].as_str() != Some("preserved-existing-name") {
                row["status"] = json!(if final_name.as_deref() == row["recovered"].as_str() {
                    "accepted-gateway-name"
                } else {
                    "rejected-final-name"
                });
            }
            row["final_name"] = json!(final_name);
        }
        std::fs::write("./DUMP/proto-gateway-name-evidence.json", serde_json::to_vec_pretty(&json!({
            "game_version":&*crate::version::GAME_VERSION,"native":self.native,"evidence":self.evidence,
            "boundary":"static factory native provenance and unique current response content classes; no response values are saved"
        })).map_err(std::io::Error::other)?)
    }
}

pub(in crate::proto) fn process_all(type_to_item: &TypeToItemMap) -> GateNames {
    // A failed metadata lookup must not leave a previous dump's tag map active.
    decode_gateway::set_proto_fields(HashMap::new());
    let parsed = parse_gate_server::process(type_to_item);
    let mut map = parsed.names;
    let mut result = GateNames {
        global: stop_info::process_stop_info(type_to_item),
        evidence: parsed.evidence,
        native: parsed.report,
        ..GateNames::default()
    };
    let decode_nt = decode_gateway::run();
    result.native["content"] = decode_nt.summary;
    let mut added = 0;
    let mut conflicts = 0;
    for (obf_name, inferred_name) in decode_nt.names {
        match map.entry(obf_name) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                if let Some(message) = &parsed.message {
                    for (&tag, raw) in &parsed.fields {
                        if raw == entry.key() {
                            result.evidence.push(json!({"message":message,"tag":tag,"original":raw,
                            "recovered":snake_field(&inferred_name),"source":"unique-current-content-class",
                            "content_proof":decode_nt.evidence.get(&tag),"status":"candidate"}));
                        }
                    }
                }
                entry.insert(inferred_name);
                added += 1;
            }
            std::collections::hash_map::Entry::Occupied(entry) => {
                if entry.get() != &inferred_name {
                    conflicts += 1;
                    if conflicts <= 8 {
                        log::warn!(
                            "[Gateway] name conflict for {}: keeping direct code mapping {}, rejecting content candidate {}",
                            entry.key(),
                            entry.get(),
                            inferred_name
                        );
                    }
                }
            }
        }
    }
    log::info!(
        "[Gateway] name merge complete: total={}, content_added={added}, content_conflicts={conflicts}",
        map.len()
    );
    if let Some(message) = parsed.message {
        let names = result.scoped.entry(message).or_default();
        for (tag, raw) in parsed.fields {
            if let Some(name) = map.get(&raw) {
                names.insert(tag, name.clone());
            }
        }
    }
    result
}

pub fn full_reg(r: Register) -> Register {
    match r {
        Register::EAX | Register::AX | Register::AL | Register::AH => Register::RAX,
        Register::EBX | Register::BX | Register::BL | Register::BH => Register::RBX,
        Register::ECX | Register::CX | Register::CL | Register::CH => Register::RCX,
        Register::EDX | Register::DX | Register::DL | Register::DH => Register::RDX,
        Register::ESI | Register::SI => Register::RSI,
        Register::EDI | Register::DI => Register::RDI,
        Register::EBP | Register::BP => Register::RBP,
        Register::R8D | Register::R8W | Register::R8L => Register::R8,
        Register::R9D | Register::R9W | Register::R9L => Register::R9,
        Register::R10D | Register::R10W | Register::R10L => Register::R10,
        Register::R11D | Register::R11W | Register::R11L => Register::R11,
        Register::R12D | Register::R12W | Register::R12L => Register::R12,
        Register::R13D | Register::R13W | Register::R13L => Register::R13,
        Register::R14D | Register::R14W | Register::R14L => Register::R14,
        Register::R15D | Register::R15W | Register::R15L => Register::R15,
        _ => r,
    }
}

pub const VOLATILE_REGS: [Register; 7] = [
    Register::RAX,
    Register::RCX,
    Register::RDX,
    Register::R8,
    Register::R9,
    Register::R10,
    Register::R11,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::output::{Field, Message, MessageType};
    use reflection::runtime_type::RuntimeType;
    use std::{cell::RefCell, rc::Rc};

    fn message(name: &str, field: &str) -> Rc<RefCell<ProtoItem>> {
        Rc::new(RefCell::new(ProtoItem::Message(Message {
            name: name.into(),
            fields: vec![Field {
                name: field.into(),
                kind: "string".into(),
                number: 3,
                offset: 40,
            }],
            cmd_id: 0,
            deobfuscated_name: None,
            oneofs: vec![],
            children: vec![],
            has_parent: false,
            msg_type: MessageType::None,
            write_to_rva: 0,
            merge_from_rva: 0,
        })))
    }

    #[test]
    fn gateway_names_stay_on_the_proven_message_and_preserve_existing_names() {
        let mut items = TypeToItemMap::from([
            (RuntimeType(1), message("GATE", "AJHCNDDFMJO")),
            (RuntimeType(2), message("OTHER", "AJHCNDDFMJO")),
        ]);
        let mut names = GateNames {
            scoped: HashMap::from([(
                "GATE".into(),
                HashMap::from([(3, "gate_server_address".into())]),
            )]),
            ..GateNames::default()
        };
        names.retain_unresolved(&items);
        crate::proto::names::apply_field_maps(&mut items, &HashMap::new(), &names.scoped);
        let field_name = |key| {
            let item = items[&RuntimeType(key)].borrow();
            let ProtoItem::Message(message) = &*item else {
                unreachable!()
            };
            message.fields[0].name.clone()
        };
        assert_eq!(field_name(1), "gate_server_address");
        assert_eq!(field_name(2), "AJHCNDDFMJO");
        names
            .scoped
            .get_mut("GATE")
            .unwrap()
            .insert(3, "other_address".into());
        names.retain_unresolved(&items);
        assert!(!names.scoped["GATE"].contains_key(&3));
    }
}
