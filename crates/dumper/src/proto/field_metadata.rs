//! Recover a field name only when a literal on its own message declares the
//! exact wire field number. String literals elsewhere in the client are not
//! evidence of a field's owner or number.
use std::{collections::HashMap, io, path::Path};

use anyhow::{Context, Result, ensure};
use il2cpp::vm::{object::Il2CppObject, string::Il2CppString};
use reflection::{attributes::FieldAttributes, field_info::FieldInfo, runtime_type::RuntimeType};
use serde::Serialize;

use crate::{dump_progress::Progress, script::memory};

use super::{
    cache::{CachedType, TypeCache},
    names::{ScopedFieldNames, identifier},
    output::{Message, ProtoItem, TypeToItemMap, snake_field},
    util::is_obf,
};

#[derive(Default, Serialize)]
pub(super) struct FieldMetadata {
    pub messages_scanned: usize,
    pub static_fields_scanned: usize,
    pub int32_literals: usize,
    pub obfuscated_int32_literals: usize,
    pub obfuscated_literal_samples: Vec<LiteralSample>,
    pub named_constants: usize,
    pub unmatched_constants: usize,
    pub conflicts: usize,
    pub metadata_errors: usize,
    pub evidence: Vec<Evidence>,
    #[serde(skip)]
    pub names: ScopedFieldNames,
}

#[derive(Serialize)]
pub(super) struct LiteralSample {
    message: String,
    literal: String,
    value: i32,
}

#[derive(Serialize)]
pub(super) struct Evidence {
    message: String,
    tag: u32,
    original: String,
    constant: String,
    recovered: String,
    status: &'static str,
    final_name: Option<String>,
}

fn constant_name(name: &str) -> Option<String> {
    let raw = name.strip_suffix("FieldNumber")?.trim_end_matches('_');
    if raw.is_empty() || is_obf(raw) || !identifier(raw) {
        return None;
    }
    let recovered = snake_field(raw);
    identifier(&recovered).then_some(recovered)
}

fn valid_tag(value: i32) -> Option<u32> {
    let value = u32::try_from(value).ok()?;
    (value != 0 && value <= 0x1fff_ffff && !(19000..=19999).contains(&value)).then_some(value)
}

fn string_body(
    address: usize,
    length: usize,
    object_size: usize,
) -> Result<std::ops::Range<usize>> {
    let bytes = length
        .checked_mul(size_of::<u16>())
        .context("string length overflow")?;
    let total = 20usize.checked_add(bytes).context("string size overflow")?;
    ensure!(
        total <= object_size,
        "string body exceeds managed object size"
    );
    let start = address.checked_add(20).context("string address overflow")?;
    let end = start
        .checked_add(bytes)
        .context("string address overflow")?;
    ensure!(start % align_of::<u16>() == 0, "unaligned string body");
    Ok(start..end)
}

pub(super) fn checked_name(value: Il2CppString) -> Result<String> {
    memory::readable(value.0, 20)?;
    let object = Il2CppObject(value.0);
    ensure!(
        Some(object.get_class()) == il2cpp::get_cached_class("System.String"),
        "field name is not a string object"
    );
    let length = unsafe {
        (value.0.checked_add(16).context("string header overflow")? as *const u32).read_unaligned()
    } as usize;
    // Ownership comes from the reflection API, the type check, and the
    // managed allocation size; readable pages alone are not a string bound.
    let object_size = il2cpp::api::il2cpp_object_get_size(object) as usize;
    let body = string_body(value.0, length, object_size)?;
    memory::readable(body.start, body.len())?;
    let units = unsafe { std::slice::from_raw_parts(body.start as *const u16, length) };
    String::from_utf16(units).context("invalid UTF16 field name")
}

impl FieldMetadata {
    fn add_constants(&mut self, message: &Message, constants: Vec<(String, i32)>) {
        let mut tags = HashMap::<u32, Vec<_>>::new();
        for field in message
            .fields
            .iter()
            .chain(message.oneofs.iter().flat_map(|oneof| &oneof.fields))
        {
            tags.entry(field.number).or_default().push(field);
        }
        // All candidates for a tag must agree. This bound comes from the
        // message's declared fields and static literals, never a version cap.
        let mut candidates = HashMap::<u32, Vec<(String, String)>>::new();
        for (constant, value) in constants {
            let Some(recovered) = constant_name(&constant) else {
                continue;
            };
            self.named_constants += 1;
            let Some(tag) = valid_tag(value) else {
                self.unmatched_constants += 1;
                continue;
            };
            candidates
                .entry(tag)
                .or_default()
                .push((constant, recovered));
        }
        for (tag, candidates) in candidates {
            let Some(fields) = tags.get(&tag).filter(|fields| fields.len() == 1) else {
                self.unmatched_constants += candidates.len();
                continue;
            };
            let field = fields[0];
            let agreed = candidates.iter().all(|(_, name)| name == &candidates[0].1);
            let recovered = &candidates[0].1;
            let readable_agrees = is_obf(&field.name) || snake_field(&field.name) == *recovered;
            let status = if !agreed || !readable_agrees {
                self.conflicts += 1;
                "conflicting-metadata"
            } else {
                self.names
                    .entry(message.name.clone())
                    .or_default()
                    .insert(tag, recovered.clone());
                "candidate"
            };
            for (constant, recovered) in candidates {
                self.evidence.push(Evidence {
                    message: message.name.clone(),
                    tag,
                    original: field.name.clone(),
                    constant,
                    recovered,
                    status,
                    final_name: None,
                });
            }
        }
    }

    pub(super) fn write(&mut self, items: &TypeToItemMap, path: &Path) -> io::Result<()> {
        let final_names: HashMap<_, _> = items
            .values()
            .flat_map(|item| {
                let item = item.borrow();
                match &*item {
                    ProtoItem::Message(message) => message
                        .fields
                        .iter()
                        .chain(message.oneofs.iter().flat_map(|oneof| &oneof.fields))
                        .map(|field| {
                            (
                                (message.name.clone(), field.number),
                                snake_field(&field.name),
                            )
                        })
                        .collect::<Vec<_>>(),
                    _ => Vec::new(),
                }
            })
            .collect();
        let mut accepted = 0;
        let mut recovered = 0;
        for evidence in &mut self.evidence {
            evidence.final_name = final_names
                .get(&(evidence.message.clone(), evidence.tag))
                .cloned();
            if evidence.status == "candidate" {
                evidence.status = if evidence.final_name.as_deref() == Some(&evidence.recovered) {
                    accepted += 1;
                    recovered += usize::from(is_obf(&evidence.original));
                    "accepted"
                } else {
                    "rejected-by-output-validation"
                };
            }
        }
        log::info!(
            "[Field Metadata] complete: messages={} static_fields={} int32_literals={} obfuscated_literals={} named_constants={} candidates={} accepted_evidence={} recovered_evidence={} unmatched={} conflicts={} metadata_errors={}",
            self.messages_scanned,
            self.static_fields_scanned,
            self.int32_literals,
            self.obfuscated_int32_literals,
            self.named_constants,
            self.names.values().map(HashMap::len).sum::<usize>(),
            accepted,
            recovered,
            self.unmatched_constants,
            self.conflicts,
            self.metadata_errors,
        );
        // One write per dump. Evidence is limited by this invocation's own
        // metadata and carries the final acceptance result, unlike nt.txt.
        let output = serde_json::json!({
            "game_version": &*crate::version::GAME_VERSION,
            "source": "declared int32 literal FieldNumber constants matched to recovered wire tags",
            "summary": self,
        });
        std::fs::write(path, serde_json::to_vec_pretty(&output)?)
    }
}

fn read_constant(
    field: FieldInfo,
    owner: RuntimeType,
    cache: &TypeCache,
) -> Result<Option<(String, i32)>> {
    let attributes = field.get_attributes()?;
    memory::readable(attributes.0, 16 + size_of::<i32>())?;
    let attributes = attributes.unbox();
    if !attributes.contains(FieldAttributes::Static | FieldAttributes::Literal) {
        return Ok(None);
    }
    let name = checked_name(field.get_name()?)?;
    ensure!(
        field.get_declaringtype()? == owner,
        "constant belongs to another message"
    );
    let field_type = field.get_field_type()?;
    if cache.type_map.get(&field_type) != Some(&CachedType::Int32) {
        return Ok(None);
    }
    let value = field.get_value(Il2CppObject::NULL)?;
    // The managed reflection API supplies this boxed literal. Check both the
    // declared value type and returned object type before reading its payload.
    memory::readable(value.0, 16 + size_of::<i32>())?;
    ensure!(
        value.get_class() == field_type.get_il2cpp_type().get_class(),
        "literal box type mismatch"
    );
    Ok(Some((name, value.unbox::<i32>())))
}

pub(super) fn collect(
    items: &TypeToItemMap,
    cache: &TypeCache,
    progress: &Progress,
) -> io::Result<FieldMetadata> {
    let mut output = FieldMetadata::default();
    for (index, (owner, item)) in items.iter().enumerate() {
        let item = item.borrow();
        let ProtoItem::Message(message) = &*item else {
            continue;
        };
        if message.fields.is_empty() && message.oneofs.is_empty() {
            continue;
        }
        output.messages_scanned += 1;
        progress.step(index, owner.0, "read message FieldNumber constants");
        let mut constants = Vec::new();
        // DeclaredOnly | Public | NonPublic | Static: inherited literals must
        // never name a field on a different message.
        let fields = microseh::try_seh(|| owner.get_fields_checked(58))
            .map_err(|error| {
                io::Error::other(format!(
                    "FieldNumber enumeration message={} owner=0x{:X}: {error:?}",
                    message.name, owner.0
                ))
            })?
            .map_err(|error| {
                io::Error::other(format!(
                    "FieldNumber enumeration message={} owner=0x{:X}: {error:#}",
                    message.name, owner.0
                ))
            })?;
        for field in fields {
            output.static_fields_scanned += 1;
            let constant =
                microseh::try_seh(|| read_constant(field, *owner, cache)).map_err(|error| {
                    io::Error::other(format!(
                        "FieldNumber read message={} field=0x{:X}: {error:?}",
                        message.name, field.0
                    ))
                })?;
            match constant {
                Ok(Some(constant)) => {
                    output.int32_literals += 1;
                    if is_obf(&constant.0) {
                        output.obfuscated_int32_literals += 1;
                        if output.obfuscated_literal_samples.len() < 12 {
                            output.obfuscated_literal_samples.push(LiteralSample {
                                message: message.name.clone(),
                                literal: constant.0.clone(),
                                value: constant.1,
                            });
                        }
                    }
                    constants.push(constant);
                }
                Ok(None) => {}
                Err(error) => {
                    if output.metadata_errors < 12 {
                        log::warn!(
                            "[Field Metadata] cannot read literal: message={} field=0x{:X} reason={error:#}",
                            message.name,
                            field.0
                        );
                    }
                    output.metadata_errors += 1;
                }
            }
        }
        output.add_constants(message, constants);
    }
    log::info!(
        "[Field Metadata] candidates: messages={} tags={} conflicts={} unmatched={}",
        output.names.len(),
        output.names.values().map(HashMap::len).sum::<usize>(),
        output.conflicts,
        output.unmatched_constants
    );
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::output::{Field, MessageType, OneOf};

    fn message() -> Message {
        Message {
            cmd_id: 0,
            name: "Message".into(),
            deobfuscated_name: None,
            fields: vec![Field {
                name: "ABCDEFGHIJK".into(),
                number: 7,
                offset: 32,
                kind: "uint32".into(),
            }],
            oneofs: vec![],
            children: vec![],
            has_parent: false,
            msg_type: MessageType::None,
            write_to_rva: 0,
            merge_from_rva: 0,
        }
    }

    #[test]
    fn parses_semantic_constants_and_checks_protocol_tag_limits() {
        assert_eq!(
            constant_name("ShopIdFieldNumber").as_deref(),
            Some("shop_id")
        );
        assert_eq!(
            constant_name("ItemList_FieldNumber").as_deref(),
            Some("item_list")
        );
        for name in [
            "ABCDEFGHIJKFieldNumber",
            "FieldNumber",
            "1IdFieldNumber",
            "ShopId",
        ] {
            assert_eq!(constant_name(name), None, "{name}");
        }
        for tag in [-1, 0, 19000, 19999, 0x2000_0000] {
            assert_eq!(valid_tag(tag), None);
        }
        for tag in [1, 18999, 20000, 0x1fff_ffff] {
            assert_eq!(valid_tag(tag), Some(tag as u32));
        }
    }

    #[test]
    fn string_body_is_bounded_by_its_actual_managed_allocation() {
        assert_eq!(string_body(0x100, 2, 24).unwrap(), 0x114..0x118);
        assert!(string_body(0x100, 3, 24).is_err());
        assert!(string_body(usize::MAX - 8, 0, 20).is_err());
        assert!(string_body(0x100, usize::MAX, usize::MAX).is_err());
        assert!(string_body(0x101, 1, 24).is_err());
    }

    #[test]
    fn matches_constants_by_actual_tag_including_oneofs() {
        let mut message = message();
        message.oneofs.push(OneOf {
            name: "Payload".into(),
            fields: vec![Field {
                name: "BCDEFGHIJKL".into(),
                number: 11,
                offset: 0,
                kind: "string".into(),
            }],
        });
        let mut output = FieldMetadata::default();
        output.add_constants(
            &message,
            vec![
                ("ShopIdFieldNumber".into(), 7),
                ("TextFieldNumber".into(), 11),
                ("AbsentFieldNumber".into(), 13),
            ],
        );
        assert_eq!(output.names["Message"][&7], "shop_id");
        assert_eq!(output.names["Message"][&11], "text");
        assert_eq!(output.unmatched_constants, 1);
    }

    #[test]
    fn conflicting_constants_duplicate_tags_and_readable_disagreement_are_rejected() {
        let mut output = FieldMetadata::default();
        let mut message = message();
        output.add_constants(
            &message,
            vec![
                ("ShopIdFieldNumber".into(), 7),
                ("AvatarIdFieldNumber".into(), 7),
            ],
        );
        assert!(output.names.is_empty());
        assert_eq!(output.conflicts, 1);
        message.fields[0].name = "Existing".into();
        output.add_constants(&message, vec![("ShopIdFieldNumber".into(), 7)]);
        assert!(output.names.is_empty());
        message.fields.push(Field {
            name: "BCDEFGHIJKL".into(),
            number: 7,
            offset: 40,
            kind: "uint32".into(),
        });
        output.add_constants(&message, vec![("ShopIdFieldNumber".into(), 7)]);
        assert!(output.names.is_empty());
        assert_eq!(output.unmatched_constants, 1);
    }
}
