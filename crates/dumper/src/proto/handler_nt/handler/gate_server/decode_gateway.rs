use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::RwLock;

use super::{decoder, dispatch};
use crate::version::GAME_VERSION;

static PROTO_FIELDS: RwLock<Option<HashMap<u32, String>>> = RwLock::new(None);

pub fn set_proto_fields(fields: HashMap<u32, String>) {
    let mut cache = PROTO_FIELDS
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *cache = Some(fields);
}

pub fn run() -> HashMap<String, String> {
    let proto_fields = PROTO_FIELDS
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
        .unwrap_or_default();
    if proto_fields.is_empty() {
        log::warn!(
            "[Gateway] content inference skipped: current GateServer field metadata is unavailable"
        );
        return HashMap::new();
    }

    let version = &*GAME_VERSION;
    let seed = &*dispatch::DISPATCH_SEED;

    let Some(dispatch_url) = dispatch::get_dispatch_url() else {
        log::warn!("[Gateway] content inference skipped: dispatch URL lookup returned no URL");
        return HashMap::new();
    };
    let full_dispatch_url = format!(
        "{dispatch_url}?version={version}&language_type=3&platform_type=3&channel_id=1&sub_channel_id=1&is_new_format=1"
    );
    log::debug!("[Gateway] dispatch_url = {full_dispatch_url}");

    let Some(gateway_url) = dispatch::fetch_gateway_url(&dispatch_url, version) else {
        log::warn!(
            "[Gateway] content inference skipped: dispatch fetch/decoding returned no gateway URL"
        );
        return HashMap::new();
    };

    let full_gateway_url = format!(
        "{gateway_url}?version={version}&platform_type=1&language_type=3&dispatch_seed={seed}&channel_id=1&sub_channel_id=1&is_need_url=1"
    );
    log::debug!("[Gateway] gateway_url = {full_gateway_url}");

    let Some(result) = dispatch::fetch_gateway_response(&gateway_url, version, seed) else {
        log::warn!(
            "[Gateway] content inference skipped: gateway fetch/decoding returned no response"
        );
        return HashMap::new();
    };

    let mut candidates = Vec::new();

    for f in &result.fields {
        match &f.value {
            decoder::DecodedValue::Buffer(bytes) => {
                let Ok(s) = std::str::from_utf8(bytes) else {
                    continue;
                };
                let deobf_name = if is_ip(s) {
                    "GateServerAddress"
                } else if is_ec2b(s) {
                    "client_secret_key"
                } else if s.contains("/asb/") {
                    "asset_bundle_url"
                } else if s.contains("/design_data/") {
                    "ex_resource_url"
                } else if s.contains("/lua/") {
                    "lua_url"
                } else if s.contains("/ifix/") {
                    "ifix_url"
                } else {
                    continue;
                };

                candidates.push((f.field, deobf_name));
            }
            decoder::DecodedValue::BigInt(num) => {
                if *num < 23301 || *num > 23302 {
                    continue;
                }
                candidates.push((f.field, "port"));
            }
            _ => {}
        }
    }

    let resolution = resolve_candidates(&proto_fields, candidates);
    for (name, tags) in resolution.ambiguous_names.iter().take(8) {
        log::warn!(
            "[Gateway] content candidate {name} matches {} distinct tags (sample: {:?}); keeping original field names",
            tags.len(),
            tags.iter().take(8).collect::<Vec<_>>()
        );
    }
    for (tag, names) in resolution.conflicting_tags.iter().take(8) {
        log::warn!(
            "[Gateway] tag {tag} has conflicting content candidates {names:?}; keeping its original field name"
        );
    }
    log::info!(
        "[Gateway] content inference complete: candidate_tags={}, restored={}, ambiguous_names={}, conflicting_tags={}, unmapped_tags={}",
        resolution.candidate_tags,
        resolution.names.len(),
        resolution.ambiguous_names.len(),
        resolution.conflicting_tags.len(),
        resolution.unmapped_tags
    );

    resolution.names
}

#[derive(Debug, Default)]
struct CandidateResolution {
    names: HashMap<String, String>,
    candidate_tags: usize,
    ambiguous_names: BTreeMap<&'static str, BTreeSet<u32>>,
    conflicting_tags: BTreeMap<u32, BTreeSet<&'static str>>,
    unmapped_tags: usize,
}

fn resolve_candidates(
    proto_fields: &HashMap<u32, String>,
    candidates: impl IntoIterator<Item = (u32, &'static str)>,
) -> CandidateResolution {
    let mut names_by_tag: BTreeMap<u32, BTreeSet<&'static str>> = BTreeMap::new();
    let mut tags_by_name: BTreeMap<&'static str, BTreeSet<u32>> = BTreeMap::new();
    for (tag, name) in candidates {
        names_by_tag.entry(tag).or_default().insert(name);
        tags_by_name.entry(name).or_default().insert(tag);
    }

    let mut result = CandidateResolution {
        candidate_tags: names_by_tag.len(),
        unmapped_tags: names_by_tag
            .keys()
            .filter(|tag| !proto_fields.contains_key(*tag))
            .count(),
        ..CandidateResolution::default()
    };
    for (&tag, names) in &names_by_tag {
        if names.len() > 1 {
            result.conflicting_tags.insert(tag, names.clone());
        }
    }
    for (name, tags) in tags_by_name {
        if tags.len() != 1 {
            result.ambiguous_names.insert(name, tags);
            continue;
        }
        let Some(&tag) = tags.first() else {
            continue;
        };
        // Content classifies values, but does not distinguish two fields with the
        // same kind of URL. Repeated occurrences of one tag are one candidate.
        if names_by_tag[&tag].len() == 1
            && let Some(obf_name) = proto_fields.get(&tag)
        {
            result.names.insert(obf_name.clone(), name.to_string());
        }
    }
    result
}

fn is_ip(s: &str) -> bool {
    s.parse::<std::net::Ipv4Addr>().is_ok()
}

fn is_ec2b(s: &str) -> bool {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .is_ok_and(|v| v.starts_with(b"Ec2b"))
}

#[cfg(test)]
mod tests {
    use super::resolve_candidates;
    use std::collections::HashMap;

    fn proto_fields() -> HashMap<u32, String> {
        [(1, "OBF_A"), (2, "OBF_B")]
            .into_iter()
            .map(|(tag, name)| (tag, name.to_string()))
            .collect()
    }

    #[test]
    fn repeated_values_of_one_tag_restore_one_name() {
        let result = resolve_candidates(
            &proto_fields(),
            [(1, "asset_bundle_url"), (1, "asset_bundle_url")],
        );
        assert_eq!(result.names.get("OBF_A").unwrap(), "asset_bundle_url");
        assert_eq!(result.candidate_tags, 1);
        assert!(result.ambiguous_names.is_empty());
    }

    #[test]
    fn two_tags_with_one_content_class_keep_original_names() {
        let result = resolve_candidates(
            &proto_fields(),
            [(1, "asset_bundle_url"), (2, "asset_bundle_url")],
        );
        assert!(result.names.is_empty());
        assert_eq!(result.ambiguous_names["asset_bundle_url"].len(), 2);
    }

    #[test]
    fn conflicting_values_of_one_tag_do_not_restore_either_name() {
        let result = resolve_candidates(&proto_fields(), [(1, "lua_url"), (1, "ifix_url")]);
        assert!(result.names.is_empty());
        assert_eq!(result.conflicting_tags[&1].len(), 2);
    }

    #[test]
    fn unknown_tag_still_prevents_false_unique_match() {
        let result = resolve_candidates(
            &proto_fields(),
            [(1, "asset_bundle_url"), (99, "asset_bundle_url")],
        );
        assert!(result.names.is_empty());
        assert_eq!(result.unmapped_tags, 1);
        assert_eq!(result.ambiguous_names["asset_bundle_url"].len(), 2);
    }

    #[test]
    fn independent_content_classes_can_both_restore_names() {
        let result = resolve_candidates(&proto_fields(), [(1, "lua_url"), (2, "ifix_url")]);
        assert_eq!(result.names.get("OBF_A").unwrap(), "lua_url");
        assert_eq!(result.names.get("OBF_B").unwrap(), "ifix_url");
    }
}
