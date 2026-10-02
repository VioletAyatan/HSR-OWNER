//! Recover a property name from the property metadata or its accessor names.
//!
//! This module establishes name provenance only. It does not bind the property
//! to an owner, type, native offset, or control-flow copy; callers must verify
//! those relationships independently before using a recovered name.

use serde::{Deserialize, Serialize};

use super::super::{names::identifier, util::is_obf};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "kebab-case")]
pub(super) enum PropertyNameProof {
    PropertyMetadata {
        metadata_name: String,
    },
    AccessorMethods {
        metadata_name: Option<String>,
        getter_name: Option<String>,
        setter_name: Option<String>,
    },
}

pub(super) fn recover(
    metadata_name: Option<&str>,
    getter_name: Option<&str>,
    setter_name: Option<&str>,
) -> Option<(String, PropertyNameProof)> {
    let metadata_name = metadata_name?;

    if !is_obf(metadata_name) {
        return identifier(metadata_name).then(|| {
            (
                metadata_name.to_owned(),
                PropertyNameProof::PropertyMetadata {
                    metadata_name: metadata_name.to_owned(),
                },
            )
        });
    }

    let (Some(getter_name), Some(setter_name)) = (getter_name, setter_name) else {
        return None;
    };
    let name = getter_name.strip_prefix("get_")?;
    if !identifier(name)
        || is_obf(name)
        || getter_name != format!("get_{name}")
        || setter_name != format!("set_{name}")
    {
        return None;
    }

    Some((
        name.to_owned(),
        PropertyNameProof::AccessorMethods {
            metadata_name: Some(metadata_name.to_owned()),
            getter_name: Some(getter_name.to_owned()),
            setter_name: Some(setter_name.to_owned()),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::{PropertyNameProof, recover};

    #[test]
    fn preserves_plain_identifier_property_metadata() {
        let result = recover(
            Some("CurrentPeakGroupID"),
            Some("get_wrong"),
            Some("set_wrong"),
        );
        assert_eq!(
            result,
            Some((
                "CurrentPeakGroupID".to_owned(),
                PropertyNameProof::PropertyMetadata {
                    metadata_name: "CurrentPeakGroupID".to_owned(),
                },
            ))
        );
    }

    #[test]
    fn accepts_matching_plain_names_from_both_accessors_for_obfuscated_metadata() {
        let result = recover(Some("ABCDQWERTYZ"), Some("get_CakeID"), Some("set_CakeID"));
        assert_eq!(
            result,
            Some((
                "CakeID".to_owned(),
                PropertyNameProof::AccessorMethods {
                    metadata_name: Some("ABCDQWERTYZ".to_owned()),
                    getter_name: Some("get_CakeID".to_owned()),
                    setter_name: Some("set_CakeID".to_owned()),
                },
            ))
        );
    }

    #[test]
    fn rejects_wrong_or_inconsistent_accessor_names() {
        assert!(recover(Some("ABCDQWERTYZ"), Some("get_CakeID"), Some("set_CakeUid")).is_none());
        assert!(recover(Some("ABCDQWERTYZ"), Some("Get_CakeID"), Some("set_CakeID")).is_none());
        assert!(recover(Some("ABCDQWERTYZ"), Some("get_CakeID"), None).is_none());
        assert!(
            recover(
                Some("ABCDQWERTYZ"),
                Some("get_ABCDQWERTYZ"),
                Some("set_ABCDQWERTYZ")
            )
            .is_none()
        );
    }

    #[test]
    fn rejects_invalid_or_missing_metadata_without_fallback() {
        assert!(recover(Some("not a name"), Some("get_CakeID"), Some("set_CakeID")).is_none());
        assert!(recover(None, Some("get_CakeID"), Some("set_CakeID")).is_none());
        assert!(recover(Some("ABCDQWERTYZ"), Some("get_1Cake"), Some("set_1Cake")).is_none());
    }

    #[test]
    fn serializes_proof_source_as_tagged_provenance() {
        let proof = PropertyNameProof::AccessorMethods {
            metadata_name: Some("ABCDQWERTYZ".to_owned()),
            getter_name: Some("get_CakeID".to_owned()),
            setter_name: Some("set_CakeID".to_owned()),
        };
        let value = serde_json::to_value(proof).unwrap();
        assert_eq!(value["source"], "accessor-methods");
        assert_eq!(value["metadata_name"], "ABCDQWERTYZ");
        assert_eq!(value["getter_name"], "get_CakeID");
        assert_eq!(value["setter_name"], "set_CakeID");
    }
}
