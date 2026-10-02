//! Parameter-name provenance and diagnostics, without native or type inference.
//!
//! A valid name is only a candidate business alias. Callers must independently
//! bind the actual callee, ParameterInfo ordinal/type, return ABI, own property,
//! and complete native argument flow before applying any field-name policy.

use serde::{Deserialize, Serialize};

use super::{names::identifier, output::snake_field, util::is_obf};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "kebab-case")]
pub(super) enum CallParameterNameProof {
    CallParameter {
        parameter_name: String,
        parameter_index: usize,
        callee_signature: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum NameRejection {
    InvalidParameterIdentifier,
    ObfuscatedParameterName,
    InvalidRecoveredIdentifier,
}

/// These strings come from actual metadata, not decompiler local variables.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct CandidateInput {
    pub original_proto_type: String,
    pub original_proto_field: String,
    pub proto_kind: String,
    pub native_bytes: usize,
    pub callee_signature: String,
    pub parameter_name: String,
    /// Zero-based managed ParameterInfo ordinal; excludes an instance receiver.
    pub parameter_index: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub(super) enum ArgumentLocation {
    Register {
        name: String,
    },
    /// Offset from callee entry RSP, before its native prologue changes RSP.
    Stack {
        offset_from_entry_rsp: u32,
    },
}

/// Evidence already checked by the caller. This helper does not validate it.
/// All native addresses below are RVAs, not runtime VAs or file offsets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct TypeBoundEvidence {
    pub caller_signature: String,
    pub caller_rva: usize,
    pub callee_rva: usize,
    pub call_rva: usize,
    pub load_sites: Vec<usize>,
    pub proto_offset: u32,
    pub actual_parameter_type: String,
    pub actual_return_type: String,
    pub return_abi: String,
    /// Zero-based native argument ordinal, with any receiver/ABI shift included.
    /// It is deliberately separate from CandidateInput.parameter_index.
    pub abi_argument_index: usize,
    pub abi_location: ArgumentLocation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum NameStatus {
    Candidate,
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct CallArgumentNameReport {
    pub input: CandidateInput,
    pub name_status: NameStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovered: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_proof: Option<CallParameterNameProof>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejection: Option<NameRejection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_binding: Option<TypeBoundEvidence>,
}

fn normalized_name(name: &str) -> Result<String, NameRejection> {
    if !identifier(name) {
        return Err(NameRejection::InvalidParameterIdentifier);
    }
    if is_obf(name) {
        return Err(NameRejection::ObfuscatedParameterName);
    }
    let recovered = snake_field(name);
    if !identifier(&recovered) {
        return Err(NameRejection::InvalidRecoveredIdentifier);
    }
    Ok(recovered)
}

pub(super) fn recover(
    parameter_name: &str,
    callee_signature: &str,
    parameter_index: usize,
) -> Result<(String, CallParameterNameProof), NameRejection> {
    let recovered = normalized_name(parameter_name)?;
    Ok((
        recovered,
        CallParameterNameProof::CallParameter {
            parameter_name: parameter_name.to_owned(),
            parameter_index,
            callee_signature: callee_signature.to_owned(),
        },
    ))
}

/// Name agreement only; it does not establish same owner, type, or property.
#[cfg(test)]
pub(super) fn names_agree(first: &str, second: &str) -> bool {
    match (normalized_name(first), normalized_name(second)) {
        (Ok(first), Ok(second)) => first == second,
        _ => false,
    }
}

impl CallArgumentNameReport {
    /// This never reports an accepted native copy or applies a Proto rename.
    pub(super) fn new(input: CandidateInput, native_binding: Option<TypeBoundEvidence>) -> Self {
        let result = recover(
            &input.parameter_name,
            &input.callee_signature,
            input.parameter_index,
        );
        let (name_status, recovered, name_proof, rejection) = match result {
            Ok((name, proof)) => (NameStatus::Candidate, Some(name), Some(proof), None),
            Err(reason) => (NameStatus::Rejected, None, None, Some(reason)),
        };
        Self {
            input,
            name_status,
            recovered,
            name_proof,
            rejection,
            native_binding,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_whitespace_and_invalid_parameter_identifiers() {
        for name in [
            "",
            " ",
            " totalScore",
            "totalScore ",
            "1Score",
            "x.y",
            "名字",
        ] {
            assert_eq!(
                recover(name, "Owner::Read(System.UInt32)", 0),
                Err(NameRejection::InvalidParameterIdentifier)
            );
        }
    }

    #[test]
    fn rejects_obfuscated_parameter_names() {
        assert_eq!(
            recover("ABCDQWERTYZ", "Owner::Read(System.UInt32)", 0),
            Err(NameRejection::ObfuscatedParameterName)
        );
    }

    #[test]
    fn normalizes_id_and_preserves_actual_name_ordinal_and_callee() {
        let (name, proof) = recover("currentAvatarID", "Owner::Read(System.UInt32)", 2).unwrap();
        assert_eq!(name, "current_avatar_id");
        assert_eq!(
            proof,
            CallParameterNameProof::CallParameter {
                parameter_name: "currentAvatarID".to_owned(),
                parameter_index: 2,
                callee_signature: "Owner::Read(System.UInt32)".to_owned(),
            }
        );
    }

    #[test]
    fn rejects_inconsistent_or_unreadable_name_agreement() {
        assert!(names_agree("totalScore", "TotalScore"));
        assert!(names_agree("currentAvatarID", "current_avatar_id"));
        assert!(!names_agree("score", "totalScore"));
        assert!(!names_agree("ABCDQWERTYZ", "ABCDQWERTYZ"));
        assert!(!names_agree("", ""));
    }

    #[test]
    fn does_not_invent_generic_parameter_name_exclusions() {
        for name in ["this", "instance", "value"] {
            assert_eq!(
                recover(name, "Owner::Read(System.UInt32)", 0).unwrap().0,
                name
            );
        }
    }

    #[test]
    fn serializes_candidate_proof_and_separate_native_argument_binding() {
        let input = CandidateInput {
            original_proto_type: "ABCDQWERTYZ".to_owned(),
            original_proto_field: "QWERTYABCDE".to_owned(),
            proto_kind: "uint32".to_owned(),
            native_bytes: 4,
            callee_signature: "Owner::Read(System.UInt32)".to_owned(),
            parameter_name: "avatarID".to_owned(),
            parameter_index: 0,
        };
        let binding = TypeBoundEvidence {
            caller_signature: "Owner::Copy(ABCDQWERTYZ)".to_owned(),
            caller_rva: 0x1000,
            callee_rva: 0x2000,
            call_rva: 0x1010,
            load_sites: vec![0x1004],
            proto_offset: 24,
            actual_parameter_type: "System.UInt32".to_owned(),
            actual_return_type: "Owner".to_owned(),
            return_abi: "reference".to_owned(),
            abi_argument_index: 1,
            abi_location: ArgumentLocation::Register {
                name: "RDX".to_owned(),
            },
        };
        let report = CallArgumentNameReport::new(input, Some(binding));
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["name_status"], "candidate");
        assert_eq!(value["recovered"], "avatar_id");
        assert_eq!(value["name_proof"]["source"], "call-parameter");
        assert_eq!(value["name_proof"]["parameter_name"], "avatarID");
        assert_eq!(value["name_proof"]["parameter_index"], 0);
        assert_eq!(value["native_binding"]["abi_argument_index"], 1);
        assert_eq!(value["native_binding"]["abi_location"]["name"], "RDX");
        assert_eq!(
            serde_json::from_value::<CallArgumentNameReport>(value).unwrap(),
            report
        );
    }

    #[test]
    fn serializes_rejected_metadata_without_claiming_recovery() {
        let input = CandidateInput {
            original_proto_type: "ABCDQWERTYZ".to_owned(),
            original_proto_field: "QWERTYABCDE".to_owned(),
            proto_kind: "uint32".to_owned(),
            native_bytes: 4,
            callee_signature: "Owner::Read(System.UInt32)".to_owned(),
            parameter_name: "ABCDQWERTYZ".to_owned(),
            parameter_index: 0,
        };
        let value = serde_json::to_value(CallArgumentNameReport::new(input, None)).unwrap();
        assert_eq!(value["name_status"], "rejected");
        assert_eq!(value["rejection"], "obfuscated-parameter-name");
        assert_eq!(value["input"]["parameter_name"], "ABCDQWERTYZ");
        assert!(value.get("recovered").is_none());
        assert!(value.get("name_proof").is_none());
        assert!(value.get("native_binding").is_none());
    }
}
