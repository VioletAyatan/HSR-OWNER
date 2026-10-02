//! Bounded ABI classification for managed parameters used by Sync scanning.
//!
//! Enum acceptance is based on live reflection and owner-scoped native field
//! metadata. It does not infer enum representation from a type name.

use std::ffi::CString;

use anyhow::{Context, Result, ensure};
use il2cpp::api;
use reflection::{attributes::FieldAttributes, r#enum::Enum, runtime_type::RuntimeType};
use serde::Serialize;

use super::{CachedType, TypeCache, checked_name, reflection_bool, scalar_parameter};
use crate::script::memory;

const INSTANCE_BINDING_FLAGS: i32 = 2 | 4 | 16 | 32;
const OBJECT_HEADER_BYTES: usize = 16;

#[derive(Clone, Serialize)]
pub(super) struct ParameterProof {
    pub index: usize,
    pub actual_type: String,
    pub abi: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enum_underlying_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enum_value_field_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enum_value_field_declaring_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enum_value_field_handle: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enum_value_field_offset: Option<usize>,
}

impl ParameterProof {
    pub(super) fn proto(index: usize, actual_type: String) -> Self {
        Self::plain(index, actual_type, "proto-reference")
    }

    pub(super) fn unsupported(index: usize, actual_type: String) -> Self {
        Self::plain(index, actual_type, "unsupported")
    }

    fn plain(index: usize, actual_type: String, abi: &'static str) -> Self {
        Self {
            index,
            actual_type,
            abi,
            enum_underlying_type: None,
            enum_value_field_name: None,
            enum_value_field_declaring_type: None,
            enum_value_field_handle: None,
            enum_value_field_offset: None,
        }
    }
}

/// Classify only exact cached primitives or closed enums whose actual
/// underlying type and own `value__` field are independently proven.
pub(super) fn classify(
    index: usize,
    ty: RuntimeType,
    cache: &TypeCache,
) -> Result<Option<ParameterProof>> {
    ensure!(ty.0 != 0, "null parameter RuntimeType");
    memory::readable(ty.0, 24)?;
    let actual_type = checked_name(ty.get_full_name()?)?;

    if scalar_parameter(cache.type_map.get(&ty)) {
        return Ok(Some(ParameterProof::plain(
            index,
            actual_type,
            "primitive-scalar",
        )));
    }

    if !enum_shape_is_supported(
        &actual_type,
        reflection_bool(ty.get_isenum()?)?,
        reflection_bool(ty.get_isvaluetype()?)?,
        reflection_bool(ty.get_isbyref()?)?,
        reflection_bool(ty.get_ispointer()?)?,
        reflection_bool(ty.get_is_generic_parameter()?)?,
        reflection_bool(ty.get_is_generic_type_definition()?)?,
        reflection_bool(ty.contains_generic_parameters()?)?,
        reflection_bool(ty.get_isgenerictype()?)?,
    ) {
        return Ok(None);
    }

    let underlying = Enum::get_underlying_type(ty).context("resolve enum underlying type")?;
    ensure!(underlying.0 != 0, "enum underlying RuntimeType is null");
    memory::readable(underlying.0, 24)?;
    let underlying_name = checked_name(underlying.get_full_name()?)?;
    let Some((underlying_abi, width)) = integer_underlying(cache.type_map.get(&underlying)) else {
        return Ok(None);
    };

    let value_field = ty.get_field("value__".into(), INSTANCE_BINDING_FLAGS)?;
    ensure!(value_field.0 != 0, "enum value__ FieldInfo is null");
    memory::readable(value_field.0, 32)?;
    ensure!(
        value_field.get_declaringtype()? == ty,
        "enum value__ field is not declared by the enum"
    );
    let value_field_name = checked_name(value_field.get_name()?)?;
    ensure!(
        value_field_name == "value__",
        "unexpected enum value field name"
    );

    let attributes = value_field.get_attributes()?;
    ensure!(attributes.0 != 0, "enum value__ attributes are null");
    memory::readable(attributes.0, 20)?;
    ensure!(
        !attributes
            .unbox()
            .intersects(FieldAttributes::Static | FieldAttributes::Literal),
        "enum value__ field is static or literal"
    );

    let reflected_field_type = value_field.get_field_type()?;
    ensure!(
        reflected_field_type.0 != 0,
        "enum value__ reflection field type is null"
    );
    memory::readable(reflected_field_type.0, 24)?;
    ensure!(
        reflected_field_type == underlying,
        "enum underlying type disagrees with value__ reflection field type"
    );

    let owner_class = ty.get_il2cpp_type().get_class();
    ensure!(owner_class.0 != 0, "enum RuntimeType has null Il2CppClass");
    memory::readable(owner_class.0, 16)?;
    let raw_field = value_field.get_il2cpp_field();
    ensure!(raw_field.0 != 0, "enum value__ native field handle is null");
    memory::readable(raw_field.0, 32)?;
    let c_name = CString::new(value_field_name.as_bytes())
        .context("enum value__ field name contains NUL")?;
    ensure!(
        api::il2cpp_class_get_field_from_name(owner_class, c_name.as_ptr()).0 == raw_field.0,
        "enum value__ native field does not resolve from declaring class"
    );

    let reflected_type_handle = reflected_field_type.get_il2cpp_type();
    ensure!(
        reflected_type_handle.0 != 0,
        "enum value__ reflected Il2CppType is null"
    );
    memory::readable(reflected_type_handle.0, 16)?;
    let native_type_handle = api::il2cpp_field_get_type(raw_field);
    ensure!(
        native_type_handle.0 != 0,
        "enum value__ native Il2CppType is null"
    );
    memory::readable(native_type_handle.0, 16)?;
    ensure!(
        api::il2cpp_type_equals(native_type_handle, reflected_type_handle),
        "enum value__ native and reflection field types disagree"
    );

    let offset = value_field.get_offset();
    let offset_end = offset
        .checked_add(width)
        .context("enum value__ field span overflow")?;
    let instance_size = api::il2cpp_class_instance_size(owner_class);
    let instance_size = usize::try_from(instance_size).context("invalid enum instance size")?;
    ensure!(
        offset >= OBJECT_HEADER_BYTES && offset_end <= instance_size,
        "enum value__ field lies outside enum instance data"
    );

    Ok(Some(ParameterProof {
        index,
        actual_type: actual_type.clone(),
        abi: underlying_abi,
        enum_underlying_type: Some(underlying_name),
        enum_value_field_name: Some(value_field_name),
        enum_value_field_declaring_type: Some(actual_type.clone()),
        enum_value_field_handle: Some(raw_field.0),
        enum_value_field_offset: Some(offset),
    }))
}

fn enum_shape_is_supported(
    actual_type: &str,
    is_enum: bool,
    is_value_type: bool,
    is_byref: bool,
    is_pointer: bool,
    is_generic_parameter: bool,
    is_generic_type_definition: bool,
    contains_generic_parameters: bool,
    is_generic_type: bool,
) -> bool {
    actual_type != "System.Enum"
        && is_enum
        && is_value_type
        && !is_byref
        && !is_pointer
        && !is_generic_parameter
        && !is_generic_type_definition
        && !contains_generic_parameters
        && !is_generic_type
}

fn integer_underlying(cached: Option<&CachedType>) -> Option<(&'static str, usize)> {
    match cached {
        Some(CachedType::Byte) => Some(("enum-u8", 1)),
        Some(CachedType::SByte) => Some(("enum-i8", 1)),
        Some(CachedType::UInt16) => Some(("enum-u16", 2)),
        Some(CachedType::Int16) => Some(("enum-i16", 2)),
        Some(CachedType::UInt32) => Some(("enum-u32", 4)),
        Some(CachedType::Int32) => Some(("enum-i32", 4)),
        Some(CachedType::UInt64) => Some(("enum-u64", 8)),
        Some(CachedType::Int64) => Some(("enum-i64", 8)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{ParameterProof, enum_shape_is_supported, integer_underlying};
    use crate::proto::cache::CachedType;

    #[test]
    fn accepts_only_exact_cached_signed_and_unsigned_integer_types() {
        for cached in [
            CachedType::Byte,
            CachedType::SByte,
            CachedType::UInt16,
            CachedType::Int16,
            CachedType::UInt32,
            CachedType::Int32,
            CachedType::UInt64,
            CachedType::Int64,
        ] {
            assert!(integer_underlying(Some(&cached)).is_some());
        }
    }

    #[test]
    fn rejects_bool_float_object_enum_and_uncached_underlying_types() {
        for cached in [
            CachedType::Boolean,
            CachedType::Single,
            CachedType::Double,
            CachedType::Object,
            CachedType::Enum,
        ] {
            assert!(integer_underlying(Some(&cached)).is_none());
        }
        assert!(integer_underlying(None).is_none());
    }

    #[test]
    fn rejects_enum_base_and_non_value_byref_pointer_or_open_generic_shapes() {
        let valid = || {
            enum_shape_is_supported(
                "Game.Mode",
                true,
                true,
                false,
                false,
                false,
                false,
                false,
                false,
            )
        };
        assert!(valid());
        assert!(!enum_shape_is_supported(
            "System.Enum",
            true,
            true,
            false,
            false,
            false,
            false,
            false,
            false
        ));
        assert!(!enum_shape_is_supported(
            "Game.NotEnum",
            false,
            true,
            false,
            false,
            false,
            false,
            false,
            false
        ));
        assert!(!enum_shape_is_supported(
            "Game.Class",
            true,
            false,
            false,
            false,
            false,
            false,
            false,
            false
        ));
        assert!(!enum_shape_is_supported(
            "Game.Mode&",
            true,
            true,
            true,
            false,
            false,
            false,
            false,
            false
        ));
        assert!(!enum_shape_is_supported(
            "Game.Mode*",
            true,
            true,
            false,
            true,
            false,
            false,
            false,
            false
        ));
        assert!(!enum_shape_is_supported(
            "Game.Open`1",
            true,
            true,
            false,
            false,
            false,
            true,
            true,
            true
        ));
        assert!(!enum_shape_is_supported(
            "Game.GenericParam",
            true,
            true,
            false,
            false,
            true,
            false,
            true,
            true
        ));
    }

    #[test]
    fn proto_and_unsupported_proofs_keep_enum_binding_optional() {
        let proto = serde_json::to_value(ParameterProof::proto(1, "Proto.Message".into())).unwrap();
        assert_eq!(proto["abi"], "proto-reference");
        assert!(proto.get("enum_underlying_type").is_none());
        assert!(proto.get("enum_value_field_handle").is_none());

        let unsupported = serde_json::to_value(ParameterProof::unsupported(2, "T".into())).unwrap();
        assert_eq!(unsupported["abi"], "unsupported");
        assert_eq!(unsupported["index"], 2);
        assert_eq!(unsupported["actual_type"], "T");
    }
}
