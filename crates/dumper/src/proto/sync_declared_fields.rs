//! Own declared fields usable as direct native copy destinations.
//!
//! Every own instance field participates in overlap rejection, including
//! fields whose names or native widths are not suitable for recovery.

use std::ffi::CString;

use anyhow::{Context, Result, ensure};
use il2cpp::api;
use reflection::{attributes::FieldAttributes, field_info::FieldInfo, runtime_type::RuntimeType};

use super::{Accessor, CachedType, SyncFields, TypeCache, accessor_kind, checked_name, references};
use crate::script::memory;

const DECLARED_INSTANCE_FIELDS: i32 = 2 | 4 | 16 | 32;
const OBJECT_HEADER_BYTES: u32 = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FieldSpan {
    start: u32,
    end: u32,
}

impl FieldSpan {
    fn checked(start: usize, width: Option<usize>, instance_size: u32) -> Result<Self> {
        let start = u32::try_from(start).context("field offset exceeds u32")?;
        ensure!(
            start >= OBJECT_HEADER_BYTES && start < instance_size,
            "field offset outside object instance data"
        );
        let end = if let Some(width) = width {
            let width = u32::try_from(width).context("field width exceeds u32")?;
            ensure!(width != 0, "zero-sized field");
            start.checked_add(width).context("field span overflow")?
        } else {
            // Unknown value layout: conservatively block the rest of the
            // object instead of guessing a size from the next field offset.
            instance_size
        };
        ensure!(
            end <= instance_size,
            "field span exceeds object instance size"
        );
        Ok(Self { start, end })
    }

    fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

struct DeclaredField {
    span: FieldSpan,
    name: Option<String>,
    kind: Option<String>,
    ty: RuntimeType,
    bytes: Option<usize>,
}

fn recoverable_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim_start_matches('_');
    if !super::identifier(raw) || trimmed.is_empty() || super::is_obf(trimmed) {
        return None;
    }
    let name = super::snake_field(trimmed);
    super::identifier(&name).then_some(name)
}

fn unambiguous_members(fields: &[DeclaredField]) -> Vec<usize> {
    fields
        .iter()
        .enumerate()
        .filter_map(|(index, field)| {
            let eligible = field.name.is_some() && field.kind.is_some() && field.bytes.is_some();
            let overlaps = fields.iter().enumerate().any(|(other_index, other)| {
                index != other_index && field.span.overlaps(other.span)
            });
            (eligible && !overlaps).then_some(index)
        })
        .collect()
}

pub(super) fn collect(
    owner: RuntimeType,
    cache: &TypeCache,
    out: &mut SyncFields,
) -> Result<Vec<Accessor>> {
    let previous_context = std::mem::replace(
        &mut out.context,
        format!("declared fields owner=0x{:X}", owner.0),
    );
    let result = collect_inner(owner, cache, out)
        .with_context(|| format!("declared fields owner=0x{:X}", owner.0));
    out.context = previous_context;
    result
}

fn collect_inner(
    owner: RuntimeType,
    cache: &TypeCache,
    out: &mut SyncFields,
) -> Result<Vec<Accessor>> {
    ensure!(owner.0 != 0, "null owner RuntimeType");
    memory::readable(owner.0, 24)?;
    let owner_class = owner.get_il2cpp_type().get_class();
    ensure!(owner_class.0 != 0, "owner RuntimeType has null Il2CppClass");
    memory::readable(owner_class.0, 16)?;
    let instance_size = api::il2cpp_class_instance_size(owner_class);
    let instance_size = u32::try_from(instance_size).context("invalid class instance size")?;
    ensure!(
        instance_size > OBJECT_HEADER_BYTES,
        "owner has no instance data"
    );

    // The parent exposes the raw GetFields result so `references` can validate
    // its real managed allocation and length before materializing FieldInfo.
    let fields = references::<FieldInfo>(
        owner.get_fields_array(DECLARED_INSTANCE_FIELDS)?,
        "System.Reflection.FieldInfo",
        out,
    )?;
    let mut declared = Vec::with_capacity(fields.len());
    for field in fields {
        ensure!(field.0 != 0, "null FieldInfo in owner field array");
        memory::readable(field.0, 32)?;
        ensure!(
            field.get_declaringtype()? == owner,
            "enumerated field is not declared by owner"
        );

        let attributes = field.get_attributes()?;
        memory::readable(attributes.0, 20)?;
        let attributes = attributes.unbox();
        if attributes.intersects(FieldAttributes::Static | FieldAttributes::Literal) {
            // These do not occupy per-instance storage. GetFields was asked
            // for instance fields; ignore any unexpected static result.
            continue;
        }

        // FieldInfo's current MonoField wrapper stores Il2CppField at +0x18.
        // Establish the returned handle through owner-scoped lookup too; the
        // reflection declaring type alone is not used to bless an arbitrary
        // raw pointer.
        let raw = field.get_il2cpp_field();
        ensure!(raw.0 != 0, "FieldInfo has null native field handle");
        memory::readable(raw.0, 32)?;
        let raw_name = checked_name(field.get_name()?)?;
        let c_name = CString::new(raw_name.as_bytes()).context("field name contains NUL")?;
        ensure!(
            api::il2cpp_class_get_field_from_name(owner_class, c_name.as_ptr()).0 == raw.0,
            "native field handle does not resolve from declaring owner"
        );

        let reflected_type = field.get_field_type()?;
        ensure!(reflected_type.0 != 0, "field has null reflection type");
        memory::readable(reflected_type.0, 24)?;
        let reflected_type_handle = reflected_type.get_il2cpp_type();
        ensure!(
            reflected_type_handle.0 != 0,
            "field has null reflected Il2CppType"
        );
        memory::readable(reflected_type_handle.0, 16)?;
        let native_type = api::il2cpp_field_get_type(raw);
        ensure!(native_type.0 != 0, "native field has null Il2CppType");
        memory::readable(native_type.0, 16)?;
        ensure!(
            api::il2cpp_type_equals(native_type, reflected_type_handle),
            "native and reflection field types disagree"
        );

        let accessor = accessor_kind(reflected_type, cache)?;
        let (kind, bytes) = accessor
            .map(|(kind, bytes)| (Some(kind), Some(bytes)))
            .unwrap_or((None, None));
        // A non-recoverable primitive still has a known layout width. It must
        // block only its actual bytes, rather than all later instance fields.
        let layout_width = bytes.or_else(|| match cache.type_map.get(&reflected_type) {
            Some(CachedType::Byte | CachedType::SByte) => Some(1),
            Some(CachedType::UInt16 | CachedType::Int16) => Some(2),
            Some(CachedType::Single) => Some(4),
            Some(CachedType::Double) => Some(8),
            _ => None,
        });
        let span = FieldSpan::checked(field.get_offset(), layout_width, instance_size)?;
        let name = recoverable_name(&raw_name).filter(|_| kind.is_some());
        declared.push(DeclaredField {
            span,
            name,
            kind,
            ty: reflected_type,
            bytes,
        });
    }

    Ok(unambiguous_members(&declared)
        .into_iter()
        .map(|index| {
            let field = &declared[index];
            Accessor {
                name: field.name.clone().unwrap(),
                kind: field.kind.clone().unwrap(),
                ty: field.ty,
                bytes: field.bytes.unwrap(),
                offset: field.span.start,
                getter_rva: 0,
                setter_rva: 0,
                member_kind: "declared-field",
                name_proof: None,
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::{DeclaredField, FieldSpan, unambiguous_members};
    use reflection::runtime_type::RuntimeType;

    fn span(start: usize, width: Option<usize>) -> FieldSpan {
        FieldSpan::checked(start, width, 64).unwrap()
    }

    fn field(start: usize, width: Option<usize>, name: Option<&str>) -> DeclaredField {
        DeclaredField {
            span: span(start, width),
            name: name.map(str::to_owned),
            kind: name.map(|_| "uint32".to_owned()),
            ty: RuntimeType(1),
            bytes: width,
        }
    }

    #[test]
    fn adjacent_spans_are_distinct_but_partial_spans_conflict() {
        assert!(!span(16, Some(4)).overlaps(span(20, Some(8))));
        assert!(span(16, Some(8)).overlaps(span(20, Some(4))));
        assert!(span(24, Some(4)).overlaps(span(24, Some(4))));
    }

    #[test]
    fn unknown_width_blocks_every_later_field_without_inventing_a_size() {
        let unknown = span(24, None);
        assert_eq!(unknown.end, 64);
        assert!(unknown.overlaps(span(40, Some(4))));
        assert!(!unknown.overlaps(span(16, Some(4))));
    }

    #[test]
    fn only_named_members_without_any_declared_field_overlap_survive() {
        let fields = [
            field(16, Some(4), Some("visible")),
            field(20, None, None),
            field(32, Some(8), Some("hidden_by_unknown")),
            field(48, Some(4), Some("separate")),
        ];
        assert_eq!(unambiguous_members(&fields), [0]);
    }
}
