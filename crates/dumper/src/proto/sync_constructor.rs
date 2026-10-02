//! Bind eligible instance constructors through native IL2CPP method metadata.
//!
//! `System.Reflection.ConstructorInfo` uses `MonoCMethod`, so this deliberately
//! avoids converting an `Il2CppMethod` into `MethodInfo`.

use std::slice;

use anyhow::{Context, Result, ensure};
use il2cpp::{api, vm::method::Il2CppMethod};
use reflection::runtime_type::RuntimeType;

use super::{checked_name, managed_reference, reflection_bool};
use crate::script::memory;

pub(super) struct Constructor {
    pub owner: RuntimeType,
    pub proto: RuntimeType,
    pub return_type: RuntimeType,
}

pub(super) fn bind(handle: Il2CppMethod) -> Result<Option<Constructor>> {
    bind_inner(handle).with_context(|| format!("constructor handle=0x{:X}", handle.0))
}

fn bind_inner(handle: Il2CppMethod) -> Result<Option<Constructor>> {
    ensure!(handle.0 != 0, "null Il2CppMethod");
    memory::readable(handle.0, 16)?;

    let name = api::il2cpp_method_get_name(handle);
    ensure!(!name.is_null(), "constructor name pointer is null");
    memory::readable(name as usize, 6)?;
    // Exact bounded comparison; do not walk an arbitrary native C string.
    let name_bytes = unsafe { slice::from_raw_parts(name.cast::<u8>(), 6) };
    if name_bytes != b".ctor\0" {
        return Ok(None);
    }
    if !api::il2cpp_method_is_instance(handle) || api::il2cpp_method_get_param_count(handle) != 1 {
        return Ok(None);
    }

    let owner_class = api::il2cpp_method_get_class(handle);
    ensure!(owner_class.0 != 0, "constructor owner class is null");
    memory::readable(owner_class.0, 16)?;
    let owner = RuntimeType::from_class(owner_class).context("resolve constructor owner type")?;
    ensure!(owner.0 != 0, "constructor owner RuntimeType is null");
    memory::readable(owner.0, 24)?;
    if !managed_reference(owner)? || reflection_bool(owner.get_isgenerictype()?)? {
        return Ok(None);
    }

    let parameter_type = api::il2cpp_method_get_param(handle, 0);
    ensure!(
        parameter_type.0 != 0,
        "constructor parameter Il2CppType is null"
    );
    memory::readable(parameter_type.0, 16)?;
    let proto = RuntimeType::from_il2cpp_type(parameter_type)
        .context("resolve constructor parameter RuntimeType")?;
    ensure!(proto.0 != 0, "constructor parameter RuntimeType is null");
    memory::readable(proto.0, 24)?;

    let native_return_type = api::il2cpp_method_get_return_type(handle);
    ensure!(
        native_return_type.0 != 0,
        "constructor return Il2CppType is null"
    );
    memory::readable(native_return_type.0, 16)?;
    let return_type = RuntimeType::from_il2cpp_type(native_return_type)
        .context("resolve constructor return RuntimeType")?;
    ensure!(return_type.0 != 0, "constructor return RuntimeType is null");
    memory::readable(return_type.0, 24)?;
    if checked_name(return_type.get_full_name()?)? != "System.Void" {
        return Ok(None);
    }

    Ok(Some(Constructor {
        owner,
        proto,
        return_type,
    }))
}
