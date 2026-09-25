use anyhow::{Result, bail, ensure};
use il2cpp::{api, vm::object::Il2CppObject};

/// Inspect metadata and the stored message only: never call Exception getters,
/// ToString or the existing Debug implementation while handling another failure.
pub(super) fn invoke_error(error: il2cpp::vm::exception::Il2CppException) -> anyhow::Error {
    describe(error.0, || {
        let object = Il2CppObject(error.0);
        let class = object.get_class();
        ensure!(class.0 != 0, "null exception class");
        let name = class_name(class)?;
        // Keep the type even if this runtime has a different message layout.
        let message = guarded(|| stored_message(object))
            .unwrap_or_else(|reason| format!("<message unavailable: {reason:#}>"));
        Ok(format!("type={name} message={message:?}"))
    })
}

fn describe(address: usize, inspect: impl FnMut() -> Result<String>) -> anyhow::Error {
    let detail = if address == 0 {
        "details unavailable: null exception".to_string()
    } else {
        guarded(inspect).unwrap_or_else(|error| format!("details unavailable: {error:#}"))
    };
    anyhow::anyhow!("IL2CPP invocation raised exception at 0x{address:X}: {detail}")
}

fn guarded<T>(mut inspect: impl FnMut() -> Result<T>) -> Result<T> {
    // The Rust panic boundary must be INSIDE the SEH callback's foreign ABI.
    microseh::try_seh(|| std::panic::catch_unwind(std::panic::AssertUnwindSafe(&mut inspect)))
        .map_err(|error| anyhow::anyhow!("native fault reading exception: {error:?}"))?
        .map_err(|_| anyhow::anyhow!("panic reading exception"))?
}

fn class_name(class: api::Il2CppClass) -> Result<String> {
    let namespace = metadata_string(api::il2cpp_class_get_namespace(class))?;
    let name = metadata_string(api::il2cpp_class_get_name(class))?;
    Ok(if namespace.is_empty() {
        name
    } else {
        format!("{namespace}.{name}")
    })
}

fn metadata_string(pointer: *const i8) -> Result<String> {
    ensure!(!pointer.is_null(), "null metadata string");
    let mut bytes = Vec::new();
    for index in 0..512 {
        // Called only within guarded(); also bound reads and allocations.
        let byte = unsafe { pointer.add(index).read() as u8 };
        if byte == 0 {
            return Ok(String::from_utf8_lossy(&bytes).into_owned());
        }
        bytes.push(byte);
    }
    bail!("metadata string exceeds diagnostic limit")
}

fn stored_message(object: Il2CppObject) -> Result<String> {
    let mut class = object.get_class();
    for _ in 0..32 {
        ensure!(class.0 != 0, "System.Exception base not found");
        if class_name(class)? == "System.Exception" {
            for name in [c"_message", c"message"] {
                let field = api::il2cpp_class_get_field_from_name(class, name.as_ptr());
                if field.0 == 0 {
                    continue;
                }
                let message = api::il2cpp_field_get_value_object(field, object);
                if message.0 == 0 {
                    return Ok("<null stored message>".into());
                }
                ensure!(
                    class_name(message.get_class())? == "System.String",
                    "message field is not a string"
                );
                // Existing runtime string layout; bounded, lossy decoding avoids
                // panicking on malformed UTF-16 while reporting the original error.
                let length = unsafe { ((message.0 + 16) as *const i32).read() };
                ensure!(length >= 0, "invalid message length");
                let mut units = Vec::new();
                for index in 0..(length as usize).min(2048) {
                    units.push(unsafe { ((message.0 + 20) as *const u16).add(index).read() });
                }
                let mut text = String::from_utf16_lossy(&units);
                if length > 2048 {
                    text.push_str("…[truncated]");
                }
                return Ok(text);
            }
            bail!("stored message field not found");
        }
        class = api::il2cpp_class_get_parent(class);
    }
    bail!("exception base traversal limit reached")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exception_details_preserve_original_address_on_success_and_failure() {
        let detail = describe(0x1234, || {
            Ok("type=System.InvalidOperationException message=changed".into())
        })
        .to_string();
        assert!(detail.contains("0x1234"));
        assert!(detail.contains("System.InvalidOperationException"));
        let error = describe(0x1234, || bail!("layout unavailable")).to_string();
        assert!(error.contains("0x1234"));
        assert!(error.contains("layout unavailable"));
        let panic = describe(0x1234, || panic!("diagnostic panic")).to_string();
        assert!(panic.contains("0x1234"));
        assert!(panic.contains("panic reading exception"));
        assert!(
            describe(0, || panic!("must not inspect null"))
                .to_string()
                .contains("null exception")
        );
    }
}
