use crate::{api, vm::value::Il2CppValue};

#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct Il2CppField(pub usize);

#[allow(unused)]
impl Il2CppField {
    #[inline]
    pub fn offset(&self) -> usize {
        api::il2cpp_field_get_offset(*self)
    }
}

impl Il2CppValue for Il2CppField {
    fn as_raw(&self) -> usize {
        &self.0 as *const usize as usize
    }
}

#[cfg(test)]
mod tests {
    use super::Il2CppField;
    use crate::{vm::method::Il2CppMethod, vm::r#type::Il2CppType, vm::value::Il2CppValue};

    fn assert_borrowed_handle(handle: &impl Il2CppValue, value: usize) {
        let raw = handle.as_raw();
        assert_eq!(
            raw,
            handle.as_raw(),
            "repeated calls must preserve identity"
        );
        assert_eq!(raw as *const usize, handle as *const _ as *const usize);
        // SAFETY: all tested handles are repr(transparent) wrappers around one usize,
        // and each handle remains alive for the duration of this read.
        assert_eq!(unsafe { *(raw as *const usize) }, value);
    }

    #[test]
    fn metadata_handle_as_raw_borrows_the_stored_value() {
        let field = Il2CppField(0x1234);
        let method = Il2CppMethod(0x5678);
        let ty = Il2CppType(0x9ABC);

        assert_borrowed_handle(&field, field.0);
        assert_borrowed_handle(&method, method.0);
        assert_borrowed_handle(&ty, ty.0);
    }
}
