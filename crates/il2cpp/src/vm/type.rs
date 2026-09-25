use crate::vm::value::Il2CppValue;
use crate::{api, vm::class::Il2CppClass};
use std::{
    borrow::Cow,
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

// The IL2CPP name API returns a native-allocated C string and this binding exposes no
// matching release function. Keep one returned name for each runtime type pointer for
// the lifetime of this process; this assumes the active game's type pointers stay valid.
static TYPE_NAMES: OnceLock<Mutex<HashMap<usize, &'static str>>> = OnceLock::new();

#[repr(u32)]
pub enum Il2CppTypeNameFormat {
    IL = 0,
    Reflection = 1,
    FullName = 2,
    AssemblyQualified = 3,
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Il2CppType(pub usize);

#[allow(unused)]
impl Il2CppType {
    #[inline]
    pub fn get_class(&self) -> Il2CppClass {
        api::il2cpp_class_from_type(*self)
    }

    #[inline]
    pub fn full_name(&self) -> Cow<'static, str> {
        self.get_name(Il2CppTypeNameFormat::FullName)
    }

    #[inline]
    pub fn il_name(&self) -> Cow<'static, str> {
        self.get_name(Il2CppTypeNameFormat::IL)
    }

    #[inline]
    /// TODO: Not actually using the formatting
    pub fn get_name(&self, format: Il2CppTypeNameFormat) -> Cow<'static, str> {
        let names = TYPE_NAMES.get_or_init(|| Mutex::new(HashMap::new()));
        let mut names = names
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(name) = names.get(&self.0) {
            return Cow::Borrowed(name);
        }

        let name = unsafe { utils::cstr_to_str(api::il2cpp_type_get_name(*self)) };
        let name = match name {
            Cow::Borrowed(name) => name,
            Cow::Owned(name) => Box::leak(name.into_boxed_str()),
        };
        names.insert(self.0, name);
        Cow::Borrowed(name)
    }
}

impl Il2CppValue for Il2CppType {
    fn is_null(&self) -> bool {
        self.0 == 0
    }

    fn as_raw(&self) -> usize {
        &self.0 as *const usize as usize
    }
}
