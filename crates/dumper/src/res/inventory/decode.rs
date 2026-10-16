//! Decode a DesignData entry with the client's own deserializer.
//!
//! A `GameCoreConfigLoader.LoadX(string)` loader is `JsonToBinaryPath` ->
//! `IMNECEGBJLE.BAPACPLOLNH` (allocates the binary reader, stores the entry
//! bytes, leaves the position at 0) -> a static `(reader, out T)` deserializer.
//! The deserializer the loader really calls is taken from the loader's machine
//! code (it is often declared on a base or helper type), then run on a reader
//! built exactly like the client builds it. A result counts only when the
//! reader consumed every byte; a wrong type raises or stops early.
//!
//! Loaders without that pattern are invoked with the JSON path instead (the
//! client reads the entry itself); those results carry no consumption check.
use super::super::invoke_error;
use anyhow::{Context, Result, bail, ensure};
use iced_x86::{Decoder as X86, DecoderOptions, FlowControl, Instruction, Mnemonic};
use il2cpp::{
    api, get_cached_class, get_native_method,
    vm::{
        array::Il2CppArray, class::Il2CppClass, field::Il2CppField, method::Il2CppMethod,
        object::Il2CppObject, string::Il2CppString,
    },
};
use reflection::{field_info::FieldInfo, runtime_type::RuntimeType, serializer::BoxedSerializer};
use serde_json::Value;
use std::collections::{BTreeSet, HashMap, HashSet};
use utils::game_assembly_slice;

const FIELD_ATTRIBUTE_STATIC: u32 = 0x10;

pub enum Route {
    Deserializer(Il2CppMethod),
    Loader,
}

pub struct Decoder {
    pub loader: Il2CppMethod,
    pub return_type: RuntimeType,
    pub return_class: Il2CppClass,
    pub route: Route,
}

impl Decoder {
    pub fn checked(&self) -> bool {
        matches!(self.route, Route::Deserializer(_))
    }
}

struct Reader {
    class: Il2CppClass,
    name: String,
    buffer_field: FieldInfo,
    buffer_offset: usize,
    position_offset: usize,
    byte_array: Il2CppClass,
}

pub struct Decoders {
    reader: Reader,
    /// Static `(reader, out T&)` methods by RVA.
    deserializers: HashMap<usize, Vec<Il2CppMethod>>,
    cache: HashMap<String, Option<Decoder>>,
    pub unavailable: Vec<(String, String)>,
}

fn loader_method(name: &str) -> Option<Il2CppMethod> {
    get_native_method(&format!(
        "RPG.GameCore.GameCoreConfigLoader::{name}(System.String)"
    ))
}

/// Direct call/jump targets (RVAs) in a function body, up to its padding.
fn call_targets(rva: usize) -> HashSet<usize> {
    let code = game_assembly_slice();
    let mut targets = HashSet::new();
    let Some(bytes) = code.get(rva..rva.saturating_add(0x600).min(code.len())) else {
        return targets;
    };
    let base = *il2cpp::GA_BASE;
    let mut decoder = X86::with_ip(64, bytes, (base + rva) as u64, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    let mut seen_return = false;
    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        match instruction.flow_control() {
            FlowControl::Call | FlowControl::UnconditionalBranch => {
                let target = instruction.near_branch_target() as usize;
                if target >= base {
                    targets.insert(target - base);
                }
            }
            FlowControl::Return => seen_return = true,
            _ => {}
        }
        if instruction.mnemonic() == Mnemonic::Int3 && seen_return {
            break;
        }
    }
    targets
}

fn is_static_field(field: Il2CppField) -> bool {
    api::il2cpp_type_get_attrs(api::il2cpp_field_get_type(field)) & FIELD_ATTRIBUTE_STATIC != 0
}

fn class_name(class: Il2CppClass) -> String {
    class.byval_arg().il_name().to_string()
}

fn is_assignable(mut class: Il2CppClass, target: Il2CppClass) -> bool {
    for _ in 0..64 {
        if class.0 == 0 {
            return false;
        }
        if class == target {
            return true;
        }
        class = api::il2cpp_class_get_parent(class);
    }
    false
}

impl Decoders {
    /// `loaders`: every loader the rules can select; only their callees are
    /// inspected, so no unrelated method or generic class is touched.
    pub fn new(loaders: &BTreeSet<String>) -> Result<Self> {
        let binary_loader = loader_method("LoadBinaryConfig")
            .context("missing GameCoreConfigLoader.LoadBinaryConfig(System.String)")?;
        let class = api::il2cpp_class_from_type(api::il2cpp_method_get_return_type(binary_loader));
        ensure!(class.0 != 0, "LoadBinaryConfig has no class return type");
        let name = class_name(class);
        let byte_array = get_cached_class("System.Byte")
            .context("missing System.Byte")?
            .get_array_class(1);
        let int32 = get_cached_class("System.Int32").context("missing System.Int32")?;
        let mut buffers = Vec::new();
        let mut positions = Vec::new();
        for field in class.get_fields() {
            if is_static_field(field) {
                continue;
            }
            let field_class = api::il2cpp_class_from_type(api::il2cpp_field_get_type(field));
            if field_class == byte_array {
                buffers.push(field);
            } else if field_class == int32 {
                positions.push(field);
            } else {
                bail!(
                    "{name}: unexpected instance field of type {}",
                    class_name(field_class)
                );
            }
        }
        ensure!(
            buffers.len() == 1 && positions.len() == 1,
            "{name}: expected one byte[] buffer and one int position, found {} and {}",
            buffers.len(),
            positions.len()
        );
        let base = *il2cpp::GA_BASE;
        let targets: HashSet<usize> = loaders
            .iter()
            .filter_map(|name| loader_method(name))
            .filter(|method| method.rva() != 0)
            .flat_map(|method| call_targets(method.rva()))
            .collect();
        let mut deserializers: HashMap<usize, Vec<Il2CppMethod>> = HashMap::new();
        for method in il2cpp::FUNCTIONS_TABLE
            .get()
            .context("IL2CPP method table is not initialized")?
            .values()
        {
            let va = method.va();
            if va <= base || !targets.contains(&(va - base)) {
                continue;
            }
            if api::il2cpp_method_is_instance(*method)
                || api::il2cpp_method_get_param_count(*method) != 2
            {
                continue;
            }
            let first = api::il2cpp_method_get_param(*method, 0);
            let second = api::il2cpp_method_get_param(*method, 1);
            if first.0 == 0
                || second.0 == 0
                || api::il2cpp_type_is_byref(first)
                || !api::il2cpp_type_is_byref(second)
                || api::il2cpp_class_from_type(first) != class
            {
                continue;
            }
            deserializers.entry(va - base).or_default().push(*method);
        }
        ensure!(
            !deserializers.is_empty(),
            "no static ({name}, out T) methods found"
        );
        Ok(Self {
            reader: Reader {
                class,
                buffer_field: FieldInfo::from_il2cpp_field(buffers[0])
                    .with_context(|| format!("{name}: reflect buffer field"))?,
                buffer_offset: buffers[0].offset(),
                position_offset: positions[0].offset(),
                byte_array,
                name,
            },
            deserializers,
            cache: HashMap::new(),
            unavailable: Vec::new(),
        })
    }

    pub fn describe(&self) -> String {
        format!(
            "reader={} buffer@{:#x} position@{:#x} deserializers={}",
            self.reader.name,
            self.reader.buffer_offset,
            self.reader.position_offset,
            self.deserializers.len()
        )
    }

    fn resolve(&self, loader_name: &str) -> Result<Decoder> {
        let loader = loader_method(loader_name).with_context(|| {
            format!("missing GameCoreConfigLoader::{loader_name}(System.String)")
        })?;
        let return_class = api::il2cpp_class_from_type(api::il2cpp_method_get_return_type(loader));
        ensure!(return_class.0 != 0, "{loader_name}: no class return type");
        ensure!(
            !api::il2cpp_class_is_valuetype(return_class),
            "{loader_name}: value-type root {} is not supported",
            class_name(return_class)
        );
        ensure!(loader.rva() != 0, "{loader_name}: no native body");
        let return_type = RuntimeType::from_class(return_class)
            .with_context(|| format!("{loader_name}: runtime type"))?;
        let mut found: Vec<(usize, Il2CppMethod)> = call_targets(loader.rva())
            .into_iter()
            .filter_map(|rva| {
                self.deserializers
                    .get(&rva)
                    .and_then(|methods| methods.first())
                    .map(|method| (rva, *method))
            })
            .collect();
        found.sort_by_key(|(rva, _)| *rva);
        let route = match found.as_slice() {
            [(_, method)] => Route::Deserializer(*method),
            [] => Route::Loader,
            many => bail!(
                "{loader_name}: {} different ({}, out T) callees",
                many.len(),
                self.reader.name
            ),
        };
        Ok(Decoder {
            loader,
            return_type,
            return_class,
            route,
        })
    }

    /// Resolve a loader's decoder once; false when unavailable.
    pub fn prepare(&mut self, loader_name: &str) -> bool {
        if !self.cache.contains_key(loader_name) {
            let resolved = match self.resolve(loader_name) {
                Ok(decoder) => {
                    let route = match decoder.route {
                        Route::Deserializer(method) => format!(
                            "{}::{} rva={:#x}",
                            class_name(method.class()),
                            method.get_name(),
                            method.rva()
                        ),
                        Route::Loader => "loader call (no reader deserializer)".to_string(),
                    };
                    super::super::checkpoint(format!(
                        "DesignData: decoder {loader_name} -> {route}"
                    ));
                    Some(decoder)
                }
                Err(error) => {
                    log::warn!("[Resources] DesignData: decoder unavailable: {error:#}");
                    self.unavailable
                        .push((loader_name.to_string(), format!("{error:#}")));
                    None
                }
            };
            self.cache.insert(loader_name.to_string(), resolved);
        }
        self.cache.get(loader_name).is_some_and(Option::is_some)
    }

    pub fn decoder(&self, loader_name: &str) -> Option<&Decoder> {
        self.cache.get(loader_name).and_then(Option::as_ref)
    }

    /// Same object state `BAPACPLOLNH` produces: fresh reader, buffer set, position 0.
    fn new_reader(&self, data: &[u8]) -> Result<Il2CppObject> {
        let reader = self.reader.class.create_instance();
        ensure!(reader.0 != 0, "allocate {}", self.reader.name);
        let mut array = Il2CppArray::new(self.reader.byte_array, data.len());
        ensure!(array.0 != 0, "allocate byte[{}]", data.len());
        array.as_mut_slice::<u8>().copy_from_slice(data);
        self.reader
            .buffer_field
            .set_value(reader, Il2CppObject(array.0))
            .context("set reader buffer")?;
        let stored = unsafe { ((reader.0 + self.reader.buffer_offset) as *const usize).read() };
        ensure!(
            stored == array.0,
            "reader buffer field did not take the array"
        );
        let position = unsafe { ((reader.0 + self.reader.position_offset) as *const i32).read() };
        ensure!(position == 0, "fresh reader starts at {position}");
        Ok(reader)
    }

    fn object(&self, decoder: &Decoder, json_path: &str, data: &[u8]) -> Result<Il2CppObject> {
        match decoder.route {
            Route::Deserializer(method) => {
                ensure!(!data.is_empty(), "empty entry");
                let reader = self.new_reader(data)?;
                let mut out: usize = 0;
                method
                    .invoke2::<usize>(
                        Il2CppObject::NULL,
                        vec![reader.0, &mut out as *mut usize as usize],
                    )
                    .map_err(invoke_error)
                    .context("deserializer raised")?;
                let position = unsafe {
                    ((reader.0 + self.reader.position_offset) as *const i32).read_volatile()
                };
                ensure!(
                    usize::try_from(position).ok() == Some(data.len()),
                    "consumed {position} of {} bytes",
                    data.len()
                );
                ensure!(out != 0, "deserializer produced null");
                Ok(Il2CppObject(out))
            }
            Route::Loader => {
                let argument = Il2CppString::from(json_path);
                let object = decoder
                    .loader
                    .invoke::<Il2CppObject>(Il2CppObject::NULL, &[&argument])
                    .map_err(invoke_error)
                    .context("loader raised")?;
                ensure!(object.0 != 0, "loader returned null");
                Ok(object)
            }
        }
    }

    /// Decode and serialize one entry. Returns the JSON and, when the object
    /// is not of the loader's declared type, the actual type name.
    pub fn decode(
        &self,
        decoder: &Decoder,
        json_path: &str,
        data: &[u8],
        serializer: &mut BoxedSerializer,
    ) -> Result<(Value, Option<String>)> {
        let mut run = || -> Result<(Value, Option<String>)> {
            let object = self.object(decoder, json_path, data)?;
            let actual = object.get_class();
            let note = (!is_assignable(actual, decoder.return_class)).then(|| class_name(actual));
            let value = serializer
                .serialize(decoder.return_type, object)
                .context("serialize")?;
            Ok((value, note))
        };
        microseh::try_seh(|| std::panic::catch_unwind(std::panic::AssertUnwindSafe(&mut run)))
            .map_err(|error| {
                // A caught overflow consumed the guard page; without re-arming
                // it the next overflow on this thread kills the process.
                let note = if error.code() != microseh::ExceptionCode::StackOverflow {
                    ""
                } else if reflection::stack::reset_guard() {
                    " (stack guard re-armed)"
                } else {
                    log::warn!("[Resources] DesignData: stack guard could not be re-armed");
                    " (stack guard NOT re-armed)"
                };
                anyhow::anyhow!("native exception {error:?}{note}")
            })?
            .map_err(|payload| {
                let message = payload
                    .downcast_ref::<String>()
                    .map(String::as_str)
                    .or_else(|| payload.downcast_ref::<&str>().copied())
                    .unwrap_or("unknown panic payload");
                anyhow::anyhow!("Rust panic: {message}")
            })?
    }
}
