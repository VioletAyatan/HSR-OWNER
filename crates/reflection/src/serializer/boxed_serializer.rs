use crate::{
    array::Array, r#enum::Enum, field_info::FieldInfo, method_info::MethodInfo,
    property_info::PropertyInfo, runtime_type::RuntimeType,
};
use anyhow::Result;
use il2cpp::{
    get_cached_class, get_native_method,
    vm::{object::Il2CppObject, string::Il2CppString, value::Il2CppValue},
};
use serde_json::{Map, Value, json};
use std::{
    collections::{HashMap, HashSet},
    rc::Rc,
    sync::LazyLock,
};

static SYSTEM_STRING_TYPE: LazyLock<RuntimeType> =
    LazyLock::new(|| RuntimeType::from_class(get_cached_class("System.String").unwrap()).unwrap());

static SYSTEM_DECIMAL_TYPE: LazyLock<RuntimeType> =
    LazyLock::new(|| RuntimeType::from_class(get_cached_class("System.Decimal").unwrap()).unwrap());

static SYSTEM_RUNTIME_TYPE_TYPE: LazyLock<RuntimeType> = LazyLock::new(|| {
    RuntimeType::from_class(get_cached_class("System.RuntimeType").unwrap()).unwrap()
});

static SYSTEM_TYPE_TYPE: LazyLock<RuntimeType> =
    LazyLock::new(|| RuntimeType::from_class(get_cached_class("System.Type").unwrap()).unwrap());

static IENUMERABLE_TYPE: LazyLock<RuntimeType> = LazyLock::new(|| {
    RuntimeType::from_class(get_cached_class("System.Collections.IEnumerable").unwrap()).unwrap()
});

type TCustomSerializer =
    HashMap<RuntimeType, Rc<dyn Fn(RuntimeType, Il2CppObject) -> Result<Value>>>;

struct CustomSerializer(TCustomSerializer);

unsafe impl Send for CustomSerializer {}
unsafe impl Sync for CustomSerializer {}

impl Default for CustomSerializer {
    fn default() -> Self {
        let mut map: TCustomSerializer = HashMap::with_capacity(4);
        map.insert(
            RuntimeType::from_class(get_cached_class("RPG.GameCore.FixPoint").unwrap()).unwrap(),
            Rc::new(|_, object| {
                const CONSTANT: f64 = f64::from_bits(0x3DF0000000000000);
                let value = unsafe { *((object.0 + 0x10) as *const i64) } as f64;
                Ok(json!({
                    "Value": value * CONSTANT
                }))
            }),
        );
        map.insert(
            RuntimeType::from_class(get_cached_class("RPG.Client.TextID").unwrap()).unwrap(),
            Rc::new(|_, object| {
                let hash = unsafe { *((object.0 + 0x10) as *const i32) };
                let hash64 = unsafe { *((object.0 + 0x18) as *const u64) };
                Ok(json!({
                    "Hash": hash,
                    "Hash64": hash64
                }))
            }),
        );
        map.insert(
            RuntimeType::from_class(get_cached_class("RPG.GameCore.DynamicValue").unwrap())
                .unwrap(),
            Rc::new(|_, object| {
                let rt = RuntimeType::from_object(object)?;

                let value_type = rt.get_property("ValueType".into(), 62)?;
                if value_type.is_null() {
                    return Ok(json!({}));
                }

                let value_enum_object = value_type.get_value(object)?;

                let value_enum = Enum::get_name(
                    RuntimeType::from_object(value_enum_object)?,
                    value_enum_object,
                )
                .map(|n| Value::String(n.as_str().into()))?;

                let value_string = get_native_method("RPG.GameCore.DynamicValue::ToString()")
                    .unwrap()
                    .invoke::<Il2CppString>(object, &[])?;

                Ok(json!({
                    "Type": value_enum,
                    "Value": value_string.as_str()
                }))
            }),
        );

        map.insert(super::postfix_expr_type(), Rc::new(|_, _| Ok(json!({}))));
        map.insert(super::dynamic_values_type(), Rc::new(|_, _| Ok(json!({}))));

        Self(map)
    }
}

type Callback = HashMap<String, Rc<dyn Fn(&Value)>>;

#[derive(Default)]
struct TypeMetadata {
    name: Option<String>,
    il_name: Option<String>,
    is_primitive: Option<bool>,
    is_enum: Option<bool>,
    is_value_type: Option<bool>,
    is_array: Option<bool>,
    is_enumerable: Option<bool>,
}

#[derive(Clone)]
struct CachedField {
    info: FieldInfo,
    field_type: Option<RuntimeType>,
    name: Option<Rc<str>>,
}

#[derive(Clone)]
struct CachedProperty {
    info: PropertyInfo,
    property_type: Option<RuntimeType>,
    name: Option<Rc<str>>,
}

#[derive(Default)]
pub struct BoxedSerializer {
    cached_properties: HashMap<RuntimeType, Rc<Vec<CachedProperty>>>,
    cached_fields: HashMap<RuntimeType, Rc<Vec<CachedField>>>,
    type_metadata: HashMap<RuntimeType, TypeMetadata>,
    skip_names: HashSet<String>,
    skip_name_type_pair: HashSet<(String, String)>,
    enum_as_value: bool,
    custom_serializer: CustomSerializer,
    callbacks: Callback,
    fields_only: bool,
    default_value_as_null: bool,
    checkpoint: Option<Box<dyn FnMut() -> Result<()>>>,
    checkpoint_visits: usize,
    serialization_depth: usize,
    checkpoint_error: Option<String>,
}

impl BoxedSerializer {
    pub fn new(skip_names: HashSet<String>) -> Self {
        Self {
            skip_names,
            ..Default::default()
        }
    }

    pub fn new2(enum_as_value: bool) -> Self {
        Self {
            enum_as_value,
            ..Default::default()
        }
    }

    /// Installs a callback invoked every 256 recursive serialization visits.
    pub fn set_checkpoint(&mut self, checkpoint: Box<dyn FnMut() -> Result<()>>) {
        self.checkpoint = Some(checkpoint);
        self.checkpoint_visits = 0;
        self.checkpoint_error = None;
    }

    #[inline]
    pub fn serialize(&mut self, ty: RuntimeType, object: Il2CppObject) -> Result<Value> {
        let entry_depth = self.serialization_depth;
        let serialized = microseh::try_seh(|| {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.private_serialize(ty, object, false)
            }))
        });
        let result = match serialized {
            Ok(Ok(result)) => result,
            Ok(Err(payload)) => {
                self.serialization_depth = entry_depth;
                if entry_depth == 0 {
                    self.checkpoint_visits = 0;
                    self.checkpoint_error = None;
                }
                let message = payload
                    .downcast_ref::<String>()
                    .map(String::as_str)
                    .or_else(|| payload.downcast_ref::<&str>().copied())
                    .unwrap_or("unknown panic payload");
                return Err(anyhow::anyhow!("BoxedSerializer caught a panic: {message}"));
            }
            Err(error) => {
                self.serialization_depth = entry_depth;
                if entry_depth == 0 {
                    self.checkpoint_visits = 0;
                    self.checkpoint_error = None;
                }
                log::debug!(
                    "[BoxedSerializer] Failed to serialize {}. code: {:?}",
                    ty.il_name(),
                    error.code()
                );
                return Err(anyhow::anyhow!("{error:?}"));
            }
        };
        result
    }

    fn private_serialize(
        &mut self,
        ty: RuntimeType,
        object: Il2CppObject,
        is_array: bool,
    ) -> Result<Value> {
        self.serialization_depth += 1;
        let result = self
            .check_checkpoint()
            .and_then(|()| self.private_serialize_inner(ty, object, is_array));

        self.serialization_depth -= 1;
        if self.serialization_depth == 0 {
            if let Some(error) = self.checkpoint_error.take() {
                self.checkpoint_visits = 0;
                return Err(anyhow::anyhow!("serialization checkpoint failed: {error}"));
            }
            self.checkpoint_visits = 0;
        }
        result
    }

    fn private_serialize_inner(
        &mut self,
        ty: RuntimeType,
        object: Il2CppObject,
        is_array: bool,
    ) -> Result<Value> {
        if object.is_null() {
            return Ok(Value::Null);
        }

        // Custom serializer
        if let Some(custom_serializer) = self.custom_serializer.0.get(&ty) {
            return custom_serializer(ty, object);
        }

        // C# Primitives
        if self.is_primitive(ty)? || ty == *SYSTEM_STRING_TYPE || ty == *SYSTEM_DECIMAL_TYPE {
            return self.serialize_primitive(ty, object, is_array, self.default_value_as_null);
        }

        // Enum
        if self.is_enum(ty)? {
            if !self.enum_as_value {
                if let Ok(Ok(Ok(name))) = microseh::try_seh(|| {
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        Enum::get_name(ty, object).map(|n| Value::String(n.as_str().into()))
                    }))
                }) {
                    return Ok(name);
                }
                return Self::to_string(ty, object).map_or(Ok(Value::Null), Ok);
            }
            return self.serialize(Enum::get_underlying_type(ty)?, object);
        }

        // IEnumerable<T>
        if self.is_enumerable_like(ty) && ty != *SYSTEM_STRING_TYPE {
            return self.serialize_enumerable(ty, object);
        }

        // System.Type | System.RuntimeType
        if ty == *SYSTEM_RUNTIME_TYPE_TYPE || ty == *SYSTEM_TYPE_TYPE {
            return Ok(Value::String(
                RuntimeType(object.0)
                    .get_full_name()
                    .unwrap()
                    .as_str()
                    .into_owned(),
            ));
        }

        // ValueType
        if self.is_value_type(ty)? {
            return self.serialize_type(ty, object);
        }

        // Object
        let actual_type = RuntimeType::from_object(object)?;
        let mut serialized: serde_json::Value = self.serialize_type(actual_type, object)?;

        // Add $type
        if ty != actual_type
            && let Value::Object(ref mut object) = serialized
        {
            object.shift_insert(
                0,
                "$type".into(),
                json!(actual_type.format_type_name_with_namespace(true, false)),
            );
        }

        Ok(serialized)
    }

    fn serialize_primitive(
        &mut self,
        ty: RuntimeType,
        object: Il2CppObject,
        is_array: bool,
        default_value_as_null: bool,
    ) -> Result<Value> {
        macro_rules! handle_primitive {
            ($type:ty, $convert:expr) => {{
                let val = object.unbox::<$type>();
                if default_value_as_null && val == <$type>::default() && !is_array {
                    Value::Null
                } else {
                    $convert(val)
                }
            }};
        }

        Ok(match self.type_name(ty)?.as_str() {
            "String" => {
                let s = Il2CppString(object.0).as_str().into_owned();
                Value::String(s)
            }
            "Boolean" => handle_primitive!(bool, |v: bool| Value::Bool(v)),
            "Byte" => handle_primitive!(u8, |v: u8| Value::Number(v.into())),
            "SByte" => handle_primitive!(i8, |v: i8| Value::Number(v.into())),
            "Int16" => handle_primitive!(i16, |v: i16| Value::Number(v.into())),
            "UInt16" => handle_primitive!(u16, |v: u16| Value::Number(v.into())),
            "Int32" => handle_primitive!(i32, |v: i32| Value::Number(v.into())),
            "UInt32" => handle_primitive!(u32, |v: u32| Value::Number(v.into())),
            "Int64" | "IntPtr" => handle_primitive!(i64, |v: i64| Value::Number(v.into())),
            "UInt64" | "UIntPtr" => handle_primitive!(u64, |v: u64| Value::Number(v.into())),
            "Single" => handle_primitive!(f32, |v: f32| json!(v)),
            "Double" => handle_primitive!(f64, |v: f64| json!(v)),
            "Char" => handle_primitive!(char, |v: char| Value::String(v.into())),
            "Decimal" => {
                #[derive(Clone, Copy, Default)]
                #[repr(C)]
                struct Decimal {
                    pub flags: i32,
                    pub hi: i32,
                    pub lo: i32,
                    pub mid: i32,
                }
                impl PartialEq for Decimal {
                    fn eq(&self, other: &Self) -> bool {
                        self.flags == other.flags
                            && self.hi == other.hi
                            && self.lo == other.lo
                            && self.mid == other.mid
                    }
                }

                let decimal = object.unbox::<Decimal>();
                if default_value_as_null && decimal == Decimal::default() {
                    Value::Null
                } else {
                    let scale = (decimal.flags >> 16) & 0xFF;
                    let is_negative = (decimal.flags as u32 & 0x80000000) != 0;
                    let value = ((decimal.hi as i128) << 64)
                        | ((decimal.mid as i128) << 32)
                        | decimal.lo as i128;
                    let scaled_value = value as f64 / 10f64.powi(scale);
                    if is_negative {
                        json!(-scaled_value)
                    } else {
                        json!(scaled_value)
                    }
                }
            }
            other => {
                log::debug!("[Boxed Serializer] Unhandled primitive type: {other}");
                Value::Null
            }
        })
    }

    fn serialize_enumerable(&mut self, ty: RuntimeType, object: Il2CppObject) -> Result<Value> {
        let ty_name = self.type_name(ty)?.clone();

        // Dictionary
        if ty_name == "Dictionary`2" {
            let entries_field = ty.get_field("entries".into(), 62)?;
            let entry_type = entries_field.get_field_type()?.get_element_type()?; // Entry<K, V>
            let entries = entries_field.get_value(object)?;

            if entries.is_null() {
                return Ok(json!({}));
            }

            let count = ty
                .get_field("count".into(), 62)?
                .get_value(object)?
                .unbox::<i32>();

            let key_field = entry_type.get_field("key".into(), 62)?;
            let key_type = key_field.get_field_type()?;

            let value_field = entry_type.get_field("value".into(), 62)?;
            let value_type = value_field.get_field_type()?;

            let mut map = Map::new();
            for entry_object in Array(entries.0).iter(Some(count)) {
                self.check_checkpoint()?;
                let Ok(key_object) = key_field.get_value(entry_object) else {
                    continue;
                };
                let key = match self.private_serialize(key_type, key_object, true) {
                    Ok(key) => key,
                    Err(_) => {
                        self.check_checkpoint()?;
                        continue;
                    }
                };

                let key_str = if let Value::String(s) = key {
                    s
                } else {
                    key.to_string()
                };
                let Ok(value_object) = value_field.get_value(entry_object) else {
                    continue;
                };
                let value = match self.private_serialize(value_type, value_object, true) {
                    Ok(value) => value,
                    Err(_) => {
                        self.check_checkpoint()?;
                        continue;
                    }
                };
                map.insert(key_str, value);
            }

            return Ok(Value::Object(map));
        }

        // HashSet
        if ty_name == "HashSet`1" {
            let slots_field = ty.get_field("_slots".into(), 62)?;
            let slots = slots_field.get_value(object)?;

            if slots.is_null() {
                return Ok(json!([]));
            }

            let count = ty
                .get_field("count".into(), 62)?
                .get_value(object)?
                .unbox::<i32>();

            let slot_type = slots_field.get_field_type()?.get_element_type()?; // Slot<T>

            let slot_value_field = slot_type.get_field("value".into(), 62)?;
            let slot_value_type = slot_value_field.get_field_type()?;

            let mut values = Vec::new();
            for slot_object in Array(slots.0).iter(Some(count)) {
                self.check_checkpoint()?;
                let Ok(value_object) = slot_value_field.get_value(slot_object) else {
                    continue;
                };
                match self.private_serialize(slot_value_type, value_object, true) {
                    Ok(value) if !value.is_null() => values.push(value),
                    Ok(_) => {}
                    Err(_) => self.check_checkpoint()?,
                }
            }
            return Ok(Value::Array(values));
        }

        // Array
        if self.is_array(ty)? {
            let array_element_type = ty.get_element_type()?;
            let mut values = Vec::new();
            for element in Array(object.0).iter(None) {
                self.check_checkpoint()?;
                match self.private_serialize(array_element_type, element, true) {
                    Ok(value) => values.push(value),
                    Err(_) => self.check_checkpoint()?,
                }
            }
            return Ok(Value::Array(values));
        }

        // HoyoTagContainer
        if ty_name == "HoyoTagContainer" {
            let list_field = ty.get_field("List".into(), 62)?;
            let hoyo_tag_type = list_field.get_field_type()?.get_element_type()?;

            let list = list_field.get_value(object)?;
            if list.is_null() {
                return Ok(json!([]));
            }

            let mut values = Vec::new();
            for tag in Array(list.0).iter(None) {
                self.check_checkpoint()?;
                match self.serialize(hoyo_tag_type, tag) {
                    Ok(value) if !value.is_null() => values.push(value),
                    Ok(_) => {}
                    Err(_) => self.check_checkpoint()?,
                }
            }
            return Ok(Value::Array(values));
        }

        // Others
        for field_name in &["entries", "_items", "_array", "slots", "m_slots", "_slots"] {
            let field = ty.get_field((*field_name).into(), 62)?;
            if !field.is_null() {
                let array = field.get_value(object)?;
                if array.is_null() {
                    return Ok(json!([]));
                }

                let field_type = field.get_field_type()?;

                if !self.is_array(field_type)? {
                    return Ok(Value::Null);
                }

                let array_like_element_type = field_type.get_element_type()?; // T[]
                let mut values = Vec::new();
                for element in Array(array.0).iter(None) {
                    self.check_checkpoint()?;
                    match self.private_serialize(array_like_element_type, element, true) {
                        Ok(value) if !value.is_null() => values.push(value),
                        Ok(_) => {}
                        Err(_) => self.check_checkpoint()?,
                    }
                }
                return Ok(Value::Array(values));
            }
        }

        // log::debug!(
        //     "[Boxed Serializer] Unhandled enumerable! {}",
        //     ty.get_name()?.as_str()
        // );

        Ok(Value::Array(Vec::new()))
    }

    fn serialize_type(&mut self, ty: RuntimeType, object: Il2CppObject) -> Result<Value> {
        let fields = self
            .cached_fields
            .entry(ty)
            .or_insert_with(|| {
                let mut fields = ty
                    .all_fields()
                    .into_iter()
                    .filter(|f| {
                        let modifier = f.modifier();
                        !modifier.contains("static ") && !modifier.contains("const ")
                    })
                    .collect::<Vec<_>>();
                fields.sort_by_key(super::super::field_info::FieldInfo::get_metadata_token);
                fields
                    .into_iter()
                    .map(|info| CachedField {
                        field_type: info.get_field_type().ok(),
                        name: info
                            .get_name()
                            .ok()
                            .map(|name| Rc::<str>::from(name.as_str().as_ref())),
                        info,
                    })
                    .collect::<Vec<_>>()
                    .into()
            })
            .clone();

        let mut map = Map::with_capacity(fields.len());

        for field in fields.iter().cloned() {
            self.check_checkpoint()?;
            let field_info = field.info;
            let Some(field_type) = field.field_type else {
                continue;
            };

            // Self referencing loop
            if field_type == ty {
                continue;
            }

            let Some(key) = field.name else {
                continue;
            };

            if self.skip_names.contains(key.as_ref()) {
                continue;
            }

            if !self.skip_name_type_pair.is_empty() {
                let il_name = self.type_il_name(field_type);
                if self
                    .skip_name_type_pair
                    .contains(&(key.to_string(), il_name))
                {
                    continue;
                }
            }

            let Ok(value) = field_info.get_value(object) else {
                continue;
            };

            // log::debug!(
            //     "[Boxed Serializer] Field | Key: {} Type: {}",
            //     key,
            //     field_type.format_type_name(true)
            // );

            if let Ok(value) = self.serialize(field_type, value)
                && !value.is_null()
            {
                self.call_callback(&key, &value);
                map.insert(key.to_string(), value);
            }
        }

        // Early return
        if self.fields_only {
            return Ok(Value::Object(map));
        }

        let properties = self
            .cached_properties
            .entry(ty)
            .or_insert_with(|| {
                let mut properties = ty
                    .all_properties()
                    .into_iter()
                    .filter(|p| {
                        let getter = p.get_get_method(true);
                        let setter = p.get_set_method(true);
                        let is_accessor_static = |m: std::result::Result<MethodInfo, _>| {
                            m.is_ok_and(|m| !m.is_null() && m.is_static())
                        };
                        !is_accessor_static(getter) && !is_accessor_static(setter)
                    })
                    .collect::<Vec<_>>();
                properties
                    .sort_by_key(super::super::property_info::PropertyInfo::get_metadata_token);
                properties
                    .into_iter()
                    .map(|info| CachedProperty {
                        property_type: info.get_property_type().ok(),
                        name: info
                            .get_name()
                            .ok()
                            .map(|name| Rc::<str>::from(name.as_str().as_ref())),
                        info,
                    })
                    .collect::<Vec<_>>()
                    .into()
            })
            .clone();

        for property in properties.iter().cloned() {
            self.check_checkpoint()?;
            let property_info = property.info;
            let Some(property_type) = property.property_type else {
                continue;
            };

            // Self referencing loop
            if property_type == ty {
                continue;
            }

            let Some(key) = property.name else {
                continue;
            };

            if self.skip_names.contains(key.as_ref()) {
                continue;
            }

            if !self.skip_name_type_pair.is_empty() {
                let il_name = self.type_il_name(property_type);
                if self
                    .skip_name_type_pair
                    .contains(&(key.to_string(), il_name))
                {
                    continue;
                }
            }

            let Ok(value) = property_info.get_value(object) else {
                continue;
            };

            // log::debug!(
            //     "[Boxed Serializer] Property | Key: {} Type: {}",
            //     key,
            //     property_type.format_type_name(true)
            // );

            if let Ok(value) = self.serialize(property_type, value)
                && !value.is_null()
            {
                self.call_callback(&key, &value);
                map.insert(key.to_string(), value);
            }
        }

        Ok(Value::Object(map))
    }

    fn type_name(&mut self, ty: RuntimeType) -> Result<&String> {
        if !self
            .type_metadata
            .get(&ty)
            .is_some_and(|meta| meta.name.is_some())
        {
            let name = ty.get_name()?.as_str().into_owned();
            self.type_metadata.entry(ty).or_default().name = Some(name);
        }
        Ok(self.type_metadata.get(&ty).unwrap().name.as_ref().unwrap())
    }

    fn type_il_name(&mut self, ty: RuntimeType) -> String {
        if !self
            .type_metadata
            .get(&ty)
            .is_some_and(|meta| meta.il_name.is_some())
        {
            let name = ty.il_name().into_owned();
            self.type_metadata.entry(ty).or_default().il_name = Some(name);
        }
        self.type_metadata
            .get(&ty)
            .unwrap()
            .il_name
            .as_ref()
            .unwrap()
            .clone()
    }

    fn is_primitive(&mut self, ty: RuntimeType) -> Result<bool> {
        if let Some(value) = self.type_metadata.get(&ty).and_then(|m| m.is_primitive) {
            return Ok(value);
        }
        let value = ty.get_isprimitive()?.unbox();
        self.type_metadata.entry(ty).or_default().is_primitive = Some(value);
        Ok(value)
    }

    fn is_enum(&mut self, ty: RuntimeType) -> Result<bool> {
        if let Some(value) = self.type_metadata.get(&ty).and_then(|m| m.is_enum) {
            return Ok(value);
        }
        let value = ty.get_isenum()?.unbox();
        self.type_metadata.entry(ty).or_default().is_enum = Some(value);
        Ok(value)
    }

    fn is_value_type(&mut self, ty: RuntimeType) -> Result<bool> {
        if let Some(value) = self.type_metadata.get(&ty).and_then(|m| m.is_value_type) {
            return Ok(value);
        }
        let value = ty.get_isvaluetype()?.unbox();
        self.type_metadata.entry(ty).or_default().is_value_type = Some(value);
        Ok(value)
    }

    fn is_array(&mut self, ty: RuntimeType) -> Result<bool> {
        if let Some(value) = self.type_metadata.get(&ty).and_then(|m| m.is_array) {
            return Ok(value);
        }
        let value = ty.get_isarray()?.unbox();
        self.type_metadata.entry(ty).or_default().is_array = Some(value);
        Ok(value)
    }

    fn is_enumerable_like(&mut self, ty: RuntimeType) -> bool {
        if let Some(value) = self.type_metadata.get(&ty).and_then(|m| m.is_enumerable) {
            return value;
        }
        let value = IENUMERABLE_TYPE
            .is_assignable_from(ty)
            .map(|v| v.unbox())
            .unwrap_or_default();
        self.type_metadata.entry(ty).or_default().is_enumerable = Some(value);
        value
    }

    fn check_checkpoint(&mut self) -> Result<()> {
        self.checkpoint_visits += 1;
        if self.checkpoint_error.is_none()
            && (self.checkpoint_visits == 1 || self.checkpoint_visits % 256 == 0)
            && let Some(checkpoint) = self.checkpoint.as_mut()
            && let Err(error) = checkpoint()
        {
            self.checkpoint_error = Some(error.to_string());
        }
        if let Some(error) = &self.checkpoint_error {
            Err(anyhow::anyhow!("serialization checkpoint failed: {error}"))
        } else {
            Ok(())
        }
    }

    fn to_string(ty: RuntimeType, object: Il2CppObject) -> Result<Value> {
        let to_string_method = ty.find_method_specific("ToString", 60, &[]).unwrap();
        if to_string_method.is_null() {
            return Ok(Value::Null);
        }

        Ok(Value::String(
            to_string_method
                .get_il2cpp_method()
                .invoke::<Il2CppString>(object, &[])?
                .as_str()
                .into(),
        ))
    }

    pub fn add_callback(&mut self, field_name: String, func: Rc<dyn Fn(&Value)>) {
        self.callbacks.insert(field_name, func);
    }

    pub fn remove_callback(&mut self, field_name: &str) {
        self.callbacks.remove(field_name);
    }

    fn call_callback(&mut self, field_name: &str, value: &Value) {
        if let Some(callback) = self.callbacks.get(field_name) {
            callback(value);
        }
    }
}

#[cfg(test)]
mod checkpoint_tests {
    use super::*;

    fn serializer_without_game() -> BoxedSerializer {
        BoxedSerializer {
            cached_properties: HashMap::new(),
            cached_fields: HashMap::new(),
            type_metadata: HashMap::new(),
            skip_names: HashSet::new(),
            skip_name_type_pair: HashSet::new(),
            enum_as_value: false,
            custom_serializer: CustomSerializer(HashMap::new()),
            callbacks: HashMap::new(),
            fields_only: false,
            default_value_as_null: false,
            checkpoint: None,
            checkpoint_visits: 0,
            serialization_depth: 0,
            checkpoint_error: None,
        }
    }

    #[test]
    fn checkpoint_error_survives_a_swallowed_nested_result() {
        let mut serializer = serializer_without_game();
        serializer.set_checkpoint(Box::new(|| Err(anyhow::anyhow!("memory limit reached"))));

        // Model entry from an already active parent. A null object keeps this test
        // independent of IL2CPP runtime functions while exercising the checkpoint state.
        serializer.serialization_depth = 1;
        serializer.checkpoint_visits = 255;
        let swallowed = serializer
            .private_serialize(RuntimeType(0), Il2CppObject::NULL, false)
            .ok();

        assert!(swallowed.is_none());
        assert_eq!(serializer.serialization_depth, 1);
        assert!(serializer.check_checkpoint().is_err());
    }

    #[test]
    fn checkpoint_error_fails_an_outermost_null_serialization() {
        let mut serializer = serializer_without_game();
        serializer.set_checkpoint(Box::new(|| Err(anyhow::anyhow!("memory limit reached"))));

        let result = serializer.serialize(RuntimeType(0), Il2CppObject::NULL);

        assert!(result.is_err());
        assert_eq!(serializer.serialization_depth, 0);
        assert_eq!(serializer.checkpoint_visits, 0);
        assert!(serializer.checkpoint_error.is_none());
    }

    #[test]
    fn panic_is_caught_inside_seh_callback_and_serializer_can_be_reused() {
        let mut serializer = serializer_without_game();
        serializer.set_checkpoint(Box::new(|| panic!("checkpoint panic")));
        let error = serializer
            .serialize(RuntimeType(0), Il2CppObject::NULL)
            .unwrap_err();
        assert!(error.to_string().contains("checkpoint panic"));
        assert_eq!(serializer.serialization_depth, 0);
        serializer.set_checkpoint(Box::new(|| Ok(())));
        assert_eq!(
            serializer
                .serialize(RuntimeType(0), Il2CppObject::NULL)
                .unwrap(),
            Value::Null
        );
    }
}
