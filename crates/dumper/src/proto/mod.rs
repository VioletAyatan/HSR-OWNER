use std::{
    borrow::Cow,
    collections::HashMap,
    io::{self, Write},
    sync::LazyLock,
};

use crate::dump_progress::Progress;
use cache::{CachedType, TypeCache};
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic};
use il2cpp::{
    CLASS_TABLE_VEC, get_cached_class, get_native_method,
    vm::{metadata_cache, value::Il2CppValue},
};
use reflection::{property_info::PropertyInfo, runtime_type::RuntimeType};
use utils::game_assembly_slice;

mod asm_address;
mod cache;
pub mod handler_nt;
mod logic_nt;
mod merge_from;
mod method_nt;
mod nt;
mod output;
mod proto_asm_parser;
mod proto_stream;
mod rsp_scan;
pub mod util;
mod write_to;

static IL2CPP_OBJECT_NEW_API_RVA: LazyLock<usize> = LazyLock::new(|| unsafe {
    let api_ptr_addr = (*il2cpp::API_BASE_PTR) + 8 * 130;
    let api_addr = *((*il2cpp::UP_BASE + api_ptr_addr) as *const usize);
    asm_address::module_rva(api_addr, *il2cpp::GA_BASE, game_assembly_slice().len()).unwrap_or_else(
        || {
            log::warn!(
                "[Proto Dumper] object allocator API is outside GameAssembly: va=0x{api_addr:X}"
            );
            0
        },
    )
});

static IL2CPP_OBJECT_NEW_RVA: LazyLock<usize> = LazyLock::new(|| {
    let api_rva = *IL2CPP_OBJECT_NEW_API_RVA;
    if api_rva == 0 {
        return 0;
    }
    let slice = game_assembly_slice();
    let mut decoder = Decoder::with_ip(
        64,
        &slice[api_rva..api_rva.saturating_add(0x80).min(slice.len())],
        (*il2cpp::GA_BASE + api_rva) as u64,
        DecoderOptions::NONE,
    );
    let mut instruction = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        if instruction.mnemonic() == Mnemonic::Call
            && let Some(real_rva) =
                asm_address::direct_branch_rva(&instruction, *il2cpp::GA_BASE, slice.len())
        {
            log::debug!("[Proto Dumper] Il2CppObject::New => 0x{real_rva:X}");
            return real_rva;
        }
        if instruction.mnemonic() == Mnemonic::Ret || instruction.mnemonic() == Mnemonic::Int3 {
            break;
        }
    }
    log::debug!("[Proto Dumper] failed to find il2cpp_object_new rva, using api rva");
    api_rva
});

static XLUA_REGISTER_OBJECT_RVA: LazyLock<usize> = LazyLock::new(|| {
    let raw_class_name = &*XLUA_OBJECT_TRANSLATOR_STATIC_FIELDS_CLASS;
    if raw_class_name.is_empty() {
        return 0;
    }
    let class_name = raw_class_name
        .split('<')
        .next()
        .unwrap()
        .trim_end_matches('.');
    let Some(xlua_object_translator_class) = get_cached_class(class_name) else {
        log::debug!("[Proto Dumper] failed to resolve XLua ObjectTranslator class");
        return 0;
    };
    let Ok(static_class_type) = RuntimeType::from_class(xlua_object_translator_class) else {
        log::debug!("[Proto Dumper] failed to create XLua ObjectTranslator runtime type");
        return 0;
    };
    let delegate_name = &*XLUA_OBJECT_TRANSLATOR_DELEGATE;
    if delegate_name.is_empty() {
        return 0;
    }

    let methods = static_class_type.get_methods_il2cpp();
    if let Some(next) = methods
        .iter()
        .position(|method| {
            let params = method.get_parameters();
            params.len() == 1 && params[0].get_parameter_type().unwrap().il_name() == *delegate_name
        })
        .and_then(|idx| methods.get(idx + 1))
    {
        let va = next.get_il2cpp_method().va();
        let Some(rva) = asm_address::module_rva(va, *il2cpp::GA_BASE, game_assembly_slice().len())
        else {
            log::warn!("[Proto Dumper] XLua RegisterObject is outside GameAssembly: va=0x{va:X}");
            return 0;
        };
        log::debug!("[Proto Dumper] XLua::RegisterObject => 0x{rva:X}");
        return rva;
    }

    log::debug!("[Proto Dumper] failed to find XLua::RegisterObject via method index!");
    0
});

static RETCODE_FIELD_NAME: LazyLock<Cow<'static, str>> = LazyLock::new(|| {
    let Some(cake_race_base_rsp_message_class) =
        get_cached_class("RPG.Client.LittleGame.CakeRace.CakeRaceBaseRspMessage<T>")
    else {
        log::debug!("[Proto Dumper] CakeRaceBaseRspMessage<T> not found; using retcode fallback");
        return Cow::Borrowed("retcode");
    };

    let Ok(cake_race_type) = RuntimeType::from_class(cake_race_base_rsp_message_class) else {
        log::debug!("[Proto Dumper] invalid CakeRaceBaseRspMessage<T>; using retcode fallback");
        return Cow::Borrowed("retcode");
    };

    let Ok(base_type) = cake_race_type.get_base_type() else {
        log::debug!("[Proto Dumper] CakeRace base type unavailable; using retcode fallback");
        return Cow::Borrowed("retcode");
    };
    let base_class = base_type.get_il2cpp_type().get_class();

    let properties = base_type.get_properties(62);

    let Some(property) = properties.first() else {
        log::debug!(
            "[Proto Dumper] there are no properties in {} to get MsgRetcode",
            base_class.byval_arg().il_name()
        );
        return Cow::Borrowed("retcode");
    };

    let property_name = property.get_name().unwrap().as_str();

    log::debug!("[Proto Dumper] retcode => {property_name}");

    property_name
});

pub static NETWORK_MANAGER_SEND_NAME: LazyLock<Cow<'static, str>> = LazyLock::new(|| {
    let Some(class) = get_cached_class("RPG.Client.CycleScoreService") else {
        log::debug!("[Proto Dumper] CycleScoreService not found");
        return Cow::Borrowed("");
    };
    let Ok(cycle_score_service) = RuntimeType::from_class(class) else {
        log::debug!("[Proto Dumper] CycleScoreService runtime type is invalid");
        return Cow::Borrowed("");
    };

    let Ok(the_class) = cycle_score_service.get_base_type() else {
        log::debug!("[Proto Dumper] CycleScoreService base type is unavailable");
        return Cow::Borrowed("");
    };
    for method in the_class.get_methods_il2cpp() {
        if method.get_is_generic_method().unwrap().unbox() {
            let params = method.get_parameters();
            if params.len() == 3
                && let Some(m_method) = crate::script::METADATA_METHODS
                    .get()
                    .unwrap()
                    .get(&the_class.get_metadata_token())
                    .and_then(|m| m.get(&method.get_metadata_token()))
                    .and_then(|m| m.first())
            {
                let method_name = m_method.get_name().unwrap().as_str();
                log::debug!("[Proto Dumper] NetworkManager::Send => {method_name}");
                return method_name;
            }
        }
    }

    log::debug!("[Proto Dumper] failed to get NetworkManager::Send name");
    Cow::Borrowed("")
});

pub static NETWORK_MANAGER_SEND_VA: LazyLock<usize> = LazyLock::new(|| {
    let Some(class) = get_cached_class("RPG.Client.CycleScoreService") else {
        return 0;
    };
    let Ok(cycle_score_service) = RuntimeType::from_class(class) else {
        return 0;
    };

    let Ok(the_class) = cycle_score_service.get_base_type() else {
        return 0;
    };
    for method in the_class.get_methods_il2cpp() {
        if method.get_is_generic_method().unwrap().unbox() {
            let params = method.get_parameters();
            if params.len() == 3
                && let Some(m_method) = crate::script::METADATA_METHODS
                    .get()
                    .unwrap()
                    .get(&the_class.get_metadata_token())
                    .and_then(|m| m.get(&method.get_metadata_token()))
                    .and_then(|m| m.first())
            {
                let va = m_method.get_il2cpp_method().va();
                let Some(rva) =
                    asm_address::module_rva(va, *il2cpp::GA_BASE, game_assembly_slice().len())
                else {
                    log::warn!(
                        "[Proto Dumper] NetworkManager::Send2 is outside GameAssembly: va=0x{va:X}"
                    );
                    return 0;
                };
                log::debug!("[Proto Dumper] NetworkManager::Send2 => 0x{:X}", rva);
                return va;
            }
        }
    }

    log::debug!("[Proto Dumper] failed to get NetworkManager::Send2");
    0
});

pub static FIGHT_GAME_SEND: LazyLock<usize> = LazyLock::new(|| {
    let Some(global_vars_class) = get_cached_class("RPG.Client.GlobalVars") else {
        log::debug!("[Proto Dumper] GlobalVars not found; skipping FightGame::Send mapping");
        return 0;
    };
    let Ok(global_vars) = RuntimeType::from_class(global_vars_class) else {
        log::debug!(
            "[Proto Dumper] GlobalVars runtime type invalid; skipping FightGame::Send mapping"
        );
        return 0;
    };
    let Ok(multiplayer_manager) = global_vars.get_field("s_MultiplayerManager".into(), 62) else {
        log::debug!(
            "[Proto Dumper] s_MultiplayerManager not found; skipping FightGame::Send mapping"
        );
        return 0;
    };

    if !multiplayer_manager.is_null() {
        let multiplayer_manager = multiplayer_manager.get_field_type().unwrap();

        for method in multiplayer_manager.get_methods_il2cpp() {
            let params = method.get_parameters();
            if params.len() == 3
                && params[1].get_parameter_type().unwrap().il_name() == "System.UInt16"
            {
                let va = method.get_il2cpp_method().va();
                let method_name = method.get_name().unwrap().as_str();
                log::debug!("[Proto Dumper] FightGame::Send => {method_name}");
                return va;
            }
        }
    }

    log::debug!(
        "[Proto Dumper] failed to get FightGame::Send; continuing without fight request mapping"
    );
    0
});

static XLUA_OBJECT_TRANSLATOR_DELEGATE: LazyLock<Cow<'static, str>> = LazyLock::new(|| {
    let method_class_name = &*XLUA_OBJECT_TRANSLATOR_METHOD_CLASS;
    if method_class_name.is_empty() {
        return Cow::Borrowed("");
    }
    let Some(obj_translator_method_class) = get_cached_class(method_class_name) else {
        log::debug!("[Proto Dumper] XLua ObjectTranslator method class not found");
        return Cow::Borrowed("");
    };

    let Some(obj_translator_method_idx) = CLASS_TABLE_VEC
        .get()
        .unwrap()
        .iter()
        .position(|&v| v == obj_translator_method_class)
        .and_then(|index| index.checked_sub(1))
    else {
        log::debug!(
            "[Proto Dumper] failed to find XLUA_OBJECT_TRANSLATOR_METHOD_CLASS to get XLUA_OBJECT_TRANSLATOR_DELEGATE"
        );
        return Cow::Borrowed("");
    };

    let the_class =
        metadata_cache::get_typeinfo_from_typedefindex(obj_translator_method_idx as u32);

    let the_class_name = the_class.byval_arg().il_name();

    log::debug!("[Proto Dumper] XLUA_OBJECT_TRANSLATOR_DELEGATE => {the_class_name}");

    the_class_name
});

static XLUA_OBJECT_TRANSLATOR_METHOD_CLASS: LazyLock<Cow<'static, str>> = LazyLock::new(|| {
    let static_class_name = &*XLUA_OBJECT_TRANSLATOR_STATIC_FIELDS_CLASS;
    if static_class_name.is_empty() {
        return Cow::Borrowed("");
    }
    let Some(obj_translator_static_class) = get_cached_class(static_class_name) else {
        log::debug!("[Proto Dumper] XLua ObjectTranslator static class not found");
        return Cow::Borrowed("");
    };

    let Some(obj_translator_static_idx) = CLASS_TABLE_VEC
        .get()
        .unwrap()
        .iter()
        .position(|&v| v == obj_translator_static_class)
        .and_then(|index| index.checked_sub(1))
    else {
        log::debug!(
            "[Proto Dumper] failed to find XLUA_OBJECT_TRANSLATOR_STATIC_FIELDS_CLASS to get XLUA_OBJECT_TRANSLATOR_METHOD_CLASS"
        );
        return Cow::Borrowed("");
    };

    let the_class =
        metadata_cache::get_typeinfo_from_typedefindex(obj_translator_static_idx as u32);

    let the_class_name = the_class.byval_arg().il_name();

    log::debug!("[Proto Dumper] XLUA_OBJECT_TRANSLATOR_METHOD_CLASS => {the_class_name}");

    the_class_name
});

static XLUA_OBJECT_TRANSLATOR_STATIC_FIELDS_CLASS: LazyLock<Cow<'static, str>> = LazyLock::new(
    || {
        let Some(gen_13_wrap_class) = get_cached_class("XLua.CSObjectWrap.Gen_13_Wrap") else {
            log::debug!(
                "[Proto Dumper] XLua.CSObjectWrap.Gen_13_Wrap not found; request name translation will be skipped"
            );
            return Cow::Borrowed("");
        };

        let Some(gen_13_wrap_idx) = CLASS_TABLE_VEC
            .get()
            .unwrap()
            .iter()
            .position(|&v| v == gen_13_wrap_class)
            .and_then(|index| index.checked_sub(1))
        else {
            log::debug!(
                "[Proto Dumper] failed to find XLua.CSObjectWrap.Gen_13_Wrap to get XLUA_OBJECT_TRANSLATOR_STATIC_FIELDS_CLASS"
            );
            return Cow::Borrowed("");
        };

        let the_class = metadata_cache::get_typeinfo_from_typedefindex(gen_13_wrap_idx as u32);

        let the_class_name = the_class.byval_arg().il_name();

        log::debug!(
            "[Proto Dumper] XLUA_OBJECT_TRANSLATOR_STATIC_FIELDS_CLASS => {the_class_name}"
        );

        the_class_name
    },
);

const CODED_INPUT_STREAM: &str = "Google.Protobuf.CodedInputStream";
const MERGE_FROM: &str = "MergeFrom";
const CODED_OUTPUT_STREAM: &str = "Google.Protobuf.CodedOutputStream";
const WRITE_TO: &str = "WriteTo";
const UNKNOWN_FIELD_SET: &str = "Google.Protobuf.UnknownFieldSet";
const BYTE_STRING: &str = "Google.Protobuf.ByteString";
const PROTOBUF_ANY: &str = "MiHoYo.SDK.Protobuf.WellKnownTypes.Any";
const GET_COUNT_PROPERTY: &str = "Count";

pub struct MessageMinimalInfo {
    #[allow(unused)]
    pub cmd_id: u16,
    pub fields: Vec<FieldMinimalInfo>,
    pub write_to_rva: usize,
    pub merge_from_rva: usize,
}

impl MessageMinimalInfo {
    pub fn new(cmd_id: u16) -> Self {
        Self {
            cmd_id,
            fields: Vec::new(),
            write_to_rva: 0,
            merge_from_rva: 0,
        }
    }
}

pub struct FieldMinimalInfo {
    pub tag: u32,
    #[allow(unused)]
    pub xor: u32,
    pub offset: u32,
    pub oneof_extra_data: Option<OneofVariantInfo>,
    pub number_type: NumberType,
    pub property: Option<PropertyInfo>,
}

#[derive(Clone, Copy)]
pub enum NumberType {
    None,
    Varint,
    Normal,
    #[allow(unused)]
    ZigZagVarint,
}

pub struct OneofVariantInfo {
    pub oneof_enum_offset: u32,
    pub variant_type: RuntimeType,
    pub property: Option<PropertyInfo>,
}

#[allow(dead_code)]
pub enum ProtoDumpMode {
    ClassFieldNumber,
    MergeFrom,
    WriteTo,
    Asm,
}

#[allow(unused)]
pub fn dump<W: Write>(
    out: &mut W,
    cmdid_out: &mut W,
    dump_mode: ProtoDumpMode,
    enable_logging: bool,
) -> io::Result<()> {
    let progress = Progress::start("Proto").map_err(io::Error::other)?;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        dump_inner(out, cmdid_out, dump_mode, enable_logging, &progress)
    }))
    .unwrap_or_else(|payload| {
        let message = payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .unwrap_or("non-string panic");
        Err(io::Error::other(format!(
            "{}: panic: {message}",
            progress.summary()
        )))
    });
    progress.finish(&result);
    result
}

fn dump_inner<W: Write>(
    out: &mut W,
    cmdid_out: &mut W,
    dump_mode: ProtoDumpMode,
    enable_logging: bool,
    progress: &Progress,
) -> io::Result<()> {
    progress.stage("initialize type cache", 0);
    let type_cache = TypeCache::init();
    progress.stage("initialize proto stream", 0);
    proto_stream::init();

    log::debug!("[Proto Dumper] dumping minimal proto infos...");

    let mut minimal_info_map = HashMap::<RuntimeType, MessageMinimalInfo>::new();
    progress.stage("response/notify mapping", 0);
    let mut rsp_notify_map = nt::get_rsp_notify_map();
    let mut req_map = HashMap::<RuntimeType, (u16, Option<String>)>::new();

    let start = unsafe { il2cpp::RPG_NETWORK_PROTO_START };
    let end = unsafe { il2cpp::RPG_NETWORK_PROTO_END };
    progress.stage("minimal proto info", end.saturating_sub(start) as usize);
    for i in start..end {
        let proto_class = metadata_cache::get_typeinfo_from_typedefindex(i);
        progress.step((i - start) as usize, proto_class.0, "inspect proto class");
        let proto_type = RuntimeType::from_class(proto_class).unwrap();

        let Some(merge_from) = proto_type.find_method_il2cpp(MERGE_FROM) else {
            continue;
        };

        let proto_name = proto_type.il_name();

        if enable_logging {
            log::debug!("[Proto Dumper] Generating minimal info for proto {proto_name}");
        }

        let cmd_id = 0;
        let mut message_info = MessageMinimalInfo::new(cmd_id);
        let write_to_method =
            get_native_method(&format!("{proto_name}::{WRITE_TO}({CODED_OUTPUT_STREAM})"))
                .unwrap_or_else(|| panic!("{proto_name}::{WRITE_TO}({CODED_OUTPUT_STREAM})"));
        message_info.merge_from_rva =
            get_native_method(&format!("{proto_name}::{MERGE_FROM}({CODED_INPUT_STREAM})"))
                .unwrap_or_else(|| panic!("{proto_name}::{MERGE_FROM}({CODED_INPUT_STREAM})"))
                .rva();
        message_info.write_to_rva = write_to_method.rva();

        progress.step(
            (i - start) as usize,
            write_to_method.va(),
            "extract proto fields",
        );
        match dump_mode {
            ProtoDumpMode::ClassFieldNumber => {
                util::generate_minimal_info_from_constants(
                    proto_type,
                    &mut message_info,
                    &type_cache,
                );
            }
            ProtoDumpMode::Asm => {
                // Asm example
                proto_asm_parser::dump_from_write_to_asm(&proto_name, &mut message_info);
            }
            ProtoDumpMode::MergeFrom => {
                let proto_instance = proto_class.create_instance();
                proto_type
                    .find_method_il2cpp(".ctor")
                    .unwrap()
                    .get_il2cpp_method()
                    .invoke::<usize>(proto_instance, &[])
                    .unwrap();
                merge_from::dump_merge_from(
                    proto_type,
                    proto_instance,
                    &mut message_info,
                    &type_cache,
                );
            }
            ProtoDumpMode::WriteTo => {
                let ctor_method = get_native_method(&format!("{proto_name}::.ctor()"))
                    .unwrap_or_else(|| panic!("{proto_name}::.ctor()"));

                write_to::dump_writeto(
                    enable_logging,
                    i,
                    proto_type,
                    ctor_method,
                    write_to_method,
                    &mut message_info,
                );
            }
        }

        minimal_info_map.insert(proto_type, message_info);
    }

    log::debug!("[Proto Dumper] generating nt...");

    progress.stage("request name mapping", minimal_info_map.len());
    let req_rvas = nt::get_req_map(&minimal_info_map, &rsp_notify_map, &mut req_map, progress);
    let req_named_count = req_map.values().filter(|(_, name)| name.is_some()).count();
    log::debug!(
        "[Proto Dumper] req nt: req={}, nt={}",
        req_map.len(),
        req_named_count
    );

    progress.stage("response/notify names", rsp_notify_map.len());
    let response_mappings =
        nt::collect_rsp_notify_mappings(&minimal_info_map, progress).map_err(io::Error::other)?;
    let rsp_notify_names = &response_mappings.names;
    progress.stage("method handler names", 0);
    let (method_handler_map, method_nt_map) = method_nt::get_method_nt_map();

    progress.stage("prepare message names", minimal_info_map.len());
    let (cmd_ids, proto_name_map, type_to_item) = output::generate_protobuf(
        &type_cache,
        &minimal_info_map,
        &rsp_notify_map,
        &req_map,
        rsp_notify_names,
        &method_nt_map,
        &HashMap::new(),
        std::io::sink(),
    );

    let mut req_rsp_enum_nt = proto_name_map.clone();

    let cs_type_infos = {
        let mut result_map: HashMap<String, Vec<String>> = HashMap::new();
        let mut table_entries: Vec<(String, String, usize)> = Vec::new();

        for (rt, req_rvas) in &req_rvas {
            let valid_rvas: Vec<String> = req_rvas
                .iter()
                .filter(|rva| *rva != "0x0")
                .cloned()
                .collect();

            if valid_rvas.is_empty() {
                continue;
            }

            let formatted_name = rt.format_type_name(true);
            let obf_name = rt.il_name().into_owned();
            let deobf_name = proto_name_map
                .get(&formatted_name)
                .cloned()
                .unwrap_or_else(|| formatted_name.clone());
            result_map.insert(deobf_name.clone(), valid_rvas.clone());

            for rva_str in &valid_rvas {
                if let Ok(rva) = usize::from_str_radix(rva_str.trim_start_matches("0x"), 16) {
                    table_entries.push((obf_name.clone(), deobf_name.clone(), rva));
                }
            }
        }

        let _ = crate::proto::handler_nt::CS_HANDLER_TABLE.set(table_entries);

        result_map
    };

    let sc_packet_handlers = {
        progress.stage("response handler addresses", 0);
        let mut method_map: HashMap<RuntimeType, Vec<String>> = HashMap::new();
        let mut proto_param_map: HashMap<RuntimeType, Vec<String>> = HashMap::new();
        let rsp_notify_method_rvas = &response_mappings.method_rvas;

        let count = unsafe { il2cpp::MAX_TYPEDEFINDEX };
        progress.stage("scan handler parameters", count as usize);
        for i in 0..count {
            progress.step(i as usize, 0, "inspect handler class");
            if let Ok(runtime_type) =
                RuntimeType::from_class(metadata_cache::get_typeinfo_from_typedefindex(i))
            {
                for method in runtime_type.get_methods_il2cpp() {
                    progress.step(i as usize, method.0, "inspect handler method parameters");
                    let args = method.get_parameters();
                    for arg in args {
                        if let Ok(arg_type) = arg.get_parameter_type()
                            && arg_type != runtime_type
                        {
                            let rva = method.get_il2cpp_method().rva();
                            if rva != 0 {
                                method_map
                                    .entry(arg_type)
                                    .or_default()
                                    .push(format!("0x{rva:X}"));

                                if let Ok(arg_name) = arg.get_name()
                                    && arg_name.as_str() == "proto"
                                {
                                    proto_param_map
                                        .entry(arg_type)
                                        .or_default()
                                        .push(format!("0x{rva:X}"));
                                }
                            }
                        }
                    }
                }
            }
        }

        let mut result_map: HashMap<String, Vec<String>> = HashMap::new();
        for rt in rsp_notify_map.keys() {
            if let Some(handlers) = method_map.get(rt) {
                let formatted_name = rt.format_type_name(true);
                let key = rsp_notify_names
                    .get(&formatted_name)
                    .cloned()
                    .unwrap_or_else(|| rt.il_name().into_owned());

                result_map.insert(key, handlers.clone());
            }
        }
        for (formatted_name, cmd_rvas) in rsp_notify_method_rvas {
            for cmd_rva in cmd_rvas {
                if cmd_rva != "0x0" {
                    let key = rsp_notify_names
                        .get(formatted_name)
                        .cloned()
                        .unwrap_or(formatted_name.clone());

                    result_map.entry(key).or_default().push(cmd_rva.clone());
                }
            }
        }

        for (rt, handlers) in proto_param_map {
            let il_name = rt.il_name();
            if il_name.len() == 11 && il_name.chars().all(|c| c.is_ascii_uppercase()) {
                let formatted_name = rt.format_type_name(true);
                let key = rsp_notify_names
                    .get(&formatted_name)
                    .cloned()
                    .unwrap_or_else(|| il_name.into_owned());

                result_map.entry(key).or_default().extend(handlers);
            }
        }

        for (key, handlers) in method_handler_map {
            result_map.entry(key).or_default().extend(handlers);
        }

        result_map
    };

    progress.stage("global field names", 0);
    let mut proto_field_map = method_nt::dump_global_field_map();
    progress.stage("handler field names", type_to_item.len());
    for (k, v) in handler_nt::get_handler_nt_map(&type_to_item) {
        proto_field_map.entry(k).or_insert(v);
    }

    let logic_field_map = proto_field_map.clone();

    progress.stage("logic field names", type_to_item.len());
    logic_nt::run_logic_nt(
        &type_to_item.values().cloned().collect::<Vec<_>>(),
        &proto_name_map,
        &logic_field_map,
    );

    progress.stage("write handler metadata", 0);
    std::fs::write(
        "./DUMP/cs-type-infos.json",
        serde_json::to_string_pretty(&cs_type_infos)?,
    )?;

    std::fs::write(
        "./DUMP/sc-packet-handlers.json",
        serde_json::to_string_pretty(&sc_packet_handlers)?,
    )?;

    log::debug!("[Proto Dumper] generating protobuf...");
    progress.stage("write protobuf", minimal_info_map.len());

    let (cmd_ids_final, nt_map_final, _type_to_item) = output::generate_protobuf(
        &type_cache,
        &minimal_info_map,
        &rsp_notify_map,
        &req_map,
        rsp_notify_names,
        &method_nt_map,
        &proto_field_map,
        out,
    );

    for (obf_name, deobf_name) in nt_map_final {
        req_rsp_enum_nt
            .entry(obf_name)
            .or_insert_with(|| deobf_name);
    }

    progress.stage("write packet IDs", 0);
    writeln!(
        cmdid_out,
        "{}",
        serde_json::to_string_pretty(&cmd_ids_final)?
    )?;

    log::debug!("[Proto Dumper] Protos dumped!");

    Ok(())
}
