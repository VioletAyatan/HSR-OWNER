use std::{
    fs::OpenOptions,
    io::{BufWriter, Write},
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, ensure};
use il2cpp::vm::{array::Il2CppArray, object::Il2CppObject, value::Il2CppValue};
use reflection::{array::Array, runtime_type::RuntimeType, serializer::BoxedSerializer};
use serde::Serialize;
use serde_json::{Map, Value};

const BINDING_FLAGS_ALL_DECLARED: i32 = 62;
const MAX_LOG_ENTRIES: usize = 100_000;
const MAX_MESSAGE_FIELDS: usize = 128;
const MAX_AUXILIARY_ARRAY_ENTRIES: usize = 1_024;
const CONSOLE_SERVICE_TYPES: [&str; 2] = [
    "SRDebugger.Services.IConsoleService",
    "SRDebugger.Services.Implementation.StandardConsoleService",
];
static NEXT_REPORT_FILE: AtomicU64 = AtomicU64::new(1);
static NEXT_CAPTURE_RUN: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QaLogFieldKind {
    Message,
    Array,
    List,
}

impl QaLogFieldKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::Array => "array",
            Self::List => "list",
        }
    }

    fn is_collection(self) -> bool {
        matches!(self, Self::Array | Self::List)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeLogPhase {
    BeforeProtoExport,
    AfterProtoExport,
}

impl RuntimeLogPhase {
    pub fn label(self) -> &'static str {
        match self {
            Self::BeforeProtoExport => "before Proto export",
            Self::AfterProtoExport => "after Proto export",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::BeforeProtoExport => "before_proto_export",
            Self::AfterProtoExport => "after_proto_export",
        }
    }

    pub fn file_name(self) -> &'static str {
        match self {
            Self::BeforeProtoExport => "runtime-log-before-proto-export.json",
            Self::AfterProtoExport => "runtime-log-after-proto-export.json",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct RuntimeLogEntry {
    index: usize,
    runtime_type: String,
    proto_candidate: bool,
    value: Option<Value>,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct RuntimeBufferField {
    name: String,
    runtime_type: String,
    value: Option<Value>,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct CollectedRuntimeLogs {
    source: &'static str,
    process_id: u32,
    captured_unix_seconds: u64,
    game_version: Option<String>,
    game_assembly_base: String,
    service_resolution: String,
    service_type: String,
    buffer_type: String,
    buffer_address: String,
    array_type: String,
    array_address: String,
    entry_count: usize,
    proto_candidate_count: usize,
    buffer_scalar_fields: Vec<RuntimeBufferField>,
    entries: Vec<RuntimeLogEntry>,
}

#[derive(Debug, Serialize)]
struct QaManagerStaticField {
    name: String,
    runtime_type: String,
    address: Option<String>,
    is_null: bool,
    log_field_kind: Option<&'static str>,
    is_log_collection: bool,
    entry_count: usize,
    proto_candidate_count: usize,
    proto_candidate: bool,
    value: Option<Value>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct QaManagerEvidence {
    source: &'static str,
    process_id: u32,
    captured_unix_seconds: u64,
    game_version: Option<String>,
    game_assembly_base: String,
    manager_type: String,
    static_field_count: usize,
    log_field_count: usize,
    entry_count: usize,
    proto_candidate_count: usize,
    static_fields: Vec<QaManagerStaticField>,
}

#[derive(Debug, Serialize)]
struct RuntimeLogSource<T> {
    status: &'static str,
    evidence: Option<T>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct RuntimeLogReport {
    schema_version: u32,
    status: &'static str,
    capture_run_id: String,
    capture_phase: &'static str,
    console: RuntimeLogSource<CollectedRuntimeLogs>,
    qa_manager: RuntimeLogSource<QaManagerEvidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeLogSummary {
    pub status: &'static str,
    pub entry_count: usize,
    pub proto_candidate_count: usize,
}

pub fn new_capture_run_id() -> String {
    let unix_millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!(
        "{}-{unix_millis}-{}",
        std::process::id(),
        NEXT_CAPTURE_RUN.fetch_add(1, Ordering::Relaxed)
    )
}

pub fn dump(
    path: &Path,
    latest_path: &Path,
    phase: RuntimeLogPhase,
    capture_run_id: &str,
) -> anyhow::Result<RuntimeLogSummary> {
    let console = collect_safely("SRDebugger console", collect_console);
    let qa_manager = collect_safely("QAManager", collect_qa_manager);
    let entry_count = console.as_ref().map_or(0, |evidence| evidence.entry_count)
        + qa_manager
            .as_ref()
            .map_or(0, |evidence| evidence.entry_count);
    let proto_candidate_count = console
        .as_ref()
        .map_or(0, |evidence| evidence.proto_candidate_count)
        + qa_manager
            .as_ref()
            .map_or(0, |evidence| evidence.proto_candidate_count);
    let available_source_count = usize::from(console.is_ok()) + usize::from(qa_manager.is_ok());
    let status = report_status(available_source_count, entry_count);
    let errors = [console.as_ref().err(), qa_manager.as_ref().err()]
        .into_iter()
        .flatten()
        .map(|error| format!("{error:#}"))
        .collect::<Vec<_>>();
    let report = RuntimeLogReport {
        schema_version: 3,
        status,
        capture_run_id: capture_run_id.to_string(),
        capture_phase: phase.as_str(),
        console: source_report(console),
        qa_manager: source_report(qa_manager),
    };

    write_report_atomic(path, &report)?;
    write_report_atomic(latest_path, &report)?;

    ensure!(available_source_count > 0, "{}", errors.join("; "));
    Ok(RuntimeLogSummary {
        status,
        entry_count,
        proto_candidate_count,
    })
}

fn report_status(available_source_count: usize, entry_count: usize) -> &'static str {
    match (available_source_count, entry_count) {
        (0, _) => "unavailable",
        (1, 0) => "partial_empty",
        (_, 0) => "empty",
        (1, _) => "partial",
        _ => "collected",
    }
}

struct PendingReportFile(PathBuf);

impl Drop for PendingReportFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn write_report_atomic(path: &Path, report: &RuntimeLogReport) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create runtime log report directory {}", parent.display()))?;
    }
    let temporary_path = path.with_extension(format!(
        "json.runtime-log-part-{}-{}",
        std::process::id(),
        NEXT_REPORT_FILE.fetch_add(1, Ordering::Relaxed)
    ));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary_path)
        .with_context(|| {
            format!(
                "create temporary runtime log report {}",
                temporary_path.display()
            )
        })?;
    let pending = PendingReportFile(temporary_path);
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, report)
        .with_context(|| format!("serialize runtime log report {}", path.display()))?;
    writer
        .flush()
        .with_context(|| format!("flush runtime log report {}", pending.0.display()))?;
    drop(writer);
    std::fs::rename(&pending.0, path)
        .with_context(|| format!("publish runtime log report {}", path.display()))?;
    Ok(())
}

fn source_report<T>(result: anyhow::Result<T>) -> RuntimeLogSource<T> {
    match result {
        Ok(evidence) => RuntimeLogSource {
            status: "collected",
            evidence: Some(evidence),
            error: None,
        },
        Err(error) => RuntimeLogSource {
            status: "unavailable",
            evidence: None,
            error: Some(format!("{error:#}")),
        },
    }
}

fn collect_safely<T>(
    label: &str,
    mut collector: impl FnMut() -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    match microseh::try_seh(|| catch_unwind(AssertUnwindSafe(&mut collector))) {
        Ok(Ok(result)) => result,
        Ok(Err(payload)) => {
            let message = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("unknown panic payload");
            Err(anyhow::anyhow!(
                "{label} runtime log probe panicked: {message}"
            ))
        }
        Err(error) => Err(anyhow::anyhow!(
            "{label} runtime log probe raised SEH exception: {error:?}"
        )),
    }
}

fn invoke_i32_getter(
    ty: RuntimeType,
    object: Il2CppObject,
    method_name: &str,
) -> anyhow::Result<i32> {
    let method = ty
        .find_method_specific(method_name, BINDING_FLAGS_ALL_DECLARED, &[])
        .with_context(|| format!("{method_name}() is unavailable on {}", display_type(ty)))?;
    let value = method
        .get_il2cpp_method()
        .invoke::<Il2CppObject>(object, &[])
        .map_err(|error| anyhow::anyhow!("invoke {method_name}(): {error:?}"))?;
    ensure!(!value.is_null(), "{method_name}() returned null");
    Ok(value.unbox::<i32>())
}

fn collect_console() -> anyhow::Result<CollectedRuntimeLogs> {
    let (service, service_resolution) = resolve_console_service()?;

    let service_type = RuntimeType::from_object(service).context("resolve console service type")?;
    let get_all_entries = service_type
        .find_method_specific("get_AllEntries", BINDING_FLAGS_ALL_DECLARED, &[])
        .context("console service get_AllEntries() is unavailable")?;
    let buffer = get_all_entries
        .get_il2cpp_method()
        .invoke::<Il2CppObject>(service, &[])
        .map_err(|error| anyhow::anyhow!("invoke console service get_AllEntries(): {error:?}"))?;
    ensure!(
        !buffer.is_null(),
        "console service returned a null log buffer"
    );

    let buffer_type = RuntimeType::from_object(buffer).context("resolve console buffer type")?;
    let buffer_capacity = invoke_i32_getter(buffer_type, buffer, "get_Capacity")?;
    let observed_count = invoke_i32_getter(buffer_type, buffer, "get_Count")?;
    ensure!(
        buffer_capacity >= 0,
        "console log buffer reported a negative capacity"
    );
    ensure!(
        observed_count >= 0,
        "console log buffer reported a negative count"
    );
    let buffer_capacity = buffer_capacity as usize;
    let observed_count = observed_count as usize;
    ensure!(
        buffer_capacity <= MAX_LOG_ENTRIES,
        "console log buffer capacity {buffer_capacity} exceeds safety limit {MAX_LOG_ENTRIES}"
    );
    ensure!(
        observed_count <= buffer_capacity,
        "console log buffer count {observed_count} exceeds capacity {buffer_capacity}"
    );
    let to_array = buffer_type
        .find_method_specific("ToArray", BINDING_FLAGS_ALL_DECLARED, &[])
        .context("console log buffer ToArray() is unavailable")?;
    let array = to_array
        .get_il2cpp_method()
        .invoke::<Il2CppObject>(buffer, &[])
        .map_err(|error| anyhow::anyhow!("invoke console log buffer ToArray(): {error:?}"))?;
    ensure!(!array.is_null(), "console log buffer returned a null array");

    let array_type = RuntimeType::from_object(array).context("resolve console entry array type")?;
    ensure!(
        array_type.get_isarray()?.unbox(),
        "console log buffer ToArray() returned a non-array type: {}",
        display_type(array_type)
    );
    let entry_type = array_type
        .get_element_type()
        .context("resolve console entry array element type")?;
    let entry_count = Il2CppArray(array.0).len();
    ensure!(
        entry_count <= buffer_capacity,
        "console log snapshot count {entry_count} exceeds prechecked capacity {buffer_capacity}"
    );

    let mut serializer = BoxedSerializer::new2(false);
    let mut entries = Vec::with_capacity(entry_count);
    for (index, object) in Array(array.0).iter(Some(entry_count as i32)).enumerate() {
        if object.is_null() {
            entries.push(RuntimeLogEntry {
                index,
                runtime_type: display_type(entry_type),
                proto_candidate: false,
                value: None,
                error: Some("null console entry".into()),
            });
            continue;
        }

        let actual_type = RuntimeType::from_object(object).unwrap_or(entry_type);
        match serializer.serialize(entry_type, object) {
            Ok(value) => entries.push(RuntimeLogEntry {
                index,
                runtime_type: display_type(actual_type),
                proto_candidate: is_proto_log_candidate(&value.to_string()),
                value: Some(value),
                error: None,
            }),
            Err(error) => entries.push(RuntimeLogEntry {
                index,
                runtime_type: display_type(actual_type),
                proto_candidate: false,
                value: None,
                error: Some(format!("{error:#}")),
            }),
        }
    }

    let proto_candidate_count = entries.iter().filter(|entry| entry.proto_candidate).count();

    Ok(CollectedRuntimeLogs {
        source: "SRServiceManager.GetService(Type) -> StandardConsoleService.get_AllEntries() -> CircularBuffer<ConsoleEntry>.ToArray()",
        process_id: std::process::id(),
        captured_unix_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        game_version: catch_unwind(AssertUnwindSafe(|| {
            crate::version::GAME_VERSION.to_string()
        }))
        .ok(),
        game_assembly_base: format!("0x{:X}", *il2cpp::GA_BASE),
        service_resolution,
        service_type: display_type(service_type),
        buffer_type: display_type(buffer_type),
        buffer_address: format!("0x{:X}", buffer.0),
        array_type: display_type(array_type),
        array_address: format!("0x{:X}", array.0),
        entry_count,
        proto_candidate_count,
        buffer_scalar_fields: collect_scalar_fields(buffer_type, buffer),
        entries,
    })
}

fn collect_qa_manager() -> anyhow::Result<QaManagerEvidence> {
    let manager_type = runtime_type("RPG.QA.QAManager")?;
    let fields = manager_type
        .get_fields_checked(BINDING_FLAGS_ALL_DECLARED)
        .context("enumerate QAManager fields")?;
    let mut static_fields = Vec::new();

    for field in fields {
        if !field.get_isstatic().is_ok_and(|value| value.unbox())
            || field.get_isliteral().is_ok_and(|value| value.unbox())
        {
            continue;
        }

        let name = field
            .get_name()
            .map(|value| value.as_str().into_owned())
            .unwrap_or_else(|_| "<unreadable>".to_string());
        let field_type = match field.get_field_type() {
            Ok(field_type) => field_type,
            Err(error) => {
                static_fields.push(QaManagerStaticField {
                    name,
                    runtime_type: "<unreadable>".to_string(),
                    address: None,
                    is_null: true,
                    log_field_kind: None,
                    is_log_collection: false,
                    entry_count: 0,
                    proto_candidate_count: 0,
                    proto_candidate: false,
                    value: None,
                    error: Some(format!("read field type: {error:?}")),
                });
                continue;
            }
        };
        let runtime_type = display_type(field_type);
        let log_field_kind = qa_log_field_kind(&runtime_type);
        let is_log_collection = log_field_kind.is_some_and(QaLogFieldKind::is_collection);
        let should_serialize = log_field_kind.is_some()
            || is_scalar(field_type)
            || is_qa_auxiliary_collection_type(&runtime_type);

        let object = match field.get_value(Il2CppObject::NULL) {
            Ok(object) => object,
            Err(error) => {
                static_fields.push(QaManagerStaticField {
                    name,
                    runtime_type,
                    address: None,
                    is_null: true,
                    log_field_kind: log_field_kind.map(QaLogFieldKind::as_str),
                    is_log_collection,
                    entry_count: 0,
                    proto_candidate_count: 0,
                    proto_candidate: false,
                    value: None,
                    error: Some(format!("read static field: {error:?}")),
                });
                continue;
            }
        };

        if object.is_null() || !should_serialize {
            static_fields.push(QaManagerStaticField {
                name,
                runtime_type,
                address: (!object.is_null()).then(|| format!("0x{:X}", object.0)),
                is_null: object.is_null(),
                log_field_kind: log_field_kind.map(QaLogFieldKind::as_str),
                is_log_collection,
                entry_count: 0,
                proto_candidate_count: 0,
                proto_candidate: false,
                value: None,
                error: None,
            });
            continue;
        }

        if let Some(kind) = log_field_kind {
            let label = format!("QAManager field {name}");
            match collect_safely(&label, || serialize_qa_log_field(kind, field_type, object)) {
                Ok(serialized) => static_fields.push(QaManagerStaticField {
                    name,
                    runtime_type,
                    address: Some(format!("0x{:X}", object.0)),
                    is_null: false,
                    log_field_kind: Some(kind.as_str()),
                    is_log_collection,
                    entry_count: serialized.entry_count,
                    proto_candidate_count: serialized.proto_candidate_count,
                    proto_candidate: serialized.proto_candidate_count > 0,
                    value: serialized.value,
                    error: serialized.error,
                }),
                Err(error) => static_fields.push(QaManagerStaticField {
                    name,
                    runtime_type,
                    address: Some(format!("0x{:X}", object.0)),
                    is_null: false,
                    log_field_kind: Some(kind.as_str()),
                    is_log_collection,
                    entry_count: 0,
                    proto_candidate_count: 0,
                    proto_candidate: false,
                    value: None,
                    error: Some(format!("snapshot log field: {error:#}")),
                }),
            }
            continue;
        }

        let label = format!("QAManager field {name}");
        let value = collect_safely(&label, || {
            if is_qa_auxiliary_collection_type(&runtime_type) {
                serialize_bounded_auxiliary_array(field_type, object)
            } else {
                let mut serializer = BoxedSerializer::new2(false);
                serializer.serialize(field_type, object)
            }
        });
        match value {
            Ok(value) => static_fields.push(QaManagerStaticField {
                name,
                runtime_type,
                address: Some(format!("0x{:X}", object.0)),
                is_null: false,
                log_field_kind: None,
                is_log_collection: false,
                entry_count: 0,
                proto_candidate_count: 0,
                proto_candidate: false,
                value: Some(value),
                error: None,
            }),
            Err(error) => static_fields.push(QaManagerStaticField {
                name,
                runtime_type,
                address: Some(format!("0x{:X}", object.0)),
                is_null: false,
                log_field_kind: None,
                is_log_collection: false,
                entry_count: 0,
                proto_candidate_count: 0,
                proto_candidate: false,
                value: None,
                error: Some(format!("serialize static field: {error:#}")),
            }),
        }
    }

    let log_field_count = static_fields
        .iter()
        .filter(|field| field.log_field_kind.is_some())
        .count();
    let entry_count = static_fields.iter().map(|field| field.entry_count).sum();
    ensure!(
        entry_count <= MAX_LOG_ENTRIES,
        "QAManager log entry count {entry_count} exceeds safety limit {MAX_LOG_ENTRIES}"
    );
    let proto_candidate_count = static_fields
        .iter()
        .map(|field| field.proto_candidate_count)
        .sum();

    Ok(QaManagerEvidence {
        source: "RPG.QA.QAManager bounded static-field snapshots",
        process_id: std::process::id(),
        captured_unix_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        game_version: catch_unwind(AssertUnwindSafe(|| {
            crate::version::GAME_VERSION.to_string()
        }))
        .ok(),
        game_assembly_base: format!("0x{:X}", *il2cpp::GA_BASE),
        manager_type: display_type(manager_type),
        static_field_count: static_fields.len(),
        log_field_count,
        entry_count,
        proto_candidate_count,
        static_fields,
    })
}

struct SerializedQaLogField {
    entry_count: usize,
    proto_candidate_count: usize,
    value: Option<Value>,
    error: Option<String>,
}

fn serialize_qa_log_field(
    kind: QaLogFieldKind,
    field_type: RuntimeType,
    object: Il2CppObject,
) -> anyhow::Result<SerializedQaLogField> {
    let records = snapshot_qa_log_records(kind, field_type, object)?;
    let observed_count = records.len();
    let mut values = Vec::with_capacity(observed_count);
    let mut errors = Vec::new();

    for (index, record) in records.into_iter().enumerate() {
        if record.is_null() {
            values.push(Value::Null);
            errors.push(format!("entry {index}: null message"));
            continue;
        }
        let message_type = RuntimeType::from_object(record)
            .with_context(|| format!("entry {index}: resolve message type"))?;
        let label = format!("QAManager message entry {index}");
        match collect_safely(&label, || serialize_qa_message(message_type, record)) {
            Ok(value) => values.push(value),
            Err(error) => {
                values.push(Value::Null);
                errors.push(format!("entry {index}: {error:#}"));
            }
        }
    }

    let value = match kind {
        QaLogFieldKind::Message => values.into_iter().next(),
        QaLogFieldKind::Array | QaLogFieldKind::List => Some(Value::Array(values)),
    };
    let entry_count = match (kind, value.as_ref()) {
        (QaLogFieldKind::Message, Some(value)) => serialized_record_count(kind, value),
        (QaLogFieldKind::Message, None) => 0,
        (QaLogFieldKind::Array | QaLogFieldKind::List, _) => observed_count,
    };
    let proto_candidate_count = value.as_ref().map_or(0, |value| {
        serialized_record_proto_candidate_count(kind, value)
    });

    Ok(SerializedQaLogField {
        entry_count,
        proto_candidate_count,
        value,
        error: (!errors.is_empty()).then(|| errors.join("; ")),
    })
}

fn snapshot_qa_log_records(
    kind: QaLogFieldKind,
    field_type: RuntimeType,
    object: Il2CppObject,
) -> anyhow::Result<Vec<Il2CppObject>> {
    match kind {
        QaLogFieldKind::Message => Ok(vec![object]),
        QaLogFieldKind::Array => {
            let element_type = field_type
                .get_element_type()
                .context("resolve QAManager message array element type")?;
            ensure!(
                is_qa_message_type(&display_type(element_type)),
                "QAManager array element is not an exact Message type: {}",
                display_type(element_type)
            );
            bounded_reference_array_snapshot(object, MAX_LOG_ENTRIES)
        }
        QaLogFieldKind::List => snapshot_qa_message_list(field_type, object),
    }
}

fn snapshot_qa_message_list(
    list_type: RuntimeType,
    list: Il2CppObject,
) -> anyhow::Result<Vec<Il2CppObject>> {
    let generic_arguments = list_type.get_generic_arguments();
    ensure!(
        generic_arguments.len() == 1 && is_qa_message_type(&display_type(generic_arguments[0])),
        "QAManager list does not have one exact Message generic argument"
    );
    let size_field = ["_size", "size"]
        .into_iter()
        .find_map(|name| {
            list_type
                .get_field(name.into(), BINDING_FLAGS_ALL_DECLARED)
                .ok()
        })
        .context("QAManager message list size field is unavailable")?;
    let items_field = ["_items", "items"]
        .into_iter()
        .find_map(|name| {
            list_type
                .get_field(name.into(), BINDING_FLAGS_ALL_DECLARED)
                .ok()
        })
        .context("QAManager message list backing array field is unavailable")?;
    let size = size_field
        .get_value(list)
        .context("read QAManager message list size")?
        .unbox::<i32>();
    ensure!(size >= 0, "QAManager message list reported a negative size");
    let size = size as usize;
    ensure!(
        size <= MAX_LOG_ENTRIES,
        "QAManager message list size {size} exceeds safety limit {MAX_LOG_ENTRIES}"
    );
    let items = items_field
        .get_value(list)
        .context("read QAManager message list backing array")?;
    if size == 0 {
        return Ok(Vec::new());
    }
    ensure!(
        !items.is_null(),
        "QAManager message list has a null backing array with size {size}"
    );
    let capacity = Il2CppArray(items.0).len();
    ensure!(
        size <= capacity,
        "QAManager message list size {size} exceeds backing capacity {capacity}"
    );
    bounded_reference_array_snapshot_with_len(items, size)
}

fn bounded_reference_array_snapshot(
    array: Il2CppObject,
    limit: usize,
) -> anyhow::Result<Vec<Il2CppObject>> {
    ensure!(!array.is_null(), "cannot snapshot a null managed array");
    let len = Il2CppArray(array.0).len();
    ensure!(
        len <= limit,
        "managed array length {len} exceeds safety limit {limit}"
    );
    bounded_reference_array_snapshot_with_len(array, len)
}

fn bounded_reference_array_snapshot_with_len(
    array: Il2CppObject,
    len: usize,
) -> anyhow::Result<Vec<Il2CppObject>> {
    let len_i32 = i32::try_from(len).context("managed array length does not fit i32")?;
    Ok(Array(array.0).iter(Some(len_i32)).collect())
}

fn serialize_qa_message(message_type: RuntimeType, message: Il2CppObject) -> anyhow::Result<Value> {
    ensure!(
        is_qa_message_type(&display_type(message_type)),
        "runtime object is not an exact QAManager.Message: {}",
        display_type(message_type)
    );
    let fields = message_type
        .get_fields_checked(BINDING_FLAGS_ALL_DECLARED)
        .context("enumerate QAManager.Message fields")?;
    ensure!(
        fields.len() <= MAX_MESSAGE_FIELDS,
        "QAManager.Message field count {} exceeds safety limit {MAX_MESSAGE_FIELDS}",
        fields.len()
    );
    let mut values = Map::new();
    for field in fields {
        if field.get_isstatic().is_ok_and(|value| value.unbox())
            || field.get_isliteral().is_ok_and(|value| value.unbox())
        {
            continue;
        }
        let field_type = field
            .get_field_type()
            .context("read QAManager.Message field type")?;
        if !is_scalar(field_type) {
            continue;
        }
        let name = field
            .get_name()
            .context("read QAManager.Message field name")?
            .as_str()
            .into_owned();
        let object = field
            .get_value(message)
            .with_context(|| format!("read QAManager.Message field {name}"))?;
        if object.is_null() {
            values.insert(name, Value::Null);
            continue;
        }
        let mut serializer = BoxedSerializer::new2(false);
        let value = serializer
            .serialize(field_type, object)
            .with_context(|| format!("serialize QAManager.Message field {name}"))?;
        values.insert(name, value);
    }
    Ok(Value::Object(values))
}

fn serialize_bounded_auxiliary_array(
    field_type: RuntimeType,
    object: Il2CppObject,
) -> anyhow::Result<Value> {
    ensure!(
        field_type.get_isarray()?.unbox(),
        "QAManager auxiliary value is not an array"
    );
    let len = Il2CppArray(object.0).len();
    ensure!(
        len <= MAX_AUXILIARY_ARRAY_ENTRIES,
        "QAManager auxiliary array length {len} exceeds safety limit {MAX_AUXILIARY_ARRAY_ENTRIES}"
    );
    let mut serializer = BoxedSerializer::new2(false);
    serializer.serialize(field_type, object)
}

fn resolve_console_service() -> anyhow::Result<(Il2CppObject, String)> {
    let get_service =
        il2cpp::get_native_method("SRF.Service.SRServiceManager::GetService(System.Type)")
            .context("SRServiceManager.GetService(System.Type) is unavailable")?;
    let mut failures = Vec::new();
    for type_name in CONSOLE_SERVICE_TYPES {
        let service_type = runtime_type(type_name)?;
        match get_service.invoke::<Il2CppObject>(Il2CppObject::NULL, &[&service_type]) {
            Ok(service) if !service.is_null() => {
                return Ok((service, type_name.to_string()));
            }
            Ok(_) => failures.push(format!("{type_name}: returned null")),
            Err(error) => failures.push(format!("{type_name}: {error:?}")),
        }
    }
    Err(anyhow::anyhow!(
        "resolve console service: {}",
        failures.join("; ")
    ))
}

fn runtime_type(name: &str) -> anyhow::Result<RuntimeType> {
    let class =
        il2cpp::get_cached_class(name).with_context(|| format!("type not found: {name}"))?;
    RuntimeType::from_class(class).with_context(|| format!("create runtime type: {name}"))
}

fn collect_scalar_fields(ty: RuntimeType, object: Il2CppObject) -> Vec<RuntimeBufferField> {
    let mut serializer = BoxedSerializer::new2(false);
    ty.get_fields(BINDING_FLAGS_ALL_DECLARED)
        .into_iter()
        .filter_map(|field| {
            let name = field.get_name().ok()?.as_str().into_owned();
            let field_type = field.get_field_type().ok()?;
            if !is_scalar(field_type) {
                return None;
            }
            let value = field
                .get_value(object)
                .context("read field")
                .and_then(|value| serializer.serialize(field_type, value));
            Some(match value {
                Ok(value) => RuntimeBufferField {
                    name,
                    runtime_type: display_type(field_type),
                    value: Some(value),
                    error: None,
                },
                Err(error) => RuntimeBufferField {
                    name,
                    runtime_type: display_type(field_type),
                    value: None,
                    error: Some(format!("{error:#}")),
                },
            })
        })
        .collect()
}

fn is_scalar(ty: RuntimeType) -> bool {
    ty.get_isprimitive().is_ok_and(|value| value.unbox())
        || ty.get_isenum().is_ok_and(|value| value.unbox())
        || ty.il_name() == "System.String"
}

fn display_type(ty: RuntimeType) -> String {
    ty.format_type_name_with_namespace(true, false).into_owned()
}

fn qa_log_field_kind(type_name: &str) -> Option<QaLogFieldKind> {
    let type_name = type_name.to_ascii_lowercase().replace(' ', "");
    if is_qa_message_type(&type_name) {
        return Some(QaLogFieldKind::Message);
    }
    if [
        "rpg.qa.qamanager.message[]",
        "qamanager.message[]",
        "rpg.qa.qamanager+message[]",
        "qamanager+message[]",
    ]
    .contains(&type_name.as_str())
    {
        return Some(QaLogFieldKind::Array);
    }
    if [
        "system.collections.generic.list<rpg.qa.qamanager.message>",
        "system.collections.generic.list<qamanager.message>",
        "system.collections.generic.list<rpg.qa.qamanager+message>",
        "system.collections.generic.list<qamanager+message>",
    ]
    .contains(&type_name.as_str())
    {
        return Some(QaLogFieldKind::List);
    }
    None
}

fn is_qa_message_type(type_name: &str) -> bool {
    matches!(
        type_name.to_ascii_lowercase().replace(' ', "").as_str(),
        "rpg.qa.qamanager.message"
            | "qamanager.message"
            | "rpg.qa.qamanager+message"
            | "qamanager+message"
    )
}

fn is_qa_auxiliary_collection_type(type_name: &str) -> bool {
    matches!(
        type_name.to_ascii_lowercase().as_str(),
        "system.string[]" | "system.bool[]" | "system.boolean[]"
    )
}

fn serialized_record_count(kind: QaLogFieldKind, value: &Value) -> usize {
    match kind {
        QaLogFieldKind::Message => usize::from(value_has_record_content(value)),
        QaLogFieldKind::Array | QaLogFieldKind::List => value.as_array().map_or(0, Vec::len),
    }
}

fn serialized_record_proto_candidate_count(kind: QaLogFieldKind, value: &Value) -> usize {
    match kind {
        QaLogFieldKind::Message => usize::from(
            value_has_record_content(value) && is_proto_log_candidate(&value.to_string()),
        ),
        QaLogFieldKind::Array | QaLogFieldKind::List => value.as_array().map_or(0, |values| {
            values
                .iter()
                .filter(|value| {
                    value_has_record_content(value) && is_proto_log_candidate(&value.to_string())
                })
                .count()
        }),
    }
}

fn value_has_record_content(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(_) | Value::Number(_) => true,
        Value::String(value) => !value.is_empty(),
        Value::Array(values) => values.iter().any(value_has_record_content),
        Value::Object(values) => values.values().any(value_has_record_content),
    }
}

fn is_proto_log_candidate(text: &str) -> bool {
    let text = text.to_ascii_lowercase();
    [
        "cmdid",
        "codedoutputstream",
        "codedinputstream",
        "google.protobuf",
        "messageparser",
        "writeto(",
        "mergefrom(",
    ]
    .iter()
    .any(|marker| text.contains(marker))
}

#[cfg(test)]
mod tests {
    use super::{
        CONSOLE_SERVICE_TYPES, QaLogFieldKind, RuntimeLogPhase, is_proto_log_candidate,
        is_qa_auxiliary_collection_type, qa_log_field_kind, report_status, serialized_record_count,
        serialized_record_proto_candidate_count,
    };
    use serde_json::json;

    #[test]
    fn console_service_resolution_falls_back_to_concrete_implementation() {
        assert_eq!(
            CONSOLE_SERVICE_TYPES,
            [
                "SRDebugger.Services.IConsoleService",
                "SRDebugger.Services.Implementation.StandardConsoleService",
            ]
        );
    }

    #[test]
    fn qa_log_field_types_are_exact_and_separate() {
        assert_eq!(
            qa_log_field_kind("RPG.QA.QAManager.Message"),
            Some(QaLogFieldKind::Message)
        );
        assert_eq!(
            qa_log_field_kind("RPG.QA.QAManager.Message[]"),
            Some(QaLogFieldKind::Array)
        );
        assert_eq!(
            qa_log_field_kind("System.Collections.Generic.List<QAManager.Message>"),
            Some(QaLogFieldKind::List)
        );
        assert_eq!(
            qa_log_field_kind("System.Collections.Generic.HashSet<RPG.QA.QAManager.Message>"),
            None
        );
        assert_eq!(qa_log_field_kind("RPG.QA.QAManager.MessageMetadata"), None);
        assert_eq!(
            qa_log_field_kind("System.Collections.Generic.List<System.String>"),
            None
        );
    }

    #[test]
    fn qa_message_is_counted_once_per_record() {
        let record = json!({
            "message": "WriteTo(CodedOutputStream)",
            "stack": "Google.Protobuf.MessageParser"
        });
        assert_eq!(serialized_record_count(QaLogFieldKind::Message, &record), 1);
        assert_eq!(
            serialized_record_proto_candidate_count(QaLogFieldKind::Message, &record),
            1
        );
        assert_eq!(
            serialized_record_count(QaLogFieldKind::Message, &json!({})),
            0
        );
    }

    #[test]
    fn runtime_log_status_distinguishes_empty_partial_and_unavailable() {
        assert_eq!(report_status(0, 0), "unavailable");
        assert_eq!(report_status(1, 0), "partial_empty");
        assert_eq!(report_status(2, 0), "empty");
        assert_eq!(report_status(1, 2), "partial");
        assert_eq!(report_status(2, 2), "collected");
    }

    #[test]
    fn runtime_log_capture_phases_use_distinct_files() {
        assert_eq!(
            RuntimeLogPhase::BeforeProtoExport.file_name(),
            "runtime-log-before-proto-export.json"
        );
        assert_eq!(
            RuntimeLogPhase::AfterProtoExport.file_name(),
            "runtime-log-after-proto-export.json"
        );
        assert_ne!(
            RuntimeLogPhase::BeforeProtoExport.file_name(),
            RuntimeLogPhase::AfterProtoExport.file_name()
        );
    }

    #[test]
    fn qa_auxiliary_log_configuration_arrays_are_serializable() {
        assert!(is_qa_auxiliary_collection_type("System.string[]"));
        assert!(is_qa_auxiliary_collection_type("System.bool[]"));
        assert!(!is_qa_auxiliary_collection_type(
            "System.Collections.Generic.HashSet<int>"
        ));
        assert!(!is_qa_auxiliary_collection_type("RPG.Client.UIController"));
    }

    #[test]
    fn proto_log_candidates_require_specific_runtime_protocol_evidence() {
        assert!(is_proto_log_candidate(
            "Network recv CmdID=1234 RPG.Network.CsReq WriteTo(CodedOutputStream)"
        ));
        assert!(is_proto_log_candidate(
            "Google.Protobuf.MessageParser created for RPG.Network.SceneEntityInfo"
        ));
        assert!(!is_proto_log_candidate(
            "HTTP protocol packet cmd completed successfully"
        ));
        assert!(!is_proto_log_candidate("normal Unity render warning"));
    }
}
