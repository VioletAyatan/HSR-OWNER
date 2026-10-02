//! These fixtures validate native provenance, not live Class/API identities.
//! Supplying a hand-built context is not a runtime ownership or naming proof.
use super::*;

const RVA: usize = 0x1000;
const CLASS: usize = 0x3000;
const OTHER_CLASS: usize = 0x3100;
const LITERAL: usize = 0x3200;
const OTHER_LITERAL: usize = 0x3300;
const ALLOCATOR: usize = 0x4000;
const UNKNOWN: usize = 0x5000;
const KEY_CALL: usize = 0x6000;

fn call(code: &mut Vec<u8>, target: usize) -> usize {
    let site = RVA + code.len();
    code.push(0xe8);
    code.extend_from_slice(
        &i32::try_from(target as i64 - (site + 5) as i64)
            .unwrap()
            .to_le_bytes(),
    );
    site
}

fn rip_load(code: &mut Vec<u8>, opcode: &[u8], slot: usize) -> usize {
    let site = RVA + code.len();
    code.extend_from_slice(opcode);
    code.extend_from_slice(
        &i32::try_from(slot as i64 - (RVA + code.len() + 4) as i64)
            .unwrap()
            .to_le_bytes(),
    );
    site
}

fn context() -> FactoryContext {
    FactoryContext {
        allocator_rva: ALLOCATOR,
        ..FactoryContext::default()
    }
}

fn run(code: &[u8], bytes: usize, context: &FactoryContext) -> ScanResult {
    scan_factory_planned_typed(
        code,
        RVA,
        &BTreeSet::new(),
        &BTreeMap::new(),
        &BTreeMap::new(),
        None,
        bytes,
        &BTreeSet::new(),
        context,
    )
}

fn allocated() -> (Vec<u8>, FactoryContext, usize) {
    let mut code = vec![0x48, 0x89, 0xce]; // RSI preserves the actual RCX Proto.
    let mut context = context();
    let site = rip_load(&mut code, &[0x48, 0x8b, 0x0d], CLASS);
    context.owner_class_loads.insert(site, CLASS);
    let allocator = call(&mut code, ALLOCATOR);
    (code, context, allocator)
}

fn key_call_prefix(bytes: usize) -> (Vec<u8>, FactoryContext, usize, usize) {
    let mut code = vec![0x48, 0x89, 0xce];
    let source = RVA + code.len();
    code.extend_from_slice(match bytes {
        1 => &[0x44, 0x0f, 0xb6, 0x46, 0x18], // movzx r8d,byte [rsi+24]
        4 => &[0x44, 0x8b, 0x46, 0x18],       // mov r8d,[rsi+24]
        8 => &[0x4c, 0x8b, 0x46, 0x18],       // mov r8,[rsi+24]
        _ => unreachable!(),
    });
    let literal = rip_load(&mut code, &[0x48, 0x8b, 0x15], LITERAL);
    let mut context = context();
    context.literal_loads.insert(literal, LITERAL);
    (code, context, source, literal)
}

#[test]
fn static_factory_requires_an_actual_owned_allocation_and_keeps_source_sites() {
    for bytes in [1, 4, 8] {
        let (mut code, context, _) = allocated();
        code.extend_from_slice(&[0x48, 0x89, 0xc7]); // RDI := owned return RAX.
        let load = RVA + code.len();
        code.extend_from_slice(match bytes {
            1 => &[0x0f, 0xb6, 0x46, 0x18],
            4 => &[0x8b, 0x46, 0x18],
            8 => &[0x48, 0x8b, 0x46, 0x18],
            _ => unreachable!(),
        });
        let store = RVA + code.len();
        code.extend_from_slice(match bytes {
            1 => &[0x88, 0x47, 0x4c],
            4 => &[0x89, 0x47, 0x4c],
            8 => &[0x48, 0x89, 0x47, 0x4c],
            _ => unreachable!(),
        });
        code.push(0xc3);
        let result = run(&code, bytes, &context);
        assert_eq!(result.rejected_paths, 0);
        assert_eq!(
            result.copies,
            [CopyEvidence {
                proto_offset: 24,
                business_offset: 76,
                load_rva: load,
                store_rva: store,
                setter_call: false,
            }]
        );
    }
    let no_allocation = [0x8b, 0x41, 0x18, 0x89, 0x41, 0x4c, 0xc3];
    assert!(run(&no_allocation, 4, &context()).copies.is_empty());
    // The original instance entry still treats RCX as its real receiver.
    assert_eq!(
        scan_typed(
            &[0x8b, 0x42, 0x18, 0x89, 0x41, 0x4c, 0xc3],
            RVA,
            Mode::Sync,
            4
        )
        .copies
        .len(),
        1
    );
}

#[test]
fn other_class_and_wrong_allocator_never_establish_the_owner() {
    for (slot, target) in [(OTHER_CLASS, ALLOCATOR), (CLASS, UNKNOWN)] {
        let mut code = vec![0x48, 0x89, 0xce];
        let mut context = context();
        let site = rip_load(&mut code, &[0x48, 0x8b, 0x0d], slot);
        if slot == CLASS {
            context.owner_class_loads.insert(site, slot);
        }
        call(&mut code, target);
        code.extend_from_slice(&[0x8b, 0x56, 0x18, 0x89, 0x50, 0x4c, 0xc3]);
        assert!(run(&code, 4, &context).copies.is_empty());
    }
}

#[test]
fn class_and_owner_registers_lose_proof_on_partial_arithmetic_or_unknown_writes() {
    for clobber in [&[0xb1, 1][..], &[0x31, 0xc9][..], &[0x48, 0x8b, 0x0e][..]] {
        let mut code = vec![0x48, 0x89, 0xce];
        let mut context = context();
        let site = rip_load(&mut code, &[0x48, 0x8b, 0x0d], CLASS);
        context.owner_class_loads.insert(site, CLASS);
        code.extend_from_slice(clobber);
        call(&mut code, ALLOCATOR);
        code.extend_from_slice(&[0x8b, 0x56, 0x18, 0x89, 0x50, 0x4c, 0xc3]);
        assert!(run(&code, 4, &context).copies.is_empty());
    }
    for clobber in [
        &[0x40, 0xb7, 1][..],
        &[0x31, 0xff][..],
        &[0x48, 0x8b, 0x3e][..],
    ] {
        let (mut code, context, _) = allocated();
        code.extend_from_slice(&[0x48, 0x89, 0xc7]);
        code.extend_from_slice(clobber);
        code.extend_from_slice(&[0x8b, 0x56, 0x18, 0x89, 0x57, 0x4c, 0xc3]);
        assert!(run(&code, 4, &context).copies.is_empty());
    }
}

#[test]
fn only_full_width_class_aliases_survive_abi_calls() {
    for alias in [&[0x48, 0x89, 0xcb][..], &[0x89, 0xcb][..]] {
        let mut code = vec![0x48, 0x89, 0xce];
        let mut context = context();
        let site = rip_load(&mut code, &[0x48, 0x8b, 0x0d], CLASS);
        context.owner_class_loads.insert(site, CLASS);
        code.extend_from_slice(alias);
        call(&mut code, UNKNOWN);
        code.extend_from_slice(&[0x48, 0x89, 0xd9]);
        call(&mut code, ALLOCATOR);
        code.extend_from_slice(&[0x8b, 0x56, 0x18, 0x89, 0x50, 0x4c, 0xc3]);
        assert_eq!(
            run(&code, 4, &context).copies.len(),
            usize::from(alias.len() == 3)
        );
    }
}

#[test]
fn owner_or_class_joined_with_unknown_is_not_proved() {
    let mut code = vec![0x48, 0x89, 0xce];
    let mut context = context();
    let site = rip_load(&mut code, &[0x48, 0x8b, 0x0d], CLASS);
    context.owner_class_loads.insert(site, CLASS);
    code.extend_from_slice(&[0x85, 0xd2, 0x74, 2, 0x31, 0xc9]);
    call(&mut code, ALLOCATOR);
    code.extend_from_slice(&[0x8b, 0x56, 0x18, 0x89, 0x50, 0x4c, 0xc3]);
    assert!(run(&code, 4, &context).copies.is_empty());

    let (mut code, context, _) = allocated();
    code.extend_from_slice(&[0x48, 0x89, 0xc7, 0x85, 0xd2, 0x74, 2, 0x31, 0xff]);
    code.extend_from_slice(&[0x8b, 0x56, 0x18, 0x89, 0x57, 0x4c, 0xc3]);
    assert!(run(&code, 4, &context).copies.is_empty());
}

#[test]
fn a_later_different_allocation_cannot_inherit_rax_ownership() {
    let (mut code, context, _) = allocated();
    code.extend_from_slice(&[0x48, 0x89, 0xc7]);
    rip_load(&mut code, &[0x48, 0x8b, 0x0d], OTHER_CLASS);
    call(&mut code, ALLOCATOR);
    let load = RVA + code.len();
    code.extend_from_slice(&[0x8b, 0x56, 0x18]);
    code.extend_from_slice(&[0x89, 0x50, 0x4c]); // wrong newly allocated class
    let store = RVA + code.len();
    code.extend_from_slice(&[0x89, 0x57, 0x50, 0xc3]); // original owned RDI
    assert_eq!(
        run(&code, 4, &context).copies,
        [CopyEvidence {
            proto_offset: 24,
            business_offset: 80,
            load_rva: load,
            store_rva: store,
            setter_call: false,
        }]
    );
}

#[test]
fn allocator_owner_return_is_absent_on_exception_edges_and_shared_targets() {
    let (mut code, context, allocator) = allocated();
    let normal = RVA + code.len();
    code.extend_from_slice(&[0x8b, 0x56, 0x18, 0x89, 0x50, 0x4c, 0xc3]);
    let exceptional = RVA + code.len();
    code.extend_from_slice(&[0x8b, 0x56, 0x1c, 0x89, 0x50, 0x50, 0xc3]);
    for (target, expected) in [(exceptional, 1), (normal, 0)] {
        let result = scan_factory_planned_typed(
            &code,
            RVA,
            &BTreeSet::new(),
            &BTreeMap::from([(allocator, vec![target])]),
            &BTreeMap::new(),
            None,
            4,
            &BTreeSet::new(),
            &context,
        );
        assert_eq!(result.rejected_paths, 0);
        assert_eq!(result.copies.len(), expected);
        assert!(result.copies.iter().all(|copy| copy.proto_offset == 24));
    }
}

#[test]
fn literal_key_calls_keep_exact_target_slot_and_all_typed_source_widths() {
    for bytes in [1, 4, 8] {
        let (mut code, context, source, _) = key_call_prefix(bytes);
        let site = call(&mut code, KEY_CALL);
        code.push(0xc3);
        let result = run(&code, bytes, &context);
        assert_eq!(result.rejected_paths, 0);
        assert_eq!(
            result.literal_key_calls,
            [LiteralKeyCall {
                call_rva: site,
                target_rva: KEY_CALL,
                proto_offset: 24,
                load_rva: source,
                literal_slot_rva: LITERAL,
            }]
        );
        assert!(result.copies.is_empty()); // no business owner or semantic binding
    }
}

#[test]
fn literal_or_proto_value_clobbers_do_not_leave_stale_key_calls() {
    for clobber in [
        &[0xb2, 1][..],
        &[0x31, 0xd2][..],
        &[0x48, 0x8b, 0x16][..],
        &[0x45, 0x31, 0xc0][..],
        &[0x41, 0x83, 0xc0, 1][..],
        &[0x41, 0xb0, 1][..],
    ] {
        let (mut code, context, _, _) = key_call_prefix(4);
        code.extend_from_slice(clobber);
        call(&mut code, KEY_CALL);
        code.push(0xc3);
        assert!(run(&code, 4, &context).literal_key_calls.is_empty());
    }
    let (mut code, context, _, _) = key_call_prefix(4);
    let unknown = call(&mut code, UNKNOWN);
    call(&mut code, KEY_CALL);
    code.push(0xc3);
    // The first call really receives both arguments, but this does not bind
    // its semantics. Its ABI clobber must remove proof from the later call.
    let result = run(&code, 4, &context);
    assert_eq!(result.literal_key_calls.len(), 1);
    assert_eq!(result.literal_key_calls[0].target_rva, UNKNOWN);
    assert_eq!(result.literal_key_calls[0].call_rva, unknown);
}

#[test]
fn literal_pointer_aliases_require_64_bits() {
    for alias in [&[0x48, 0x89, 0xd3][..], &[0x89, 0xd3][..]] {
        let (mut code, context, _, _) = key_call_prefix(4);
        code.extend_from_slice(alias);
        code.extend_from_slice(&[0x31, 0xd2, 0x48, 0x89, 0xda]);
        call(&mut code, KEY_CALL);
        code.push(0xc3);
        assert_eq!(
            run(&code, 4, &context).literal_key_calls.len(),
            usize::from(alias.len() == 3)
        );
    }
}

#[test]
fn differing_literals_or_proto_offsets_at_a_join_reject_key_calls() {
    let (mut code, mut context, _, _) = key_call_prefix(4);
    code.extend_from_slice(&[0x85, 0xc0, 0x74, 7]);
    let site = rip_load(&mut code, &[0x48, 0x8b, 0x15], OTHER_LITERAL);
    context.literal_loads.insert(site, OTHER_LITERAL);
    call(&mut code, KEY_CALL);
    code.push(0xc3);
    assert!(run(&code, 4, &context).literal_key_calls.is_empty());

    let (mut code, context, _, _) = key_call_prefix(4);
    code.extend_from_slice(&[0x85, 0xc0, 0x74, 4, 0x44, 0x8b, 0x46, 0x1c]);
    call(&mut code, KEY_CALL);
    code.push(0xc3);
    assert!(run(&code, 4, &context).literal_key_calls.is_empty());
}

#[test]
fn literal_calls_are_not_public_from_an_incomplete_or_truncated_cfg() {
    for suffix in [&[0x0f, 0x85, 0, 0, 0, 0x10][..], &[0x0f][..]] {
        let (mut code, context, _, _) = key_call_prefix(4);
        call(&mut code, KEY_CALL);
        code.extend_from_slice(suffix);
        let result = run(&code, 4, &context);
        assert!(result.rejected_paths > 0);
        assert!(result.literal_key_calls.is_empty());
        assert!(result.call_arguments.is_empty());
    }
}

#[test]
fn contextual_sites_must_match_exact_unprefixed_qword_rip_loads() {
    let (mut code, context, _) = allocated();
    code.push(0xc3);
    let class_site = *context.owner_class_loads.keys().next().unwrap();
    for (site, slot) in [
        (class_site + 1, CLASS),
        (class_site, OTHER_CLASS),
        (RVA, CLASS),
    ] {
        let bad = FactoryContext {
            allocator_rva: ALLOCATOR,
            owner_class_loads: BTreeMap::from([(site, slot)]),
            literal_loads: BTreeMap::new(),
        };
        let result = run(&code, 4, &bad);
        assert!(result.rejected_paths > 0);
        assert!(result.copies.is_empty() && result.literal_key_calls.is_empty());
    }
    let both = FactoryContext {
        allocator_rva: ALLOCATOR,
        owner_class_loads: BTreeMap::from([(class_site, CLASS)]),
        literal_loads: BTreeMap::from([(class_site, CLASS)]),
    };
    assert!(run(&code, 4, &both).rejected_paths > 0);
    assert!(run(&code, 4, &FactoryContext::default()).rejected_paths > 0);
    for opcode in [
        &[0x8b, 0x0d][..],
        &[0x65, 0x48, 0x8b, 0x0d][..],
        &[0xf3, 0x48, 0x8b, 0x0d][..],
    ] {
        let mut code = Vec::new();
        let site = rip_load(&mut code, opcode, CLASS);
        code.push(0xc3);
        let bad = FactoryContext {
            allocator_rva: ALLOCATOR,
            owner_class_loads: BTreeMap::from([(site, CLASS)]),
            literal_loads: BTreeMap::new(),
        };
        assert!(run(&code, 4, &bad).rejected_paths > 0);
    }
}

/// Disk-only replay. Explicit metadata slots and the observed allocator target
/// are mock context; this does not establish live Class/API identities.
#[test]
#[ignore = "requires explicit current DLL, reviewed report and output paths"]
fn replay_current_gateway_factory() -> anyhow::Result<()> {
    use super::super::{native_flow, native_pe, native_tail};
    use anyhow::{Context, ensure};
    use serde_json::json;
    use std::{
        fs::File,
        io::{BufRead, BufReader, Read, Seek, SeekFrom},
        path::PathBuf,
        time::Instant,
    };

    fn disk_image(path: &std::path::Path) -> anyhow::Result<Vec<u8>> {
        use anyhow::{Context, ensure};
        let mut file = File::open(path)?;
        let disk_len = usize::try_from(file.metadata()?.len())?;
        let mut read = |at: usize, len: usize| -> anyhow::Result<Vec<u8>> {
            ensure!(
                at.checked_add(len).is_some_and(|end| end <= disk_len),
                "disk PE range outside file"
            );
            let mut bytes = vec![0; len];
            file.seek(SeekFrom::Start(u64::try_from(at)?))?;
            file.read_exact(&mut bytes)?;
            Ok(bytes)
        };
        let dos = read(0, 64)?;
        ensure!(&dos[..2] == b"MZ", "DOS signature mismatch");
        let pe = u32::from_le_bytes(dos[60..64].try_into()?) as usize;
        let coff = read(pe, 24)?;
        ensure!(&coff[..4] == b"PE\0\0", "PE signature mismatch");
        ensure!(
            u16::from_le_bytes(coff[4..6].try_into()?) == 0x8664,
            "not AMD64"
        );
        let count = u16::from_le_bytes(coff[6..8].try_into()?) as usize;
        let optional_size = u16::from_le_bytes(coff[20..22].try_into()?) as usize;
        let optional_at = pe.checked_add(24).context("optional offset overflow")?;
        let optional = read(optional_at, optional_size)?;
        ensure!(optional_size >= 112, "short PE32+ optional header");
        ensure!(
            u16::from_le_bytes(optional[..2].try_into()?) == 0x20b,
            "not PE32+"
        );
        let image_len = u32::from_le_bytes(optional[56..60].try_into()?) as usize;
        let headers = u32::from_le_bytes(optional[60..64].try_into()?) as usize;
        ensure!(
            image_len > 0 && headers > 0 && headers <= image_len,
            "invalid image/header size"
        );
        let table_at = optional_at
            .checked_add(optional_size)
            .context("section table overflow")?;
        let table_len = count.checked_mul(40).context("section count overflow")?;
        ensure!(
            table_at
                .checked_add(table_len)
                .is_some_and(|end| end <= headers),
            "sections outside headers"
        );
        let sections = read(table_at, table_len)?;
        let mut image = Vec::new();
        image
            .try_reserve_exact(image_len)
            .context("mapped image allocation failed")?;
        image.resize(image_len, 0);
        image[..headers].copy_from_slice(&read(0, headers)?);
        for section in sections.chunks_exact(40) {
            let u32_at = |at| u32::from_le_bytes(section[at..at + 4].try_into().unwrap()) as usize;
            let virtual_len = u32_at(8);
            let rva = u32_at(12);
            let raw_len = u32_at(16);
            let raw_at = u32_at(20);
            ensure!(
                rva.checked_add(virtual_len.max(raw_len))
                    .is_some_and(|end| end <= image_len),
                "section outside image"
            );
            image[rva..rva + raw_len].copy_from_slice(&read(raw_at, raw_len)?);
        }
        Ok(image)
    }

    fn hex(value: &str) -> anyhow::Result<Vec<u8>> {
        ensure!(
            value.len() % 2 == 0 && value.is_ascii(),
            "invalid hex encoding"
        );
        (0..value.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&value[at..at + 2], 16).context("invalid hex byte"))
            .collect()
    }

    fn scan_json(scan: &ScanResult) -> serde_json::Value {
        json!({
            "copies": scan.copies.iter().map(|c| json!({
                "proto_offset": c.proto_offset, "business_offset": c.business_offset,
                "load_rva": c.load_rva, "store_rva": c.store_rva,
            })).collect::<Vec<_>>(),
            "literal_key_calls": scan.literal_key_calls.iter().map(|c| json!({
                "proto_offset": c.proto_offset, "load_rva": c.load_rva,
                "call_rva": c.call_rva, "target_rva": c.target_rva,
                "literal_slot_rva": c.literal_slot_rva,
            })).collect::<Vec<_>>(),
            "rejected_paths": scan.rejected_paths, "rejected_sites": scan.rejected_sites,
            "decoded": scan.decoded, "ambiguous": scan.ambiguous,
        })
    }

    let started = Instant::now();
    let report_path = PathBuf::from(std::env::var("HSR_GATEWAY_FACTORY_REPORT")?);
    let output_path = PathBuf::from(std::env::var("HSR_GATEWAY_FACTORY_OUT")?);
    let report: serde_json::Value = serde_json::from_reader(File::open(&report_path)?)?;
    let dll_path = PathBuf::from(
        report["sources"]["dll"]["path"]
            .as_str()
            .context("missing DLL path")?,
    );
    let script_path = PathBuf::from(
        report["sources"]["script_mini_current"]["path"]
            .as_str()
            .context("missing script path")?,
    );
    let image = disk_image(&dll_path)?;
    let pe = native_pe::Pe::new(&image, |_, _| Ok(()))?;
    let range = report["complete_pe_bounds"]
        .as_array()
        .context("missing bounds")?;
    ensure!(range.len() == 2, "invalid bounds");
    let rva = usize::try_from(range[0].as_u64().context("invalid start")?)?;
    let end = usize::try_from(range[1].as_u64().context("invalid end")?)?;
    let function = pe.function(rva)?;
    ensure!(
        function.start == rva && function.end == end && end > rva,
        "current full PE bounds differ"
    );
    let code = pe.bytes(rva, end - rva)?;
    ensure!(
        pe.executable(rva, code.len()),
        "body outside executable PE section"
    );
    let mut capture = Vec::new();
    for instruction in report["complete_native_disassembly"]
        .as_array()
        .context("missing reviewed bytes")?
    {
        ensure!(
            instruction["rva"].as_u64() == Some((rva + capture.len()) as u64),
            "reviewed instruction gap"
        );
        capture.extend(hex(instruction["bytes"]
            .as_str()
            .context("missing instruction bytes")?)?);
    }
    ensure!(
        capture == code,
        "current DLL bytes differ from reviewed full body"
    );

    // Stream addresses only; response/literal contents are neither read nor output.
    let mut entries = BTreeSet::new();
    let mut strings = BTreeSet::new();
    let mut section = "";
    for line in BufReader::new(File::open(script_path)?).lines() {
        let line = line?;
        let trimmed = line.trim();
        if line.starts_with("  \"Script") {
            section = if trimmed.starts_with("\"ScriptMethod\":") {
                "method"
            } else if trimmed.starts_with("\"ScriptString\":") {
                "string"
            } else {
                ""
            };
        }
        if !section.is_empty() && trimmed.starts_with("\"Address\":") {
            let address: usize = trimmed
                .split_once(':')
                .context("invalid address record")?
                .1
                .trim()
                .trim_end_matches(',')
                .parse()?;
            if address > 0 {
                if section == "method" {
                    entries.insert(address);
                } else {
                    strings.insert(address);
                }
            }
        }
    }
    ensure!(
        entries.contains(&rva),
        "factory entry absent from current ScriptMethod"
    );
    let mut context = FactoryContext::default();
    for binding in report["type_info_bindings"]
        .as_array()
        .context("missing type slots")?
    {
        if binding["metadata_symbol"].as_str() != Some("RPG.Client.ServerDispatchData_TypeInfo") {
            continue;
        }
        let slot = usize::try_from(binding["slot_rva"].as_u64().context("missing owner slot")?)?;
        for site in binding["load_sites"]
            .as_array()
            .context("missing owner load sites")?
        {
            context.owner_class_loads.insert(
                usize::try_from(site.as_u64().context("invalid load site")?)?,
                slot,
            );
        }
    }
    ensure!(
        !context.owner_class_loads.is_empty(),
        "no explicit reviewed mock owner slot"
    );
    let instructions: Vec<_> = Decoder::with_ip(64, code, rva as u64, DecoderOptions::NONE)
        .into_iter()
        .collect();
    let mut allocator_targets = BTreeSet::new();
    for (index, instruction) in instructions.iter().enumerate() {
        if context
            .owner_class_loads
            .contains_key(&(instruction.ip() as usize))
        {
            let call = instructions
                .get(index + 1)
                .context("owner load at end of body")?;
            ensure!(
                call.flow_control() == FlowControl::Call && call.op0_kind() == OpKind::NearBranch64,
                "reviewed class load not immediately followed by direct allocator"
            );
            allocator_targets.insert(call.near_branch_target() as usize);
        }
        if instruction.mnemonic() == Mnemonic::Mov
            && instruction.op0_kind() == OpKind::Register
            && instruction.op0_register().size() == 8
            && instruction.op1_kind() == OpKind::Memory
            && instruction.memory_size().size() == 8
            && instruction.is_ip_rel_memory_operand()
            && strings.contains(&(instruction.ip_rel_memory_address() as usize))
        {
            context.literal_loads.insert(
                instruction.ip() as usize,
                instruction.ip_rel_memory_address() as usize,
            );
        }
    }
    ensure!(
        allocator_targets.len() == 1,
        "nonunique observed mock allocator target"
    );
    context.allocator_rva = *allocator_targets.first().unwrap();
    let tail = native_tail::exits(code, rva, Some(rva..end), |target| {
        entries.contains(&target) && pe.function(target).is_ok() && pe.executable(target, 1)
    });
    let tail_exits = tail
        .as_ref()
        .map(|proof| {
            proof
                .exits
                .iter()
                .map(|exit| exit.site)
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    let mut resolver = native_flow::Resolver::new(
        native_pe::Pe::new(&image, |_, _| Ok(()))?,
        native_flow::Binding::DeclaredDisk,
    );
    let plan = resolver.plan(rva, code);
    let mut scans = Vec::new();
    let mut checked_target_copy = false;
    for bytes in [1, 4, 8] {
        let ordinary = scan_factory_planned_typed(
            code,
            rva,
            &BTreeSet::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
            None,
            bytes,
            &BTreeSet::new(),
            &context,
        );
        if let Ok(plan) = &plan {
            let planned = scan_factory_planned_typed(
                code,
                rva,
                &plan.terminal_calls,
                &plan.exceptional_edges,
                &plan.switch_edges,
                plan.code_bytes,
                bytes,
                &tail_exits,
                &context,
            );
            if bytes == 8 {
                checked_target_copy = !planned
                    .copies
                    .iter()
                    .any(|c| c.proto_offset == 40 && c.business_offset == 16)
                    && planned
                        .copies
                        .iter()
                        .any(|c| c.proto_offset == 312 && c.business_offset == 16);
            }
            let mut scan = scan_json(&planned);
            scan["bytes"] = json!(bytes);
            scan["ordinary"] = scan_json(&ordinary);
            scans.push(scan);
        } else {
            scans.push(json!({"bytes": bytes, "ordinary": scan_json(&ordinary), "planned_error": plan.as_ref().err().map(|error| format!("{error:#}"))}));
        }
    }
    let output = json!({
        "validation": if checked_target_copy { "target-owner-regression-passed" } else { "target-owner-regression-failed" },
        "report": report_path, "dll": dll_path, "expected_dll_sha256": report["sources"]["dll"]["sha256"],
        "current_full_pe_bytes_equal_reviewed": true, "bounds": [rva, end],
        "rva": rva, "body_end": end, "code_sha256": report["code_sha256"],
        "observed_allocator_rva": context.allocator_rva,
        "offline_mock_class_binding": true, "runtime_reflection_verified": false,
        "live_allocator_api_verified": false, "copy_is_recovered_name": false,
        "owner_class_loads": context.owner_class_loads, "literal_loads": context.literal_loads,
        "current_metadata_entry_count": entries.len(), "literal_slot_count": strings.len(),
        "plan": plan.as_ref().ok(), "plan_error": plan.as_ref().err().map(|error| format!("{error:#}")),
        "tail": tail.as_ref().ok(), "tail_error": tail.as_ref().err().map(|error| format!("{error:#}")),
        "scans": scans, "statistics": resolver.stats, "elapsed_seconds": started.elapsed().as_secs_f64(),
    });
    std::fs::write(&output_path, serde_json::to_vec_pretty(&output)?)?;
    println!("gateway factory replay output: {}", output_path.display());
    ensure!(
        checked_target_copy,
        "current typed target-owner regression not proven; inspect complete report"
    );
    Ok(())
}
