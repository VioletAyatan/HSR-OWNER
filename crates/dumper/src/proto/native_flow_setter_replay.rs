//! Disk-only focused regression for direct Proto-field-to-property-setter calls.
//! This is a fixture test only; it does not perform name recovery or require a game.

use super::super::super::native_tail;
use super::*;
use anyhow::{Context, Result, ensure};
use iced_x86::{Decoder, DecoderOptions};
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs, path::PathBuf};

const OWNER: &str = "RPG.Client.GridFightPlayer";
const CALLER_SIGNATURE: &str = "SetData(NIHNGPKHEPC)";
const CALLER_RVA: usize = 0xDA442D0;
const SHARE_GETTER_SIGNATURE: &str = "get_AppliedGameRefShareCode()";
const SHARE_SETTER_SIGNATURE: &str = "set_AppliedGameRefShareCode(System.String)";
const SHARE_GETTER_RVA: usize = 0xDA49C90;
const SHARE_SETTER_RVA: usize = 0xDA455F0;
const GOLD_SETTER_SIGNATURE: &str = "set_Gold(System.Int32)";
const GOLD_SETTER_RVA: usize = 0xDA44E20;

fn readable(_: usize, _: usize) -> Result<()> {
    Ok(())
}

fn captured<'a>(input: &'a Input, signature: &str, rva: usize) -> Result<&'a Method> {
    let rows: Vec<_> = input
        .methods
        .iter()
        .filter(|method| {
            method.owner == OWNER && method.signature == signature && method.rva == rva
        })
        .collect();
    ensure!(
        rows.len() == 1,
        "expected one fixture row for {signature} at {rva:#X}"
    );
    Ok(rows[0])
}

fn arg_json(argument: &sync_scan::CallArgument) -> Value {
    json!({
        "call_rva": argument.call_rva,
        "target_rva": argument.target_rva,
        "argument_index": argument.argument_index,
        "receiver_is_business": argument.receiver_is_business,
        "proto_offset": argument.proto_offset,
        "load_rva": argument.load_rva,
    })
}

fn copy_json(copy: &sync_scan::CopyEvidence) -> Value {
    json!({
        "proto_offset": copy.proto_offset,
        "business_offset": copy.business_offset,
        "load_rva": copy.load_rva,
        "store_rva": copy.store_rva,
        "setter_call": copy.setter_call,
    })
}

fn instruction_context(code: &[u8], rva: usize, start: usize, end: usize) -> Vec<Value> {
    let mut decoder = Decoder::with_ip(64, code, rva as u64, DecoderOptions::NONE);
    let mut rows = Vec::new();
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            break;
        }
        let ip = instruction.ip() as usize;
        if (start..end).contains(&ip) {
            rows.push(json!({
                "rva": ip,
                "length": instruction.len(),
                "debug": format!("{instruction:?}"),
            }));
        }
    }
    rows
}

fn rejected_contexts(code: &[u8], rva: usize, sites: &[usize]) -> Vec<Value> {
    sites
        .iter()
        .map(|&site| {
            json!({
                "rva": site,
                "instructions": instruction_context(
                    code,
                    rva,
                    site.saturating_sub(0x20),
                    site.saturating_add(0x10),
                ),
            })
        })
        .collect()
}

fn tail_function_range(pe: &Pe<'_>, rva: usize) -> Result<std::ops::Range<usize>> {
    let function = pe
        .containing_function(rva)
        .context("caller has no current PE function")?;
    ensure!(
        function.start == rva,
        "caller RVA is not an exact current PE entry"
    );
    Ok(function.start..function.end)
}

#[test]
#[ignore = "requires HSR_PROTO_FLOW_DLL/INPUT/OUT; disk-only fixture replay, no game"]
fn replay_setter_call_field_evidence() -> Result<()> {
    let dll_path = PathBuf::from(std::env::var("HSR_PROTO_FLOW_DLL")?);
    let input_path = PathBuf::from(std::env::var("HSR_PROTO_FLOW_INPUT")?);
    let output_dir = PathBuf::from(std::env::var("HSR_PROTO_FLOW_OUT")?);
    let raw_input = fs::read(&input_path)?;
    let fixture_value: Value = serde_json::from_slice(&raw_input)?;
    let input: Input = serde_json::from_value(fixture_value.clone())?;
    let expectations = fixture_value
        .get("fixture_expectations")
        .context("missing fixture_expectations")?;
    ensure!(
        input.methods.len() == 4,
        "unexpected focused fixture method count"
    );

    let image = mapped_disk(&fs::read(&dll_path)?, input.image_size)?;
    let pe = Pe::new(&image, readable)?;
    let mut resolver = Resolver::new(pe, Binding::DeclaredDisk);

    let caller_method = captured(&input, CALLER_SIGNATURE, CALLER_RVA)?;
    let caller_code = validate_method(&resolver.pe, caller_method)?;
    ensure!(
        caller_code.len() == 2523,
        "SetData is not the expected complete function body"
    );
    let plan = resolver.plan(CALLER_RVA, &caller_code)?;
    let declared_tail_entries = expectations
        .get("declared_tail_entries")
        .and_then(Value::as_array)
        .context("missing declared_tail_entries")?;
    ensure!(
        declared_tail_entries.len() == 1,
        "expected one prepared declared tail entry"
    );
    let declared_tail = &declared_tail_entries[0];
    let tail_target = declared_tail
        .get("target_rva")
        .and_then(Value::as_u64)
        .context("declared tail target missing")? as usize;
    ensure!(
        declared_tail
            .get("script_method_entry_present")
            .and_then(Value::as_bool)
            == Some(true)
            && declared_tail
                .get("metadata_name")
                .and_then(Value::as_str)
                .is_some_and(|name| !name.is_empty())
            && declared_tail
                .get("script_method_input_sha256")
                .and_then(Value::as_str)
                .is_some_and(|hash| hash.len() == 64)
            && declared_tail
                .get("methods2_input_sha256")
                .and_then(Value::as_str)
                .is_some_and(|hash| hash.len() == 64)
            && declared_tail
                .get("code_sha256")
                .and_then(Value::as_str)
                .is_some_and(|hash| hash.len() == 64),
        "declared tail provenance is incomplete"
    );
    let tail_function = resolver
        .pe
        .containing_function(tail_target)
        .context("declared tail target has no current PE function")?;
    ensure!(
        tail_function.start == tail_target,
        "declared tail target is not an exact current PE function entry"
    );
    let recorded_bounds = declared_tail
        .get("function_bounds")
        .and_then(Value::as_array)
        .context("declared tail function bounds missing")?;
    ensure!(
        recorded_bounds.len() == 2
            && recorded_bounds[0].as_u64() == Some(tail_function.start as u64)
            && recorded_bounds[1].as_u64() == Some(tail_function.end as u64),
        "declared tail bounds differ from current PE"
    );
    let current_tail_code = resolver
        .pe
        .bytes(tail_function.start, tail_function.end - tail_function.start)?;
    let captured_tail_code = code(
        declared_tail
            .get("code")
            .and_then(Value::as_str)
            .context("declared tail body bytes missing")?,
    )?;
    ensure!(
        captured_tail_code == current_tail_code,
        "declared tail helper bytes differ from current PE"
    );
    ensure!(
        declared_tail.get("code_bytes").and_then(Value::as_u64)
            == Some(current_tail_code.len() as u64),
        "declared tail helper length differs from current PE"
    );
    let tail_proof = native_tail::exits(
        &caller_code,
        CALLER_RVA,
        Some(tail_function_range(&resolver.pe, CALLER_RVA)?),
        |target| {
            target == tail_target
                && resolver
                    .pe
                    .containing_function(target)
                    .is_some_and(|function| function.start == target)
        },
    )?;
    ensure!(
        tail_proof.exits.len() == 1
            && tail_proof.exits[0].target == tail_target
            && tail_proof.exits[0].site == 0xDA447A7,
        "caller tail exit proof differs from the prepared fixture"
    );
    let tail_sites: BTreeSet<_> = tail_proof.exits.iter().map(|exit| exit.site).collect();
    let ordinary_4 = sync_scan::scan_typed(&caller_code, CALLER_RVA, Mode::Sync, 4);
    let ordinary_8 = sync_scan::scan_typed(&caller_code, CALLER_RVA, Mode::Sync, 8);
    let planned_4 = sync_scan::scan_planned_typed(
        &caller_code,
        CALLER_RVA,
        Mode::Sync,
        &plan.terminal_calls,
        &plan.exceptional_edges,
        &plan.switch_edges,
        plan.code_bytes,
        4,
    );
    let planned_8 = sync_scan::scan_planned_typed(
        &caller_code,
        CALLER_RVA,
        Mode::Sync,
        &plan.terminal_calls,
        &plan.exceptional_edges,
        &plan.switch_edges,
        plan.code_bytes,
        8,
    );
    let planned_tail_4 = sync_scan::scan_planned_exits_typed(
        &caller_code,
        CALLER_RVA,
        Mode::Sync,
        &plan.terminal_calls,
        &plan.exceptional_edges,
        &plan.switch_edges,
        plan.code_bytes,
        4,
        &tail_sites,
    );
    let planned_tail_8 = sync_scan::scan_planned_exits_typed(
        &caller_code,
        CALLER_RVA,
        Mode::Sync,
        &plan.terminal_calls,
        &plan.exceptional_edges,
        &plan.switch_edges,
        plan.code_bytes,
        8,
        &tail_sites,
    );

    let diagnostic = json!({
        "phase": "before_setter_call_assertions",
        "source_dll": dll_path,
        "fixture_input": input_path,
        "caller": {"rva": CALLER_RVA, "bytes": caller_code.len()},
        "declared_tail_entry": declared_tail,
        "tail_proof": tail_proof,
        "instruction_contexts": {
            "prolog": instruction_context(&caller_code, CALLER_RVA, CALLER_RVA, CALLER_RVA + 0x40),
            "gold_call": instruction_context(&caller_code, CALLER_RVA, 0xDA44380, 0xDA443B0),
            "share_string_call": instruction_context(&caller_code, CALLER_RVA, 0xDA44730, 0xDA44770),
        },
        "plan": plan,
        "rejected_site_contexts": {
            "ordinary_4byte": rejected_contexts(&caller_code, CALLER_RVA, &ordinary_4.rejected_sites),
            "planned_4byte": rejected_contexts(&caller_code, CALLER_RVA, &planned_4.rejected_sites),
            "ordinary_8byte": rejected_contexts(&caller_code, CALLER_RVA, &ordinary_8.rejected_sites),
            "planned_8byte": rejected_contexts(&caller_code, CALLER_RVA, &planned_8.rejected_sites),
            "planned_tail_4byte": rejected_contexts(&caller_code, CALLER_RVA, &planned_tail_4.rejected_sites),
            "planned_tail_8byte": rejected_contexts(&caller_code, CALLER_RVA, &planned_tail_8.rejected_sites),
        },
        "ordinary_4byte": {
            "decoded": ordinary_4.decoded,
            "rejected_paths": ordinary_4.rejected_paths,
            "witnessed_call_arguments": ordinary_4.witnessed_call_arguments,
            "rejected_sites": ordinary_4.rejected_sites,
            "ambiguous": ordinary_4.ambiguous,
            "call_arguments": ordinary_4.call_arguments.iter().map(|argument| arg_json(argument)).collect::<Vec<_>>(),
            "copies": ordinary_4.copies.iter().map(|copy| copy_json(copy)).collect::<Vec<_>>(),
        },
        "planned_4byte": {
            "decoded": planned_4.decoded,
            "rejected_paths": planned_4.rejected_paths,
            "witnessed_call_arguments": planned_4.witnessed_call_arguments,
            "rejected_sites": planned_4.rejected_sites,
            "ambiguous": planned_4.ambiguous,
            "call_arguments": planned_4.call_arguments.iter().map(|argument| arg_json(argument)).collect::<Vec<_>>(),
            "copies": planned_4.copies.iter().map(|copy| copy_json(copy)).collect::<Vec<_>>(),
        },
        "ordinary_8byte": {
            "decoded": ordinary_8.decoded,
            "rejected_paths": ordinary_8.rejected_paths,
            "witnessed_call_arguments": ordinary_8.witnessed_call_arguments,
            "rejected_sites": ordinary_8.rejected_sites,
            "ambiguous": ordinary_8.ambiguous,
            "call_arguments": ordinary_8.call_arguments.iter().map(|argument| arg_json(argument)).collect::<Vec<_>>(),
            "copies": ordinary_8.copies.iter().map(|copy| copy_json(copy)).collect::<Vec<_>>(),
        },
        "planned_8byte": {
            "decoded": planned_8.decoded,
            "rejected_paths": planned_8.rejected_paths,
            "witnessed_call_arguments": planned_8.witnessed_call_arguments,
            "rejected_sites": planned_8.rejected_sites,
            "ambiguous": planned_8.ambiguous,
            "call_arguments": planned_8.call_arguments.iter().map(|argument| arg_json(argument)).collect::<Vec<_>>(),
            "copies": planned_8.copies.iter().map(|copy| copy_json(copy)).collect::<Vec<_>>(),
        },
        "planned_tail_4byte": {
            "decoded": planned_tail_4.decoded,
            "rejected_paths": planned_tail_4.rejected_paths,
            "witnessed_call_arguments": planned_tail_4.witnessed_call_arguments,
            "rejected_sites": planned_tail_4.rejected_sites,
            "ambiguous": planned_tail_4.ambiguous,
            "call_arguments": planned_tail_4.call_arguments.iter().map(|argument| arg_json(argument)).collect::<Vec<_>>(),
            "copies": planned_tail_4.copies.iter().map(|copy| copy_json(copy)).collect::<Vec<_>>(),
        },
        "planned_tail_8byte": {
            "decoded": planned_tail_8.decoded,
            "rejected_paths": planned_tail_8.rejected_paths,
            "witnessed_call_arguments": planned_tail_8.witnessed_call_arguments,
            "rejected_sites": planned_tail_8.rejected_sites,
            "ambiguous": planned_tail_8.ambiguous,
            "call_arguments": planned_tail_8.call_arguments.iter().map(|argument| arg_json(argument)).collect::<Vec<_>>(),
            "copies": planned_tail_8.copies.iter().map(|copy| copy_json(copy)).collect::<Vec<_>>(),
        },
        "interpretation_boundary": "The original scans preserve their rejection diagnostics. Tail-aware scans add only the current-PE and declared ScriptMethod exact-entry tail proof recorded above.",
    });
    fs::create_dir_all(&output_dir)?;
    fs::write(
        output_dir.join("setter-call-replay-diagnostic.json"),
        serde_json::to_vec_pretty(&diagnostic)?,
    )?;

    let positive = expectations
        .get("positive")
        .context("missing positive fixture expectation")?;
    let positive_call = positive
        .get("call_rva")
        .and_then(Value::as_u64)
        .context("positive call_rva missing")? as usize;
    ensure!(
        planned_tail_8.rejected_paths == 0,
        "tail-aware 8-byte scan still rejects reachable paths"
    );
    ensure!(
        planned_tail_4.rejected_paths == 0,
        "tail-aware 4-byte scan still rejects reachable paths"
    );
    let positive_arguments: Vec<_> = planned_tail_8
        .call_arguments
        .iter()
        .filter(|argument| {
            argument.call_rva == positive_call
                && argument.target_rva == SHARE_SETTER_RVA
                && argument.argument_index == 1
                && argument.receiver_is_business
                && argument.proto_offset == 80
        })
        .collect();
    ensure!(
        positive_arguments.len() == 1,
        "string setter call did not carry Proto offset 80 in RDX"
    );
    let positive_argument = positive_arguments[0];
    ensure!(
        positive_argument.load_rva == 0xDA4474A,
        "string field load site changed"
    );
    let positive_load_rva = positive_argument.load_rva;
    let positive_call_rva = positive_argument.call_rva;
    let positive_arguments_json: Vec<_> = positive_arguments
        .iter()
        .map(|argument| arg_json(argument))
        .collect();

    let negative = expectations
        .get("negative")
        .context("missing negative fixture expectation")?;
    let negative_call = negative
        .get("call_rva")
        .and_then(Value::as_u64)
        .context("negative call_rva missing")? as usize;
    let negative_arguments: Vec<_> = planned_tail_4
        .call_arguments
        .iter()
        .filter(|argument| {
            argument.call_rva == negative_call
                && argument.target_rva == GOLD_SETTER_RVA
                && argument.argument_index == 1
                && argument.receiver_is_business
                && argument.proto_offset == 92
        })
        .collect();
    ensure!(
        negative_arguments.len() == 1,
        "Gold call flow did not expose Proto offset 92"
    );
    let negative_arguments_json: Vec<_> = negative_arguments
        .iter()
        .map(|argument| arg_json(argument))
        .collect();
    drop(positive_arguments);
    drop(negative_arguments);

    let getter_method = captured(&input, SHARE_GETTER_SIGNATURE, SHARE_GETTER_RVA)?;
    let getter_code = validate_method(&resolver.pe, getter_method)?;
    let getter_scan = sync_scan::scan_typed(
        &getter_code,
        SHARE_GETTER_RVA,
        Mode::Getter,
        getter_method.scalar_bytes,
    );
    let setter_method = captured(&input, SHARE_SETTER_SIGNATURE, SHARE_SETTER_RVA)?;
    let setter_code = validate_method(&resolver.pe, setter_method)?;
    let setter_scan = sync_scan::scan_typed(
        &setter_code,
        SHARE_SETTER_RVA,
        Mode::Setter,
        setter_method.scalar_bytes,
    );
    ensure!(
        getter_scan.accessor_offset == Some(40),
        "getter no longer proves business offset 40"
    );
    ensure!(
        setter_scan.accessor_offset == Some(40),
        "setter no longer proves business offset 40"
    );
    let business_offset = getter_scan.accessor_offset.expect("checked getter offset");
    ensure!(
        setter_scan.accessor_offset == Some(business_offset),
        "getter and setter offset proofs disagree"
    );
    ensure!(
        positive.get("business_type").and_then(Value::as_str) == Some("System.String")
            && positive.get("proto_type").and_then(Value::as_str) == Some("string")
            && positive.get("business_offset").and_then(Value::as_u64) == Some(40),
        "positive typed fixture metadata changed"
    );

    let mut bound = planned_tail_8;
    bound.bind_setter_calls(8, |target| {
        (target == SHARE_SETTER_RVA).then_some((business_offset, 8))
    });
    let positive_copies: Vec<_> = bound
        .copies
        .iter()
        .filter(|copy| {
            copy.setter_call
                && copy.proto_offset == 80
                && copy.business_offset == 40
                && copy.load_rva == positive_load_rva
                && copy.store_rva == positive_call_rva
        })
        .collect();
    ensure!(
        positive_copies.len() == 1,
        "setter binding did not produce exact 80 -> 40 evidence"
    );
    ensure!(
        !bound
            .copies
            .iter()
            .any(|copy| copy.setter_call && copy.proto_offset == 92),
        "fixture metadata unexpectedly bound the Gold setter"
    );

    let gold_setter = captured(&input, GOLD_SETTER_SIGNATURE, GOLD_SETTER_RVA)?;
    let gold_code = validate_method(&resolver.pe, gold_setter)?;
    let gold_expectation = json!({
        "proto_type": negative.get("proto_type"),
        "business_type": negative.get("business_type"),
        "proto_offset": negative.get("proto_offset"),
        "setter_rva": GOLD_SETTER_RVA,
        "setter_body_bytes": gold_code.len(),
        "equal_scalar_width_does_not_prove_type_compatibility": true,
        "typed_runtime_gate": "The scanner reports this four-byte call flow. Runtime Proto-field and owned property type metadata must reject uint32 -> System.Int32; this test does not claim the scalar scanner rejects it.",
    });
    ensure!(
        negative.get("proto_type").and_then(Value::as_str) == Some("uint32")
            && negative.get("business_type").and_then(Value::as_str) == Some("System.Int32"),
        "Gold negative fixture types changed"
    );

    let report = json!({
        "status": "passed",
        "source_dll": dll_path,
        "fixture_input": input_path,
        "binding": "declared-disk-only",
        "caller": {"rva": CALLER_RVA, "bytes": caller_code.len(), "plan": plan,
            "original_planned_rejections": {"4byte": planned_4.rejected_sites, "8byte": planned_8.rejected_sites},
            "tail_proof": tail_proof, "tail_sites": tail_sites},
        "positive_call_arguments": positive_arguments_json,
        "owned_accessors": {
            "getter": {"rva": SHARE_GETTER_RVA, "bytes": getter_code.len(), "offset": getter_scan.accessor_offset},
            "setter": {"rva": SHARE_SETTER_RVA, "bytes": setter_code.len(), "offset": setter_scan.accessor_offset},
        },
        "positive_setter_copies": positive_copies.iter().map(|copy| copy_json(copy)).collect::<Vec<_>>(),
        "negative_gold_call_arguments": negative_arguments_json,
        "negative_gold_type_gate": gold_expectation,
        "boundary": "Current disk PE bytes, supported CFG/EH plan, and scanner provenance only; no runtime reflection, naming write, or game validation.",
    });
    fs::create_dir_all(&output_dir)?;
    fs::write(
        output_dir.join("setter-call-replay.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    Ok(())
}
