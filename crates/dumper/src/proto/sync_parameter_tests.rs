//! Explicit instance-parameter provenance fixtures. These bytes do not prove
//! metadata types, return ABI or native exits; the caller must bind those facts.
use super::*;

const RVA: usize = 0x1000;
const SETTER: usize = 0x4000;
const UNKNOWN: usize = 0x5000;

fn scan_parameter(code: &[u8], bytes: usize, index: usize) -> ScanResult {
    scan_planned_parameter_typed(
        code,
        RVA,
        Mode::Sync,
        &BTreeSet::new(),
        &BTreeMap::new(),
        &BTreeMap::new(),
        None,
        bytes,
        index,
    )
}

fn direct_call(code: &mut Vec<u8>, target: usize) -> usize {
    let site = RVA + code.len();
    let displacement = i32::try_from(target as i64 - (site + 5) as i64).unwrap();
    code.push(0xe8);
    code.extend_from_slice(&displacement.to_le_bytes());
    site
}

#[test]
fn default_rdx_entry_preserves_previous_copy_evidence() {
    let code = [
        0x8b, 0x42, 0x24, // mov eax,[rdx+36]
        0x89, 0x41, 0x4c, // mov [rcx+76],eax
        0xc3,
    ];
    let old = scan_typed(&code, RVA, Mode::Sync, 4);
    let explicit = scan_parameter(&code, 4, 0);
    assert_eq!(old.copies, explicit.copies);
    assert_eq!(
        explicit.copies,
        [CopyEvidence {
            proto_offset: 36,
            business_offset: 76,
            load_rva: RVA,
            store_rva: RVA + 3,
            setter_call: false,
        }]
    );
    for index in [1, 2] {
        assert!(scan_parameter(&code, 4, index).copies.is_empty());
    }
}

#[test]
fn r8_entry_proves_a_byte_or_dword_load_with_exact_sites() {
    for (bytes, code, store) in [
        (
            1,
            vec![
                0x41, 0x0f, 0xb6, 0x40, 0x24, // movzx eax,byte [r8+36]
                0x88, 0x41, 0x4c, // mov [rcx+76],al
                0xc3,
            ],
            RVA + 5,
        ),
        (
            4,
            vec![
                0x41, 0x8b, 0x40, 0x24, // mov eax,[r8+36]
                0x89, 0x41, 0x4c, // mov [rcx+76],eax
                0xc3,
            ],
            RVA + 4,
        ),
    ] {
        let result = scan_parameter(&code, bytes, 1);
        assert_eq!(result.rejected_paths, 0);
        assert_eq!(
            result.copies,
            [CopyEvidence {
                proto_offset: 36,
                business_offset: 76,
                load_rva: RVA,
                store_rva: store,
                setter_call: false,
            }]
        );
        for wrong_index in [0, 2] {
            let wrong = scan_parameter(&code, bytes, wrong_index);
            assert!(wrong.copies.is_empty());
            assert!(wrong.call_arguments.is_empty());
        }
    }
}

#[test]
fn r9_entry_proves_a_qword_copy_without_treating_rdx_as_proto() {
    let code = [
        0x49, 0x8b, 0x41, 0x28, // mov rax,[r9+40]
        0x48, 0x89, 0x41, 0x50, // mov [rcx+80],rax
        0xc3,
    ];
    let result = scan_parameter(&code, 8, 2);
    assert_eq!(result.rejected_paths, 0);
    assert_eq!(
        result.copies,
        [CopyEvidence {
            proto_offset: 40,
            business_offset: 80,
            load_rva: RVA,
            store_rva: RVA + 4,
            setter_call: false,
        }]
    );
    for wrong_index in [0, 1] {
        assert!(scan_parameter(&code, 8, wrong_index).copies.is_empty());
    }
}

#[test]
fn extra_register_parameters_remain_unknown() {
    let code = [
        0x8b, 0x42, 0x20, // unknown RDX: mov eax,[rdx+32]
        0x89, 0x41, 0x48, // mov [rcx+72],eax
        0x41, 0x8b, 0x41, 0x28, // unknown R9: mov eax,[r9+40]
        0x89, 0x41, 0x50, // mov [rcx+80],eax
        0x41, 0x8b, 0x40, 0x24, // Proto R8: mov eax,[r8+36]
        0x89, 0x41, 0x4c, // mov [rcx+76],eax
        0xc3,
    ];
    let result = scan_parameter(&code, 4, 1);
    assert_eq!(result.rejected_paths, 0);
    assert_eq!(
        result.copies,
        [CopyEvidence {
            proto_offset: 36,
            business_offset: 76,
            load_rva: RVA + 13,
            store_rva: RVA + 17,
            setter_call: false,
        }]
    );
}

#[test]
fn r8_proto_origin_can_be_passed_in_the_actual_setter_rdx_slot() {
    let setter = scan_typed(&[0x89, 0x51, 0x4c, 0xc3], SETTER, Mode::Setter, 4);
    assert_eq!(setter.accessor_offset, Some(76));
    let mut code = vec![0x41, 0x8b, 0x50, 0x24]; // mov edx,[r8+36]
    assert_eq!(direct_call(&mut code, SETTER), RVA + 4);
    code.push(0xc3);
    let mut result = scan_parameter(&code, 4, 1);
    assert_eq!(
        result.call_arguments,
        [CallArgument {
            call_rva: RVA + 4,
            target_rva: SETTER,
            argument_index: 1,
            receiver_is_business: true,
            proto_offset: 36,
            load_rva: RVA,
        }]
    );
    result.bind_setter_calls(4, |target| {
        (target == SETTER).then_some((setter.accessor_offset.unwrap(), 4))
    });
    assert_eq!(
        result.copies,
        [CopyEvidence {
            proto_offset: 36,
            business_offset: 76,
            load_rva: RVA,
            store_rva: RVA + 4,
            setter_call: true,
        }]
    );
    assert!(scan_parameter(&code, 4, 0).call_arguments.is_empty());
}

#[test]
fn caller_proto_parameter_index_does_not_change_setter_value_ordinal() {
    let mut code = vec![0x45, 0x8b, 0x41, 0x28]; // mov r8d,[r9+40]
    direct_call(&mut code, SETTER);
    code.push(0xc3);
    let mut result = scan_parameter(&code, 4, 2);
    assert_eq!(result.call_arguments.len(), 1);
    assert_eq!(result.call_arguments[0].argument_index, 2);
    assert_eq!(result.call_arguments[0].proto_offset, 40);
    assert_eq!(result.call_arguments[0].load_rva, RVA);
    result.bind_setter_calls(4, |target| (target == SETTER).then_some((76, 4)));
    assert!(result.copies.is_empty());
}

#[test]
fn overwriting_a_later_proto_pointer_or_its_loaded_value_loses_evidence() {
    for overwrite in [
        &[0x45, 0x31, 0xc0][..],       // xor r8d,r8d: partial pointer write
        &[0x49, 0x83, 0xc0, 0x01][..], // add r8,1: arithmetic pointer change
    ] {
        let mut code = overwrite.to_vec();
        code.extend_from_slice(&[0x41, 0x8b, 0x40, 0x24, 0x89, 0x41, 0x4c, 0xc3]);
        assert!(scan_parameter(&code, 4, 1).copies.is_empty());
    }
    let mut code = vec![
        0x41, 0x8b, 0x50, 0x24, // mov edx,[r8+36]
        0x83, 0xc2, 0x01, // add edx,1: no longer a bit-copy
    ];
    direct_call(&mut code, SETTER);
    code.push(0xc3);
    let result = scan_parameter(&code, 4, 1);
    assert!(result.call_arguments.is_empty());
}

#[test]
fn unknown_calls_clobber_a_later_volatile_proto_pointer() {
    let mut code = vec![0x48, 0x89, 0xce]; // preserve business receiver in RSI
    direct_call(&mut code, UNKNOWN);
    code.extend_from_slice(&[
        0x48, 0x89, 0xf1, // mov rcx,rsi
        0x41, 0x8b, 0x40, 0x24, // clobbered R8 has no Proto provenance
        0x89, 0x41, 0x4c, 0xc3,
    ]);
    let result = scan_parameter(&code, 4, 1);
    assert!(result.copies.is_empty());
    assert!(result.call_arguments.is_empty());
}

#[test]
fn later_destination_overwrites_still_reject_later_parameter_copies() {
    let code = [
        0x41, 0x8b, 0x40, 0x24, // mov eax,[r8+36]
        0x89, 0x41, 0x4c, // mov [rcx+76],eax
        0xc7, 0x41, 0x4c, 0x00, 0x00, 0x00, 0x00, // overwrite the same field
        0xc3,
    ];
    let result = scan_parameter(&code, 4, 1);
    assert!(result.copies.is_empty());
    assert!(result.ambiguous);
}

#[test]
fn invalid_or_non_sync_parameter_entries_reject_before_decoding() {
    let code = [0x8b, 0x42, 0x24, 0x89, 0x41, 0x4c, 0xc3];
    for (mode, index) in [
        (Mode::Sync, 3),
        (Mode::Sync, usize::MAX),
        (Mode::Getter, 1),
        (Mode::Getter, 2),
        (Mode::Setter, 1),
        (Mode::Setter, 2),
    ] {
        let result = scan_planned_exits_parameter_typed(
            &code,
            RVA,
            mode,
            &BTreeSet::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
            None,
            4,
            &BTreeSet::new(),
            index,
        );
        assert_eq!(result.rejected_paths, 1);
        assert_eq!(result.decoded, 0);
        assert!(result.copies.is_empty());
        assert!(result.call_arguments.is_empty());
        assert_eq!(result.accessor_offset, None);
    }
}

#[test]
fn later_parameter_entry_preserves_explicit_tail_exit_validation() {
    let mut code = vec![0x49, 0x8b, 0x50, 0x28]; // mov rdx,[r8+40]
    let call_site = direct_call(&mut code, SETTER);
    let exit_site = RVA + code.len();
    let displacement = i32::try_from(UNKNOWN as i64 - (exit_site + 5) as i64).unwrap();
    code.push(0xe9);
    code.extend_from_slice(&displacement.to_le_bytes());
    let denied = scan_parameter(&code, 8, 1);
    assert!(denied.rejected_paths > 0);
    assert!(denied.call_arguments.is_empty());
    let allowed = scan_planned_exits_parameter_typed(
        &code,
        RVA,
        Mode::Sync,
        &BTreeSet::new(),
        &BTreeMap::new(),
        &BTreeMap::new(),
        None,
        8,
        &BTreeSet::from([exit_site]),
        1,
    );
    assert_eq!(allowed.rejected_paths, 0);
    assert_eq!(
        allowed.call_arguments,
        [CallArgument {
            call_rva: call_site,
            target_rva: SETTER,
            argument_index: 1,
            receiver_is_business: true,
            proto_offset: 40,
            load_rva: RVA,
        }]
    );
}
