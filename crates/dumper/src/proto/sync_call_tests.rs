//! Native argument/call-write regression fixtures. Loaded under sync_scan.
use super::*;

const RVA: usize = 0x1000;
const SETTER: usize = 0x4000;
const OTHER_SETTER: usize = 0x4100;
const UNKNOWN: usize = 0x5000;

fn direct_call(code: &mut Vec<u8>, target: usize) -> usize {
    let site = RVA + code.len();
    let displacement = i32::try_from(target as i64 - (site + 5) as i64).unwrap();
    code.push(0xe8);
    code.extend_from_slice(&displacement.to_le_bytes());
    site
}

fn saved_owner_and_proto() -> Vec<u8> {
    vec![
        0x48, 0x89, 0xce, // mov rsi,rcx: preserve the actual receiver
        0x48, 0x89, 0xd7, // mov rdi,rdx: preserve the Proto pointer
    ]
}

fn known_setter(target: usize) -> Option<(u32, usize)> {
    (target == SETTER).then_some((76, 4))
}

#[test]
fn direct_instance_setter_keeps_exact_source_and_call_addresses() {
    // Independently prove the small setter's destination before supplying it.
    let setter = scan(&[0x89, 0x51, 0x4c, 0xc3], SETTER, Mode::Setter);
    assert_eq!(setter.accessor_offset, Some(76));
    let mut code = vec![0x8b, 0x52, 0x24]; // mov edx,[rdx+36]
    assert_eq!(direct_call(&mut code, SETTER), RVA + 3);
    code.push(0xc3);
    let mut result = scan(&code, RVA, Mode::Sync);
    assert!(result.copies.is_empty()); // a call is not itself a bound copy
    assert_eq!(
        result.call_arguments,
        [CallArgument {
            call_rva: RVA + 3,
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
            store_rva: RVA + 3,
            setter_call: true,
        }]
    );
}

#[test]
fn setter_target_requires_metadata_binding_and_matching_width() {
    let mut code = vec![0x8b, 0x52, 0x24];
    direct_call(&mut code, SETTER);
    code.push(0xc3);
    for target in [None, Some((76, 8))] {
        let mut result = scan(&code, RVA, Mode::Sync);
        assert_eq!(result.call_arguments[0].target_rva, SETTER);
        result.bind_setter_calls(4, |_| target);
        assert!(result.copies.is_empty());
    }
}

#[test]
fn a_proto_or_unknown_receiver_is_not_the_owned_instance() {
    for receiver in [
        &[0x48, 0x89, 0xd1][..], // mov rcx,rdx: Proto object, not this owner
        &[0x31, 0xc9][..],       // xor ecx,ecx: unknown/non-owner receiver
    ] {
        let mut code = receiver.to_vec();
        code.extend_from_slice(&[0x8b, 0x52, 0x24]);
        let call_site = direct_call(&mut code, SETTER);
        code.push(0xc3);
        let mut result = scan(&code, RVA, Mode::Sync);
        assert_eq!(result.call_arguments.len(), 1);
        let argument = &result.call_arguments[0];
        assert_eq!(argument.target_rva, SETTER);
        assert_eq!(argument.call_rva, call_site);
        assert_eq!(argument.load_rva, RVA + receiver.len());
        assert_eq!(argument.argument_index, 1);
        assert!(!argument.receiver_is_business);
        result.bind_setter_calls(4, known_setter);
        assert!(result.copies.is_empty());
    }
}

#[test]
fn later_register_argument_slots_are_not_instance_setter_values() {
    for (load, ordinal) in [
        ([0x44, 0x8b, 0x42, 0x24], 2), // mov r8d,[rdx+36]
        ([0x44, 0x8b, 0x4a, 0x24], 3), // mov r9d,[rdx+36]
    ] {
        let mut code = load.to_vec();
        direct_call(&mut code, SETTER);
        code.push(0xc3);
        let mut result = scan(&code, RVA, Mode::Sync);
        assert_eq!(
            result.call_arguments,
            [CallArgument {
                call_rva: RVA + 4,
                target_rva: SETTER,
                argument_index: ordinal,
                receiver_is_business: true,
                proto_offset: 36,
                load_rva: RVA,
            }]
        );
        result.bind_setter_calls(4, known_setter);
        assert!(result.copies.is_empty());
    }
}

#[test]
fn an_unknown_call_clobbers_volatile_argument_provenance() {
    let mut code = saved_owner_and_proto();
    code.extend_from_slice(&[0x8b, 0x57, 0x24]); // mov edx,[rdi+36]
    let unknown_site = direct_call(&mut code, UNKNOWN);
    code.extend_from_slice(&[0x48, 0x89, 0xf1]); // restore RCX, but not clobbered RDX
    let setter_site = direct_call(&mut code, SETTER);
    code.push(0xc3);
    let mut result = scan(&code, RVA, Mode::Sync);
    assert_eq!(unknown_site, RVA + 9);
    assert_eq!(setter_site, RVA + 17);
    assert_eq!(result.call_arguments.len(), 1);
    assert_eq!(result.call_arguments[0].target_rva, UNKNOWN);
    assert_eq!(result.call_arguments[0].load_rva, RVA + 6);
    result.bind_setter_calls(4, known_setter);
    assert!(result.copies.is_empty());
}

#[test]
fn arithmetic_and_partial_register_writes_destroy_the_call_argument_source() {
    for destroy in [
        &[0x83, 0xc2, 0x01][..], // add edx,1
        &[0xb2, 0x01][..],       // mov dl,1
        &[0x66, 0xba, 1, 0][..], // mov dx,1
    ] {
        let mut code = vec![0x8b, 0x52, 0x24];
        code.extend_from_slice(destroy);
        direct_call(&mut code, SETTER);
        code.push(0xc3);
        let mut result = scan(&code, RVA, Mode::Sync);
        assert!(result.call_arguments.is_empty(), "destroy={destroy:x?}");
        result.bind_setter_calls(4, known_setter);
        assert!(result.copies.is_empty());
    }
}

#[test]
fn branch_join_requires_the_same_proto_source_on_both_paths() {
    for (alternate, accepted) in [(0x28, false), (0x24, true)] {
        let mut code = vec![
            0x85, 0xc0, // test eax,eax
            0x74, 0x05, // jz alternate load at +9
            0x8b, 0x52, 0x24, // mov edx,[rdx+36]
            0xeb, 0x03, // jmp common call at +12
            0x8b, 0x52, alternate,
        ];
        direct_call(&mut code, SETTER);
        code.push(0xc3);
        let mut result = scan(&code, RVA, Mode::Sync);
        assert_eq!(result.rejected_paths, 0);
        if accepted {
            assert_eq!(result.call_arguments.len(), 1);
            assert_eq!(result.call_arguments[0].proto_offset, 36);
            assert_eq!(result.call_arguments[0].load_rva, RVA + 4);
            assert_eq!(result.call_arguments[0].call_rva, RVA + 12);
            assert_eq!(result.call_arguments[0].target_rva, SETTER);
        } else {
            assert!(result.call_arguments.is_empty());
        }
        result.bind_setter_calls(4, known_setter);
        assert_eq!(result.copies.len(), usize::from(accepted));
    }
}

#[test]
fn competing_setter_sources_drop_only_the_conflicting_destination() {
    let mut code = saved_owner_and_proto();
    for (source, target) in [(0x24, SETTER), (0x28, SETTER), (0x2c, OTHER_SETTER)] {
        code.extend_from_slice(&[0x8b, 0x57, source, 0x48, 0x89, 0xf1]);
        direct_call(&mut code, target);
    }
    code.push(0xc3);
    let mut result = scan(&code, RVA, Mode::Sync);
    assert_eq!(result.call_arguments.len(), 3);
    assert_eq!(result.call_arguments[0].call_rva, RVA + 12);
    assert_eq!(result.call_arguments[1].call_rva, RVA + 23);
    assert_eq!(result.call_arguments[2].call_rva, RVA + 34);
    result.bind_setter_calls(4, |target| match target {
        SETTER => Some((76, 4)),
        OTHER_SETTER => Some((96, 4)),
        _ => None,
    });
    assert_eq!(
        result.copies,
        [CopyEvidence {
            proto_offset: 44,
            business_offset: 96,
            load_rva: RVA + 28,
            store_rva: RVA + 34,
            setter_call: true,
        }]
    );
}

#[test]
fn direct_overwrites_block_setter_binding_before_or_after_the_call() {
    let overwrite = [0xc7, 0x46, 0x4c, 0, 0, 0, 0]; // mov [rsi+76],0
    for before in [true, false] {
        let mut code = saved_owner_and_proto();
        if before {
            code.extend_from_slice(&overwrite);
        }
        code.extend_from_slice(&[0x8b, 0x57, 0x24, 0x48, 0x89, 0xf1]);
        let call_site = direct_call(&mut code, SETTER);
        if !before {
            code.extend_from_slice(&overwrite);
        }
        code.push(0xc3);
        let mut result = scan(&code, RVA, Mode::Sync);
        assert_eq!(result.call_arguments.len(), 1);
        assert_eq!(result.call_arguments[0].call_rva, call_site);
        result.bind_setter_calls(4, known_setter);
        assert!(result.copies.is_empty(), "overwrite before call={before}");
    }
}

#[test]
fn a_later_immediate_setter_value_revokes_the_earlier_setter_copy() {
    let mut code = saved_owner_and_proto();
    code.extend_from_slice(&[0x8b, 0x57, 0x24, 0x48, 0x89, 0xf1]);
    direct_call(&mut code, SETTER);
    code.extend_from_slice(&[
        0x31, 0xd2, // xor edx,edx: later setter writes a constant zero
        0x48, 0x89, 0xf1,
    ]);
    direct_call(&mut code, SETTER);
    code.push(0xc3);
    let mut result = scan(&code, RVA, Mode::Sync);
    assert_eq!(result.call_arguments.len(), 1);
    assert_eq!(result.call_arguments[0].call_rva, RVA + 12);
    result.bind_setter_calls(4, known_setter);
    assert!(result.copies.is_empty());
}

#[test]
fn a_narrow_setter_write_revokes_an_overlapping_qword_setter_copy() {
    let mut code = saved_owner_and_proto();
    code.extend_from_slice(&[0x48, 0x8b, 0x57, 0x20, 0x48, 0x89, 0xf1]);
    direct_call(&mut code, SETTER);
    code.extend_from_slice(&[0x31, 0xd2, 0x48, 0x89, 0xf1]);
    direct_call(&mut code, OTHER_SETTER);
    code.push(0xc3);
    let mut result = scan_typed(&code, RVA, Mode::Sync, 8);
    assert_eq!(result.call_arguments.len(), 1);
    assert_eq!(result.call_arguments[0].proto_offset, 32);
    assert_eq!(result.call_arguments[0].load_rva, RVA + 6);
    assert_eq!(result.call_arguments[0].call_rva, RVA + 13);
    result.bind_setter_calls(8, |target| match target {
        SETTER => Some((48, 8)),
        OTHER_SETTER => Some((52, 4)), // upper half of bytes 48..56
        _ => None,
    });
    assert!(result.copies.is_empty());
}

#[test]
fn a_known_setter_overwrite_also_revokes_an_existing_direct_store() {
    let mut code = vec![
        0x8b, 0x42, 0x24, // mov eax,[rdx+36]
        0x89, 0x41, 0x4c, // mov [rcx+76],eax
        0x31, 0xd2, // xor edx,edx
    ];
    direct_call(&mut code, SETTER);
    code.push(0xc3);
    let mut result = scan(&code, RVA, Mode::Sync);
    assert_eq!(result.copies.len(), 1);
    assert_eq!(result.copies[0].load_rva, RVA);
    assert_eq!(result.copies[0].store_rva, RVA + 3);
    assert!(!result.copies[0].setter_call);
    assert!(result.call_arguments.is_empty());
    result.bind_setter_calls(4, known_setter);
    assert!(result.copies.is_empty());
    assert!(result.ambiguous);
}

#[test]
fn a_partial_width_setter_revokes_an_existing_qword_direct_store() {
    let mut code = vec![
        0x48, 0x8b, 0x42, 0x20, // mov rax,[rdx+32]
        0x48, 0x89, 0x41, 0x30, // mov [rcx+48],rax
        0x31, 0xd2,
    ];
    direct_call(&mut code, OTHER_SETTER);
    code.push(0xc3);
    let mut result = scan_typed(&code, RVA, Mode::Sync, 8);
    assert_eq!(result.copies.len(), 1);
    assert_eq!(result.copies[0].proto_offset, 32);
    assert_eq!(result.copies[0].business_offset, 48);
    result.bind_setter_calls(8, |target| (target == OTHER_SETTER).then_some((52, 4)));
    assert!(result.copies.is_empty());
    assert!(result.ambiguous);
}

#[test]
fn complete_cfg_failures_clear_previously_witnessed_call_arguments() {
    for tail in [
        &[0x75, 0x7f, 0xc3][..], // conditional edge outside the actual function
        &[0xeb, 0x01, 0x8b, 0x42, 0x24, 0xc3][..], // target inside a MOV instruction
        &[0x0f][..],             // undecodable reachable fallthrough after CALL
    ] {
        let mut code = vec![0x8b, 0x52, 0x24];
        direct_call(&mut code, SETTER);
        code.extend_from_slice(tail);
        let mut result = scan(&code, RVA, Mode::Sync);
        assert!(result.rejected_paths > 0, "tail={tail:x?}");
        assert!(result.call_arguments.is_empty(), "tail={tail:x?}");
        result.bind_setter_calls(4, known_setter);
        assert!(result.copies.is_empty());
    }
}

#[test]
fn indirect_calls_do_not_invent_an_exact_setter_target() {
    let result = scan(
        &[0x8b, 0x52, 0x24, 0xff, 0xd0, 0xc3], // mov edx,[rdx+36]; call rax; ret
        RVA,
        Mode::Sync,
    );
    assert!(result.call_arguments.is_empty());
    assert!(result.copies.is_empty());
}

#[test]
fn an_exact_planned_external_exit_preserves_the_qword_setter_argument() {
    let setter = scan_typed(&[0x48, 0x89, 0x51, 0x28, 0xc3], SETTER, Mode::Setter, 8);
    assert_eq!(setter.accessor_offset, Some(40));
    let mut code = vec![0x48, 0x8b, 0x52, 0x20]; // mov rdx,[rdx+32]
    let call_site = direct_call(&mut code, SETTER);
    let exit_site = RVA + code.len();
    code.push(0xe9); // jmp rel32 to a separately proven external function
    let displacement = i32::try_from(UNKNOWN as i64 - (exit_site + 5) as i64).unwrap();
    code.extend_from_slice(&displacement.to_le_bytes());
    assert_eq!(call_site, RVA + 4);
    assert_eq!(exit_site, RVA + 9);

    let ordinary = scan_typed(&code, RVA, Mode::Sync, 8);
    assert!(ordinary.rejected_paths > 0);
    assert!(ordinary.call_arguments.is_empty());
    assert!(ordinary.copies.is_empty());

    // This fixture exercises wrapper validation only. The hand-written set is
    // not evidence of the PE ownership or actual frame restore of a real exit.
    let mut planned = scan_planned_exits_typed(
        &code,
        RVA,
        Mode::Sync,
        &BTreeSet::new(),
        &BTreeMap::new(),
        &BTreeMap::new(),
        None,
        8,
        &BTreeSet::from([exit_site]),
    );
    assert_eq!(planned.rejected_paths, 0);
    assert_eq!(
        planned.call_arguments,
        [CallArgument {
            call_rva: call_site,
            target_rva: SETTER,
            argument_index: 1,
            receiver_is_business: true,
            proto_offset: 32,
            load_rva: RVA,
        }]
    );
    planned.bind_setter_calls(8, |target| {
        (target == SETTER).then_some((setter.accessor_offset.unwrap(), 8))
    });
    assert_eq!(
        planned.copies,
        [CopyEvidence {
            proto_offset: 32,
            business_offset: 40,
            load_rva: RVA,
            store_rva: call_site,
            setter_call: true,
        }]
    );
}

#[test]
fn malformed_exit_sites_reject_the_plan_and_clear_setter_arguments() {
    let mut prefix = vec![0x48, 0x8b, 0x52, 0x20]; // Proto qword into RDX, this in RCX
    let call_site = direct_call(&mut prefix, SETTER);
    let exit_site = RVA + prefix.len();
    let mut external = prefix.clone();
    external.push(0xe9);
    let displacement = i32::try_from(UNKNOWN as i64 - (exit_site + 5) as i64).unwrap();
    external.extend_from_slice(&displacement.to_le_bytes());
    let mut internal = prefix.clone();
    internal.extend_from_slice(&[0xe9, 0, 0, 0, 0, 0xc3]); // jmp to in-body RET at +14
    let mut conditional = prefix.clone();
    conditional.extend_from_slice(&[0x75, 0x7f, 0xc3]); // jne outside the function
    let mut indirect = prefix;
    indirect.extend_from_slice(&[0xff, 0xe0]); // jmp rax is not NearBranch64

    for (label, code, site) in [
        ("not a branch", &external, RVA),
        ("inside branch bytes", &external, exit_site + 1),
        ("outside body", &external, RVA + external.len()),
        ("CALL is not an exit JMP", &external, call_site),
        ("internal target", &internal, exit_site),
        ("conditional branch", &conditional, exit_site),
        ("indirect branch", &indirect, exit_site),
    ] {
        let mut result = scan_planned_exits_typed(
            code,
            RVA,
            Mode::Sync,
            &BTreeSet::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
            None,
            8,
            &BTreeSet::from([site]),
        );
        assert!(result.rejected_paths > 0, "{label}");
        assert!(result.call_arguments.is_empty(), "{label}");
        result.bind_setter_calls(8, |target| (target == SETTER).then_some((40, 8)));
        assert!(result.copies.is_empty(), "{label}");
    }
}
