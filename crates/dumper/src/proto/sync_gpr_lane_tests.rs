//! Instruction-only GPR lane fixtures: no metadata, runtime or naming claims.
use super::*;

const RVA: usize = 0x1000;
const PACKED_COPY: [u8; 8] = [
    0x48, 0x8b, 0x42, 0x20, // mov rax,[rdx+32]
    0x48, 0x89, 0x41, 0x1c, // mov [rcx+28],rax
];

fn offsets(result: &ScanResult) -> Vec<(u32, u32)> {
    result
        .copies
        .iter()
        .map(|copy| (copy.proto_offset, copy.business_offset))
        .collect()
}

#[test]
fn packed_mov64_proves_two_independent_dword_offsets_and_sites() {
    let mut code = PACKED_COPY.to_vec();
    code.push(0xc3);
    let result = scan_typed(&code, RVA, Mode::Sync, 4);
    assert_eq!(result.rejected_paths, 0);
    assert!(!result.ambiguous);
    assert_eq!(
        result.copies,
        [
            CopyEvidence {
                proto_offset: 32,
                business_offset: 28,
                load_rva: RVA,
                store_rva: RVA + 4,
                setter_call: false,
            },
            CopyEvidence {
                proto_offset: 36,
                business_offset: 32,
                load_rva: RVA,
                store_rva: RVA + 4,
                setter_call: false,
            },
        ]
    );
}

#[test]
fn packed_register_copy_keeps_lanes_without_creating_an_object_pointer() {
    let code = [
        0x48, 0x8b, 0x52, 0x20, // mov rdx,[rdx+32]: consume the old pointer
        0x48, 0x89, 0xd3, // mov rbx,rdx
        0x48, 0x89, 0x59, 0x1c, // mov [rcx+28],rbx
        0x8b, 0x42, 0x28, // mov eax,[rdx+40]: RDX is no longer a pointer
        0x89, 0x41, 0x50, // mov [rcx+80],eax
        0xc3,
    ];
    let result = scan_typed(&code, RVA, Mode::Sync, 4);
    assert_eq!(offsets(&result), [(32, 28), (36, 32)]);
    assert!(
        result
            .copies
            .iter()
            .all(|copy| { copy.load_rva == RVA && copy.store_rva == RVA + 7 && !copy.setter_call })
    );
}

#[test]
fn single_lane_overwrites_revoke_only_that_lane_in_both_orders() {
    for (overwrite, expected) in [
        (&[0xc7, 0x41, 0x1c, 0, 0, 0, 0][..], vec![(36, 32)]),
        (&[0xc7, 0x41, 0x20, 0, 0, 0, 0][..], vec![(32, 28)]),
        (&[0xc6, 0x41, 0x23, 0][..], vec![(32, 28)]),
    ] {
        for overwrite_first in [false, true] {
            let mut code = Vec::new();
            if overwrite_first {
                code.extend_from_slice(overwrite);
            }
            code.extend_from_slice(&PACKED_COPY);
            if !overwrite_first {
                code.extend_from_slice(overwrite);
            }
            code.push(0xc3);
            let result = scan_typed(&code, RVA, Mode::Sync, 4);
            assert_eq!(offsets(&result), expected, "{code:x?}");
            assert!(result.ambiguous);
        }
    }
}

#[test]
fn truncating_or_zero_extending_dword_moves_never_preserve_the_high_lane() {
    for (middle, store) in [
        (&[0x89, 0xc0][..], &[0x48, 0x89, 0x41, 0x1c][..]), // mov eax,eax
        (&[0x89, 0xc3][..], &[0x48, 0x89, 0x59, 0x1c][..]), // mov ebx,eax
        (&[0x89, 0xc0][..], &[0x89, 0x41, 0x1c][..]),       // explicit dword store
    ] {
        let mut code = PACKED_COPY[..4].to_vec();
        code.extend_from_slice(middle);
        code.extend_from_slice(store);
        code.push(0xc3);
        let result = scan_typed(&code, RVA, Mode::Sync, 4);
        assert_eq!(offsets(&result), [(32, 28)], "{code:x?}");
        assert_eq!(result.copies[0].load_rva, RVA);
        assert!(scan_typed(&code, RVA, Mode::Sync, 8).copies.is_empty());
    }
    let code = [
        0x8b, 0x42, 0x20, // mov eax,[rdx+32]: upper RAX bits are zero, not a field
        0x48, 0x89, 0x41, 0x1c, 0xc3,
    ];
    assert_eq!(offsets(&scan_typed(&code, RVA, Mode::Sync, 4)), [(32, 28)]);
}

#[test]
fn unknown_high_lane_of_a_packed_store_still_revokes_a_prior_scalar_copy() {
    let code = [
        0x8b, 0x42, 0x24, 0x89, 0x41, 0x20, // scalar 36 -> 32
        0x8b, 0x42, 0x20, // only low 32 bits are a field
        0x48, 0x89, 0x41, 0x1c, // high lane writes zeros over owner+32
        0xc3,
    ];
    let result = scan_typed(&code, RVA, Mode::Sync, 4);
    assert_eq!(offsets(&result), [(32, 28)]);
    assert!(result.ambiguous);
}

#[test]
fn agreeing_scalar_and_packed_writes_do_not_revoke_each_other() {
    let mut code = vec![0x8b, 0x42, 0x20, 0x89, 0x41, 0x1c];
    code.extend_from_slice(&PACKED_COPY);
    code.push(0xc3);
    let result = scan_typed(&code, RVA, Mode::Sync, 4);
    assert_eq!(offsets(&result), [(32, 28), (32, 28), (36, 32)]);
    assert!(!result.ambiguous);
}

#[test]
fn packed_branch_joins_require_matching_source_offsets() {
    for second_offset in [0x20, 0x28] {
        let code = [
            0x85,
            0xc0, // test eax,eax
            0x74,
            0x06, // je second-load
            0x48,
            0x8b,
            0x5a,
            0x20, // mov rbx,[rdx+32]
            0xeb,
            0x04, // jmp store
            0x48,
            0x8b,
            0x5a,
            second_offset,
            0x48,
            0x89,
            0x59,
            0x1c,
            0xc3,
        ];
        let result = scan_typed(&code, RVA, Mode::Sync, 4);
        assert_eq!(result.rejected_paths, 0);
        let expected = if second_offset == 0x20 {
            vec![(32, 28), (36, 32)]
        } else {
            vec![]
        };
        assert_eq!(offsets(&result), expected);
        assert!(result.copies.iter().all(|copy| {
            [RVA + 4, RVA + 10].contains(&copy.load_rva) && copy.store_rva == RVA + 14
        }));
    }
}

#[test]
fn packed_join_drops_conflicting_high_lane_but_keeps_matching_low_lane() {
    let code = [
        0x48, 0x8b, 0x5a, 0x20, // mov rbx,[rdx+32]
        0x85, 0xc0, 0x74, 0x06, // skip low-only assignment on one path
        0x8b, 0x42, 0x20, // mov eax,[rdx+32]
        0x48, 0x89, 0xc3, // mov rbx,rax: high bits have no field provenance
        0x48, 0x89, 0x59, 0x1c, 0xc3,
    ];
    let result = scan_typed(&code, RVA, Mode::Sync, 4);
    assert_eq!(result.rejected_paths, 0);
    assert_eq!(offsets(&result), [(32, 28)]);
}

#[test]
fn volatile_calls_clobber_both_gpr_lanes_but_not_an_abi_nonvolatile_copy() {
    for (load, store, expected) in [
        (
            &[0x48, 0x8b, 0x4f, 0x20][..], // RCX
            &[0x48, 0x89, 0x4e, 0x1c][..],
            vec![],
        ),
        (
            &[0x48, 0x8b, 0x57, 0x20][..], // RDX
            &[0x48, 0x89, 0x56, 0x1c][..],
            vec![],
        ),
        (
            &[0x48, 0x8b, 0x47, 0x20][..],
            &[0x48, 0x89, 0x46, 0x1c][..],
            vec![],
        ),
        (
            &[0x4c, 0x8b, 0x47, 0x20][..],
            &[0x4c, 0x89, 0x46, 0x1c][..],
            vec![],
        ),
        (
            &[0x4c, 0x8b, 0x4f, 0x20][..],
            &[0x4c, 0x89, 0x4e, 0x1c][..],
            vec![],
        ),
        (
            &[0x4c, 0x8b, 0x57, 0x20][..],
            &[0x4c, 0x89, 0x56, 0x1c][..],
            vec![],
        ),
        (
            &[0x4c, 0x8b, 0x5f, 0x20][..],
            &[0x4c, 0x89, 0x5e, 0x1c][..],
            vec![],
        ),
        (
            &[0x48, 0x8b, 0x5f, 0x20][..],
            &[0x48, 0x89, 0x5e, 0x1c][..],
            vec![(32, 28), (36, 32)],
        ),
    ] {
        let mut code = vec![0x48, 0x89, 0xd7, 0x48, 0x89, 0xce]; // saved pointers
        code.extend_from_slice(load);
        code.extend_from_slice(&[0xe8, 0, 0, 0, 0]);
        code.extend_from_slice(store);
        code.push(0xc3);
        let result = scan_typed(&code, RVA, Mode::Sync, 4);
        assert_eq!(result.rejected_paths, 0);
        assert_eq!(offsets(&result), expected, "{code:x?}");
    }
}

#[test]
fn pointers_never_become_integer_lanes_or_truncated_owner_aliases() {
    for code in [
        &[0x48, 0x89, 0xd0, 0x48, 0x89, 0x41, 0x1c, 0xc3][..], // ProtoPtr
        &[0x48, 0x89, 0xc8, 0x48, 0x89, 0x41, 0x1c, 0xc3][..], // BusinessPtr
        &[0x89, 0xd0, 0x48, 0x89, 0x41, 0x1c, 0xc3][..],       // truncated ProtoPtr
        &[
            0x89, 0xd2, 0x48, 0x8b, 0x42, 0x20, 0x48, 0x89, 0x41, 0x1c, 0xc3,
        ][..],
    ] {
        assert!(scan_typed(code, RVA, Mode::Sync, 4).copies.is_empty());
    }
}

#[test]
fn partial_register_writes_and_integer_transforms_destroy_packed_provenance() {
    for destroy in [
        &[0xb0, 0][..],                // mov al,0
        &[0xb4, 0][..],                // mov ah,0
        &[0x66, 0x89, 0xc0][..],       // mov ax,ax
        &[0x48, 0x83, 0xc0, 1][..],    // add rax,1
        &[0x48, 0xc1, 0xe8, 0x20][..], // shr rax,32 is not a proved lane extraction
        &[0x48, 0x63, 0xc0][..],       // movsxd rax,eax
    ] {
        let mut code = PACKED_COPY[..4].to_vec();
        code.extend_from_slice(destroy);
        code.extend_from_slice(&PACKED_COPY[4..]);
        code.push(0xc3);
        assert!(
            scan_typed(&code, RVA, Mode::Sync, 4).copies.is_empty(),
            "{code:x?}"
        );
    }
}

#[test]
fn dword_getter_rejects_a_qword_load_followed_by_eax_self_truncation() {
    let code = [
        0x48, 0x8b, 0x41, 0x20, // mov rax,[rcx+32]
        0x89, 0xc0, // mov eax,eax
        0xc3,
    ];
    let result = scan_typed(&code, RVA, Mode::Getter, 4);
    assert_eq!(result.accessor_offset, None);
    assert!(result.accessor_sites.is_empty());
}

#[test]
fn dword_getter_rejects_qword_register_copies_followed_by_truncation() {
    for tail in [
        &[0x89, 0xc3, 0x89, 0xd8, 0xc3][..], // mov ebx,eax; mov eax,ebx; ret
        &[0x48, 0x89, 0xc3, 0x89, 0xd8, 0xc3][..], // mov rbx,rax; mov eax,ebx; ret
    ] {
        let mut code = vec![0x48, 0x8b, 0x41, 0x20]; // mov rax,[rcx+32]
        code.extend_from_slice(tail);
        for bytes in [4, 8] {
            let result = scan_typed(&code, RVA, Mode::Getter, bytes);
            assert_eq!(result.rejected_paths, 0);
            assert_eq!(result.accessor_offset, None, "bytes={bytes} code={code:x?}");
            assert!(result.accessor_sites.is_empty());
        }
    }
}

#[test]
fn dword_getter_rejects_scalar_packed_branch_joins_in_both_orders() {
    let scalar = [0x8b, 0x59, 0x20]; // mov ebx,[rcx+32]
    let packed = [0x48, 0x8b, 0x59, 0x20]; // mov rbx,[rcx+32]
    for (first, second) in [(&scalar[..], &packed[..]), (&packed[..], &scalar[..])] {
        let mut code = vec![0x85, 0xd2, 0x74, u8::try_from(first.len() + 2).unwrap()];
        code.extend_from_slice(first);
        code.extend_from_slice(&[0xeb, u8::try_from(second.len()).unwrap()]);
        code.extend_from_slice(second);
        code.extend_from_slice(&[0x89, 0xd8, 0xc3]); // mov eax,ebx; ret
        let result = scan_typed(&code, RVA, Mode::Getter, 4);
        assert_eq!(result.rejected_paths, 0);
        assert_eq!(result.accessor_offset, None, "{code:x?}");
        assert!(result.accessor_sites.is_empty());
    }
}

#[test]
fn dword_accessors_keep_legacy_scalar_register_moves() {
    let getter = [
        0x8b, 0x41, 0x20, // mov eax,[rcx+32]: a scalar load, not packed
        0x48, 0x89, 0xc3, // mov rbx,rax
        0x89, 0xd8, // mov eax,ebx
        0xc3,
    ];
    assert_eq!(
        scan_typed(&getter, RVA, Mode::Getter, 4).accessor_offset,
        Some(32)
    );
    let setter = [
        0x48, 0x89, 0xd0, // mov rax,rdx: legacy setter-input propagation
        0x89, 0xc0, // mov eax,eax
        0x89, 0x41, 0x1c, // mov [rcx+28],eax
        0xc3,
    ];
    assert_eq!(
        scan_typed(&setter, RVA, Mode::Setter, 4).accessor_offset,
        Some(28)
    );
}

#[test]
fn dword_setter_rejects_qword_overwrites_in_both_orders() {
    let scalar = [0x89, 0x51, 0x1c]; // mov [rcx+28],edx
    let qword = [0x48, 0x89, 0x51, 0x1c]; // mov [rcx+28],rdx: not a dword input store
    for (first, second) in [(&scalar[..], &qword[..]), (&qword[..], &scalar[..])] {
        let mut code = first.to_vec();
        code.extend_from_slice(second);
        code.push(0xc3);
        let result = scan_typed(&code, RVA, Mode::Setter, 4);
        assert_eq!(result.accessor_offset, None, "{code:x?}");
        assert!(result.accessor_sites.is_empty());
        assert!(result.ambiguous);
    }
}

#[test]
fn packed_load_checks_the_complete_eight_byte_numeric_extent() {
    let state = State::from([(Register::RDX, Value::ProtoPtr)]);
    let mut load =
        Decoder::with_ip(64, &PACKED_COPY[..4], RVA as u64, DecoderOptions::NONE).decode();
    // Probe the helper's u32 arithmetic boundary directly: x64 base-relative
    // disp32 cannot encode these positive offsets in an actual byte fixture.
    load.set_memory_displacement64(u64::from(u32::MAX - 8));
    assert_eq!(
        gpr_operand(&load, 1, &state),
        Some([
            Some(Lane::ProtoField {
                offset: u32::MAX - 8,
                loads: BTreeSet::from([RVA]),
            }),
            Some(Lane::ProtoField {
                offset: u32::MAX - 4,
                loads: BTreeSet::from([RVA]),
            }),
        ])
    );
    for offset in [u32::MAX - 7, u32::MAX - 4] {
        load.set_memory_displacement64(u64::from(offset));
        // A valid low dword alone must not prove an overflowing qword load.
        assert!(offset.checked_add(4).is_some());
        assert_eq!(gpr_operand(&load, 1, &state), None);
        assert_eq!(direct_offset_width(&load, 1, &state, 8), None);
    }
}

#[test]
fn packed_store_checks_the_complete_eight_byte_numeric_extent() {
    let low = Lane::ProtoField {
        offset: 32,
        loads: BTreeSet::from([RVA]),
    };
    let high = Lane::ProtoField {
        offset: 36,
        loads: BTreeSet::from([RVA]),
    };
    let state = State::from([
        (Register::RCX, Value::BusinessPtr),
        (
            Register::RAX,
            Value::GprLanes([Some(low.clone()), Some(high.clone())]),
        ),
    ]);
    let mut store = Decoder::with_ip(
        64,
        &PACKED_COPY[4..],
        (RVA + 4) as u64,
        DecoderOptions::NONE,
    )
    .decode();
    // Numeric helper boundary, not an encodable positive disp32 body.
    store.set_memory_displacement64(u64::from(u32::MAX - 8));
    assert_eq!(
        known_stores(&store, &state, 4, true),
        [(u32::MAX - 8, low), (u32::MAX - 4, high)]
    );
    assert!(known_stores(&store, &state, 4, false).is_empty());
    for offset in [u32::MAX - 7, u32::MAX - 4] {
        store.set_memory_displacement64(u64::from(offset));
        assert!(offset.checked_add(4).is_some());
        assert!(known_stores(&store, &state, 4, true).is_empty());
        assert_eq!(direct_offset_width(&store, 0, &state, 8), None);
    }
}

#[test]
fn packed_values_are_not_implicitly_scalar_call_arguments_or_accessors() {
    let code = [
        0x48, 0x8b, 0x42, 0x20, 0x48, 0x89,
        0xc2, // mov rdx,rax: packed, not a typed scalar argument
        0xe8, 0, 0, 0, 0, 0xc3,
    ];
    let result = scan_typed(&code, RVA, Mode::Sync, 4);
    assert_eq!(result.witnessed_call_arguments, 0);
    assert!(result.call_arguments.is_empty());
    assert_eq!(
        scan_typed(&[0x48, 0x8b, 0x41, 0x20, 0xc3], RVA, Mode::Getter, 4).accessor_offset,
        None
    );
    assert_eq!(
        scan_typed(&[0x48, 0x89, 0x51, 0x1c, 0xc3], RVA, Mode::Setter, 4).accessor_offset,
        None
    );
}

#[test]
fn indexed_segment_relative_or_negative_packed_reads_are_not_proofs() {
    for load in [
        &[0x48, 0x8b, 0x44, 0x82, 0x20][..], // indexed
        &[0x64, 0x48, 0x8b, 0x42, 0x20][..], // FS
        &[0x67, 0x48, 0x8b, 0x42, 0x20][..], // EDX address base
        &[0x48, 0x8b, 0x42, 0xff][..],       // negative offset
        &[0xf3, 0x48, 0x8b, 0x42, 0x20][..], // unsupported prefixed MOV
    ] {
        let mut code = load.to_vec();
        code.extend_from_slice(&PACKED_COPY[4..]);
        code.push(0xc3);
        assert!(
            scan_typed(&code, RVA, Mode::Sync, 4).copies.is_empty(),
            "{code:x?}"
        );
    }
}

#[test]
fn packed_unknown_or_indexed_stores_still_revoke_overlapping_copy_proofs() {
    for overwrite in [
        &[0x48, 0x89, 0x59, 0x1c][..],       // unknown RBX
        &[0x48, 0x89, 0x5c, 0x81, 0x1c][..], // unknown indexed address
        &[0x66, 0xc7, 0x41, 0x1f, 0, 0][..], // straddles both lanes
    ] {
        let mut code = PACKED_COPY.to_vec();
        code.extend_from_slice(overwrite);
        code.push(0xc3);
        assert!(
            scan_typed(&code, RVA, Mode::Sync, 4).copies.is_empty(),
            "{code:x?}"
        );
    }
}

#[test]
fn gpr_to_sse_moves_are_not_unproved_lane_conversion_paths() {
    let code = [
        0x48, 0x8b, 0x42, 0x20, 0x66, 0x48, 0x0f, 0x6e, 0xc0, // movq xmm0,rax
        0x66, 0x0f, 0xd6, 0x41, 0x1c, 0xc3,
    ];
    assert!(scan_typed(&code, RVA, Mode::Sync, 4).copies.is_empty());
}

#[test]
fn genuine_qword_scanning_preserves_its_single_copy_and_accessor_results() {
    let mut code = PACKED_COPY.to_vec();
    code.push(0xc3);
    let result = scan_typed(&code, RVA, Mode::Sync, 8);
    assert_eq!(result.rejected_paths, 0);
    assert!(!result.ambiguous);
    assert_eq!(
        result.copies,
        [CopyEvidence {
            proto_offset: 32,
            business_offset: 28,
            load_rva: RVA,
            store_rva: RVA + 4,
            setter_call: false,
        }]
    );
    assert!(scan_typed(&code, RVA, Mode::Sync, 1).copies.is_empty());
    assert_eq!(
        scan_typed(&[0x48, 0x8b, 0x41, 0x20, 0xc3], RVA, Mode::Getter, 8).accessor_offset,
        Some(32)
    );
    assert_eq!(
        scan_typed(&[0x48, 0x89, 0x51, 0x1c, 0xc3], RVA, Mode::Setter, 8).accessor_offset,
        Some(28)
    );
}
