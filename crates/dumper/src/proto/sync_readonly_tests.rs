use super::{Mode, readonly_getter_offset, scan_typed};

const RVA: usize = 0x1000;

#[test]
fn readonly_leaf_getters_bind_exact_byte_dword_and_qword_slots() {
    for (code, bytes, offset) in [
        (&[0x0f, 0xb6, 0x41, 0x34, 0xc3][..], 1, 52),
        (&[0x8b, 0x41, 0x20, 0xc3][..], 4, 32),
        (&[0x48, 0x8b, 0x41, 0x28, 0xc3][..], 8, 40),
    ] {
        assert_eq!(readonly_getter_offset(code, RVA, bytes), Some(offset));
    }
}

#[test]
fn readonly_getter_does_not_inherit_a_partial_general_cfg_proof() {
    // One path returns owner+32; the other returns a computed constant.
    let code = [
        0x85, 0xd2, 0x74, 4, 0x8b, 0x41, 0x20, 0xc3, 0x31, 0xc0, 0xc3,
    ];
    assert_eq!(
        scan_typed(&code, RVA, Mode::Getter, 4).accessor_offset,
        Some(32)
    );
    assert_eq!(readonly_getter_offset(&code, RVA, 4), None);
}

#[test]
fn readonly_getters_reject_transformations_calls_and_non_owner_reads() {
    for code in [
        &[0x8b, 0x41, 0x20, 0xff, 0xc0, 0xc3][..], // incremented value
        &[0x8b, 0x41, 0x20, 0xe8, 0, 0, 0, 0, 0xc3][..], // unknown callee
        &[0x8b, 0x42, 0x20, 0xc3][..],             // another object in RDX
        &[0x8b, 0x44, 0x91, 0x20, 0xc3][..],       // indexed access
        &[0x64, 0x8b, 0x41, 0x20, 0xc3][..],       // FS-relative access
        &[0x67, 0x8b, 0x41, 0x20, 0xc3][..],       // truncated owner address
        &[0x8d, 0x41, 0x20, 0xc3][..],             // address, not field value
        &[0x8b, 0x41, 0x20, 0xeb, 0, 0xc3][..],    // non-leaf control flow
    ] {
        assert_eq!(readonly_getter_offset(code, RVA, 4), None, "{code:x?}");
    }
}

#[test]
fn readonly_getters_require_exact_width_return_register_and_plain_ret() {
    let dword = [0x8b, 0x41, 0x20, 0xc3];
    for bytes in [0, 1, 2, 8, 16] {
        assert_eq!(readonly_getter_offset(&dword, RVA, bytes), None);
    }
    for code in [
        &[0x8b, 0x41, 0x20][..],             // missing RET
        &[0x8b, 0x41, 0x20, 0xc2, 8, 0][..], // callee-adjusted stack
        &[0x8b, 0x41, 0x20, 0xf3, 0xc3][..], // prefixed RET
        &[0x8b, 0x51, 0x20, 0xc3][..],       // wrong return register
        &[0x8b, 0x41, 0x08, 0xc3][..],       // object header, not instance data
        &[0x8b, 0x41, 0xff, 0xc3][..],       // negative displacement
        &[0x8b, 0x81, 0xff, 0xff, 0xff, 0xff, 0xc3][..],
        &[][..],
    ] {
        assert_eq!(readonly_getter_offset(code, RVA, 4), None, "{code:x?}");
    }
    assert_eq!(readonly_getter_offset(&dword, usize::MAX - 1, 4), None);
}

#[test]
fn readonly_bool_leaf_can_return_al_but_never_ah_or_a_word() {
    assert_eq!(
        readonly_getter_offset(&[0x8a, 0x41, 0x20, 0xc3], RVA, 1),
        Some(32)
    );
    for code in [
        &[0x8a, 0x61, 0x20, 0xc3][..],
        &[0x0f, 0xb7, 0x41, 0x20, 0xc3][..],
        &[0x48, 0x0f, 0xb6, 0x41, 0x20, 0xc3][..],
    ] {
        assert_eq!(readonly_getter_offset(code, RVA, 1), None);
    }
}

#[test]
fn readonly_leaf_padding_cannot_change_the_proven_return_slot() {
    let code = [0x8b, 0x41, 0x20, 0xc3, 0xcc, 0x90, 0x8b, 0x41, 0x24, 0xc3];
    assert_eq!(readonly_getter_offset(&code, RVA, 4), Some(32));
}

#[test]
#[ignore = "requires explicit current DLL byte captures and output path; disk-only, no reflection"]
fn replay_current_readonly_getters() -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    use serde::Deserialize;
    use std::{
        fs,
        io::{Read, Seek, SeekFrom},
        path::PathBuf,
    };

    #[derive(Deserialize)]
    struct Input {
        source_dll: PathBuf,
        cases: Vec<Case>,
    }
    #[derive(Deserialize)]
    struct Case {
        rva: usize,
        raw_offset: u64,
        code: String,
        bytes: usize,
        expected_offset: u32,
    }
    let input = PathBuf::from(std::env::var("HSR_PROTO_READONLY_INPUT")?);
    let output = PathBuf::from(std::env::var("HSR_PROTO_READONLY_OUTPUT")?);
    let capture: Input = serde_json::from_slice(&fs::read(input)?)?;
    ensure!(
        !capture.cases.is_empty(),
        "no actual readonly getter captures"
    );
    let mut dll = fs::File::open(&capture.source_dll)?;
    let mut results = Vec::new();
    for case in capture.cases {
        ensure!(
            case.code.is_ascii() && case.code.len() % 2 == 0,
            "invalid capture hex"
        );
        let code = (0..case.code.len())
            .step_by(2)
            .map(|index| {
                u8::from_str_radix(&case.code[index..index + 2], 16).context("invalid capture byte")
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let mut actual = vec![0; code.len()];
        dll.seek(SeekFrom::Start(case.raw_offset))?;
        dll.read_exact(&mut actual)?;
        ensure!(
            actual == code,
            "current DLL differs at getter 0x{:X}",
            case.rva
        );
        let offset = readonly_getter_offset(&actual, case.rva, case.bytes);
        ensure!(
            offset == Some(case.expected_offset),
            "readonly getter offset differs at 0x{:X}",
            case.rva
        );
        results.push(serde_json::json!({"rva": case.rva, "bytes": case.bytes, "offset": offset}));
    }
    fs::write(
        &output,
        serde_json::to_vec_pretty(&serde_json::json!({
            "validation": "success", "source_dll": capture.source_dll,
            "verified_getters": results.len(), "getters": results,
            "boundary": "Current DLL bytes and production leaf-getter proof; runtime property/type/copy identity is validated separately."
        }))?,
    )?;
    println!(
        "[Readonly replay] verified_getters={} output={}",
        results.len(),
        output.display()
    );
    Ok(())
}
