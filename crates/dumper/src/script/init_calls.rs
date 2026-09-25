use super::memory;
use anyhow::{Context, Result, ensure};
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, InstructionInfoFactory, Mnemonic, OpAccess, OpKind,
    Register,
};
use std::collections::BTreeSet;

pub(super) struct InitCalls {
    pub indices: BTreeSet<u32>,
    pub sites: usize,
    pub unresolved: usize,
}

#[derive(Default, Debug)]
pub(super) struct TableSlots {
    pub types: BTreeSet<u32>,
    pub methods: BTreeSet<u32>,
    pub strings: BTreeSet<u32>,
}

pub(super) struct MetadataPlan {
    pub list_count: usize,
    pub pair_count: usize,
    pub slots: TableSlots,
}

/// The list keys are shared with morax::crypt::script. Check this initializer's
/// layout, then validate the complete decoded list before invoking game code.
/// Call-site arguments independently cross-check the resulting length.
pub(super) fn validated_metadata(
    image: &[u8],
    base: usize,
    initializer: usize,
) -> Result<MetadataPlan> {
    let code = image
        .get(initializer..image.len().min(initializer.saturating_add(2048)))
        .context("initializer outside module image")?;
    let instructions: Vec<_> =
        Decoder::with_ip(64, code, (base + initializer) as u64, DecoderOptions::NONE)
            .into_iter()
            .collect();
    let global = |register| {
        instructions
            .iter()
            .take(20)
            .find(|i| {
                i.mnemonic() == Mnemonic::Mov
                    && i.op0_register() == register
                    && i.is_ip_rel_memory_operand()
            })
            .map(|i| i.ip_rel_memory_address() as usize)
            .context("metadata global not found")
    };
    let header_global = global(Register::RDX)?;
    let payload_global = global(Register::R14)?;
    for offset in [0x1d0, 0x190] {
        ensure!(
            instructions
                .iter()
                .any(|i| i.memory_base() == Register::RDX && i.memory_displacement64() == offset),
            "unsupported metadata header layout"
        );
    }
    for key in [
        0xc9a664a5,
        0xed791073,
        0x8cd81660ee8,
        0x7afce30f,
        0xef048154,
        0x9174aed3,
        0x87c3,
        0x5fa3fad3,
        0x334fb2ba,
        0x454d10d89e6a02a,
        0x102533d7,
        0x58972d9863a807,
        0xab3a6cb5,
        0x6907ab9a,
    ] {
        ensure!(
            instructions
                .iter()
                .any(|i| (0..i.op_count()).any(|op| matches!(
                    i.op_kind(op),
                    OpKind::Immediate32 | OpKind::Immediate32to64 | OpKind::Immediate64
                ) && (i.immediate(op) == key
                    || i.immediate(op) as u32 as u64 == key))),
            "unsupported metadata usage key 0x{key:X}"
        );
    }
    for address in [header_global, payload_global] {
        ensure!(
            address
                .checked_sub(base)
                .and_then(|offset| offset.checked_add(size_of::<usize>()))
                .is_some_and(|end| end <= image.len()),
            "metadata global outside module"
        );
    }
    // The caller supplies the SEH + Rust panic boundary for all native reads.
    let header =
        unsafe { memory::read_pointer(header_global) }.context("metadata header pointer")?;
    let payload =
        unsafe { memory::read_pointer(payload_global) }.context("metadata payload pointer")?;
    ensure!(header != 0 && payload != 0, "null metadata header/payload");
    let lists = unsafe { memory::read_u32(memory::element_address(header, 0x1d0, 1)?) }?
        .wrapping_sub(0x36599b5b) as usize;
    let pairs = unsafe { memory::read_u32(memory::element_address(header, 0x190, 1)?) }?
        .wrapping_sub(0x1286ef8d) as usize;
    ensure!(lists < pairs, "invalid metadata usage offsets");
    let span = pairs - lists;
    ensure!(
        span >= 8 && span % 4 == 0,
        "invalid metadata usage-list span {span}"
    );
    let table = payload
        .checked_add(lists)
        .context("usage-list address overflow")?;
    memory::readable(table, span).context("metadata usage-list memory")?;
    let mut raw = Vec::new();
    raw.try_reserve_exact(span / 4)
        .context("allocate metadata usage list")?;
    for index in 0..span / 4 {
        raw.push(unsafe { ((table + 4 * index) as *const u32).read_unaligned() });
    }
    let (list_count, pair_count) = validate_list(&raw)?;
    let pairs_bytes = pair_count
        .checked_mul(8)
        .context("usage-pair size overflow")?;
    let pairs_start = payload
        .checked_add(pairs)
        .context("usage-pair address overflow")?;
    memory::readable(pairs_start, pairs_bytes).context("metadata usage-pair memory")?;
    let mut slots = TableSlots::default();
    for index in 0..pair_count {
        let pointer = pairs_start
            .checked_add(8 * index)
            .context("usage-pair address overflow")?;
        let low = unsafe { (pointer as *const u32).read_unaligned() };
        let high = unsafe { ((pointer + 4) as *const u32).read_unaligned() };
        slots.insert_pair(index, low, high);
    }
    ensure!(
        !slots.types.is_empty() && !slots.methods.is_empty() && !slots.strings.is_empty(),
        "metadata usage tables are empty"
    );
    Ok(MetadataPlan {
        list_count,
        pair_count,
        slots,
    })
}

// Decode the destination slot exactly as the initializer does. In particular,
// kinds 3 and 6 share one table; repeated references must visit a slot only once.
impl TableSlots {
    fn insert_pair(&mut self, index: usize, low: u32, high: u32) {
        let (kind, slot) = decode_pair(index, low, high);
        let table = match kind {
            1 => &mut self.types,
            3 | 6 => &mut self.methods,
            5 => &mut self.strings,
            _ => return, // Other usage kinds are outside Script's output.
        };
        table.insert(slot);
    }
}

fn pair_key(index: usize) -> u32 {
    let value = (index as u64).wrapping_mul(0x87c3) ^ 0x5fa3fad3;
    let value = value
        .wrapping_mul(0x334fb2ba)
        .wrapping_add(0x454d10d89e6a02a)
        >> 14;
    (value
        .wrapping_mul(0x102533d7)
        .wrapping_add(0x58972d9863a807)
        >> 23) as u32
}

fn decode_pair(index: usize, low: u32, high: u32) -> (u32, u32) {
    let key = pair_key(index);
    let kind = high.wrapping_sub(key).wrapping_sub(0x54c5934b) >> 29;
    let slot = (low ^ 0x6907ab9a).wrapping_sub(key);
    (kind, slot)
}

fn list_key(index: usize) -> u32 {
    (((0x8cd81660ee8u64.wrapping_mul(index as u64) >> 17).wrapping_add(0x7afce30f)) as u32)
        ^ 0xef048154
}

fn validate_list(raw: &[u32]) -> Result<(usize, usize)> {
    ensure!(raw.len() >= 2, "usage list has no end sentinel");
    ensure!(
        u32::try_from(raw.len() - 2).is_ok(),
        "initializer index exceeds u32 ABI"
    );
    let mut previous = 0;
    for (index, &value) in raw.iter().enumerate() {
        let start = value.wrapping_add(list_key(index)).wrapping_sub(0x6e8b512d);
        ensure!(
            (index != 0 || start == 0) && start >= previous,
            "invalid metadata usage-list block {index}: start={start} previous={previous}"
        );
        previous = start;
    }
    ensure!(previous > 0, "empty metadata usage-pair table");
    Ok((raw.len() - 1, previous as usize))
}

/// Collect arguments from executable call sites. Never probe the native
/// initializer until it faults: that can strand a runtime lock on invalid input.
pub(super) fn collect(image: &[u8], base: u64, target: u64) -> Result<InitCalls> {
    let mut calls = InitCalls {
        indices: BTreeSet::new(),
        sites: 0,
        unresolved: 0,
    };
    for range in executable_ranges(image)? {
        let code = &image[range.clone()];
        for (offset, &opcode) in code.iter().enumerate() {
            if opcode != 0xe8 || offset + 5 > code.len() {
                continue;
            }
            let displacement = i32::from_le_bytes(code[offset + 1..offset + 5].try_into().unwrap());
            let ip = base + (range.start + offset) as u64;
            if ip.wrapping_add(5).wrapping_add_signed(displacement as i64) != target {
                continue;
            }
            calls.sites += 1;
            if let Some(index) = immediate_argument(code, offset, base + range.start as u64) {
                calls.indices.insert(index);
            } else {
                calls.unresolved += 1;
            }
        }
    }
    ensure!(
        !calls.indices.is_empty(),
        "no verified metadata initialization call arguments found"
    );
    Ok(calls)
}

fn immediate_argument(code: &[u8], call: usize, base: u64) -> Option<u32> {
    let mut info = InstructionInfoFactory::new();
    // Allow register saves between MOV ECX, index and CALL. A branch, another
    // call, or any overwrite of RCX makes this candidate unusable.
    for start in (call.saturating_sub(48)..call).rev() {
        // Do not reinterpret MOV R9D/CX as MOV ECX by dropping its prefix.
        if start > 0 && matches!(code[start - 1], 0x40..=0x4f | 0x66 | 0x67) {
            continue;
        }
        let mut decoder = Decoder::with_ip(
            64,
            &code[start..call],
            base + start as u64,
            DecoderOptions::NONE,
        );
        let first = decoder.decode();
        let index = match (first.mnemonic(), first.op0_register(), first.op1_kind()) {
            (Mnemonic::Mov, Register::ECX, OpKind::Immediate32) => first.immediate32(),
            (Mnemonic::Xor, Register::ECX, OpKind::Register)
                if first.op1_register() == Register::ECX =>
            {
                0
            }
            _ => continue,
        };
        let mut valid = true;
        while decoder.can_decode() {
            let instruction = decoder.decode();
            if instruction.is_invalid()
                || instruction.flow_control() != FlowControl::Next
                || info.info(&instruction).used_registers().iter().any(|r| {
                    r.register().full_register() == Register::RCX
                        && matches!(
                            r.access(),
                            OpAccess::Write
                                | OpAccess::CondWrite
                                | OpAccess::ReadWrite
                                | OpAccess::ReadCondWrite
                        )
                })
            {
                valid = false;
                break;
            }
        }
        if valid && !first.is_invalid() && decoder.position() == call - start {
            return Some(index);
        }
    }
    None
}

fn executable_ranges(image: &[u8]) -> Result<Vec<std::ops::Range<usize>>> {
    fn word(image: &[u8], offset: usize) -> Result<usize> {
        Ok(u16::from_le_bytes(
            image
                .get(offset..offset + 2)
                .context("truncated PE word")?
                .try_into()?,
        ) as usize)
    }
    fn dword(image: &[u8], offset: usize) -> Result<usize> {
        Ok(u32::from_le_bytes(
            image
                .get(offset..offset + 4)
                .context("truncated PE dword")?
                .try_into()?,
        ) as usize)
    }
    ensure!(image.get(..2) == Some(b"MZ"), "invalid DOS signature");
    let pe = dword(image, 0x3c)?;
    ensure!(
        image.get(pe..pe + 4) == Some(b"PE\0\0"),
        "invalid PE signature"
    );
    let count = word(image, pe + 6)?;
    ensure!(count <= 96, "invalid PE section count {count}");
    let table = pe + 24 + word(image, pe + 20)?;
    let mut ranges = Vec::new();
    for index in 0..count {
        let section = table + index * 40;
        if dword(image, section + 36)? & 0x2000_0000 == 0 {
            continue;
        }
        let start = dword(image, section + 12)?;
        let size = dword(image, section + 8)?;
        let end = start.checked_add(size).context("PE section overflow")?;
        ensure!(
            end <= image.len(),
            "executable section outside module image"
        );
        ranges.push(start..end);
    }
    ensure!(!ranges.is_empty(), "module has no executable sections");
    Ok(ranges)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_list_boundary_without_native_probing() {
        let encode = |values: &[u32]| {
            values
                .iter()
                .enumerate()
                .map(|(i, v)| v.wrapping_add(0x6e8b512d).wrapping_sub(list_key(i)))
                .collect::<Vec<_>>()
        };
        assert_eq!(validate_list(&encode(&[0, 3, 3, 20])).unwrap(), (3, 20));
        assert_eq!(
            validate_list(&encode(&[0, 20_000_001])).unwrap(),
            (1, 20_000_001)
        );
        for invalid in [vec![], vec![0], vec![1, 3], vec![0, 9, 4], vec![0, 0]] {
            assert!(validate_list(&encode(&invalid)).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn decodes_usage_pair_fixtures() {
        // Raw metadata records cross-checked with the current game's initializer.
        for (index, low, high, expected) in [
            (0, 0x2a06a2be, 0xf7c6e2d4, (3, 0)),
            (18, 0xfca243de, 0x8a6b7b8f, (5, 0)),
            (100, 0x83c87a29, 0x5f9c7a39, (1, 23)),
            (10000, 0x0b3ca187, 0x17024e9d, (3, 4999)),
            (895271, 0x1ee33716, 0xacaa50b8, (7, 330)),
        ] {
            assert_eq!(decode_pair(index, low, high), expected);
        }
    }

    #[test]
    fn combines_sparse_method_slots_without_a_version_specific_ceiling() {
        let mut slots = TableSlots::default();
        let encode = |index, kind: u32, slot: u32| {
            let key = pair_key(index);
            (
                slot.wrapping_add(key) ^ 0x6907ab9a,
                (kind << 29).wrapping_add(key).wrapping_add(0x54c5934b),
            )
        };
        for (index, (kind, slot)) in [(3, 0), (6, 2), (3, 2), (1, 5), (5, 7), (4, 999)]
            .into_iter()
            .enumerate()
        {
            let (low, high) = encode(index, kind, slot);
            slots.insert_pair(index, low, high);
        }
        assert_eq!(slots.methods, BTreeSet::from([0, 2]));
        assert_eq!(slots.types, BTreeSet::from([5]));
        assert_eq!(slots.strings, BTreeSet::from([7]));
        let (low, high) = encode(6, 1, 1_000_000);
        slots.insert_pair(6, low, high);
        let (low, high) = encode(7, 1, u32::MAX);
        slots.insert_pair(7, low, high);
        assert_eq!(slots.types, BTreeSet::from([5, 1_000_000, u32::MAX]));
    }

    #[test]
    fn recovers_argument_across_register_saves() {
        assert_eq!(
            immediate_argument(&[0xb9, 0x34, 0x12, 0, 0, 0x44, 0x89, 0xc6], 8, 0),
            Some(0x1234)
        );
        assert_eq!(immediate_argument(&[0x31, 0xc9], 2, 0), Some(0));
    }

    #[test]
    fn rejects_overwritten_or_control_dependent_argument() {
        for suffix in [
            &[0x89, 0xd1][..],
            &[0xeb, 0],
            &[0xe8, 0, 0, 0, 0],
            &[0x66, 0xb9, 1, 0],
        ] {
            let mut code = vec![0xb9, 42, 0, 0, 0];
            code.extend_from_slice(suffix);
            assert_eq!(immediate_argument(&code, code.len(), 0), None);
        }
        assert_eq!(immediate_argument(&[0x41, 0xb9, 42, 0, 0, 0], 6, 0), None);
    }

    #[test]
    fn scans_only_executable_sections_and_deduplicates_indices() {
        let mut image = vec![0u8; 512];
        image[..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&64u32.to_le_bytes());
        image[64..68].copy_from_slice(b"PE\0\0");
        image[70..72].copy_from_slice(&2u16.to_le_bytes());
        for (section, start, flags) in [(88, 256u32, 0x2000_0000u32), (128, 384, 0)] {
            image[section + 8..section + 12].copy_from_slice(&64u32.to_le_bytes());
            image[section + 12..section + 16].copy_from_slice(&start.to_le_bytes());
            image[section + 36..section + 40].copy_from_slice(&flags.to_le_bytes());
        }
        for (start, index) in [(256, 7u32), (272, 7), (384, 999)] {
            image[start] = 0xb9;
            image[start + 1..start + 5].copy_from_slice(&index.to_le_bytes());
            image[start + 5] = 0xe8;
            image[start + 6..start + 10]
                .copy_from_slice(&(480i32 - start as i32 - 10).to_le_bytes());
        }
        let calls = collect(&image, 0x1000, 0x1000 + 480).unwrap();
        assert_eq!(calls.indices, BTreeSet::from([7]));
        assert_eq!(calls.sites, 2);
        assert_eq!(calls.unresolved, 0);
        assert!(collect(&image[..128], 0, 480).is_err());
    }
}
