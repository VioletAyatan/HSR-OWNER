//! Bounded reader for a loaded AMD64 PE image.
use anyhow::{Context, Result, ensure};
use std::ops::Range;

type Validator = fn(usize, usize) -> Result<()>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RuntimeFunction {
    pub start: usize,
    pub end: usize,
    pub unwind: usize,
}

#[derive(Clone)]
struct Section {
    range: Range<usize>,
    executable: bool,
}

#[derive(Clone)]
pub(super) struct Pe<'a> {
    image: &'a [u8],
    validator: Validator,
    preferred_base: usize,
    image_len: usize,
    headers: Range<usize>,
    sections: Vec<Section>,
    exception_records: &'a [u8],
    function_count: usize,
    imports: Vec<usize>,
}

impl<'a> Pe<'a> {
    pub(super) fn new(image: &'a [u8], validator: Validator) -> Result<Self> {
        fn raw(image: &[u8], validator: Validator, offset: usize, len: usize) -> Result<&[u8]> {
            let end = offset.checked_add(len).context("PE offset overflow")?;
            let bytes = image.get(offset..end).context("truncated PE metadata")?;
            let address = (image.as_ptr() as usize)
                .checked_add(offset)
                .context("PE address overflow")?;
            address
                .checked_add(len)
                .context("PE address range overflow")?;
            validator(address, len)?;
            Ok(bytes)
        }
        fn u16_at(image: &[u8], validator: Validator, offset: usize) -> Result<usize> {
            Ok(u16::from_le_bytes(raw(image, validator, offset, 2)?.try_into()?) as usize)
        }
        fn u32_at(image: &[u8], validator: Validator, offset: usize) -> Result<usize> {
            Ok(u32::from_le_bytes(raw(image, validator, offset, 4)?.try_into()?) as usize)
        }
        ensure!(
            raw(image, validator, 0, 2)? == b"MZ",
            "missing DOS signature"
        );
        let pe = u32_at(image, validator, 0x3c)?;
        ensure!(
            raw(image, validator, pe, 4)? == b"PE\0\0",
            "invalid PE signature"
        );
        let coff = pe.checked_add(4).context("COFF offset overflow")?;
        ensure!(
            u16_at(image, validator, coff)? == 0x8664,
            "expected AMD64 image"
        );
        let section_count = u16_at(image, validator, coff + 2)?;
        let optional_size = u16_at(image, validator, coff + 16)?;
        let optional = coff.checked_add(20).context("optional header overflow")?;
        ensure!(optional_size >= 112, "truncated PE32+ optional header");
        let optional_end = optional
            .checked_add(optional_size)
            .context("optional header overflow")?;
        raw(image, validator, optional, optional_size)?;
        ensure!(
            u16_at(image, validator, optional)? == 0x20b,
            "expected PE32+ image"
        );
        let image_len = u32_at(image, validator, optional + 56)?;
        let headers_len = u32_at(image, validator, optional + 60)?;
        ensure!(
            image_len != 0 && image_len <= image.len(),
            "invalid SizeOfImage"
        );
        ensure!(
            headers_len != 0 && headers_len <= image_len,
            "invalid SizeOfHeaders"
        );
        let preferred_base =
            u64::from_le_bytes(raw(image, validator, optional + 24, 8)?.try_into()?) as usize;
        let directory_count = u32_at(image, validator, optional + 108)?;
        let directory_start = optional
            .checked_add(112)
            .context("directory offset overflow")?;
        let dir = |index: usize| -> Result<(usize, usize)> {
            ensure!(
                directory_count > index,
                "PE data directory {index} is absent"
            );
            let offset = directory_start
                .checked_add(index.checked_mul(8).context("directory overflow")?)
                .context("directory overflow")?;
            ensure!(
                offset.checked_add(8).is_some_and(|end| end <= optional_end),
                "data directory exceeds optional header"
            );
            Ok((
                u32_at(image, validator, offset)?,
                u32_at(image, validator, offset + 4)?,
            ))
        };
        let sections_start = optional_end;
        let sections_bytes = section_count
            .checked_mul(40)
            .context("section table overflow")?;
        ensure!(
            sections_start
                .checked_add(sections_bytes)
                .is_some_and(|end| end <= headers_len),
            "section table is outside SizeOfHeaders"
        );
        raw(image, validator, sections_start, sections_bytes)?;
        let mut sections = Vec::with_capacity(section_count);
        for i in 0..section_count {
            let off = sections_start + i * 40;
            let virtual_size = u32_at(image, validator, off + 8)?;
            let virtual_address = u32_at(image, validator, off + 12)?;
            let raw_size = u32_at(image, validator, off + 16)?;
            let size = virtual_size.max(raw_size);
            if size == 0 {
                continue;
            }
            let end = virtual_address
                .checked_add(size)
                .context("section RVA overflow")?;
            ensure!(
                virtual_address >= headers_len && end <= image_len,
                "section outside mapped image or overlaps headers"
            );
            let characteristics = u32_at(image, validator, off + 36)?;
            sections.push(Section {
                range: virtual_address..end,
                executable: characteristics & 0x2000_0000 != 0,
            });
        }
        sections.sort_by_key(|section| section.range.start);
        for pair in sections.windows(2) {
            ensure!(
                pair[0].range.end <= pair[1].range.start,
                "overlapping PE sections"
            );
        }
        let mut pe = Self {
            image,
            validator,
            preferred_base,
            image_len,
            headers: 0..headers_len,
            sections,
            exception_records: &[],
            function_count: 0,
            imports: Vec::new(),
        };
        let (exc_rva, exc_size) = dir(3)?;
        ensure!(
            exc_rva != 0 && exc_size != 0 && exc_size % 12 == 0,
            "invalid exception directory"
        );
        exc_rva
            .checked_add(exc_size)
            .context("exception directory overflow")?;
        pe.exception_records = pe.bytes(exc_rva, exc_size)?;
        pe.function_count = exc_size / 12;
        let mut previous_end = 0;
        for index in 0..pe.function_count {
            let f = pe.read_function(index)?;
            ensure!(
                f.start >= previous_end && f.start < f.end,
                "unsorted or overlapping runtime function {index}"
            );
            ensure!(
                pe.executable(f.start, f.end - f.start),
                "runtime function is outside executable section"
            );
            pe.ensure_owned(f.unwind, 4)?;
            previous_end = f.end;
        }
        let (import_rva, import_size) = if directory_count > 1 { dir(1)? } else { (0, 0) };
        if import_rva != 0 || import_size != 0 {
            ensure!(
                import_rva != 0 && import_size >= 20,
                "invalid import directory"
            );
            pe.imports = pe.parse_imports(import_rva, import_size)?;
        }
        Ok(pe)
    }

    fn ensure_owned(&self, rva: usize, len: usize) -> Result<()> {
        let end = rva.checked_add(len).context("RVA range overflow")?;
        ensure!(end <= self.image_len(), "RVA range exceeds SizeOfImage");
        let owned = self.headers.start <= rva && end <= self.headers.end
            || self
                .sections
                .iter()
                .any(|s| s.range.start <= rva && end <= s.range.end);
        ensure!(owned, "RVA range is not owned by headers or one section");
        Ok(())
    }

    fn owner_end(&self, rva: usize) -> Result<usize> {
        if self.headers.contains(&rva) {
            return Ok(self.headers.end);
        }
        self.sections
            .iter()
            .find(|section| section.range.contains(&rva))
            .map(|section| section.range.end)
            .context("RVA is not owned by PE headers or a section")
    }

    fn owned(&self, rva: usize, len: usize) -> Result<()> {
        self.ensure_owned(rva, len)?;
        let address = (self.image.as_ptr() as usize)
            .checked_add(rva)
            .context("image address overflow")?;
        address
            .checked_add(len)
            .context("image address range overflow")?;
        (self.validator)(address, len)?;
        Ok(())
    }

    pub(super) fn bytes(&self, rva: usize, len: usize) -> Result<&'a [u8]> {
        self.owned(rva, len)?;
        let end = rva.checked_add(len).context("RVA range overflow")?;
        self.image.get(rva..end).context("RVA range outside image")
    }
    pub(super) fn u32(&self, rva: usize) -> Result<u32> {
        Ok(u32::from_le_bytes(self.bytes(rva, 4)?.try_into()?))
    }
    pub(super) fn i32(&self, rva: usize) -> Result<i32> {
        Ok(i32::from_le_bytes(self.bytes(rva, 4)?.try_into()?))
    }
    pub(super) fn u64(&self, rva: usize) -> Result<u64> {
        Ok(u64::from_le_bytes(self.bytes(rva, 8)?.try_into()?))
    }
    pub(super) fn preferred_base(&self) -> usize {
        self.preferred_base
    }
    pub(super) fn image_len(&self) -> usize {
        self.image_len
    }

    pub(super) fn executable(&self, rva: usize, len: usize) -> bool {
        let Some(end) = rva.checked_add(len) else {
            return false;
        };
        self.sections
            .iter()
            .any(|s| s.executable && s.range.start <= rva && end <= s.range.end)
    }

    fn read_function(&self, index: usize) -> Result<RuntimeFunction> {
        ensure!(
            index < self.function_count,
            "runtime function index out of range"
        );
        let offset = index.checked_mul(12).context("function index overflow")?;
        let record_end = offset.checked_add(12).context("function record overflow")?;
        let record = self
            .exception_records
            .get(offset..record_end)
            .context("runtime function record outside validated table")?;
        let read = |at: usize| -> Result<usize> {
            let end = at.checked_add(4).context("function field overflow")?;
            Ok(u32::from_le_bytes(
                record
                    .get(at..end)
                    .context("truncated runtime function record")?
                    .try_into()?,
            ) as usize)
        };
        Ok(RuntimeFunction {
            start: read(0)?,
            end: read(4)?,
            unwind: read(8)?,
        })
    }
    pub(super) fn function_count(&self) -> usize {
        self.function_count
    }
    pub(super) fn containing_function(&self, rva: usize) -> Option<RuntimeFunction> {
        let (mut low, mut high) = (0, self.function_count);
        while low < high {
            let mid = low + (high - low) / 2;
            if self.read_function(mid).ok()?.start <= rva {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        let f = self.read_function(low.checked_sub(1)?).ok()?;
        (rva < f.end).then_some(f)
    }
    pub(super) fn function(&self, rva: usize) -> Result<RuntimeFunction> {
        let (mut low, mut high) = (0, self.function_count);
        while low < high {
            let mid = low + (high - low) / 2;
            if self.read_function(mid)?.start < rva {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        ensure!(
            low < self.function_count,
            "no runtime function begins at RVA 0x{rva:X}"
        );
        let function = self.read_function(low)?;
        ensure!(
            function.start == rva,
            "RVA 0x{rva:X} is not a runtime function entry"
        );
        Ok(function)
    }

    fn c_string(&self, rva: usize) -> Result<Vec<u8>> {
        let end = self.owner_end(rva)?;
        let length = end.checked_sub(rva).context("string RVA underflow")?;
        let bytes = self.bytes(rva, length)?;
        let nul = bytes
            .iter()
            .position(|&byte| byte == 0)
            .context("unterminated import string before logical PE region end")?;
        Ok(bytes[..nul].to_vec())
    }
    fn parse_imports(&self, rva: usize, size: usize) -> Result<Vec<usize>> {
        let end = rva.checked_add(size).context("import directory overflow")?;
        let mut imports = Vec::new();
        let mut desc = rva;
        let mut terminated = false;
        while desc.checked_add(20).is_some_and(|next| next <= end) {
            let d = self.bytes(desc, 20)?;
            let fields: [u32; 5] = std::array::from_fn(|i| {
                u32::from_le_bytes(d[i * 4..i * 4 + 4].try_into().unwrap())
            });
            if fields == [0; 5] {
                terminated = true;
                break;
            }
            let oft = fields[0] as usize;
            let name_rva = fields[3] as usize;
            let first = fields[4] as usize;
            ensure!(oft != 0 && first != 0, "import descriptor lacks OFT or IAT");
            let module = self.c_string(name_rva)?;
            let accepted = module.eq_ignore_ascii_case(b"KERNEL32.dll")
                || module.eq_ignore_ascii_case(b"KERNELBASE.dll");
            let mut index = 0usize;
            loop {
                let offset = index.checked_mul(8).context("thunk offset overflow")?;
                let lookup_rva = oft.checked_add(offset).context("OFT RVA overflow")?;
                let iat_rva = first.checked_add(offset).context("IAT RVA overflow")?;
                let thunk = self.u64(lookup_rva)?;
                self.bytes(iat_rva, 8)?;
                if thunk == 0 {
                    break;
                }
                if thunk & (1u64 << 63) == 0 {
                    let name = usize::try_from(thunk).context("import name RVA overflow")?;
                    self.bytes(name, 2)?;
                    let symbol =
                        self.c_string(name.checked_add(2).context("import name overflow")?)?;
                    if accepted && symbol == b"RaiseException" {
                        imports.push(iat_rva);
                    }
                }
                index = index.checked_add(1).context("thunk count overflow")?;
            }
            desc = desc.checked_add(20).context("descriptor RVA overflow")?;
        }
        ensure!(terminated, "unterminated import descriptor table");
        Ok(imports)
    }
    pub(super) fn raise_exception_iats(&self) -> &[usize] {
        &self.imports
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn valid(_: usize, _: usize) -> Result<()> {
        Ok(())
    }
    fn fixture() -> Vec<u8> {
        let mut b = vec![0u8; 0x1000];
        b[0..2].copy_from_slice(b"MZ");
        put32(&mut b, 0x3c, 0x80);
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        put16(&mut b, 0x84, 0x8664);
        put16(&mut b, 0x86, 1);
        put16(&mut b, 0x94, 0xf0);
        let o = 0x98;
        put16(&mut b, o, 0x20b);
        put64(&mut b, o + 24, 0x140000000);
        put32(&mut b, o + 56, 0x1000);
        put32(&mut b, o + 60, 0x200);
        put32(&mut b, o + 108, 16);
        put32(&mut b, o + 112 + 3 * 8, 0x300);
        put32(&mut b, o + 112 + 3 * 8 + 4, 12);
        put32(&mut b, o + 112 + 1 * 8, 0x400);
        put32(&mut b, o + 112 + 1 * 8 + 4, 40);
        let s = o + 0xf0;
        b[s..s + 5].copy_from_slice(b".text");
        put32(&mut b, s + 8, 0x600);
        put32(&mut b, s + 12, 0x200);
        put32(&mut b, s + 16, 0x600);
        put32(&mut b, s + 36, 0x60000020);
        put32(&mut b, 0x300, 0x200);
        put32(&mut b, 0x304, 0x210);
        put32(&mut b, 0x308, 0x500);
        b[0x500] = 1;
        // Single import descriptor and terminator, OFT/IAT each have two adjacent slots.
        put32(&mut b, 0x400, 0x440);
        put32(&mut b, 0x40c, 0x480);
        put32(&mut b, 0x410, 0x460);
        put64(&mut b, 0x440, 0x4a0);
        put64(&mut b, 0x448, 0x4c0);
        put64(&mut b, 0x450, 0);
        put64(&mut b, 0x460, 0x111);
        put64(&mut b, 0x468, 0x222);
        put64(&mut b, 0x470, 0);
        b[0x480..0x48d].copy_from_slice(b"KERNEL32.dll\0");
        b[0x4a0..0x4a2].copy_from_slice(&[0, 0]);
        b[0x4a2..0x4b1].copy_from_slice(b"RaiseException\0");
        b[0x4c0..0x4c2].copy_from_slice(&[0, 0]);
        b[0x4c2..0x4c8].copy_from_slice(b"Other\0");
        b
    }
    fn put16(b: &mut [u8], o: usize, v: usize) {
        b[o..o + 2].copy_from_slice(&(v as u16).to_le_bytes())
    }
    fn put32(b: &mut [u8], o: usize, v: usize) {
        b[o..o + 4].copy_from_slice(&(v as u32).to_le_bytes())
    }
    fn put64(b: &mut [u8], o: usize, v: u64) {
        b[o..o + 8].copy_from_slice(&v.to_le_bytes())
    }
    #[test]
    fn accepts_bounded_image_and_exact_function_entry() {
        let b = fixture();
        let p = Pe::new(&b, valid).unwrap();
        assert_eq!(p.function(0x200).unwrap().end, 0x210);
        assert!(p.function(0x204).is_err());
        assert_eq!(p.raise_exception_iats(), &[0x460]);
    }
    #[test]
    fn rejects_truncated_header_and_out_of_image_metadata() {
        let mut b = fixture();
        assert!(Pe::new(&b[..0x90], valid).is_err());
        put32(&mut b, 0x98 + 112 + 24, 0xfff);
        assert!(Pe::new(&b, valid).is_err());
    }
    #[test]
    fn rejects_wrong_oft_name_and_validates_adjacent_iat_slots() {
        let mut b = fixture();
        b[0x4a2..0x4a8].copy_from_slice(b"Other\0");
        assert!(
            Pe::new(&b, valid)
                .unwrap()
                .raise_exception_iats()
                .is_empty()
        );
        let mut b = fixture();
        put32(&mut b, 0x410, 0x7f8);
        assert!(Pe::new(&b, valid).is_err());
    }

    #[test]
    fn rejects_import_strings_without_nul_before_logical_region_end() {
        let mut module = fixture();
        module[0x480..0x800].fill(b'x');
        module[0x480..0x48c].copy_from_slice(b"KERNEL32.dll");
        assert!(Pe::new(&module, valid).is_err());

        let mut symbol = fixture();
        symbol[0x4a2..0x800].fill(b'x');
        assert!(Pe::new(&symbol, valid).is_err());
    }
}
