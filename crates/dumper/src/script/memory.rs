//! Preflight native reads without treating readable memory as an array bound.
//! Page permissions can change after VirtualQuery; callers must still use the
//! Script SEH boundary and validate indices against the decoded metadata.

use anyhow::{Context, Result, ensure};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
    VirtualQuery,
};

pub(super) fn readable(address: usize, length: usize) -> Result<()> {
    ensure!(address != 0, "null memory address");
    let end = address
        .checked_add(length)
        .context("memory range overflow")?;
    let mut cursor = address;
    while cursor < end {
        let mut info = MEMORY_BASIC_INFORMATION::default();
        let queried = unsafe {
            VirtualQuery(
                Some(cursor as *const _),
                &mut info,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        ensure!(
            queried == size_of_val(&info),
            "VirtualQuery failed at 0x{cursor:X}"
        );
        let readable_flags = PAGE_READONLY
            | PAGE_READWRITE
            | PAGE_WRITECOPY
            | PAGE_EXECUTE_READ
            | PAGE_EXECUTE_READWRITE
            | PAGE_EXECUTE_WRITECOPY;
        ensure!(
            info.State == MEM_COMMIT
                && info.Protect.0 & PAGE_GUARD.0 == 0
                && info.Protect.0 & readable_flags.0 != 0,
            "unreadable memory at 0x{cursor:X}: state=0x{:X} protection=0x{:X}",
            info.State.0,
            info.Protect.0
        );
        let region_start = info.BaseAddress as usize;
        let region_end = region_start
            .checked_add(info.RegionSize)
            .context("memory region overflow")?;
        ensure!(
            region_start <= cursor && region_end > cursor,
            "invalid memory region"
        );
        cursor = region_end.min(end);
    }
    Ok(())
}

pub(super) fn element_address(base: usize, index: usize, width: usize) -> Result<usize> {
    ensure!(base != 0, "null table base");
    base.checked_add(index.checked_mul(width).context("table offset overflow")?)
        .context("table address overflow")
}

// Safety: the caller must keep the source stable and enclose native reads in
// Script's guarded() boundary. VirtualQuery alone does not establish ownership.
pub(super) unsafe fn read_pointer(address: usize) -> Result<usize> {
    readable(address, size_of::<usize>())?;
    Ok(unsafe { (address as *const usize).read_unaligned() })
}

pub(super) unsafe fn read_u32(address: usize) -> Result<u32> {
    readable(address, size_of::<u32>())?;
    Ok(unsafe { (address as *const u32).read_unaligned() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::System::{
        Memory::{
            MEM_RELEASE, MEM_RESERVE, PAGE_NOACCESS, VirtualAlloc, VirtualFree, VirtualProtect,
        },
        SystemInformation::{GetSystemInfo, SYSTEM_INFO},
    };

    #[test]
    fn checks_arithmetic_and_reads_unaligned_words() {
        assert!(readable(0, 8).is_err());
        assert!(readable(usize::MAX - 3, 8).is_err());
        assert!(element_address(0, 0, 8).is_err());
        assert!(element_address(1, usize::MAX, 8).is_err());
        assert!(element_address(usize::MAX - 3, 1, 8).is_err());
        assert_eq!(element_address(16, 1_000_001, 8).unwrap(), 8_000_024);
        let mut bytes = [0u8; 16];
        bytes[1..9].copy_from_slice(&123usize.to_ne_bytes());
        assert_eq!(
            unsafe { read_pointer(bytes.as_ptr() as usize + 1) }.unwrap(),
            123
        );
    }

    #[test]
    fn checks_every_region_and_rejects_guard_uncommitted_and_noaccess() {
        let mut system = SYSTEM_INFO::default();
        unsafe { GetSystemInfo(&mut system) };
        let page = system.dwPageSize as usize;
        let allocation = unsafe { VirtualAlloc(None, page * 3, MEM_RESERVE, PAGE_NOACCESS) };
        assert!(!allocation.is_null());
        struct Allocation(*mut core::ffi::c_void);
        impl Drop for Allocation {
            fn drop(&mut self) {
                unsafe { VirtualFree(self.0, 0, MEM_RELEASE) }.unwrap();
            }
        }
        let allocation = Allocation(allocation);
        let start = allocation.0 as usize;
        assert_eq!(
            unsafe { VirtualAlloc(Some(allocation.0), page * 2, MEM_COMMIT, PAGE_READWRITE) },
            allocation.0
        );
        readable(start, page * 2).unwrap();
        assert!(readable(start + page * 2, 1).is_err());
        let second = (start + page) as *const _;
        let mut old = PAGE_READWRITE;
        for protection in [PAGE_READONLY, PAGE_NOACCESS, PAGE_READWRITE | PAGE_GUARD] {
            unsafe { VirtualProtect(second, page, protection, &mut old) }.unwrap();
            let result = readable(start + page - 4, 8);
            assert_eq!(result.is_ok(), protection == PAGE_READONLY, "{result:?}");
        }
        // The probe must not touch/consume PAGE_GUARD; querying again still fails.
        assert!(readable(start + page, 1).is_err());
        unsafe { VirtualProtect(second, page, PAGE_READWRITE, &mut old) }.unwrap();
        readable(start + page - 4, 8).unwrap();
    }
}
