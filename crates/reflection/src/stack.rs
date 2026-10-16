//! Stack-budget helpers for deeply recursive reflection work on Windows.
//!
//! A caught `STATUS_STACK_OVERFLOW` leaves the thread without its guard
//! page; the next overflow on that thread cannot be delivered and the process
//! dies. Recursive serializers therefore stop on a headroom budget before the
//! guard page is reached, and anything that does catch an overflow re-arms the
//! guard with [`reset_guard`] once the stack has unwound.

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentThreadStackLimits(low_limit: *mut usize, high_limit: *mut usize);
}

#[cfg(windows)]
unsafe extern "C" {
    /// UCRT: re-establish the guard page below the current stack pointer.
    fn _resetstkoflw() -> i32;
}

#[cfg(windows)]
fn limits() -> (usize, usize) {
    let (mut low, mut high) = (0usize, 0usize);
    unsafe { GetCurrentThreadStackLimits(&mut low, &mut high) };
    (low, high)
}

/// Bytes between the caller's frame and the lowest address of the current
/// thread's stack reservation, or `None` when it cannot be determined.
#[cfg(windows)]
#[inline(never)]
pub fn remaining() -> Option<usize> {
    let (low, high) = limits();
    let marker = 0u8;
    let here = std::ptr::addr_of!(marker) as usize;
    (low < here && here <= high).then(|| here - low)
}

/// Size of the current thread's stack reservation.
#[cfg(windows)]
pub fn reserved() -> Option<usize> {
    let (low, high) = limits();
    (low < high).then(|| high - low)
}

/// Re-arm the stack guard page after a caught stack overflow. Call it from a
/// frame well above the faulting one; returns whether the guard is in place.
#[cfg(windows)]
pub fn reset_guard() -> bool {
    unsafe { _resetstkoflw() != 0 }
}

#[cfg(not(windows))]
pub fn remaining() -> Option<usize> {
    None
}

#[cfg(not(windows))]
pub fn reserved() -> Option<usize> {
    None
}

#[cfg(not(windows))]
pub fn reset_guard() -> bool {
    true
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[inline(never)]
    fn remaining_after(levels: usize) -> usize {
        let padding = std::hint::black_box([0u8; 1024]);
        if levels == 0 {
            return remaining().unwrap() + usize::from(padding[0]);
        }
        remaining_after(levels - 1) + usize::from(std::hint::black_box(padding)[1])
    }

    #[test]
    fn remaining_shrinks_with_depth_and_fits_the_reservation() {
        let top = remaining().unwrap();
        let deeper = remaining_after(32);
        assert!(deeper + 32 * 1024 <= top, "top={top} deeper={deeper}");
        assert!(top < reserved().unwrap());
    }

    #[test]
    fn spawned_thread_reports_its_reservation() {
        const SIZE: usize = 8 * 1024 * 1024;
        let reserved = std::thread::Builder::new()
            .stack_size(SIZE)
            .spawn(|| reserved().unwrap())
            .unwrap()
            .join()
            .unwrap();
        assert!(reserved >= SIZE, "reserved {reserved}");
    }

    #[test]
    fn guard_can_be_rearmed_on_a_healthy_stack() {
        assert!(reset_guard());
    }

    #[inline(never)]
    fn recurse_forever(depth: usize) -> usize {
        let padding = std::hint::black_box([depth as u8; 4096]);
        recurse_forever(depth + 1) + usize::from(padding[1])
    }

    /// The failure that killed the game: an overflow caught once leaves no
    /// guard page, so a second one cannot be delivered. Re-arming must make
    /// every later overflow catchable again.
    #[test]
    fn repeated_overflows_stay_catchable_after_rearming() {
        let caught = std::thread::Builder::new()
            .stack_size(1024 * 1024)
            .spawn(|| {
                let mut caught = 0;
                for _ in 0..3 {
                    let error = microseh::try_seh(|| {
                        std::hint::black_box(recurse_forever(0));
                    })
                    .unwrap_err();
                    assert_eq!(error.code(), microseh::ExceptionCode::StackOverflow);
                    assert!(reset_guard(), "guard not re-armed");
                    caught += 1;
                }
                caught
            })
            .unwrap()
            .join()
            .unwrap();
        assert_eq!(caught, 3);
    }
}
