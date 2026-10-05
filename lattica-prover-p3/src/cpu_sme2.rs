//! Opt-in component experiment. The prover's Plonky3 backend is unchanged.
use std::sync::OnceLock;

pub const MODULUS: u64 = 0xffff_ffff_0000_0001;

pub fn available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            [c"hw.optional.arm.FEAT_SME", c"hw.optional.arm.FEAT_SME2"]
                .iter()
                .all(|key| {
                    let mut value: libc::c_int = 0;
                    let mut size = std::mem::size_of_val(&value);
                    // SAFETY: NUL-terminated name and correctly sized writable int.
                    unsafe {
                        libc::sysctlbyname(
                            key.as_ptr(),
                            (&mut value as *mut libc::c_int).cast(),
                            &mut size,
                            std::ptr::null_mut(),
                            0,
                        ) == 0
                            && size == std::mem::size_of_val(&value)
                            && value == 1
                    }
                })
        }
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        {
            false
        }
    })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe extern "C" {
    fn lattica_sme2_mul(a: *const u64, b: *const u64, out: *mut u64, n: usize);
    fn lattica_sme2_lanes() -> usize;
}

pub fn streaming_lanes() -> Result<usize, &'static str> {
    if !available() {
        return Err("SME2 requires macOS arm64 with FEAT_SME and FEAT_SME2");
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        Ok(unsafe { lattica_sme2_lanes() })
    }
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        unreachable!()
    }
}

/// Multiply any full-width u64 representatives, returning canonical residues.
/// Explicit SME2 selection never silently substitutes another backend.
pub fn multiply(a: &[u64], b: &[u64], out: &mut [u64]) -> Result<(), &'static str> {
    if a.len() != b.len() || a.len() != out.len() {
        return Err("SME2 slice lengths differ");
    }
    if !available() {
        return Err("SME2 requires macOS arm64 with FEAT_SME and FEAT_SME2");
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    // SAFETY: runtime qualification precedes entry; Rust slices provide valid,
    // non-overlapping output and the C loop predicates every tail load/store.
    unsafe {
        lattica_sme2_mul(a.as_ptr(), b.as_ptr(), out.as_mut_ptr(), a.len());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_lengths_and_unsupported_hardware() {
        assert!(multiply(&[1], &[], &mut []).is_err());
        if !available() {
            assert!(multiply(&[], &[], &mut []).is_err());
        }
    }
    #[test]
    fn exact_full_width_edges_random_and_predicated_tails() {
        if !available() {
            eprintln!("SME2 hardware unavailable; hardware qualification must run separately");
            return;
        }
        let edge = [
            0,
            1,
            2,
            0xffff_ffff,
            1 << 32,
            MODULUS - 1,
            MODULUS,
            MODULUS + 1,
            u64::MAX,
        ];
        let mut a = Vec::new();
        let mut b = Vec::new();
        for x in edge {
            for y in edge {
                a.push(x);
                b.push(y);
            }
        }
        let mut seed = 0x4c617474696361_u64;
        for _ in 0..65536 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            a.push(seed);
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            b.push(seed);
        }
        let lanes = streaming_lanes().unwrap();
        for n in (0..=lanes * 3 + 1).chain([a.len()]) {
            let mut out = vec![0xdead_beef; n + 2];
            multiply(&a[..n], &b[..n], &mut out[1..=n]).unwrap();
            assert_eq!(out[0], 0xdead_beef);
            assert_eq!(out[n + 1], 0xdead_beef);
            for i in 0..n {
                assert_eq!(
                    out[i + 1],
                    ((a[i] as u128 * b[i] as u128) % MODULUS as u128) as u64,
                    "n={n} i={i}"
                );
            }
        }
    }
}
