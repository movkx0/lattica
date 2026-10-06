//! In-memory native-witness bridge for public research fixtures. Only the leaf
//! proof and public statement leave this API; raw witnesses are never exported.
use super::super::{
    codec,
    commitment::Context,
    leaf, profile,
    recursive::{Error, WalletProof},
    typed_leaf,
    typed_recursive::{self, Policy},
};
use p3_field::PrimeField64;

pub const REQUEST_MAGIC: &[u8; 8] = b"LBV2LW01";
pub const EXPORT_MAGIC: &[u8; 8] = b"LBV2WP01";
pub const REQUEST_BYTES: usize = 64;
pub const MAX_WALLET_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_EXPORT_BYTES: usize = MAX_WALLET_BYTES + 16 + 31 * 8;
pub const MAX_WITNESS_BYTES: usize = if crate::JS_WITNESS_LEN > crate::HTLC_WITNESS_LEN {
    crate::JS_WITNESS_LEN
} else {
    crate::HTLC_WITNESS_LEN
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Request {
    chain: [u8; 32],
    kind: u64,
    height: u64,
    authorized_mint: u64,
}

impl Request {
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != REQUEST_BYTES || !bytes.starts_with(REQUEST_MAGIC) {
            return Err("research wallet request version/length".into());
        }
        let request = Self {
            chain: bytes[8..40].try_into()?,
            kind: u64::from_le_bytes(bytes[40..48].try_into()?),
            height: u64::from_le_bytes(bytes[48..56].try_into()?),
            authorized_mint: u64::from_le_bytes(bytes[56..64].try_into()?),
        };
        let valid = match request.kind {
            1 => request.height == 0 && request.authorized_mint == 0,
            2 => request.height < (1 << 52) && request.authorized_mint == 0,
            3 => request.height == 0 && (1..(1 << 52)).contains(&request.authorized_mint),
            _ => false,
        };
        if !valid {
            return Err("research wallet request policy".into());
        }
        Ok(request)
    }
}

pub fn prove(request_bytes: &[u8], witness: &[u8]) -> Result<Vec<u8>, Error> {
    let request = Request::decode(request_bytes)?;
    let context = Context {
        profile_id: profile::CANDIDATE_PROFILE_ID,
        chain_id: request.chain,
    };
    let (public, envelope, policy) = match request.kind {
        1 | 3 => {
            let w = crate::parse_joinsplit_witness(witness)
                .ok_or("invalid native join-split witness")?;
            if w.mint != request.authorized_mint {
                return Err("native witness mint differs from host authorization".into());
            }
            let public = crate::joinsplit_air::public_values(&w);
            if request.kind == 1 {
                (
                    public,
                    leaf::prove_joinsplit_research(&w, &context).map_err(|e| format!("{e:?}"))?,
                    Policy::JoinSplit,
                )
            } else {
                (
                    public,
                    typed_leaf::prove_issuance_research(&w, &context, request.authorized_mint)
                        .map_err(|e| format!("{e:?}"))?,
                    Policy::Issuance {
                        authorized_mint: request.authorized_mint,
                    },
                )
            }
        }
        2 => {
            let w = crate::parse_htlc_witness(witness).ok_or("invalid native HTLC witness")?;
            if w.mint != 0 || w.current_height != request.height {
                return Err("native HTLC witness differs from host height/policy".into());
            }
            (
                crate::htlc_air::public_values(&w),
                typed_leaf::prove_htlc_research(&w, &context).map_err(|e| format!("{e:?}"))?,
                Policy::Htlc {
                    expected_height: request.height,
                },
            )
        }
        _ => unreachable!(),
    };
    let expected_fields = if request.kind == 2 { 31 } else { 26 };
    if public.len() != expected_fields {
        return Err("unsupported native public-statement shape".into());
    }
    let wallet = WalletProof {
        chain: request.chain,
        public,
        proof: codec::decode(envelope.get(72..).ok_or("short generated research leaf")?)?,
    };
    typed_recursive::verify_wallet(&wallet, policy)?;
    let mut encoded_wallet = b"LBV2TW01".to_vec();
    encoded_wallet.extend(postcard::to_allocvec(&wallet)?);
    if encoded_wallet.len() > MAX_WALLET_BYTES {
        return Err("native research wallet export limit".into());
    }
    let mut output = EXPORT_MAGIC.to_vec();
    output.extend((encoded_wallet.len() as u32).to_le_bytes());
    output.extend((wallet.public.len() as u32).to_le_bytes());
    output.extend(encoded_wallet);
    for value in wallet.public {
        output.extend(value.as_canonical_u64().to_le_bytes());
    }
    Ok(output)
}

/// Proves a native witness under the fixed research leaf configuration. The
/// output is LBV2WP01 || wallet_len(u32 LE) || public_count(u32 LE) ||
/// LBV2TW01 wallet envelope || canonical public field limbs (u64 LE).
/// Output length is zero on failure. This does not apply or authorize a block.
///
/// # Safety
/// Pointer/length pairs must be valid for the call, output must be writable,
/// and out_len must be a distinct live writable usize. Inputs remain immutable.
#[no_mangle]
pub unsafe extern "C" fn lattica_v2_research_wallet_prove_v1(
    request: *const u8,
    request_len: usize,
    witness: *const u8,
    witness_len: usize,
    output: *mut u8,
    output_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if out_len.is_null() {
        return -1;
    }
    // SAFETY: the caller supplies a distinct live output-length slot.
    unsafe {
        *out_len = 0;
    }
    if request.is_null()
        || witness.is_null()
        || output.is_null()
        || request_len != REQUEST_BYTES
        || witness_len == 0
        || witness_len > MAX_WITNESS_BYTES
        || output_cap == 0
        || output_cap > MAX_EXPORT_BYTES
    {
        return -1;
    }
    std::panic::catch_unwind(|| {
        // SAFETY: lengths were checked and inputs remain immutable for this call.
        let request = unsafe { std::slice::from_raw_parts(request, request_len) };
        let witness = unsafe { std::slice::from_raw_parts(witness, witness_len) };
        match prove(request, witness) {
            Ok(bytes) if bytes.len() <= output_cap => {
                // SAFETY: output capacity was checked; the owned result cannot alias it.
                unsafe {
                    std::ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len());
                    *out_len = bytes.len();
                }
                0
            }
            Ok(_) => -3,
            Err(_) => -2,
        }
    })
    .unwrap_or(-2)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(kind: u64, height: u64, mint: u64) -> [u8; REQUEST_BYTES] {
        let mut bytes = [0; REQUEST_BYTES];
        bytes[..8].copy_from_slice(REQUEST_MAGIC);
        bytes[8..40].fill(0x6d);
        bytes[40..48].copy_from_slice(&kind.to_le_bytes());
        bytes[48..56].copy_from_slice(&height.to_le_bytes());
        bytes[56..].copy_from_slice(&mint.to_le_bytes());
        bytes
    }

    #[test]
    fn request_policy_is_exact_and_fail_closed() {
        for (kind, height, mint) in [(1, 0, 0), (2, 10, 0), (3, 0, 7)] {
            assert!(Request::decode(&request(kind, height, mint)).is_ok());
        }
        for (kind, height, mint) in [
            (0, 0, 0),
            (4, 0, 0),
            (1, 1, 0),
            (1, 0, 7),
            (2, 10, 7),
            (2, 1 << 52, 0),
            (3, 0, 0),
            (3, 1, 7),
        ] {
            assert!(Request::decode(&request(kind, height, mint)).is_err());
        }
        let bytes = request(1, 0, 0);
        assert!(Request::decode(&bytes[..63]).is_err());
        let mut extended = bytes.to_vec();
        extended.push(0);
        assert!(Request::decode(&extended).is_err());
        let mut wrong_version = bytes;
        wrong_version[7] ^= 1;
        assert!(Request::decode(&wrong_version).is_err());
        assert!(prove(&bytes, &[]).is_err());
    }

    #[test]
    fn bounds_reject_before_dereferencing_inputs() {
        let p = std::ptr::NonNull::<u8>::dangling().as_ptr();
        let mut written = 123;
        // SAFETY: invalid lengths force rejection before the dangling inputs are read.
        unsafe {
            assert_eq!(
                lattica_v2_research_wallet_prove_v1(p, 63, p, 1, p, 1, &mut written),
                -1
            );
            assert_eq!(
                lattica_v2_research_wallet_prove_v1(p, 64, p, usize::MAX, p, 1, &mut written),
                -1
            );
        }
        assert_eq!(written, 0);
    }
}
