//! Source-derived primitive upper bounds for the affected trusted adapters.
//! These are arithmetic metadata only. They admit no graph, allocation or proof.
use super::{add, mul, CompileError};
use lattica_prover_p3::block_v2::machine::verifier::batch::shape::OperationCounts;

fn ops(scalar: usize, poseidon: usize) -> OperationCounts {
    OperationCounts {
        scalar,
        cubic: 0,
        poseidon,
    }
}
fn ceil(n: usize, d: usize) -> usize {
    n / d + usize::from(n % d != 0)
}

/// Byte::to_wire: zero Constant + eight*(weight Constant, Mul, Add).
const BYTE_TO_WIRE: usize = 25;
/// One fresh byte field: Input + eight Bit + eight Boolean + to_wire + Equal.
const BYTE_INPUT: usize = 1 + 8 + 8 + BYTE_TO_WIRE + 1;

/// pq_bytes::poseidon_commit_bytes uses four setup constants, two arithmetic
/// operations per complete byte pair and one Poseidon per eight-byte chunk.
pub fn byte_commitment(bytes: usize) -> Result<OperationCounts, CompileError> {
    Ok(ops(
        add(4, add(mul(BYTE_TO_WIRE, bytes)?, mul(2, bytes / 2)?)?)?,
        ceil(bytes, 8),
    ))
}

/// SourceBinding::new: four fresh Inputs and two kind/index Constants per
/// polynomial/byte root;12 manifest-header Constants; hash setup and4 Equals;
/// context word/byte bridge; fixed setup-seed byte commitment. See BOUNDS.md.
pub fn source_binding_initialization(
    polynomials: usize,
    bytes: usize,
) -> Result<OperationCounts, CompileError> {
    let roots = add(polynomials, bytes)?;
    let fields = add(12, mul(6, roots)?)?;
    Ok(ops(add(3507, mul(6, roots)?)?, add(ceil(fields, 4), 8)?))
}

/// Graph header:8 bounded32-bit words plus12 fixed Constant/Equal pairs.
pub const GRAPH_HEADER: OperationCounts = OperationCounts {
    scalar: 1320,
    cubic: 0,
    poseidon: 0,
};

/// Every fixed root emits four Constant/Equal pairs. Counting the two implicit
/// byte roots again is conservative when passed the full leaf coverage count.
pub fn fixed_sources(roots: usize) -> Result<OperationCounts, CompileError> {
    Ok(ops(mul(8, roots)?, 0))
}

/// Sixteen fresh serial-word Inputs, source bundle initialization/equalities,
/// and two32-byte word bridges (2392 scalar/four Poseidon each).
pub const STATEMENT_SOURCE: OperationCounts = OperationCounts {
    scalar: 16 + 4 + 8 + 2 * 2392,
    cubic: 0,
    poseidon: crate::statement_air::POLYNOMIALS + 4 + 2 * 4,
};

/// Eight fresh alpha-word Inputs, source bundle initialization/equalities,
/// and one32-byte word bridge. Neither source wrapper changes native AIR.
pub const PRIVATE_SOURCE: OperationCounts = OperationCounts {
    scalar: 8 + 4 + 4 + 2392,
    cubic: 0,
    poseidon: crate::proof_air::POLYNOMIALS + 2 + 4,
};

/// Affine joins initialize four Constants, absorb two or three ordered roots
/// per operation, then emit four Equals. Native core public inputs are separate.
pub fn affine_join(count: usize, conversion: bool) -> Result<OperationCounts, CompileError> {
    if count == 0 || count > 64 || !count.is_power_of_two() {
        return Err(CompileError::Shape("selected affine framing count"));
    }
    Ok(ops(8, mul(if conversion { 2 } else { 3 }, count)?))
}

/// Native NTT/product/permutation/linear-map/g_bound joins equate each native
/// public field to its exact graph root. No root is freshly opened here.
pub fn native_root_join(publics: usize) -> Result<OperationCounts, CompileError> {
    if publics == 0 || publics > 384 {
        return Err(CompileError::Shape("selected native framing publics"));
    }
    Ok(ops(publics, 0))
}

pub const EQUALITY: OperationCounts = OperationCounts {
    scalar: 4,
    cubic: 0,
    poseidon: 0,
};

/// Component header1332, input-root Equals4, both possible endpoint conditions
/// (8+4), and two six-field hashes (18 scalar/four Poseidon).
pub const AES_WRAPPER: OperationCounts = OperationCounts {
    scalar: 1332 + 4 + 8 + 4 + 18,
    cubic: 0,
    poseidon: 4,
};
/// Component header plus both possible request endpoints, two110-field hashes
/// and all108 boundary Equal constraints per adjacent native proof. Endpoint
/// first/final bindings are charged even when this particular span omits them.
pub fn shake_wrapper(members: usize) -> Result<OperationCounts, CompileError> {
    if !(1..=2).contains(&members) {
        return Err(CompileError::Shape("paired SHAKE wrapper member count"));
    }
    Ok(ops(1574 + 108 * (members - 1), 56))
}

fn transcript_bundle(parts: usize) -> Result<OperationCounts, CompileError> {
    if !(1..=256).contains(&parts) {
        return Err(CompileError::Shape("transcript framing part count"));
    }
    // Four initial Constants; per part four metadata Constants, two zero
    // Constants and two Poseidon calls. Source roots are already-owned wires.
    Ok(ops(add(4, mul(6, parts)?)?, mul(2, parts)?))
}

/// A fresh32-byte opening is committed under both byte and SHAKE-output
/// domains, with four equalities binding the former to its source graph root.
pub fn digest_bridge() -> Result<OperationCounts, CompileError> {
    byte_commitment(32)?
        .with_overhead(byte_commitment(32)?)?
        .with_overhead(ops(32 * BYTE_INPUT + 4, 0))
}

/// In addition to one native Transcript core and one46-public component core:
/// producer header1324, four bundle-root Equals and28 request-context/endpoint
/// Equals. Descriptor comparisons and registration checks are host operations.
pub const HASH_X_PRODUCER: OperationCounts = OperationCounts {
    scalar: 1356,
    cubic: 0,
    poseidon: 0,
};

/// AlphaUniform/AlphaSparse use the same1324-scalar producer header, four
/// output-root Equals and28 authenticated AES-request Equals as HashX.
pub const ALPHA_PRODUCER: OperationCounts = HASH_X_PRODUCER;

fn aes_key_opening() -> Result<OperationCounts, CompileError> {
    byte_commitment(32)?.with_overhead(ops(32 * BYTE_INPUT + 4, 0))
}
fn aes_key_request() -> Result<OperationCounts, CompileError> {
    // key32 || domain-le64 || counter-le32 || length-le64. Metadata contributes
    //20 constant bytes (eight bit Constants each); key bytes are already owned.
    byte_commitment(52)?.with_overhead(ops(20 * 8, 0))
}

/// Excludes common graph framing and component/Uniform cores. Four stream-root
/// Inputs,28 component request Equals, four bundle Constants/eight Equals and
/// four output-root absorbs are included.
pub fn sample_g_consumer() -> Result<OperationCounts, CompileError> {
    aes_key_opening()?
        .with_overhead(aes_key_request()?)?
        .with_overhead(ops(4 + 28 + 4 + 8, 4))
}

/// Excludes common graph framing and two38-public producer cores. Both typed
/// branches bind24 context fields, share one key opening, commit their distinct
/// request metadata, and join all ordered uniform/sparse outputs atomically.
pub fn expand_alpha_branch_consumer() -> Result<OperationCounts, CompileError> {
    aes_key_opening()?
        .with_overhead(aes_key_request()?)?
        .with_overhead(aes_key_request()?)?
        .with_overhead(ops(2 * 24 + 8 + 4 + 8, 2))
}

/// Excludes SourceBinding initialization/graph header and both verifier cores.
/// Includes24 producer-context Equals, transcript bundle/four Equals and eight
/// Sparse sampler root Equals. The producer core has38 public values.
pub fn hash_x_branch_consumer(parts: usize) -> Result<OperationCounts, CompileError> {
    transcript_bundle(parts)?.with_overhead(ops(24 + 4 + 8, 0))
}

/// Excludes SourceBinding/graph header and native Transcript/component cores.
/// Four duplicate input-root witness Inputs, bundle/eight serialization Equals,
/// digest bridge and28 authenticated component request Equals are included.
pub fn hash_alpha_consumer(parts: usize) -> Result<OperationCounts, CompileError> {
    transcript_bundle(parts)?
        .with_overhead(digest_bridge()?)?
        .with_overhead(ops(4 + 8 + 28, 0))
}

/// Excludes SourceBinding/graph header and the46-public component core.
/// The public prefix has the literal domain plus a32-byte fixed setup digest;
/// its content cannot change the upper number of Constant instructions.
pub fn parameters_pp_consumer() -> Result<OperationCounts, CompileError> {
    let prefix = b"lattica/pq-ringct/matrict-plus-n10/fixture-v1".len() + 32;
    byte_commitment(32)?
        .with_overhead(byte_commitment(prefix + 32)?)?
        .with_overhead(digest_bridge()?)?
        .with_overhead(ops(32 * BYTE_INPUT + 4 + prefix * 8 + 28, 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_domains_and_size_overflow_do_not_return_partial_bounds() {
        assert!(source_binding_initialization(usize::MAX, 1).is_err());
        assert!(source_binding_initialization(usize::MAX / 6, 0).is_err());
        assert!(byte_commitment(usize::MAX).is_err());
        assert!(hash_alpha_consumer(0).is_err());
        assert!(hash_x_branch_consumer(257).is_err());
        assert!(shake_wrapper(0).is_err());
        assert!(shake_wrapper(3).is_err());
    }
}
