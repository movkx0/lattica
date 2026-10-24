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
