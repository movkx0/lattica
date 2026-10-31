//! Allocation-free checks on the actual, immutable input owners. Descriptive
//! compiler counters cannot authorize a different program or witness capacity.
use super::*;
use crate::ring::{Account, RING_PAIRS};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Digest, Sha3_256, Shake256,
};

/// Two native bounded stage reports, their transient construction copies, and
/// fixed JSON session telemetry. These are reserved before Session::start, not
/// inferred from allocations after proving has begun. The core reports have at
/// most 19 stage variants, six backends, and 16 component slots; the actual
/// retained vector capacities are checked again before a report is retained.
pub(super) const REPORT_AND_SESSION_BYTES: usize = 256 << 10;

pub(super) fn statement_bytes(statement: &Statement) -> Result<usize, Error> {
    statement
        .ring
        .capacity()
        .checked_mul(core::mem::size_of::<[Account; crate::INPUTS]>())
        .and_then(|bytes| bytes.checked_add(core::mem::size_of::<Statement>()))
        .ok_or(Error::ResourceLimit)
}

pub(super) fn caller_bytes(statement: &Statement) -> Result<usize, Error> {
    let identity_storage = super::super::identity_reuse::source_host_bytes()?;
    // Charge the actual Vec capacity, including any caller-reserved spare
    // storage. Reject it before streaming the statement or creating an Arc.
    let bytes = statement_bytes(statement)?
        .checked_add(REPORT_AND_SESSION_BYTES)
        .and_then(|n| n.checked_add(identity_storage))
        .and_then(|n| n.checked_add(core::mem::size_of::<FreshGpuProofInput>()))
        .and_then(|n| n.checked_add(core::mem::size_of::<FreshGpuProof>()))
        .and_then(|n| n.checked_add(core::mem::size_of::<ProofReport>()))
        .and_then(|n| n.checked_add(core::mem::size_of::<ProofFailure>()))
        // Additive forwarding/self/result slots for the optional receipt path,
        // including the default entry. No move-elision credit is assumed.
        .and_then(|n| n.checked_add(3 * core::mem::size_of::<FreshGpuProofInput>()))
        .and_then(|n| {
            n.checked_add(3 * core::mem::size_of::<Result<FreshGpuProof, ProofFailure>>())
        })
        .and_then(|n| {
            n.checked_add(
                4 * core::mem::size_of::<Option<&mut super::super::identity_reuse::Transfer>>(),
            )
        })
        // The workflow separately checks actual argv/path capacities and its
        // small scalar report against this shared orchestration reservation.
        .and_then(|n| n.checked_add(32 << 10))
        .and_then(|n| n.checked_add(4096)) // bounded errors and Arc owner/header
        .ok_or(Error::ResourceLimit)?;
    if bytes > REGISTERED_GPU_CALLER_HOST_BYTES {
        return Err(Error::ResourceLimit);
    }
    Ok(bytes)
}

/// Exactly Statement::binding, streamed without its statement-sized Vec.
pub(super) fn binding(statement: &Statement) -> [Val; 4] {
    let mut hash = Shake256::default();
    hash.update(statement.profile.tag().as_bytes());
    hash.update(&statement.context.0);
    hash.update(&statement.setup_seed);
    for poly in statement
        .ring
        .iter()
        .flatten()
        .flat_map(|a| a.public_key.iter().chain(a.coin.iter()))
        .chain(statement.recipients.iter().flatten())
        .chain(statement.output_coins.iter().flatten())
    {
        for coefficient in poly {
            hash.update(&coefficient.to_le_bytes());
        }
    }
    for serial in statement.serials {
        hash.update(&serial);
    }
    let mut digest = [0u8; 32];
    hash.finalize_xof().read(&mut digest);
    let mut context_hash = Shake256::default();
    context_hash.update(crate::Profile::RingDirectV1.tag().as_bytes());
    context_hash.update(&digest);
    context_hash.finalize_xof().read(&mut digest);
    core::array::from_fn(|i| {
        Val::from_u64(
            u64::from_le_bytes(digest[8 * i..8 * i + 8].try_into().unwrap())
                % crate::GOLDILOCKS_MODULUS,
        )
    })
}

/// Same domain and stream as pq-ringct's public registry manifest. The stable
/// digest is independent of a registration session and contains no witnesses.
pub(super) fn manifest(program: &Program) -> Result<[u8; 32], Error> {
    let mut hash = Sha3_256::new();
    Digest::update(&mut hash, b"lattica/public-program-manifest/le-u64/v1");
    let mut fields = 0u64;
    program
        .visit_manifest_fields(&mut |word| {
            fields = fields
                .checked_add(1)
                .ok_or("manifest field-count overflow")?;
            Digest::update(&mut hash, word.to_le_bytes());
            Ok(())
        })
        .map_err(|_| Error::ResourceLimit)?;
    Digest::update(&mut hash, fields.to_le_bytes());
    Ok(hash.finalize().into())
}

pub(super) fn validate_compilation(
    program: &Program,
    witness: &Vec<Val>,
    public: &[Val; 4],
    summary: &Summary,
    statement: &Statement,
    expected: Context,
) -> Result<(), Error> {
    statement.admit(expected)?;
    if statement.ring.len() != RING_PAIRS || *public != binding(statement) {
        return Err(Error::Context);
    }
    let canonical =
        CompilerCapacityProfile::new(summary.limits.memory_profile, summary.limits.wire_profile)
            .limits();
    if summary.representation != CompilerRepresentation::FusedTernaryRangesV1.name()
        || summary.deferred_crypto_obligations != 0
        || summary.cryptographic_proof_available
        || summary.limits != canonical
        || summary.host_allowance_bytes < canonical.required_host_bytes
        || summary.host_allowance_bytes > HOST_BYTES
        || program.public_values() != public.len()
        || program.witness_values() != witness.len()
        || program.witness_values() != summary.witness_values
        || program.active_rows() != summary.active_rows
        || program.height() != summary.padded_rows
        || program.wire_count() != summary.wires
        || program.wire_count() > canonical.wire_limit
        || program.witness_values() > canonical.input_limit
        || program.active_rows() == 0
        || !program.height().is_power_of_two()
        || program.active_rows() > program.height()
        || program.height() > MAX_ROWS
    {
        return Err(Error::ResourceLimit);
    }
    let witness_bytes = witness
        .capacity()
        .checked_mul(core::mem::size_of::<Val>())
        .and_then(|n| u64::try_from(n).ok())
        .ok_or(Error::ResourceLimit)?;
    let program_bytes = program
        .retained_host_bytes()
        .map_err(|_| Error::ResourceLimit)?;
    if witness_bytes > canonical.witness_byte_limit
        || u64::try_from(program_bytes).map_err(|_| Error::ResourceLimit)?
            > canonical.program_byte_limit
    {
        return Err(Error::ResourceLimit);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statement() -> Statement {
        Statement {
            profile: crate::Profile::RingDirectV1,
            context: Context([19; 32]),
            setup_seed: [3; 32],
            ring: vec![
                [
                    Account {
                        public_key: [[0; crate::ring::D]; 4],
                        coin: [[0; crate::ring::D]; 5]
                    },
                    Account {
                        public_key: [[1; crate::ring::D]; 4],
                        coin: [[2; crate::ring::D]; 5]
                    }
                ];
                RING_PAIRS
            ],
            recipients: [[[0; crate::ring::D]; 4]; crate::OUTPUTS],
            output_coins: [[[0; crate::ring::D]; 5]; crate::OUTPUTS],
            serials: [[1; 32], [2; 32]],
        }
    }

    #[test]
    fn streamed_binding_matches_reference_and_binds_public_changes() {
        let mut s = statement();
        let original = binding(&s);
        assert_eq!(original, s.binding());
        s.ring[1][0].coin[2][3] = 17;
        assert_eq!(binding(&s), s.binding());
        assert_ne!(binding(&s), original);
        let changed = binding(&s);
        s.serials.swap(0, 1);
        assert_ne!(binding(&s), changed);
        assert_eq!(binding(&s), s.binding());
    }

    #[test]
    fn unused_statement_capacity_is_charged_before_binding() {
        let mut s = statement();
        let small = statement_bytes(&s).unwrap();
        assert!(caller_bytes(&s).is_ok());
        s.ring.reserve_exact(100);
        assert!(statement_bytes(&s).unwrap() > small);
        assert_eq!(caller_bytes(&s), Err(Error::ResourceLimit));
    }
}
