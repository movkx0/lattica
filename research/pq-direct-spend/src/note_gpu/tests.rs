//! Synthetic transport shapes are deliberately not cryptographic proofs.
//! The ignored reference test separately checks a genuine legacy proof.
use super::*;
use crate::{note, Context, Profile};
use p3_field::{PrimeCharacteristicRing, PrimeField64};

const CONTEXT: Context = Context([83; 32]);

pub(super) fn statement() -> note::Statement {
    use lattica_prover_p3::joinsplit_air as js;
    let mut public: Vec<_> = (1..=26).map(|x| x as u64).collect();
    public[js::PI_FEE] = 0;
    public[js::PI_MINT] = 0;
    for (i, value) in crate::context_binding(Profile::PrivateNoteDirectV1, CONTEXT)
        .iter()
        .enumerate()
    {
        public[js::PI_TXBIND + i] = value.as_canonical_u64();
    }
    note::Statement {
        profile: Profile::PrivateNoteDirectV1,
        context: CONTEXT,
        public,
    }
}

pub(super) fn fixture(schedule: &[usize]) -> Proof {
    let g = Geometry::pinned().unwrap();
    assert_eq!(schedule.iter().sum::<usize>(), g.degree_bits);
    let log_lde = g.degree_bits + g.log_blowup;
    let cap = |height: usize| Cap::new(vec![[Val::ZERO; 4]; 1 << height.min(g.cap_height)]);
    let auth = |matrices: usize, height: usize| {
        (
            vec![vec![Val::ZERO; 4]; matrices],
            vec![[Val::ZERO; 4]; height.saturating_sub(g.cap_height)],
        )
    };
    let matrices = [1, 1, g.quotient_chunks];
    let widths = [g.challenge_degree, g.trace_columns, g.challenge_degree];
    let mut height = log_lde;
    let heights: Vec<_> = schedule
        .iter()
        .map(|arity| {
            height -= arity;
            height
        })
        .collect();
    let query = || Query {
        input_proof: (0..3)
            .map(|round| Opening {
                opened_values: vec![
                    vec![Val::ZERO; widths[round] + g.random_codewords];
                    matrices[round]
                ],
                opening_proof: auth(matrices[round], log_lde),
            })
            .collect(),
        commit_phase_openings: schedule
            .iter()
            .zip(&heights)
            .map(|(&arity, &height)| Step {
                log_arity: arity as u8,
                sibling_values: vec![Challenge::ZERO; (1 << arity) - 1],
                opening_proof: auth(1, height),
            })
            .collect(),
    };
    Proof {
        commitments: p3_uni_stark::Commitments {
            trace: cap(log_lde),
            quotient_chunks: cap(log_lde),
            random: Some(cap(log_lde)),
        },
        opened_values: p3_uni_stark::OpenedValues {
            trace_local: vec![Challenge::ZERO; g.trace_columns],
            trace_next: Some(vec![Challenge::ZERO; g.trace_columns]),
            preprocessed_local: None,
            preprocessed_next: None,
            quotient_chunks: vec![vec![Challenge::ZERO; 2]; g.quotient_chunks],
            random: Some(vec![Challenge::ZERO; 2]),
        },
        opening_proof: (
            (0..3)
                .map(|round| {
                    vec![vec![vec![Challenge::ZERO; 4]; [1, 2, 1][round]]; matrices[round]]
                })
                .collect(),
            Fri {
                commit_phase_commits: heights.iter().copied().map(cap).collect(),
                commit_pow_witnesses: vec![Val::ZERO; schedule.len()],
                query_proofs: (0..g.queries).map(|_| query()).collect(),
                final_poly: vec![Challenge::ZERO],
                query_pow_witness: Val::ZERO,
            },
        ),
        degree_bits: g.degree_bits,
    }
}

pub(super) fn packet(proof: &Proof, expected: &note::Statement) -> Vec<u8> {
    packet_payload(&postcard::to_allocvec(proof).unwrap(), expected)
}
fn packet_payload(proof: &[u8], expected: &note::Statement) -> Vec<u8> {
    let mut packet = Vec::with_capacity(ARTIFACT_HEADER_BYTES + proof.len());
    packet.extend_from_slice(MAGIC);
    packet.extend_from_slice(&expected.context.0);
    for &value in &expected.public {
        packet.extend_from_slice(&value.to_le_bytes());
    }
    packet.extend_from_slice(&(proof.len() as u64).to_le_bytes());
    packet.extend_from_slice(proof);
    packet
}

#[test]
fn fixed_geometry_and_limits_never_grant_dispatch() {
    let expected = statement();
    let diagnostic = diagnose(&expected, CONTEXT, Limits::campaign()).unwrap();
    let g = diagnostic.geometry();
    assert_eq!(
        (
            g.active_rows,
            g.padded_rows,
            g.trace_columns,
            g.public_values
        ),
        (2560, 4096, 19, 26)
    );
    assert_eq!(
        (g.queries, g.max_log_fri_arity, g.challenge_degree),
        (96, 4, 2)
    );
    assert!(!diagnostic.dispatch_enabled());
    assert_eq!(
        diagnostic.require_dispatch(),
        Err(Error::IncompleteLifetimeAdmission)
    );
    assert!(diagnostic
        .missing_bounds()
        .contains(&MissingBound::IndependentCpuVerifierLifetime));
    for field in 0..8 {
        let mut limits = Limits::campaign();
        match field {
            0 => limits.worker_host_bytes += 1,
            1 => limits.managed_device_bytes += 1,
            2 => limits.context_device_bytes -= 1,
            3 => limits.native_host_bytes += 1,
            4 => limits.process_host_bytes += 1,
            5 => limits.swap_bytes = 1,
            6 => limits.max_rows *= 2,
            _ => limits.managed_device_bytes = 1,
        }
        assert!(diagnose(&expected, CONTEXT, limits).is_err());
    }
}

#[test]
fn exact_decode_budget_covers_binary_and_legacy_max_arity_shapes() {
    let expected = statement();
    for schedule in [&[4, 4, 4, 1][..], &[1; 13][..], &[2, 3, 4, 4][..]] {
        let packet = packet(&fixture(schedule), &expected);
        let required = decode_required_bytes(&packet, &expected).unwrap();
        let short = DecodeSession::new(required - 1).unwrap();
        assert!(matches!(
            short.decode(packet.clone(), &expected, CONTEXT),
            Err(Error::ResourceLimit)
        ));
        assert_eq!(short.snapshot().admitted_attempts, 0);
        let session = DecodeSession::new(required).unwrap();
        let decoded = session.decode(packet, &expected, CONTEXT).unwrap();
        let receipt = decoded.receipt();
        assert!(receipt.decoded_backing_requested_bytes <= receipt.decoded_backing_ceiling_bytes);
        assert!(!receipt.cryptographic_verification_performed);
        assert_eq!(session.snapshot().live_reserved_bytes, required);
        let round_trip = decoded.canonical_packet().to_vec();
        drop(decoded);
        assert_eq!(
            session.snapshot().live_reserved_bytes,
            session.snapshot().ledger_bytes
        );
        let decoded = session.decode(round_trip, &expected, CONTEXT).unwrap();
        drop(session);
        assert_eq!(
            decoded.proof().degree_bits,
            13,
            "owner survives moving/dropping its session"
        );
    }
}

#[test]
fn retained_artifacts_share_quota_and_release_on_drop() {
    let expected = statement();
    let packet = packet(&fixture(&[4, 4, 4, 1]), &expected);
    let one = decode_required_bytes(&packet, &expected).unwrap();
    let ledger = quota::LEDGER_BYTES;
    let session = DecodeSession::new(ledger + 2 * (one - ledger)).unwrap();
    let first = session.decode(packet.clone(), &expected, CONTEXT).unwrap();
    let second = session.decode(packet.clone(), &expected, CONTEXT).unwrap();
    assert!(matches!(
        session.decode(packet.clone(), &expected, CONTEXT),
        Err(Error::ResourceLimit)
    ));
    drop(first);
    let replacement = session.decode(packet, &expected, CONTEXT).unwrap();
    drop(second);
    drop(replacement);
    assert_eq!(session.snapshot().live_reserved_bytes, ledger);
    assert_eq!(session.snapshot().admitted_attempts, 3);
    assert_eq!(session.snapshot().rejected_attempts, 1);
}

#[test]
fn packet_and_statement_spare_capacities_are_reserved() {
    let mut expected = statement();
    let mut bytes = packet(&fixture(&[4, 4, 4, 1]), &expected);
    let before = decode_required_bytes(&bytes, &expected).unwrap();
    let old_packet = bytes.capacity();
    let old_public = expected.public.capacity();
    bytes.reserve_exact(4096);
    expected.public.reserve_exact(128);
    let required = decode_required_bytes(&bytes, &expected).unwrap();
    assert_eq!(
        required - before,
        bytes.capacity() - old_packet + (expected.public.capacity() - old_public) * 8
    );
    let session = DecodeSession::new(required).unwrap();
    let decoded = session.decode(bytes, &expected, CONTEXT).unwrap();
    assert_eq!(session.snapshot().live_reserved_bytes, required);
    drop(decoded);
}

#[test]
fn malformed_or_mismatched_artifacts_release_the_complete_reservation() {
    let expected = statement();
    let honest = packet(&fixture(&[4, 4, 4, 1]), &expected);
    let session = DecodeSession::new(64 << 20).unwrap();
    for at in [0, 8, 40, ARTIFACT_HEADER_BYTES - 8] {
        let mut changed = honest.clone();
        changed[at] ^= 1;
        assert!(session.decode(changed, &expected, CONTEXT).is_err());
        assert_eq!(
            session.snapshot().live_reserved_bytes,
            session.snapshot().ledger_bytes
        );
    }
    for length in [0, 8, ARTIFACT_HEADER_BYTES, honest.len() - 1] {
        assert!(session
            .decode(honest[..length].to_vec(), &expected, CONTEXT)
            .is_err());
        assert_eq!(
            session.snapshot().live_reserved_bytes,
            session.snapshot().ledger_bytes
        );
    }
    let mut trailing = honest[ARTIFACT_HEADER_BYTES..].to_vec();
    trailing.push(0);
    assert!(session
        .decode(packet_payload(&trailing, &expected), &expected, CONTEXT)
        .is_err());
    let mut overlong = vec![0xc0, 0]; // Non-minimal encoding of initial cap length 64.
    overlong.extend_from_slice(&honest[ARTIFACT_HEADER_BYTES + 1..]);
    assert!(session
        .decode(packet_payload(&overlong, &expected), &expected, CONTEXT)
        .is_err());
    let mut wrong = expected.clone();
    wrong.profile = Profile::RingDirectV1;
    assert!(session.decode(honest.clone(), &wrong, CONTEXT).is_err());
    assert!(session
        .decode(honest, &expected, Context([84; 32]))
        .is_err());
    assert_eq!(
        session.snapshot().live_reserved_bytes,
        session.snapshot().ledger_bytes
    );
}

#[test]
fn fixed_geometry_rejects_incomplete_or_inconsistent_proofs() {
    let expected = statement();
    let session = DecodeSession::new(64 << 20).unwrap();
    for mutation in 0..8 {
        let mut proof = fixture(&[4, 4, 4, 1]);
        match mutation {
            0 => proof.degree_bits -= 1,
            1 => {
                proof.opened_values.quotient_chunks.pop();
            }
            2 => proof.opened_values.preprocessed_local = Some(Vec::new()),
            3 => {
                proof.opening_proof.1.query_proofs.pop();
            }
            4 => proof.opening_proof.1.query_proofs[1].commit_phase_openings[0].log_arity = 3,
            5 => {
                proof.opening_proof.1.query_proofs[0].input_proof[0]
                    .opening_proof
                    .1
                    .pop();
            }
            6 => {
                proof.opening_proof.0[1][0].pop();
            }
            _ => {
                proof.opening_proof.1.query_proofs[0].commit_phase_openings[0]
                    .sibling_values
                    .push(Challenge::ZERO);
            }
        }
        assert!(session
            .decode(packet(&proof, &expected), &expected, CONTEXT)
            .is_err());
        assert_eq!(
            session.snapshot().live_reserved_bytes,
            session.snapshot().ledger_bytes
        );
    }
}

#[test]
fn statement_admission_matches_existing_profile_and_rejects_invalid_spends() {
    use lattica_prover_p3::joinsplit_air as js;
    let expected = statement();
    assert_eq!(
        codec::expected_public(&expected, CONTEXT)
            .unwrap()
            .as_slice(),
        expected.admit(CONTEXT).unwrap()
    );
    for mutation in 0..5 {
        let mut changed = expected.clone();
        match mutation {
            0 => changed.public[js::PI_FEE] = 1,
            1 => changed.public[js::PI_MINT] = 1,
            2 => {
                let first = changed.public[js::PI_NF..js::PI_NF + 4].to_vec();
                changed.public[js::PI_NF + 4..js::PI_NF + 8].copy_from_slice(&first);
            }
            3 => changed.public[0] = crate::GOLDILOCKS_MODULUS,
            _ => changed.public[js::PI_TXBIND] ^= 1,
        }
        assert!(codec::expected_public(&changed, CONTEXT).is_err());
    }
}

#[test]
#[ignore = "fresh CPU reference proof; coordinator must run under the serialized resource guard"]
fn genuine_legacy_note_proof_roundtrips_through_quadratic_decoder() {
    let (expected, witness) = note::fixture(CONTEXT).unwrap();
    let (bytes, _) = lattica_prover_p3::joinsplit_air::prove_to_bytes_with_request(
        &witness,
        crate::cpu_request(),
    )
    .unwrap();
    let packet = packet_payload(&bytes, &expected);
    let required = decode_required_bytes(&packet, &expected).unwrap();
    let session = DecodeSession::new(required).unwrap();
    let decoded = session.decode(packet, &expected, CONTEXT).unwrap();
    assert!(lattica_prover_p3::joinsplit_air::verify_bytes(
        &bytes,
        decoded.public()
    ));
    assert_eq!(postcard::to_allocvec(decoded.proof()).unwrap(), bytes);
    eprintln!("private_note_quadratic_decoder_reference payload_bytes={} reserved_bytes={} decoded_backing_bytes={} cryptographic_reference_verified=true gpu_work=false",
        bytes.len(), required, decoded.receipt().decoded_backing_requested_bytes);
    // This proves codec compatibility only, not complete verifier memory
    // admission, a GPU receipt, or a matched complete-workflow improvement.
}
