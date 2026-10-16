//! Complete archived transaction order, including both HTLC paths.
use super::*;
use p3_field::PrimeField64;

pub(super) const WALLETS: [usize; 64] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
    50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
];
pub(super) const JOBS: usize = 63;

pub(super) fn artifact_bytes() -> usize {
    let directory = PathBuf::from(std::env::var_os("LATTICA_FULL_SIZE_FIXTURE").unwrap());
    let maximum = crate::block_v2::profile::MAX_PROOF_BYTES;
    WALLETS.iter().fold(JOBS * maximum, |total, index| {
        let path = directory.join(format!("wallet.{index}"));
        assert!(fs::symlink_metadata(&path).unwrap().is_file());
        let bytes = usize::try_from(fs::metadata(path).unwrap().len()).unwrap();
        assert!((1..=maximum).contains(&bytes));
        total.checked_add(bytes).unwrap()
    })
}

pub(super) fn store_limits() -> StoreLimits {
    StoreLimits {
        // Retain one bounded proof per job and allow one atomic publication.
        bytes: artifact_bytes()
            .checked_add(crate::block_v2::profile::MAX_PROOF_BYTES)
            .unwrap() as u64,
        entries: WALLETS.len() + JOBS + 1,
    }
}

pub(super) fn limits(peak: Resources, jobs: Resources) -> Limits {
    Limits {
        jobs: JOBS,
        attempts: JOBS,
        artifact_bytes: artifact_bytes(),
        ..super::super::super::pool_resume::limits(peak, jobs)
    }
}

pub(super) fn full_fixture() -> (Registry<12>, Selection, PolicyContext) {
    ordered_fixture(WALLETS)
}

pub(super) fn ordered_fixture(wallets: [usize; 64]) -> (Registry<12>, Selection, PolicyContext) {
    let directory = PathBuf::from(std::env::var_os("LATTICA_FULL_SIZE_FIXTURE").unwrap());
    let registry = Registry::<12> {
        height: serde_json::from_slice(&read(&directory.join("height.json"))).unwrap(),
        caps: std::array::from_fn(|index| {
            let bytes = read(&directory.join(format!("key.{}", index + 1)));
            assert!(bytes.starts_with(b"LBV2TP01"));
            codec::decode(&bytes[8..]).unwrap()
        }),
    };
    assert_eq!(registry.height, 1 << 18);
    let pin = RegistryPin::new_typed(&registry, registry.id().unwrap()).unwrap();
    let body: serde_json::Value =
        serde_json::from_slice(&read(&directory.join("body.json"))).unwrap();
    let chain: [u8; 32] = serde_json::from_value(body["chain"].clone()).unwrap();
    assert_eq!(chain, typed_fixture::CHAIN);
    assert_eq!(body["transactions"].as_array().unwrap().len(), 64);
    let mut policies = Vec::with_capacity(64);
    let mut summaries = std::collections::BTreeSet::new();
    let mut kinds = BTreeMap::new();
    let inputs: Vec<_> = wallets
        .into_iter()
        .map(|index| {
            let bytes = read(&directory.join(format!("wallet.{index}")));
            let policy = wallet_policy(index);
            let kind = ["joinsplit", "htlc_redeem", "htlc_refund", "issuance"][index % 4];
            assert_eq!(body["transactions"][index]["kind"], kind);
            *kinds.entry(kind).or_insert(0usize) += 1;
            assert!(bytes.starts_with(b"LBV2TW01"));
            let storage = codec::proofs::Storage::new(codec::proofs::INPUT_STORAGE_LIMIT);
            let decoded = storage.wallet(&bytes[8..]).unwrap();
            let expected: Vec<u64> =
                serde_json::from_value(body["transactions"][index]["statement"].clone()).unwrap();
            assert_eq!(decoded.chain, chain);
            assert_eq!(
                decoded
                    .public
                    .iter()
                    .map(PrimeField64::as_canonical_u64)
                    .collect::<Vec<_>>(),
                expected
            );
            drop(decoded);
            let wallet =
                VerifiedWallet::verify_typed(pin, &registry, chain, policy, &bytes).unwrap();
            let wrong = match policy {
                Policy::JoinSplit => Policy::Issuance {
                    authorized_mint: typed_fixture::MINT,
                },
                Policy::Htlc { expected_height } => Policy::Htlc {
                    expected_height: expected_height + 1,
                },
                Policy::Issuance { authorized_mint } => Policy::Issuance {
                    authorized_mint: authorized_mint + 1,
                },
            };
            assert!(VerifiedWallet::verify_typed(pin, &registry, chain, wrong, &bytes).is_err());
            assert!(summaries.insert(wallet.summary().root));
            policies.push((wallet.artifact(), policy));
            PublicInput::new(wallet, bytes).unwrap()
        })
        .collect();
    assert_eq!(kinds.len(), 4);
    assert!(kinds.values().all(|count| *count == 16));
    let selection = Selection::new(pin, chain, &inputs).unwrap();
    assert_eq!(selection.jobs().len(), JOBS);
    assert_eq!(
        (
            selection.root().expected().count,
            selection.root().expected().level
        ),
        (64, 6)
    );
    assert_eq!(selection.root().operation().proof_mode(), programs::MERGE);
    let plan = typed_pairs::proof_plan(64).unwrap();
    assert_eq!(usize::from(plan.proposed_proofs), JOBS);
    assert_eq!(plan.finalizer_proofs, 0);
    for (mode, count) in [(4, 16), (8, 16), (3, 31)] {
        assert_eq!(
            selection
                .jobs()
                .filter(|job| job.operation().proof_mode() == mode)
                .count(),
            count
        );
    }
    (
        registry,
        selection,
        PolicyContext::new([8; 32], policies).unwrap(),
    )
}
