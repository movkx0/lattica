//! Pinned mixed public inputs and explicitly derived disk quotas for 32 wallets.
use super::super::pool_resume::limits as shared_limits;
use super::*;
use p3_field::PrimeField64;

pub(super) const WALLETS: [usize; 32] = [
    0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 3, 7, 11, 15, 19, 23, 27, 31, 35,
    39, 43, 47, 51, 55, 59, 63,
];

fn artifact_bytes() -> usize {
    let directory = PathBuf::from(std::env::var_os("LATTICA_FULL_SIZE_FIXTURE").unwrap());
    let max = crate::block_v2::profile::MAX_PROOF_BYTES;
    WALLETS.iter().fold(32 * max, |total, index| {
        let path = directory.join(format!("wallet.{index}"));
        assert!(fs::symlink_metadata(&path).unwrap().is_file());
        let bytes = usize::try_from(fs::metadata(path).unwrap().len()).unwrap();
        assert!((1..=max).contains(&bytes));
        total.checked_add(bytes).unwrap()
    })
}

pub(super) fn store_limits() -> StoreLimits {
    // Atomic publication charges both the pending and published names until
    // the directory is synced and the temporary link has been removed.
    StoreLimits {
        bytes: artifact_bytes()
            .checked_add(crate::block_v2::profile::MAX_PROOF_BYTES)
            .unwrap() as u64,
        entries: WALLETS.len() + 32 + 1,
    }
}

pub(super) fn limits(peak: Resources, jobs: Resources) -> crate::block_v2::execution::dag::Limits {
    crate::block_v2::execution::dag::Limits {
        attempts: 32,
        artifact_bytes: artifact_bytes(),
        ..shared_limits(peak, jobs)
    }
}

pub(super) fn thirty_two_wallet_fixture() -> (Registry<12>, Selection, PolicyContext) {
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
    let mut policies = Vec::new();
    let mut summaries = std::collections::BTreeSet::new();
    let inputs: Vec<_> = WALLETS
        .into_iter()
        .map(|index| {
            let bytes = read(&directory.join(format!("wallet.{index}")));
            let policy = if index % 4 == 0 {
                Policy::JoinSplit
            } else {
                assert_eq!(index % 4, 3);
                Policy::Issuance {
                    authorized_mint: typed_fixture::MINT,
                }
            };
            let kind = if index % 4 == 0 {
                "joinsplit"
            } else {
                "issuance"
            };
            assert_eq!(body["transactions"][index]["kind"], kind);
            let storage = codec::proofs::Storage::new(codec::proofs::INPUT_STORAGE_LIMIT);
            assert!(bytes.starts_with(b"LBV2TW01"));
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
            let wrong = if index % 4 == 0 {
                Policy::Issuance {
                    authorized_mint: typed_fixture::MINT,
                }
            } else {
                Policy::JoinSplit
            };
            assert!(VerifiedWallet::verify_typed(pin, &registry, chain, wrong, &bytes).is_err());
            assert!(summaries.insert(wallet.summary().root));
            policies.push((wallet.artifact(), policy));
            PublicInput::new(wallet, bytes).unwrap()
        })
        .collect();
    let selection = Selection::new(pin, chain, &inputs).unwrap();
    assert_eq!(selection.jobs().len(), 32);
    assert_eq!(
        (
            selection.root().expected().count,
            selection.root().expected().level
        ),
        (32, 6)
    );
    assert_eq!(
        selection
            .jobs()
            .filter(|job| job.operation().proof_mode() == 1)
            .count(),
        8
    );
    assert_eq!(
        selection
            .jobs()
            .filter(|job| job.operation().proof_mode() == 11)
            .count(),
        8
    );
    assert_eq!(
        selection
            .jobs()
            .filter(|job| job.operation().proof_mode() == 3)
            .count(),
        15
    );
    assert_eq!(selection.root().operation().proof_mode(), 12);
    (
        registry,
        selection,
        PolicyContext::new([8; 32], policies).unwrap(),
    )
}
