//! Explicit opt-in settings for the expensive full-graph acceptance test.
//! These are experiment choices, not measured-safe production defaults.
use super::*;

pub(super) struct Options {
    pub limits: ResourceLimits,
    pub budgets: Budgets,
}

impl Options {
    pub fn parse(get: impl Fn(&str) -> Option<String>) -> std::result::Result<Self, String> {
        let positive =
            |name: &str, fallback: Option<usize>| -> std::result::Result<usize, String> {
                let value = match get(name) {
                    Some(text) => text
                        .parse::<usize>()
                        .map_err(|_| format!("invalid {name}"))?,
                    None => fallback.ok_or_else(|| format!("explicit {name} required"))?,
                };
                if value == 0 {
                    return Err(format!("{name} must be positive"));
                }
                Ok(value)
            };
        let gib = |name: &str, fallback: Option<usize>| -> std::result::Result<u64, String> {
            let amount = positive(name, fallback)?;
            u64::try_from(amount)
                .ok()
                .and_then(|amount| amount.checked_mul(1 << 30))
                .ok_or_else(|| format!("{name} overflows byte budget"))
        };
        let global = positive("LATTICA_SPEND_ALGEBRA_BATCH", None)?;
        let ntt = positive("LATTICA_SPEND_NTT_BATCH", Some(global))?;
        let mul = positive("LATTICA_SPEND_MUL_BATCH", Some(global))?;
        if global > 128 || ntt > global || mul > global {
            return Err("algebra ceilings require NTT/Mul <= global <= 128".into());
        }
        let native_bytes = gib("LATTICA_SPEND_NATIVE_GIB", Some(8))?;
        let outer_bytes = gib("LATTICA_SPEND_OUTER_GIB", None)?;
        let serial_aes = positive("LATTICA_SPEND_AES_SERIAL_BATCH", Some(8))?;
        let serial_shake = positive("LATTICA_SPEND_SHAKE_SERIAL_BATCH", Some(8))?;
        if [serial_aes, serial_shake]
            .into_iter()
            .any(|count| !count.is_power_of_two() || count > 64)
        {
            return Err("serial crypto batches must be powers of two in 1..=64".into());
        }
        let crypto_admission = if serial_aes > 8 || serial_shake > 8 {
            // Explicit larger batches remain estimates until separately
            // qualified. A native result is not an outer-memory guarantee.
            graph_crypto::Admission::Estimated
        } else {
            graph_crypto::Admission::ValidatedLocal
        };
        let aes = if get("LATTICA_SPEND_AES_WIDE_MIN_BLOCKS").is_some() {
            AesLayout::WholeWide {
                minimum_blocks: positive("LATTICA_SPEND_AES_WIDE_MIN_BLOCKS", None)?,
            }
        } else {
            AesLayout::Serial
        };
        let transcripts = if get("LATTICA_SPEND_SHAKE_WIDE_MAX_PERMUTATIONS").is_some() {
            TranscriptLayout::Wide {
                maximum_permutations: positive("LATTICA_SPEND_SHAKE_WIDE_MAX_PERMUTATIONS", None)?,
            }
        } else {
            TranscriptLayout::Serial
        };
        let composites = match get("LATTICA_SPEND_COMPOSITE_LAYOUT").as_deref() {
            None | Some("direct") => CompositeLayout::Direct,
            Some("branches") => CompositeLayout::Branches,
            Some(_) => {
                return Err("LATTICA_SPEND_COMPOSITE_LAYOUT must be direct or branches".into())
            }
        };
        Ok(Self {
            limits: ResourceLimits {
                max_batch_count: global,
                max_ntt_batch_count: ntt,
                max_mul_batch_count: mul,
                max_trace_cells: 1 << 27,
                max_estimated_prover_bytes: native_bytes,
            },
            budgets: Budgets {
                native_bytes,
                outer_bytes,
                aes,
                transcripts,
                composites,
                crypto_policy: graph_crypto::Policy {
                    maximum_aes_blocks: serial_aes,
                    maximum_shake_permutations: serial_shake,
                    child_memory_budget_bytes: native_bytes,
                    admission: crypto_admission,
                },
                ..Budgets::default()
            },
        })
    }
}

fn from_pairs(pairs: &[(&str, &str)]) -> std::result::Result<Options, String> {
    Options::parse(|name| {
        pairs
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.to_string())
    })
}

#[test]
fn experiment_options_preserve_legacy_serial_choices() {
    let parsed = from_pairs(&[
        ("LATTICA_SPEND_ALGEBRA_BATCH", "8"),
        ("LATTICA_SPEND_OUTER_GIB", "48"),
    ])
    .unwrap();
    assert_eq!(parsed.limits.max_batch_count, 8);
    assert_eq!(parsed.limits.max_ntt_batch_count, 8);
    assert_eq!(parsed.limits.max_mul_batch_count, 8);
    assert_eq!(parsed.budgets.native_bytes, 8 << 30);
    assert_eq!(parsed.budgets.outer_bytes, 48 << 30);
    assert_eq!(parsed.budgets.aes, AesLayout::Serial);
    assert_eq!(parsed.budgets.transcripts, TranscriptLayout::Serial);
    assert_eq!(parsed.budgets.composites, CompositeLayout::Direct);
    assert_eq!(parsed.budgets.crypto_policy.maximum_aes_blocks, 8);
    assert_eq!(parsed.budgets.crypto_policy.maximum_shake_permutations, 8);
    assert!(matches!(
        parsed.budgets.crypto_policy.admission,
        graph_crypto::Admission::ValidatedLocal
    ));
}

#[test]
fn experiment_options_keep_family_ceilings_and_crypto_layouts_independent() {
    let parsed = from_pairs(&[
        ("LATTICA_SPEND_ALGEBRA_BATCH", "64"),
        ("LATTICA_SPEND_NTT_BATCH", "32"),
        ("LATTICA_SPEND_MUL_BATCH", "16"),
        ("LATTICA_SPEND_NATIVE_GIB", "16"),
        ("LATTICA_SPEND_OUTER_GIB", "128"),
        ("LATTICA_SPEND_AES_WIDE_MIN_BLOCKS", "16"),
        ("LATTICA_SPEND_SHAKE_WIDE_MAX_PERMUTATIONS", "1695"),
        ("LATTICA_SPEND_COMPOSITE_LAYOUT", "branches"),
        ("LATTICA_SPEND_AES_SERIAL_BATCH", "32"),
        ("LATTICA_SPEND_SHAKE_SERIAL_BATCH", "16"),
    ])
    .unwrap();
    assert_eq!(parsed.limits.max_batch_count, 64);
    assert_eq!(parsed.limits.max_ntt_batch_count, 32);
    assert_eq!(parsed.limits.max_mul_batch_count, 16);
    assert_eq!(parsed.limits.max_estimated_prover_bytes, 16 << 30);
    assert_eq!(parsed.budgets.native_bytes, 16 << 30);
    assert_eq!(parsed.budgets.composites, CompositeLayout::Branches);
    assert_eq!(parsed.budgets.crypto_policy.maximum_aes_blocks, 32);
    assert_eq!(parsed.budgets.crypto_policy.maximum_shake_permutations, 16);
    assert!(matches!(
        parsed.budgets.crypto_policy.admission,
        graph_crypto::Admission::Estimated
    ));
    assert_eq!(
        parsed.budgets.crypto_policy.child_memory_budget_bytes,
        16 << 30
    );
    assert_eq!(
        parsed.budgets.aes,
        AesLayout::WholeWide { minimum_blocks: 16 }
    );
    assert_eq!(
        parsed.budgets.transcripts,
        TranscriptLayout::Wide {
            maximum_permutations: 1695
        }
    );
}

#[test]
fn experiment_options_reject_missing_zero_overflow_or_silently_capped_settings() {
    assert!(from_pairs(&[]).is_err());
    let required = [
        ("LATTICA_SPEND_ALGEBRA_BATCH", "8"),
        ("LATTICA_SPEND_OUTER_GIB", "48"),
    ];
    for (key, value) in [
        ("LATTICA_SPEND_ALGEBRA_BATCH", "0"),
        ("LATTICA_SPEND_ALGEBRA_BATCH", "129"),
        ("LATTICA_SPEND_NTT_BATCH", "32"),
        ("LATTICA_SPEND_MUL_BATCH", "16"),
        ("LATTICA_SPEND_NATIVE_GIB", "0"),
        ("LATTICA_SPEND_NATIVE_GIB", "18446744073709551615"),
        ("LATTICA_SPEND_OUTER_GIB", "-1"),
        ("LATTICA_SPEND_AES_WIDE_MIN_BLOCKS", "0"),
        ("LATTICA_SPEND_SHAKE_WIDE_MAX_PERMUTATIONS", "0"),
        ("LATTICA_SPEND_COMPOSITE_LAYOUT", "partial"),
        ("LATTICA_SPEND_AES_SERIAL_BATCH", "0"),
        ("LATTICA_SPEND_AES_SERIAL_BATCH", "3"),
        ("LATTICA_SPEND_SHAKE_SERIAL_BATCH", "128"),
    ] {
        let pairs: Vec<_> = [(key, value)].into_iter().chain(required).collect();
        assert!(from_pairs(&pairs).is_err(), "accepted {key}={value}");
    }
}
