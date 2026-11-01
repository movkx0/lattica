use super::*;
fn limits() -> ConstructionLimits {
    ConstructionLimits {
        max_requested_program_bytes: 2 << 30,
        max_wires: MAX_WIRES,
        max_input_values: 1 << 20,
    }
}
#[test]
fn stale_source_profile_shape_or_content_is_never_accepted() {
    if !cfg!(all(not(debug_assertions), target_arch = "x86_64")) {
        return;
    }
    let rows: Vec<_> = [25, 28, 38, 46]
        .into_iter()
        .flat_map(|p| {
            (3..=20).map(move |log| Row {
                public_values: p,
                log_height: log,
                values: [1, 0, 0, 2, 1, 0, 1, 8, 64],
            })
        })
        .collect();
    let digest = checksum(&rows);
    assert!(valid(
        &rows,
        COMPILED_SOURCE_DIGEST,
        profile::CANDIDATE_PROFILE_ID,
        signature(),
        digest
    ));
    assert!(!valid(
        &rows,
        [0; 32],
        profile::CANDIDATE_PROFILE_ID,
        signature(),
        digest
    ));
    assert!(!valid(
        &rows,
        COMPILED_SOURCE_DIGEST,
        [0; 32],
        signature(),
        digest
    ));
    assert!(!valid(
        &rows,
        COMPILED_SOURCE_DIGEST,
        profile::CANDIDATE_PROFILE_ID,
        [0; 12],
        digest
    ));
    assert!(!valid(
        &rows,
        COMPILED_SOURCE_DIGEST,
        profile::CANDIDATE_PROFILE_ID,
        signature(),
        [0; 32]
    ));
    let mut changed = rows.clone();
    changed[0].values[0] += 1;
    assert!(!valid(
        &changed,
        COMPILED_SOURCE_DIGEST,
        profile::CANDIDATE_PROFILE_ID,
        signature(),
        digest
    ));
    changed[0].public_values = 29;
    assert!(!valid(
        &changed,
        COMPILED_SOURCE_DIGEST,
        profile::CANDIDATE_PROFILE_ID,
        signature(),
        checksum(&changed)
    ));
}
#[test]
fn tables_never_relax_the_caller_limits_or_extend_the_qualified_domain() {
    for (publics, height) in [(29, 8), (28, 7), (28, 1 << 21)] {
        assert!(lookup(publics, height, limits(), 512 << 20)
            .unwrap()
            .is_none());
    }
    for limited in [
        ConstructionLimits {
            max_requested_program_bytes: 1 << 30,
            ..limits()
        },
        ConstructionLimits {
            max_wires: 1,
            ..limits()
        },
        ConstructionLimits {
            max_input_values: 1,
            ..limits()
        },
    ] {
        assert!(lookup(28, 8, limited, 512 << 20).unwrap().is_none());
    }
    if available() {
        assert!(lookup(28, 8, limits(), 0).is_err());
        for publics in [25, 28, 38, 46] {
            for log in 3..=20 {
                let value = lookup(publics, 1 << log, limits(), 512 << 20)
                    .unwrap()
                    .unwrap();
                assert_eq!(value.heights_enumerated, log - 2);
            }
        }
    }
}
