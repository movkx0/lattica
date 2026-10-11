//! Immutable per-configuration host allowance for assigned GPU sessions.
use super::*;

fn admit(assigned: usize, configured: usize) -> Result<usize, crate::proving::Error> {
    if assigned == 0
        || configured == 0
        || configured > super::super::resident_pcs::HOST_OUTPUT_BUDGET
    {
        return Err(crate::proving::Error::ComponentRejected);
    }
    Ok(assigned.min(configured))
}

fn selected_budget(assigned: usize) -> Result<usize, crate::proving::Error> {
    let budget = admit(assigned, super::super::resident_pcs::host_output_budget())?;
    if !resident_research_enabled() {
        return Err(crate::proving::Error::ComponentRejected);
    }
    Ok(budget)
}

/// Admit the assigned allowance before obtaining entropy or creating device state.
/// Fresh proof seeds and all proof parameters match `make_proving_config`.
pub(crate) fn make_proving_config_with_host_budget(
    assigned: usize,
) -> Result<Config, crate::proving::Error> {
    let budget = selected_budget(assigned)?;
    let fusion = super::super::quotient_pcs::research_enabled();
    Ok(config_with_rngs_and_host_budget(
        ChaCha20Rng::from_rng(&mut rand::rng()),
        ChaCha20Rng::from_rng(&mut rand::rng()),
        fusion.then(|| ChaCha20Rng::from_rng(&mut rand::rng())),
        true,
        false,
        Some(budget),
    ))
}

/// Deterministic public preprocessing only; never use this to prove a witness.
pub(crate) fn preprocessing_config_with_host_budget(
    assigned: usize,
) -> Result<Config, crate::proving::Error> {
    let budget = selected_budget(assigned)?;
    Ok(config_with_rngs_and_host_budget(
        ChaCha20Rng::from_seed([0; 32]),
        ChaCha20Rng::from_seed([0; 32]),
        None,
        true,
        true,
        Some(budget),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assigned_pcs_budget_never_exceeds_the_assignment_or_process_cap() {
        let cap = 3 << 30;
        let assigned = (1 << 30) - (1 << 20);
        assert_eq!(admit(assigned, cap).unwrap(), assigned);
        assert_eq!(admit(4 << 30, cap).unwrap(), cap);
        assert_eq!(admit(usize::MAX, cap).unwrap(), cap);
        let maximum = super::super::super::resident_pcs::HOST_OUTPUT_BUDGET;
        assert_eq!(admit(usize::MAX, maximum).unwrap(), maximum);
    }

    #[test]
    fn invalid_pcs_allowances_reject_before_configuration() {
        let maximum = super::super::super::resident_pcs::HOST_OUTPUT_BUDGET;
        for (assigned, configured) in [(0, maximum), (maximum, 0), (1, maximum + 1)] {
            assert!(admit(assigned, configured).is_err());
        }
    }
}
