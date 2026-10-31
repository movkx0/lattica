use super::*;
use std::{
    fmt,
    fmt::Write,
    panic::{catch_unwind, AssertUnwindSafe},
};

const ERROR_BYTES: usize = 1024;

pub(super) fn bounded(error: &impl fmt::Debug) -> String {
    struct Bounded(String);
    impl Write for Bounded {
        fn write_str(&mut self, value: &str) -> fmt::Result {
            let mut take = (ERROR_BYTES - self.0.len()).min(value.len());
            while !value.is_char_boundary(take) {
                take -= 1;
            }
            self.0.push_str(&value[..take]);
            if take < value.len() {
                Err(fmt::Error)
            } else {
                Ok(())
            }
        }
    }
    let mut result = Bounded(String::with_capacity(ERROR_BYTES));
    let _ = write!(result, "{error:?}");
    result.0
}

pub(super) fn attempt<T>(
    phase: &Cell<&'static str>,
    registration_started: &Cell<bool>,
    cpu_started: bool,
    run: impl FnOnce() -> Result<T, VerificationFailure>,
) -> Result<T, VerificationFailure> {
    match catch_unwind(AssertUnwindSafe(run)) {
        Ok(result) => result,
        Err(payload) => {
            drop(payload);
            Err(VerificationFailure::new(
                phase.get(),
                registration_started.get(),
                cpu_started,
                &"backend panicked",
            ))
        }
    }
}

pub(super) fn cpu_attempt<T>(
    phase: &'static str,
    run: impl FnOnce() -> Result<T, VerificationFailure>,
) -> Result<T, VerificationFailure> {
    attempt(&Cell::new(phase), &Cell::new(true), true, run)
}

pub(super) trait TerminalSession {
    fn close(self) -> Result<serde_json::Value, String>;
}
impl TerminalSession for Session {
    fn close(self) -> Result<serde_json::Value, String> {
        self.close_without_completion()
    }
}

pub(super) fn finish<T>(
    session: impl TerminalSession,
    attempted: Result<T, VerificationFailure>,
) -> Result<(T, TerminalReceipt), VerificationFailure> {
    // Even successful preprocessing is not a new cryptographic proof. Cleanup
    // telemetry never claims STARK completion; the native setup report and
    // subsequent CPU verifier determine the independently reported outcome.
    let terminal = session
        .close()
        .map_err(|error| bounded(&error))
        .and_then(|value| {
            proving::terminal_receipt(&value, false).map_err(|error| bounded(&error))
        });
    match (attempted, terminal) {
        (Ok(completed), Ok(receipt)) => {
            if receipt.commits == 0 || receipt.allocations == 0 {
                let mut failure = VerificationFailure::new(
                    "preprocessing_terminal_receipt",
                    true,
                    false,
                    &Error::IncompleteProofCoverage,
                );
                failure.terminal = Some(receipt);
                return Err(failure);
            }
            Ok((completed, receipt))
        }
        (Err(mut failure), Ok(receipt)) => {
            failure.terminal = Some(receipt);
            Err(failure)
        }
        (Ok(_), Err(error)) => Err(VerificationFailure::new(
            "session_close",
            true,
            false,
            &error,
        )),
        (Err(mut failure), Err(error)) => {
            failure.cleanup_error = Some(error);
            Err(failure)
        }
    }
}

pub(super) fn mutation_checks(
    verifier: &RegisteredVerifier,
    artifact: &mut Artifact,
    public: &[Val; 4],
) -> Result<(), VerificationFailure> {
    let mut changed = *public;
    changed[0] += Val::ONE;
    cpu_attempt("wrong_public_probe", || {
        mutation::require_rejection(verifier.verify_classified(artifact.proof(), &changed))
            .map_err(|reason| VerificationFailure::new("wrong_public_probe", true, true, &reason))
    })?;
    restored_opening_probe(artifact, |artifact| {
        mutation::require_rejection(verifier.verify_classified(artifact.proof(), public))
            .map_err(|reason| VerificationFailure::new("opening_probe", true, true, &reason))
    })
}

fn restored_opening_probe<T>(
    artifact: &mut Artifact,
    probe: impl FnOnce(&Artifact) -> Result<T, VerificationFailure>,
) -> Result<T, VerificationFailure> {
    let opening = artifact
        .proof_mut()
        .opened_values
        .instances
        .first_mut()
        .and_then(|instance| instance.base_opened_values.trace_local.first_mut())
        .ok_or_else(|| VerificationFailure::new("opening_probe", true, true, &Error::Geometry))?;
    let original = *opening;
    *opening += profile::Challenge::ONE;
    let rejected = cpu_attempt("opening_probe", || probe(artifact));
    // The nested attempt catches unwinding before restoring the exact field.
    // No clone or second proof owner is needed for this negative probe.
    artifact.proof_mut().opened_values.instances[0]
        .base_opened_values
        .trace_local[0] = original;
    rejected
}

#[cfg(test)]
mod tests;
