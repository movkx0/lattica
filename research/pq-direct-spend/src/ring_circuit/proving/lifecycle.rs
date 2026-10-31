//! A single attempt always retires its registration before session teardown.
//! Backend panics are failures, never a reason to retry with another backend.
use super::*;
use std::{
    fmt::Write,
    panic::{catch_unwind, AssertUnwindSafe},
};

const ERROR_BYTES: usize = 1024;

pub(super) fn bounded(error: &impl fmt::Debug) -> String {
    struct Bounded(String);
    impl fmt::Write for Bounded {
        fn write_str(&mut self, value: &str) -> fmt::Result {
            let remaining = ERROR_BYTES - self.0.len();
            let mut take = remaining.min(value.len());
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
    proof_started: &Cell<bool>,
    run: impl FnOnce() -> Result<T, ProofFailure>,
) -> Result<T, ProofFailure> {
    match catch_unwind(AssertUnwindSafe(run)) {
        Ok(result) => result,
        Err(payload) => {
            // Do not copy a backend panic payload into a report: it is neither
            // a bounded error schema nor necessarily public information.
            drop(payload);
            Err(ProofFailure::new(
                phase.get(),
                proof_started.get(),
                &"backend panicked",
            ))
        }
    }
}

pub(super) trait TerminalSession {
    fn finish(self) -> Result<serde_json::Value, String>;
    fn cleanup(self) -> Result<serde_json::Value, String>;
}
impl TerminalSession for Session {
    fn finish(self) -> Result<serde_json::Value, String> {
        Session::finish(self)
    }
    fn cleanup(self) -> Result<serde_json::Value, String> {
        self.close_without_completion()
    }
}

pub(super) fn finish<T>(
    session: impl TerminalSession,
    attempted: Result<T, ProofFailure>,
) -> Result<(T, TerminalReceipt), ProofFailure> {
    match attempted {
        Ok(completed) => {
            let receipt = session
                .finish()
                .map_err(|error| ProofFailure::new("session_finish", true, &error))?;
            let terminal = TerminalReceipt::parse(&receipt, true)
                .map_err(|error| ProofFailure::new("terminal_receipt", true, &error))?;
            Ok((completed, terminal))
        }
        Err(mut failure) => {
            match session.cleanup() {
                Ok(receipt) => match TerminalReceipt::parse(&receipt, false) {
                    Ok(terminal) => failure.terminal = Some(terminal),
                    Err(error) => failure.cleanup_error = Some(bounded(&error)),
                },
                Err(error) => failure.cleanup_error = Some(bounded(&error)),
            }
            Err(failure)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, rc::Rc};

    struct FakeSession {
        events: Rc<RefCell<Vec<&'static str>>>,
        fail: bool,
    }
    impl TerminalSession for FakeSession {
        fn finish(self) -> Result<serde_json::Value, String> {
            self.events.borrow_mut().push("finish");
            if self.fail {
                Err("shutdown failed".into())
            } else {
                Ok(terminal())
            }
        }
        fn cleanup(self) -> Result<serde_json::Value, String> {
            self.events.borrow_mut().push("cleanup");
            if self.fail {
                Err("shutdown failed".into())
            } else {
                Ok(terminal())
            }
        }
    }
    struct Registration(Rc<RefCell<Vec<&'static str>>>);
    impl Drop for Registration {
        fn drop(&mut self) {
            self.0.borrow_mut().push("registration_dropped");
        }
    }
    fn terminal() -> serde_json::Value {
        serde_json::json!({
            "host_allowance_bytes": HOST_BYTES, "device_allowance_bytes": DEVICE_BYTES,
            "gpu_context_allowance_bytes": CONTEXT_BYTES, "max_rows": MAX_ROWS,
            "commits": 1, "allocations": 1, "managed_peak_bytes": 1,
            "uploaded_bytes": 1, "downloaded_bytes": 1,
            "context_closed": true, "queue_drained": true,
            "completion_claimed": false, "stark_completion_claimed": false,
        })
    }

    #[test]
    fn unwinding_drops_registration_before_cleanup_and_retains_no_success() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let phase = Cell::new("proving");
        let started = Cell::new(true);
        let attempted: Result<(), _> = attempt(&phase, &started, || {
            let _registration = Registration(events.clone());
            panic!("backend-private-panic-payload");
        });
        let failure = finish(
            FakeSession {
                events: events.clone(),
                fail: false,
            },
            attempted,
        )
        .unwrap_err();
        assert_eq!(&*events.borrow(), &["registration_dropped", "cleanup"]);
        assert_eq!(failure.phase, "proving");
        assert!(failure.cryptographic_proof_started);
        assert!(!failure.error.contains("backend-private-panic-payload"));
        assert!(!failure.terminal.unwrap().completion_claimed);
        assert!(failure.cleanup_error.is_none());
    }

    #[test]
    fn returned_failure_preserves_original_error_and_shutdown_failure() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let attempted: Result<(), _> =
            Err(ProofFailure::new("registration", false, &"setup failed"));
        let failure = finish(
            FakeSession {
                events: events.clone(),
                fail: true,
            },
            attempted,
        )
        .unwrap_err();
        assert_eq!(&*events.borrow(), &["cleanup"]);
        assert!(failure.error.contains("setup failed"));
        assert!(failure.cleanup_error.unwrap().contains("shutdown failed"));
        assert!(failure.terminal.is_none());
        assert!(!failure.cryptographic_proof_started);
    }

    #[test]
    fn successful_computation_is_withheld_when_shutdown_fails() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let failure = finish(
            FakeSession {
                events: events.clone(),
                fail: true,
            },
            Ok(7),
        )
        .unwrap_err();
        assert_eq!(&*events.borrow(), &["finish"]);
        assert_eq!(failure.phase, "session_finish");
        assert!(failure.terminal.is_none());
    }

    #[test]
    fn error_formatting_has_a_fixed_utf8_capacity() {
        let value = "π".repeat(2048);
        let result = bounded(&value);
        assert!(result.len() <= ERROR_BYTES);
        assert!(result.capacity() <= ERROR_BYTES);
        assert!(result.is_char_boundary(result.len()));
    }
}
