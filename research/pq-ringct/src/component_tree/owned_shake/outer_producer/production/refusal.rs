//! Inline diagnostics preserve the refusal while the planning lease destroys
//! the core planner's already-funded String. No log, allocation, or retry occurs.
use super::Error;
use core::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::component_tree::owned_shake) enum AdmissionPhase {
    Planning,
    ReportSize,
    ReportReservation,
    WrapperCensus,
    WrapperReservation,
    Limits,
    NativePartition,
    TreeOwner,
    BackendPlan,
    IncompletePhaseBounds,
    StartupOverlap,
    BackendReservation,
    BackendAdmission,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::component_tree::owned_shake) struct AdmissionRefusal {
    phase: AdmissionPhase,
    message: [u8; 256],
    used: u16,
    truncated: bool,
}

impl AdmissionRefusal {
    pub(super) fn phase(phase: AdmissionPhase) -> Self {
        Self::reason(phase, "")
    }

    pub(super) fn reason(phase: AdmissionPhase, reason: &str) -> Self {
        let mut message = [0; 256];
        let mut used = reason.len().min(message.len());
        while !reason.is_char_boundary(used) {
            used -= 1;
        }
        message[..used].copy_from_slice(&reason.as_bytes()[..used]);
        Self {
            phase,
            message,
            used: used as u16,
            truncated: used < reason.len(),
        }
    }

    fn text(&self) -> &str {
        // Only reason() initializes the private buffer and preserves UTF-8.
        core::str::from_utf8(&self.message[..self.used as usize]).unwrap_or("invalid diagnostic")
    }
}

impl fmt::Debug for AdmissionRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdmissionRefusal")
            .field("phase", &self.phase)
            .field("reason", &self.text())
            .field("truncated", &self.truncated)
            .finish()
    }
}

impl From<AdmissionRefusal> for Error {
    fn from(value: AdmissionRefusal) -> Self {
        Self::Admission(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusal_preserves_phase_and_utf8_in_fixed_inline_storage() {
        let empty = AdmissionRefusal::phase(AdmissionPhase::Planning);
        assert_eq!(empty.text(), "");
        assert!(!empty.truncated);
        let exact = AdmissionRefusal::reason(AdmissionPhase::BackendPlan, "source bound refused");
        assert_eq!(exact.text(), "source bound refused");
        assert!(!exact.truncated);
        assert_ne!(
            exact,
            AdmissionRefusal::reason(AdmissionPhase::BackendAdmission, "source bound refused")
        );
        let mut long = [b'a'; 259];
        long[255..258].copy_from_slice("€".as_bytes());
        let text = core::str::from_utf8(&long).unwrap();
        let bounded = AdmissionRefusal::reason(AdmissionPhase::BackendPlan, text);
        assert_eq!(bounded.text().len(), 255);
        assert!(bounded.truncated);
        assert!(core::mem::size_of::<AdmissionRefusal>() <= 264);
        assert_eq!(Error::from(bounded), Error::Admission(bounded));
    }
}
