//! Disjoint wall-clock metadata phases, stopped before proof execution.
use std::{cell::Cell, marker::PhantomData, rc::Rc, time::Instant};
#[derive(Clone, Copy, Debug)]
pub(super) enum Phase {
    Setup,
    GraphSources,
    SourcePreparation,
    Inventory,
    Reservation,
    Constructors,
    Native,
    Crypto,
    Graph,
    Final,
}
#[derive(Clone, Copy, Debug, Default, serde::Serialize, PartialEq, Eq)]
pub(crate) struct Statistics {
    pub setup_ns: u128,
    pub graph_sources_ns: u128,
    pub source_preparation_ns: u128,
    pub inventory_ns: u128,
    pub reservation_ns: u128,
    pub constructors_ns: u128,
    pub native_constructors_ns: u128,
    pub crypto_constructors_ns: u128,
    pub graph_constructors_ns: u128,
    pub final_aggregation_ns: u128,
    pub total_ns: u128,
}
#[derive(Clone, Copy)]
struct Clock {
    last: Instant,
    phase: Option<Phase>,
    statistics: Statistics,
}
impl Clock {
    fn advance(&mut self, phase: Option<Phase>, now: Instant) {
        let Some(previous) = self.phase else {
            return;
        };
        let ns = now.duration_since(self.last).as_nanos();
        let slot = match previous {
            Phase::Setup => &mut self.statistics.setup_ns,
            Phase::GraphSources => &mut self.statistics.graph_sources_ns,
            Phase::SourcePreparation => &mut self.statistics.source_preparation_ns,
            Phase::Inventory => &mut self.statistics.inventory_ns,
            Phase::Reservation => &mut self.statistics.reservation_ns,
            Phase::Constructors | Phase::Native => &mut self.statistics.native_constructors_ns,
            Phase::Crypto => &mut self.statistics.crypto_constructors_ns,
            Phase::Graph => &mut self.statistics.graph_constructors_ns,
            Phase::Final => &mut self.statistics.final_aggregation_ns,
        };
        *slot += ns;
        if matches!(
            previous,
            Phase::Constructors | Phase::Native | Phase::Crypto | Phase::Graph | Phase::Final
        ) {
            self.statistics.constructors_ns += ns;
        }
        self.statistics.total_ns += ns;
        self.last = now;
        self.phase = phase;
    }
}
thread_local! { static CLOCK: Cell<Option<Clock>> = const { Cell::new(None) }; }
pub(super) struct Scope(PhantomData<Rc<()>>);
impl Scope {
    pub(super) fn begin() -> Option<Self> {
        CLOCK.with(|clock| {
            if clock.get().is_some() {
                return None;
            }
            clock.set(Some(Clock {
                last: Instant::now(),
                phase: Some(Phase::Setup),
                statistics: Statistics::default(),
            }));
            Some(Self(PhantomData))
        })
    }
    pub(super) fn statistics(&self) -> Option<Statistics> {
        CLOCK.with(|clock| {
            clock
                .get()
                .filter(|c| c.phase.is_none())
                .map(|c| c.statistics)
        })
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        CLOCK.with(|clock| clock.set(None));
    }
}
fn advance(phase: Option<Phase>) {
    CLOCK.with(|clock| {
        if let Some(mut value) = clock.get() {
            value.advance(phase, Instant::now());
            clock.set(Some(value));
        }
    });
}
pub(super) fn phase(phase: Phase) {
    advance(Some(phase));
    #[cfg(test)]
    super::metadata_profile::phase_started(phase);
}
fn write_report(out: &mut impl std::io::Write, statistics: &Statistics) -> std::io::Result<()> {
    out.write_all(b"RINGCT_METADATA_TIMING ")?;
    serde_json::to_writer(&mut *out, statistics).map_err(std::io::Error::other)?;
    out.write_all(b"\n")
}
pub(super) fn finish() {
    let finished = CLOCK.with(|clock| {
        let mut value = clock.get()?;
        value.phase?;
        value.advance(None, Instant::now());
        clock.set(Some(value));
        Some(value.statistics)
    });
    // Stream the fixed numerical report immediately, before the execution
    // continuation. Reporting failure cannot change any admission decision.
    if let Some(statistics) = finished {
        let _ = write_report(&mut std::io::stderr().lock(), &statistics);
    }
}
/// Fixed TLS, copies, scope and return frames fit the existing metadata claim.
pub(super) const fn frame_bytes() -> usize {
    8 * (core::mem::size_of::<Option<Clock>>()
        + core::mem::size_of::<Scope>()
        + core::mem::size_of::<Statistics>()
        + core::mem::size_of::<Phase>())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn constructor_details_are_disjoint_and_reportable_before_execution() {
        let start = Instant::now();
        let mut clock = Clock {
            last: start,
            phase: Some(Phase::Native),
            statistics: Statistics::default(),
        };
        clock.advance(
            Some(Phase::Crypto),
            start + std::time::Duration::from_nanos(3),
        );
        clock.advance(
            Some(Phase::Graph),
            start + std::time::Duration::from_nanos(8),
        );
        clock.advance(
            Some(Phase::Final),
            start + std::time::Duration::from_nanos(15),
        );
        clock.advance(None, start + std::time::Duration::from_nanos(26));
        let s = clock.statistics;
        assert_eq!(
            (
                s.native_constructors_ns,
                s.crypto_constructors_ns,
                s.graph_constructors_ns,
                s.final_aggregation_ns
            ),
            (3, 5, 7, 11)
        );
        assert_eq!(s.constructors_ns, s.total_ns);
        assert_eq!(s.total_ns, 26);
        let mut output = Vec::new();
        write_report(&mut output, &s).unwrap();
        let text = String::from_utf8(output).unwrap();
        let report: serde_json::Value =
            serde_json::from_str(text.strip_prefix("RINGCT_METADATA_TIMING ").unwrap()).unwrap();
        assert_eq!(report["total_ns"], 26);
        assert_eq!(report["final_aggregation_ns"], 11);
    }
    #[test]
    fn disjoint_metadata_clock_excludes_execution_and_clears_scope() {
        let start = Instant::now();
        let mut clock = Clock {
            last: start,
            phase: Some(Phase::Setup),
            statistics: Statistics::default(),
        };
        clock.advance(
            Some(Phase::Constructors),
            start + std::time::Duration::from_nanos(10),
        );
        clock.advance(None, start + std::time::Duration::from_nanos(30));
        clock.advance(None, start + std::time::Duration::from_secs(50));
        assert_eq!(clock.statistics.setup_ns, 10);
        assert_eq!(clock.statistics.constructors_ns, 20);
        assert_eq!(clock.statistics.total_ns, 30);
        let scope = Scope::begin().unwrap();
        assert!(Scope::begin().is_none());
        assert!(scope.statistics().is_none());
        finish();
        assert!(scope.statistics().is_some());
        drop(scope);
        assert!(Scope::begin().is_some());
        assert!(frame_bytes() < 4096);
    }
}
