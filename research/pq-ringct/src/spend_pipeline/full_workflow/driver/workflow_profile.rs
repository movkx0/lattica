//! Bounded observations of the complete fresh case. These grant no authority.
//! Device counters remain nested observations, never extra wall-clock phases.
use super::super::closed_plan::{CryptoOutput, FinalOutput, GraphPhase, ProducerRoute};
use serde::Serialize;
use std::{cell::Cell, marker::PhantomData, rc::Rc, time::Instant};

pub(crate) const ENVIRONMENT: &str = "LATTICA_RINGCT_FULL_WORKFLOW_PROFILE";
const SCHEMA: &str = "ringct-full-workflow-profile-v1";
const GROUPS: [&str; 16] = [
    "native",
    "crypto_endpoints",
    "crypto_native",
    "crypto_compile",
    "crypto_outer",
    "fixed_compile",
    "fixed_outer",
    "leaf_compile",
    "leaf_outer",
    "direct_compile",
    "direct_outer",
    "parent_compile",
    "parent_outer",
    "final_compile",
    "final_outer",
    "final_verify",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Mode {
    Off,
    Summary,
    Detail,
}
impl Mode {
    fn parse(value: &str) -> Result<Self, &'static str> {
        match value {
            "off" => Ok(Self::Off),
            "summary" => Ok(Self::Summary),
            "detail" => Ok(Self::Detail),
            _ => Err("invalid full-workflow profile mode"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Phase {
    Generation,
    Startup,
    Metadata,
    Admission,
    Preflight,
    Preissue,
    Execution,
    Retirement,
}
const PHASES: [Phase; 8] = [
    Phase::Generation,
    Phase::Startup,
    Phase::Metadata,
    Phase::Admission,
    Phase::Preflight,
    Phase::Preissue,
    Phase::Execution,
    Phase::Retirement,
];

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct Work {
    completed: u64,
    failed: u64,
    elapsed_ns: u128,
}
impl Work {
    fn add(&mut self, ns: u128, success: bool) -> Option<()> {
        self.elapsed_ns = self.elapsed_ns.checked_add(ns)?;
        let count = if success {
            &mut self.completed
        } else {
            &mut self.failed
        };
        *count = count.checked_add(1)?;
        Some(())
    }
}

#[derive(Clone, Copy, Serialize)]
pub(crate) struct Report {
    schema: &'static str,
    clock: &'static str,
    mode: Mode,
    complete: bool,
    total_ns: u128,
    phase_order: [Phase; 8],
    phase_ns: [u128; 8],
    groups: [&'static str; 16],
    native_inputs: [Work; 4],
    preissue: [Work; 16],
    execution: [Work; 16],
    parent_compile: [Work; 11],
    parent_outer: [Work; 11],
    events: u64,
}
impl Report {
    fn new(mode: Mode) -> Self {
        Self {
            schema: SCHEMA,
            clock: "host_monotonic_wall",
            mode,
            complete: false,
            total_ns: 0,
            phase_order: PHASES,
            phase_ns: [0; 8],
            groups: GROUPS,
            native_inputs: [Work::default(); 4],
            preissue: [Work::default(); 16],
            execution: [Work::default(); 16],
            parent_compile: [Work::default(); 11],
            parent_outer: [Work::default(); 11],
            events: 0,
        }
    }
}

#[derive(Clone, Copy)]
struct Clock {
    started: Instant,
    last: Instant,
    phase: Phase,
    report: Report,
    poisoned: bool,
}
impl Clock {
    fn new(started: Instant, mode: Mode) -> Self {
        Self {
            started,
            last: started,
            phase: Phase::Generation,
            report: Report::new(mode),
            poisoned: false,
        }
    }
    fn advance(&mut self, next: Option<Phase>, now: Instant) -> Option<()> {
        if next.map_or(self.phase != Phase::Retirement, |p| {
            p as usize != self.phase as usize + 1
        }) {
            self.poisoned = true;
            return None;
        }
        let ns = now.checked_duration_since(self.last)?.as_nanos();
        let slot = &mut self.report.phase_ns[self.phase as usize];
        *slot = slot.checked_add(ns)?;
        self.last = now;
        if let Some(next) = next {
            self.phase = next;
        } else {
            self.report.total_ns = now.checked_duration_since(self.started)?.as_nanos();
            self.report.complete = !self.poisoned;
        }
        Some(())
    }
    fn work(&mut self, kind: Kind, ns: u128, success: bool) -> Option<()> {
        if kind.phase() != self.phase {
            self.poisoned = true;
            return None;
        }
        match kind {
            Kind::Input(ordinal) => self
                .report
                .native_inputs
                .get_mut(ordinal)?
                .add(ns, success)?,
            Kind::Preissue(_, route) => self.report.preissue[group(route)].add(ns, success)?,
            Kind::Execute(_, route) => {
                self.report.execution[group(route)].add(ns, success)?;
                if let ProducerRoute::Parent { level, phase, .. } = route {
                    let levels = match phase {
                        GraphPhase::Compile => &mut self.report.parent_compile,
                        GraphPhase::Outer => &mut self.report.parent_outer,
                    };
                    levels.get_mut(level)?.add(ns, success)?;
                }
            }
        }
        if !success {
            self.poisoned = true;
        }
        Some(())
    }
}

fn group(route: ProducerRoute) -> usize {
    match route {
        ProducerRoute::Native { .. } => 0,
        ProducerRoute::Crypto { output, .. } => match output {
            CryptoOutput::Endpoint(_) => 1,
            CryptoOutput::Native(_) => 2,
            CryptoOutput::Compiled(_) => 3,
            CryptoOutput::Outer(_) => 4,
        },
        ProducerRoute::Fixed { phase, .. } => 5 + usize::from(matches!(phase, GraphPhase::Outer)),
        ProducerRoute::Leaf { phase, .. } => 7 + usize::from(matches!(phase, GraphPhase::Outer)),
        ProducerRoute::Direct { phase, .. } => 9 + usize::from(matches!(phase, GraphPhase::Outer)),
        ProducerRoute::Parent { phase, .. } => 11 + usize::from(matches!(phase, GraphPhase::Outer)),
        ProducerRoute::Final { output, .. } => match output {
            FinalOutput::Compiled(_) => 13,
            FinalOutput::Outer(_) => 14,
            FinalOutput::Verified => 15,
        },
    }
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Input(usize),
    Preissue(usize, ProducerRoute),
    Execute(usize, ProducerRoute),
}
impl Kind {
    fn phase(self) -> Phase {
        match self {
            Self::Input(_) => Phase::Generation,
            Self::Preissue(..) => Phase::Preissue,
            Self::Execute(..) => Phase::Execution,
        }
    }
}
#[derive(Serialize)]
struct Event {
    schema: &'static str,
    sequence: u64,
    since_start_ns: u128,
    phase: Phase,
    event: &'static str,
    work: Option<Kind>,
    elapsed_ns: Option<u128>,
    success: Option<bool>,
}

thread_local! { static CLOCK: Cell<Option<Clock>> = const { Cell::new(None) }; }
fn update(f: impl FnOnce(&mut Clock) -> Option<()>) {
    CLOCK.with(|slot| {
        if let Some(mut value) = slot.get() {
            if f(&mut value).is_none() {
                value.poisoned = true;
            }
            slot.set(Some(value));
        }
    });
}
fn emit(event: &'static str, work: Option<Kind>, elapsed_ns: Option<u128>, success: Option<bool>) {
    update(|clock| {
        if work.is_some()
            && clock.report.mode != Mode::Detail
            && !matches!(work, Some(Kind::Input(_)))
        {
            return Some(());
        }
        let value = Event {
            schema: SCHEMA,
            sequence: clock.report.events,
            since_start_ns: clock.started.elapsed().as_nanos(),
            phase: clock.phase,
            event,
            work,
            elapsed_ns,
            success,
        };
        clock.report.events = clock.report.events.checked_add(1)?;
        use std::io::Write;
        let mut out = std::io::stderr().lock();
        out.write_all(b"RINGCT_WORKFLOW_PROGRESS ").ok()?;
        serde_json::to_writer(&mut out, &value).ok()?;
        out.write_all(b"\n").ok()?;
        Some(())
    });
}

pub(crate) struct Scope {
    active: bool,
    marker: PhantomData<Rc<()>>,
}
impl Scope {
    pub(crate) fn begin(started: Instant) -> Result<Self, &'static str> {
        let value = match std::env::var(ENVIRONMENT) {
            Ok(value) => value,
            Err(std::env::VarError::NotPresent) => "off".into(),
            Err(_) => return Err("invalid full-workflow profile environment"),
        };
        Self::begin_mode(started, Mode::parse(&value)?)
    }
    fn begin_mode(started: Instant, mode: Mode) -> Result<Self, &'static str> {
        if CLOCK.with(|slot| slot.get().is_some()) {
            return Err("nested full-workflow profiler");
        }
        if mode != Mode::Off {
            CLOCK.with(|slot| slot.set(Some(Clock::new(started, mode))));
        }
        emit("phase", None, None, None);
        Ok(Self {
            active: mode != Mode::Off,
            marker: PhantomData,
        })
    }
    pub(crate) fn finish(mut self, finished: Instant) -> Result<Option<Report>, &'static str> {
        if !self.active {
            return Ok(None);
        }
        update(|clock| clock.advance(None, finished));
        let complete = CLOCK.with(|slot| {
            slot.get()
                .is_some_and(|clock| clock.report.complete && !clock.poisoned)
        });
        emit(
            if complete { "complete" } else { "incomplete" },
            None,
            None,
            Some(complete),
        );
        self.active = false;
        let clock = CLOCK
            .with(|slot| slot.take())
            .ok_or("missing workflow profiler")?;
        if clock.poisoned || !clock.report.complete {
            return Err("incomplete workflow profiling observations");
        }
        Ok(Some(clock.report))
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        if self.active {
            emit("incomplete", None, None, Some(false));
            CLOCK.with(|slot| slot.set(None));
        }
    }
}
pub(crate) fn phase(next: Phase) {
    update(|clock| clock.advance(Some(next), Instant::now()));
    emit("phase", None, None, None);
}

pub(crate) struct Step {
    kind: Kind,
    started: Option<Instant>,
    complete: bool,
}
impl Step {
    fn begin(kind: Kind) -> Self {
        let started = CLOCK.with(|slot| slot.get().map(|_| Instant::now()));
        emit("begin", Some(kind), None, None);
        Self {
            kind,
            started,
            complete: false,
        }
    }
    pub(crate) fn input(ordinal: usize) -> Self {
        Self::begin(Kind::Input(ordinal))
    }
    pub(crate) fn preissue(ordinal: usize, route: ProducerRoute) -> Self {
        Self::begin(Kind::Preissue(ordinal, route))
    }
    pub(crate) fn execute(ordinal: usize, route: ProducerRoute) -> Self {
        Self::begin(Kind::Execute(ordinal, route))
    }
    pub(crate) fn complete(mut self) {
        self.complete = true;
    }
}
impl Drop for Step {
    fn drop(&mut self) {
        if let Some(started) = self.started {
            let ns = started.elapsed().as_nanos();
            update(|clock| clock.work(self.kind, ns, self.complete));
            emit("end", Some(self.kind), Some(ns), Some(self.complete));
        }
    }
}

/// Inline clocks, snapshots, formatting and return frames are charged before
/// native startup, and their original claim survives through case retirement.
pub(crate) const fn frame_bytes() -> usize {
    8 * (core::mem::size_of::<Clock>()
        + core::mem::size_of::<Report>()
        + core::mem::size_of::<Scope>()
        + core::mem::size_of::<Step>()
        + core::mem::size_of::<Event>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[test]
    fn real_clock_stream_and_snapshot_agree_for_both_modes() {
        use super::super::super::closed_plan::NativeFamily;
        for mode in [Mode::Summary, Mode::Detail] {
            let started = Instant::now();
            let scope = Scope::begin_mode(started, mode).unwrap();
            for ordinal in 0..3 {
                Step::input(ordinal).complete();
            }
            for next in [
                Phase::Startup,
                Phase::Metadata,
                Phase::Admission,
                Phase::Preflight,
                Phase::Preissue,
            ] {
                phase(next);
            }
            let routes = [
                ProducerRoute::Native {
                    family: NativeFamily::Source,
                    ordinal: 0,
                },
                ProducerRoute::Parent {
                    level: 0,
                    ordinal: 0,
                    phase: GraphPhase::Compile,
                },
                ProducerRoute::Parent {
                    level: 0,
                    ordinal: 0,
                    phase: GraphPhase::Outer,
                },
                ProducerRoute::Final {
                    step: 0,
                    output: FinalOutput::Verified,
                },
            ];
            for ordinal in [0, 2] {
                Step::preissue(ordinal, routes[ordinal]).complete();
            }
            phase(Phase::Execution);
            for (ordinal, route) in routes.iter().copied().enumerate() {
                Step::execute(ordinal, route).complete();
            }
            phase(Phase::Retirement);
            let profile = scope.finish(Instant::now()).unwrap().unwrap();
            assert!(profile.complete);
            assert_eq!(
                profile
                    .execution
                    .iter()
                    .map(|row| row.completed)
                    .sum::<u64>(),
                4
            );
            assert!(CLOCK.with(|slot| slot.get().is_none()));
            // An observer fixture, never a completed proof-workflow envelope.
            println!(
                "RINGCT_WORKFLOW_PROFILE_TEST {}",
                serde_json::json!({
                "routes": routes, "report": {"transactions": 3, "native_proofs": 1,
                "recursive_proofs": 1, "completed_phases": 4,
                "complete_workflow_ns": profile.total_ns, "workflow_profile": profile}})
            );
        }
    }
    #[test]
    fn unfinished_step_poisoning_does_not_leak_the_profile_into_the_next_case() {
        {
            let _scope = Scope::begin_mode(Instant::now(), Mode::Detail).unwrap();
            drop(Step::input(0));
            assert!(CLOCK.with(|slot| slot.get().unwrap().poisoned));
        }
        assert!(CLOCK.with(|slot| slot.get().is_none()));
    }

    #[test]
    fn disjoint_phases_partition_the_complete_case_and_reject_skips() {
        let start = Instant::now();
        let mut clock = Clock::new(start, Mode::Summary);
        for (i, phase) in PHASES.iter().copied().enumerate().skip(1) {
            clock
                .advance(Some(phase), start + Duration::from_nanos(i as u64 * 11))
                .unwrap();
        }
        clock
            .advance(None, start + Duration::from_nanos(88))
            .unwrap();
        assert_eq!(clock.report.phase_ns, [11; 8]);
        assert_eq!(
            clock.report.phase_ns.iter().sum::<u128>(),
            clock.report.total_ns
        );
        assert!(clock.report.complete);
        let mut clock = Clock::new(start, Mode::Detail);
        assert!(clock.advance(Some(Phase::Metadata), start).is_none());
        assert!(clock.poisoned);
    }
    #[test]
    fn actual_step_completion_and_parent_levels_are_counted_separately() {
        let start = Instant::now();
        let mut clock = Clock::new(start, Mode::Detail);
        clock.work(Kind::Input(0), 7, true).unwrap();
        assert_eq!(clock.report.native_inputs[0].completed, 1);
        assert!(clock.work(Kind::Input(4), 1, true).is_none());
        clock.phase = Phase::Execution;
        let route = ProducerRoute::Parent {
            level: 2,
            ordinal: 1,
            phase: GraphPhase::Outer,
        };
        clock.work(Kind::Execute(9, route), 17, true).unwrap();
        assert_eq!(clock.report.execution[12], clock.report.parent_outer[2]);
        assert_eq!(clock.report.parent_outer[2].elapsed_ns, 17);
        clock.work(Kind::Execute(10, route), 3, false).unwrap();
        assert!(clock.poisoned);
        assert_eq!(clock.report.execution[12].failed, 1);
    }
    #[test]
    fn unknown_modes_and_counter_overflow_are_rejected() {
        assert_eq!(Mode::parse("off"), Ok(Mode::Off));
        assert!(Mode::parse("trace").is_err());
        let mut work = Work {
            completed: u64::MAX,
            ..Work::default()
        };
        assert!(work.add(1, true).is_none());
    }
}
