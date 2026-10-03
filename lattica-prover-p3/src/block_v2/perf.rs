//! Opt-in, process-local research profiling. Never records span fields or events.
//!
//! Durations are span lifetimes, inclusive of nested work. Concurrent/nested spans
//! overlap, so their totals MUST NOT be added to infer an exclusive breakdown.
//! The fixed span names/targets are public code metadata, not prover inputs.
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    sync::{Arc, Mutex},
    time::Instant,
};
use tracing::{span, Event, Metadata, Subscriber};

mod timeline;

const MAX_LIVE_SPANS: usize = 4096;
const MAX_PHASES: usize = 256;
type Key = (&'static str, &'static str);

#[derive(Clone, Debug, Default)]
struct Timing {
    calls: u64,
    total_ns: u128,
    max_ns: u128,
    process_samples: u64,
    process_deltas: BTreeMap<&'static str, u64>,
}

struct Active {
    key: Key,
    started: Instant,
    references: u64,
    counters: Option<Counters>,
}

#[derive(Default)]
struct State {
    next_id: u64,
    live: HashMap<u64, Active>,
    timings: BTreeMap<Key, Timing>,
    dropped: u64,
    timeline: Option<timeline::Timeline>,
}

#[derive(Clone, Default)]
struct Timings(Arc<Mutex<State>>);

impl Timings {
    fn with_timeline(enabled: bool) -> Self {
        Self(Arc::new(Mutex::new(State {
            timeline: enabled.then(timeline::Timeline::default),
            ..State::default()
        })))
    }
}

// Coarse process-wide deltas include nested and concurrent work. They are not
// exclusive phase costs and must never be summed into a CPU/IO breakdown.
fn sample_process(key: Key) -> bool {
    matches!(
        key,
        (
            "lattica_block_v2_perf",
            "preprocessing setup"
                | "execution trace"
                | "native batch prove"
                | "bounded GPU commitment"
        ) | ("p3_batch_stark::prover", "compute quotient")
            | ("p3_fri::two_adic_pcs", "reduce matrix quotient")
    )
}

impl Subscriber for Timings {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.is_span()
            && (metadata.target().starts_with("p3_")
                || metadata.target() == "lattica_block_v2_perf")
    }

    fn new_span(&self, attrs: &span::Attributes<'_>) -> span::Id {
        let mut state = self.0.lock().unwrap();
        state.next_id = state
            .next_id
            .checked_add(1)
            .expect("profiling span id overflow");
        let id = state.next_id;
        if state.live.len() < MAX_LIVE_SPANS {
            let key = (attrs.metadata().target(), attrs.metadata().name());
            let counters = (state.timeline.is_some() && sample_process(key)).then(Counters::read);
            state.live.insert(
                id,
                Active {
                    key,
                    started: Instant::now(),
                    references: 1,
                    counters,
                },
            );
        } else {
            state.dropped += 1;
        }
        span::Id::from_u64(id)
    }

    // In particular, never evaluate Debug/Display visitors for trace fields.
    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
    fn event(&self, _: &Event<'_>) {}
    fn enter(&self, id: &span::Id) {
        let mut state = self.0.lock().unwrap();
        let key = state.live.get(&id.into_u64()).map(|active| active.key);
        if let Some(timeline) = &mut state.timeline {
            timeline.enter(id.into_u64(), key);
        }
    }
    fn exit(&self, id: &span::Id) {
        if let Some(timeline) = &mut self.0.lock().unwrap().timeline {
            timeline.exit(id.into_u64());
        }
    }

    fn clone_span(&self, id: &span::Id) -> span::Id {
        if let Some(active) = self.0.lock().unwrap().live.get_mut(&id.into_u64()) {
            active.references += 1;
        }
        id.clone()
    }

    fn try_close(&self, id: span::Id) -> bool {
        let mut state = self.0.lock().unwrap();
        let Some(active) = state.live.get_mut(&id.into_u64()) else {
            return false;
        };
        active.references -= 1;
        if active.references != 0 {
            return false;
        }
        let active = state.live.remove(&id.into_u64()).unwrap();
        let ns = active.started.elapsed().as_nanos();
        if state.timings.contains_key(&active.key) || state.timings.len() < MAX_PHASES {
            let timing = state.timings.entry(active.key).or_default();
            timing.calls += 1;
            timing.total_ns += ns;
            timing.max_ns = timing.max_ns.max(ns);
            if let Some(before) = active.counters {
                timing.process_samples += 1;
                for (name, delta) in Counters::read().delta(&before) {
                    let total = timing.process_deltas.entry(name).or_default();
                    *total = total.saturating_add(delta);
                }
            }
        } else {
            state.dropped += 1;
        }
        true
    }
}

#[derive(Default)]
struct Counters(BTreeMap<&'static str, u64>);

fn keyed(text: &str, key: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        let mut words = line.split_whitespace();
        (words.next()? == key)
            .then(|| words.next()?.parse().ok())
            .flatten()
    })
}

impl Counters {
    fn delta(&self, before: &Self) -> BTreeMap<&'static str, u64> {
        self.0
            .iter()
            .filter_map(|(&name, &value)| {
                before
                    .0
                    .get(name)
                    .map(|&old| (name, value.saturating_sub(old)))
            })
            .collect()
    }

    fn read() -> Self {
        let mut values = BTreeMap::new();
        if let Ok(io) = fs::read_to_string("/proc/self/io") {
            for (name, key) in [
                ("read_bytes", "read_bytes:"),
                ("write_bytes", "write_bytes:"),
            ] {
                if let Some(value) = keyed(&io, key) {
                    values.insert(name, value);
                }
            }
        }
        if let Ok(stat) = fs::read_to_string("/proc/self/stat") {
            if let Some((_, suffix)) = stat.rsplit_once(')') {
                let fields: Vec<_> = suffix.split_whitespace().collect();
                for (name, index) in [
                    ("minor_faults", 7),
                    ("major_faults", 9),
                    ("user_ticks", 11),
                    ("system_ticks", 12),
                ] {
                    if let Some(value) = fields.get(index).and_then(|v| v.parse().ok()) {
                        values.insert(name, value);
                    }
                }
            }
        }
        if let Ok(cgroup) = fs::read_to_string("/proc/self/cgroup") {
            if let Some(path) = cgroup.lines().find_map(|line| line.strip_prefix("0::/")) {
                // A kernel-provided cgroup-v2 path, never a prover-supplied path.
                let path = std::path::Path::new("/sys/fs/cgroup").join(path);
                if let Ok(events) = fs::read_to_string(path.join("memory.events")) {
                    if let Some(value) = keyed(&events, "high") {
                        values.insert("memory_high_events", value);
                    }
                }
                if let Ok(pressure) = fs::read_to_string(path.join("memory.pressure")) {
                    for (name, prefix) in [
                        ("memory_some_stall_us", "some "),
                        ("memory_full_stall_us", "full "),
                    ] {
                        if let Some(value) = pressure
                            .lines()
                            .find(|l| l.starts_with(prefix))
                            .and_then(|l| {
                                l.split_whitespace().find_map(|w| w.strip_prefix("total="))
                            })
                            .and_then(|v| v.parse().ok())
                        {
                            values.insert(name, value);
                        }
                    }
                }
            }
        }
        Self(values)
    }
}

/// Install only in the dedicated research CLI, before Rayon work starts.
/// Library callers do not install a subscriber or change global process state.
pub struct Profiler {
    timings: Timings,
    previous: Mutex<(Instant, Counters)>,
}

impl Profiler {
    pub fn from_env() -> Result<Option<Self>, Box<dyn std::error::Error>> {
        let profile = switch("LATTICA_PROFILE")?;
        let timeline = switch("LATTICA_PROFILE_TIMELINE")?;
        if !profile {
            if timeline {
                return Err("LATTICA_PROFILE_TIMELINE requires LATTICA_PROFILE=1".into());
            }
            return Ok(None);
        }
        let timings = Timings::with_timeline(timeline);
        tracing::subscriber::set_global_default(timings.clone())
            .map_err(|_| "profiling requested but a tracing subscriber is already installed")?;
        Ok(Some(Self {
            timings,
            previous: Mutex::new((Instant::now(), Counters::read())),
        }))
    }

    /// Call at a quiescent boundary, after all synchronous work for this node.
    /// `label` must be a public fixture label, never witness or proof data.
    pub fn report(&self, label: &str) {
        let now = Instant::now();
        let counters = Counters::read();
        let mut previous = self.previous.lock().unwrap();
        let mut state = self.timings.0.lock().unwrap();
        println!("performance_checkpoint label={label:?} elapsed_ms={} spans_dropped={} spans_open={} timings=inclusive_nonadditive",
            now.duration_since(previous.0).as_millis(), state.dropped, state.live.len());
        for ((target, name), timing) in std::mem::take(&mut state.timings) {
            println!(
                "performance_span target={target:?} name={name:?} calls={} total_ns={} max_ns={}",
                timing.calls, timing.total_ns, timing.max_ns
            );
            for (counter, delta) in timing.process_deltas {
                println!("performance_phase_counter target={target:?} name={name:?} counter={counter} delta={delta} samples={} scope=inclusive_process_nonadditive", timing.process_samples);
            }
        }
        if let Some(timeline) = &mut state.timeline {
            let checkpoint = timeline.checkpoint();
            println!("host_timeline_checkpoint label={label:?} threads={} events={} dropped={} malformed={} open_frames={} clock=host_monotonic_relative interpretation=entered_wall_disjoint_per_thread_not_cpu_time", checkpoint.threads, checkpoint.segments.len(), checkpoint.dropped, checkpoint.malformed, checkpoint.open_frames);
            for segment in checkpoint.segments {
                println!(
                    "host_timeline_interval thread={} target={:?} name={:?} start_ns={} end_ns={}",
                    segment.thread, segment.key.0, segment.key.1, segment.start_ns, segment.end_ns
                );
            }
        }
        for (name, value) in &counters.0 {
            if let Some(before) = previous.1 .0.get(name) {
                println!(
                    "performance_counter name={name} delta={}",
                    value.saturating_sub(*before)
                );
            }
        }
        *previous = (now, counters);
    }
}

fn switch(name: &str) -> Result<bool, Box<dyn std::error::Error>> {
    match std::env::var(name) {
        Err(std::env::VarError::NotPresent) => Ok(false),
        Ok(value) if value == "0" => Ok(false),
        Ok(value) if value == "1" => Ok(true),
        _ => Err(format!("{name} must be 0 or 1").into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt;

    struct Secret;
    impl fmt::Debug for Secret {
        fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
            panic!("profiling must never format witness/debug fields")
        }
    }

    #[test]
    fn timings_ignore_fields_events_and_count_nested_spans_separately() {
        let timings = Timings::default();
        tracing::subscriber::with_default(timings.clone(), || {
            let parent =
                tracing::info_span!(target: "lattica_block_v2_perf", "parent", secret = ?Secret);
            let _entered = parent.enter();
            tracing::info!(target: "lattica_block_v2_perf", secret = ?Secret);
            tracing::info_span!(target: "p3_test", "child").in_scope(|| {});
        });
        let state = timings.0.lock().unwrap();
        assert!(state.live.is_empty());
        assert_eq!(state.timings.len(), 2);
        assert!(state.timings.values().all(|t| t.calls == 1));
        assert_eq!(state.dropped, 0);
    }

    #[test]
    fn clones_keep_a_span_live_until_the_last_reference_is_dropped() {
        let timings = Timings::default();
        tracing::subscriber::with_default(timings.clone(), || {
            let span = tracing::info_span!(target: "p3_test", "cloned");
            let copy = span.clone();
            drop(span);
            assert_eq!(timings.0.lock().unwrap().live.len(), 1);
            std::thread::spawn(move || drop(copy)).join().unwrap();
        });
        let state = timings.0.lock().unwrap();
        assert!(state.live.is_empty());
        assert_eq!(state.timings.values().next().unwrap().calls, 1);
    }

    #[test]
    fn live_span_capacity_is_bounded_and_drops_are_reported() {
        let timings = Timings::default();
        tracing::subscriber::with_default(timings.clone(), || {
            let spans: Vec<_> = (0..MAX_LIVE_SPANS + 3)
                .map(|_| tracing::info_span!(target: "p3_test", "capacity"))
                .collect();
            {
                let state = timings.0.lock().unwrap();
                assert_eq!(state.live.len(), MAX_LIVE_SPANS);
                assert_eq!(state.dropped, 3);
            }
            drop(spans);
        });
        let state = timings.0.lock().unwrap();
        assert!(state.live.is_empty());
        assert_eq!(
            state.timings.values().next().unwrap().calls,
            MAX_LIVE_SPANS as u64
        );
        assert_eq!(state.dropped, 3);
    }

    #[test]
    fn unrelated_targets_are_not_recorded() {
        let timings = Timings::default();
        tracing::subscriber::with_default(timings.clone(), || {
            tracing::info_span!(target: "application", "private operation", secret = ?Secret)
                .in_scope(|| {});
        });
        let state = timings.0.lock().unwrap();
        assert!(state.live.is_empty());
        assert!(state.timings.is_empty());
    }

    #[test]
    fn kernel_counter_parser_uses_exact_keys() {
        assert_eq!(keyed("high 12\nhighest 99\n", "high"), Some(12));
        assert_eq!(keyed("high invalid\n", "high"), None);
        assert_eq!(keyed("other 17\n", "high"), None);
    }

    #[test]
    fn timeline_tracks_cross_thread_span_clones_without_visiting_secret_fields() {
        let timings = Timings::with_timeline(true);
        tracing::subscriber::with_default(timings.clone(), || {
            let span = tracing::info_span!(target: "p3_test", "shared", secret = ?Secret);
            span.in_scope(|| {
                tracing::info!(target: "p3_test", secret = ?Secret);
                let copy = span.clone();
                std::thread::spawn(move || copy.in_scope(|| {}))
                    .join()
                    .unwrap();
            });
        });
        let mut state = timings.0.lock().unwrap();
        assert!(state.live.is_empty());
        let checkpoint = state.timeline.as_mut().unwrap().checkpoint();
        assert_eq!(checkpoint.threads, 2);
        assert_eq!(
            (
                checkpoint.dropped,
                checkpoint.malformed,
                checkpoint.open_frames
            ),
            (0, 0, 0)
        );
        assert_eq!(checkpoint.segments.len(), 2);
        assert_ne!(checkpoint.segments[0].thread, checkpoint.segments[1].thread);
    }

    #[test]
    fn resource_deltas_are_keyed_and_only_selected_coarse_spans_are_sampled() {
        let before = Counters(BTreeMap::from([("read_bytes", 8), ("user_ticks", 9)]));
        let after = Counters(BTreeMap::from([
            ("read_bytes", 12),
            ("user_ticks", 3),
            ("new", 99),
        ]));
        assert_eq!(
            after.delta(&before),
            BTreeMap::from([("read_bytes", 4), ("user_ticks", 0)])
        );
        assert!(sample_process((
            "p3_batch_stark::prover",
            "compute quotient"
        )));
        assert!(!sample_process(("application", "compute quotient")));
        let timings = Timings::with_timeline(true);
        tracing::subscriber::with_default(timings.clone(), || {
            tracing::info_span!(target: "lattica_block_v2_perf", "execution trace", secret = ?Secret).in_scope(|| {});
        });
        let state = timings.0.lock().unwrap();
        assert_eq!(state.timings.values().next().unwrap().process_samples, 1);
    }
}
