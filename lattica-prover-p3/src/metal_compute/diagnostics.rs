//! Opt-in observations at existing submission, wait and retirement points.
//! Never submits, flushes, waits for, or retains a Metal resource.
use serde::Serialize;
use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

const MAX_EVENTS: usize = 262_144;
const MAX_IDENTITIES: usize = 131_072;

pub(crate) fn clock_ns() -> u64 {
    static TIMEBASE: OnceLock<(u32, u32)> = OnceLock::new();
    let &(numer, denom) = TIMEBASE.get_or_init(|| {
        let mut info = libc::mach_timebase_info_data_t { numer: 0, denom: 0 };
        // SAFETY: valid writable timebase structure; no process state changes.
        assert_eq!(unsafe { libc::mach_timebase_info(&mut info) }, 0);
        (info.numer, info.denom)
    });
    (u128::from(unsafe { libc::mach_absolute_time() }) * u128::from(numer) / u128::from(denom))
        as u64
}

#[derive(Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Record {
    Command {
        id: u64,
        phase: &'static str,
        dispatches: u64,
        submitted_ns: u64,
        gpu_start_ns: u64,
        gpu_end_ns: u64,
        timestamp_valid: bool,
    },
    Wait {
        id: Option<u64>,
        thread: String,
        start_ns: u64,
        end_ns: u64,
    },
}

struct Identity {
    id: u64,
    phase: &'static str,
    dispatches: u64,
    submitted_ns: u64,
    retired: bool,
}
#[derive(Default)]
struct State {
    next_id: u64,
    identities: HashMap<usize, Identity>,
    records: Vec<Record>,
    dropped: u64,
    duplicate_retirements: u64,
}
impl State {
    fn push(&mut self, record: Record, limit: usize) {
        if self.records.len() < limit {
            self.records.push(record);
        } else {
            self.dropped += 1;
        }
    }
    fn submit(&mut self, address: usize, phase: &'static str, dispatches: u64, now: u64) {
        if !self.identities.contains_key(&address) && self.identities.len() >= MAX_IDENTITIES {
            self.dropped += 1;
            return;
        }
        self.next_id += 1;
        self.identities.insert(
            address,
            Identity {
                id: self.next_id,
                phase,
                dispatches,
                submitted_ns: now,
                retired: false,
            },
        );
    }
    fn retire(&mut self, address: usize, start: f64, end: f64) {
        let Some(identity) = self.identities.get_mut(&address) else {
            self.dropped += 1;
            return;
        };
        if identity.retired {
            self.duplicate_retirements += 1;
            return;
        }
        identity.retired = true;
        let valid = start.is_finite() && end.is_finite() && start > 0.0 && end >= start;
        let record = Record::Command {
            id: identity.id,
            phase: identity.phase,
            dispatches: identity.dispatches,
            submitted_ns: identity.submitted_ns,
            gpu_start_ns: if valid { (start * 1e9) as u64 } else { 0 },
            gpu_end_ns: if valid { (end * 1e9) as u64 } else { 0 },
            timestamp_valid: valid,
        };
        self.push(record, MAX_EVENTS);
    }
}

fn state() -> Option<&'static Mutex<State>> {
    static STATE: OnceLock<Option<Mutex<State>>> = OnceLock::new();
    STATE
        .get_or_init(|| {
            (std::env::var("LATTICA_PROFILE_TIMELINE").as_deref() == Ok("1"))
                .then(|| Mutex::new(State::default()))
        })
        .as_ref()
}
pub(crate) fn enabled() -> bool {
    state().is_some()
}
pub(crate) fn submitted(address: usize, phase: &'static str, dispatches: u64) {
    if let Some(state) = state() {
        state
            .lock()
            .unwrap()
            .submit(address, phase, dispatches, clock_ns());
    }
}
pub(crate) fn retired(address: usize, start: f64, end: f64) {
    if let Some(state) = state() {
        state.lock().unwrap().retire(address, start, end);
    }
}
pub(crate) fn waited(address: usize, start_ns: u64, end_ns: u64) {
    if let Some(state) = state() {
        let mut state = state.lock().unwrap();
        let id = state.identities.get(&address).map(|identity| identity.id);
        state.push(
            Record::Wait {
                id,
                thread: format!("{:?}", std::thread::current().id()),
                start_ns,
                end_ns,
            },
            MAX_EVENTS,
        );
    }
}
pub(crate) fn report() {
    if let Some(state) = state() {
        let (records, dropped, duplicates, outstanding) = {
            let mut state = state.lock().unwrap();
            (
                std::mem::take(&mut state.records),
                state.dropped,
                state.duplicate_retirements,
                state
                    .identities
                    .values()
                    .filter(|identity| !identity.retired)
                    .count(),
            )
        };
        println!("metal_profile_checkpoint events={} dropped={} duplicate_retirements={} outstanding={} clock=mach_absolute_ns event_limit={MAX_EVENTS}", records.len(), dropped, duplicates, outstanding);
        for record in records {
            println!("metal_profile {}", serde_json::to_string(&record).unwrap());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn batches_are_retired_once_and_pointer_reuse_gets_new_identity() {
        let mut state = State::default();
        state.submit(9, "ntt_tile", 8, 100);
        state.retire(9, 1.0, 1.5);
        state.retire(9, 1.0, 1.5);
        assert_eq!(state.records.len(), 1);
        assert_eq!(state.duplicate_retirements, 1);
        assert!(matches!(
            state.records[0],
            Record::Command {
                id: 1,
                dispatches: 8,
                ..
            }
        ));
        state.submit(9, "opening_reduce", 1, 200);
        state.retire(9, 2.0, 2.1);
        assert!(matches!(state.records[1], Record::Command { id: 2, .. }));
    }
    #[test]
    fn dropped_and_invalid_events_are_explicit() {
        let mut state = State::default();
        state.submit(1, "blit", 0, 0);
        state.retire(1, f64::NAN, 0.0);
        assert!(matches!(
            state.records[0],
            Record::Command {
                timestamp_valid: false,
                ..
            }
        ));
        let record = state.records[0].clone();
        state.push(record, 1);
        assert_eq!(state.dropped, 1);
        state.records.clear();
        assert_eq!(state.dropped, 1);
    }
}
