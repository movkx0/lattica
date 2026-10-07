//! Bounded entered-span wall-time segments. These are NOT CPU-time samples.
//!
//! Segments are disjoint only within a thread; parallel threads overlap. Gaps,
//! uninstrumented work, and workers which do not enter a span are not attributed.
use super::Key;
use std::{collections::HashMap, thread::ThreadId, time::Instant};

#[derive(Clone, Copy)]
struct Limits {
    threads: usize,
    depth: usize,
    events: usize,
}
const LIMITS: Limits = Limits {
    threads: 128,
    depth: 64,
    events: 65_536,
};

struct Frame {
    id: u64,
    key: Option<Key>,
}
struct Thread {
    index: usize,
    frames: Vec<Frame>,
    overflow: usize,
    since: u64,
}
impl Thread {
    fn key(&self) -> Option<Key> {
        (self.overflow == 0)
            .then(|| self.frames.last().and_then(|f| f.key))
            .flatten()
    }
}

#[derive(Debug)]
pub(super) struct Segment {
    pub thread: usize,
    pub key: Key,
    pub start_ns: u64,
    pub end_ns: u64,
}
pub(super) struct Checkpoint {
    pub elapsed_ns: u64,
    pub threads: usize,
    pub open_frames: usize,
    pub dropped: u64,
    pub malformed: u64,
    pub segments: Vec<Segment>,
}

pub(super) struct Timeline {
    origin: Instant,
    limits: Limits,
    threads: HashMap<ThreadId, Thread>,
    segments: Vec<Segment>,
    // Cumulative: a later checkpoint must not hide earlier missing evidence.
    dropped: u64,
    malformed: u64,
}
impl Default for Timeline {
    fn default() -> Self {
        Self::with_limits(LIMITS)
    }
}
impl Timeline {
    fn with_limits(limits: Limits) -> Self {
        Self {
            origin: Instant::now(),
            limits,
            threads: HashMap::new(),
            segments: Vec::new(),
            dropped: 0,
            malformed: 0,
        }
    }
    fn now(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }
    fn record(&mut self, thread: usize, key: Option<Key>, start: u64, end: u64) {
        if end < start {
            self.malformed = self.malformed.saturating_add(1);
        } else if let Some(key) = key.filter(|_| end > start) {
            if self.segments.len() < self.limits.events {
                self.segments.push(Segment {
                    thread,
                    key,
                    start_ns: start,
                    end_ns: end,
                });
            } else {
                self.dropped = self.dropped.saturating_add(1);
            }
        }
    }
    fn boundary(&mut self, thread: ThreadId, now: u64) {
        if let Some(t) = self.threads.get_mut(&thread) {
            let (index, key, start) = (t.index, t.key(), t.since);
            t.since = now;
            self.record(index, key, start, now);
        }
    }
    pub(super) fn enter(&mut self, id: u64, key: Option<Key>) {
        self.enter_at(std::thread::current().id(), id, key, self.now());
    }
    fn enter_at(&mut self, thread: ThreadId, id: u64, key: Option<Key>, now: u64) {
        if !self.threads.contains_key(&thread) {
            if self.threads.len() == self.limits.threads {
                self.dropped = self.dropped.saturating_add(1);
                return;
            }
            self.threads.insert(
                thread,
                Thread {
                    index: self.threads.len(),
                    frames: Vec::new(),
                    overflow: 0,
                    since: now,
                },
            );
        }
        self.boundary(thread, now);
        let t = self.threads.get_mut(&thread).unwrap();
        if t.frames.len() == self.limits.depth {
            t.overflow = t.overflow.saturating_add(1);
            self.dropped = self.dropped.saturating_add(1);
        } else {
            t.frames.push(Frame { id, key });
        }
    }
    pub(super) fn exit(&mut self, id: u64) {
        self.exit_at(std::thread::current().id(), id, self.now());
    }
    fn exit_at(&mut self, thread: ThreadId, id: u64, now: u64) {
        self.boundary(thread, now);
        let Some(t) = self.threads.get_mut(&thread) else {
            self.dropped = self.dropped.saturating_add(1);
            return;
        };
        if t.overflow != 0 {
            t.overflow -= 1;
        } else if t.frames.last().is_some_and(|f| f.id == id) {
            t.frames.pop();
        } else {
            // Do not attribute subsequent work to a stale/misnested parent.
            t.frames.clear();
            self.malformed = self.malformed.saturating_add(1);
        }
    }
    pub(super) fn checkpoint(&mut self) -> Checkpoint {
        self.checkpoint_at(self.now())
    }
    fn checkpoint_at(&mut self, now: u64) -> Checkpoint {
        let ids: Vec<_> = self.threads.keys().copied().collect();
        for id in ids {
            self.boundary(id, now);
        }
        Checkpoint {
            elapsed_ns: now,
            threads: self.threads.len(),
            open_frames: self
                .threads
                .values()
                .map(|t| t.frames.len().saturating_add(t.overflow))
                .sum(),
            dropped: self.dropped,
            malformed: self.malformed,
            segments: std::mem::take(&mut self.segments),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const PARENT: Key = ("p3_test", "parent");
    const CHILD: Key = ("p3_test", "child");

    #[test]
    fn nested_reentrant_spans_are_disjoint_within_a_thread() {
        let mut t = Timeline::default();
        let id = std::thread::current().id();
        t.enter_at(id, 1, Some(PARENT), 10);
        t.enter_at(id, 2, Some(CHILD), 20);
        t.enter_at(id, 2, Some(CHILD), 30);
        t.exit_at(id, 2, 40);
        t.exit_at(id, 2, 50);
        t.exit_at(id, 1, 60);
        let c = t.checkpoint_at(70);
        assert_eq!((c.open_frames, c.dropped, c.malformed), (0, 0, 0));
        assert_eq!(c.segments.len(), 5);
        assert_eq!(
            c.segments
                .iter()
                .map(|s| s.end_ns - s.start_ns)
                .sum::<u64>(),
            50
        );
        for pair in c.segments.windows(2) {
            assert_eq!(pair[0].end_ns, pair[1].start_ns);
        }
        assert_eq!(c.segments[0].key, PARENT);
        assert_eq!(c.segments[1].key, CHILD);
        assert!(t.checkpoint_at(80).segments.is_empty());
    }

    #[test]
    fn checkpoints_split_open_spans_without_double_counting() {
        let mut t = Timeline::default();
        let id = std::thread::current().id();
        t.enter_at(id, 1, Some(PARENT), 10);
        let first = t.checkpoint_at(20);
        assert_eq!(first.open_frames, 1);
        t.exit_at(id, 1, 30);
        let second = t.checkpoint_at(40);
        assert_eq!(second.open_frames, 0);
        assert_eq!(first.segments[0].end_ns, second.segments[0].start_ns);
    }

    #[test]
    fn missing_metadata_is_a_gap_not_parent_time() {
        let mut t = Timeline::default();
        let id = std::thread::current().id();
        t.enter_at(id, 1, Some(PARENT), 10);
        t.enter_at(id, 2, None, 20);
        t.exit_at(id, 2, 40);
        t.exit_at(id, 1, 50);
        let c = t.checkpoint_at(60);
        assert_eq!(c.segments.len(), 2);
        assert_eq!(c.segments[0].end_ns, 20);
        assert_eq!(c.segments[1].start_ns, 40);
    }

    #[test]
    fn capacity_losses_and_malformed_exits_are_visible_and_bounded() {
        let mut t = Timeline::with_limits(Limits {
            threads: 1,
            depth: 1,
            events: 1,
        });
        let id = std::thread::current().id();
        let other = std::thread::spawn(|| std::thread::current().id())
            .join()
            .unwrap();
        t.enter_at(id, 1, Some(PARENT), 10);
        t.enter_at(id, 2, Some(CHILD), 20);
        t.enter_at(other, 3, Some(CHILD), 25);
        t.exit_at(other, 3, 30);
        t.exit_at(id, 2, 40);
        t.exit_at(id, 999, 50);
        let c = t.checkpoint_at(60);
        assert_eq!(c.threads, 1);
        assert_eq!(c.segments.len(), 1);
        assert_eq!(c.open_frames, 0);
        assert_eq!(c.dropped, 4);
        assert_eq!(c.malformed, 1);
        let later = t.checkpoint_at(70);
        assert_eq!((later.dropped, later.malformed), (4, 1));
    }

    #[test]
    fn the_same_span_can_be_entered_on_two_threads_without_merging_clocks() {
        let mut t = Timeline::default();
        let id = std::thread::current().id();
        let other = std::thread::spawn(|| std::thread::current().id())
            .join()
            .unwrap();
        t.enter_at(id, 1, Some(PARENT), 10);
        t.enter_at(other, 1, Some(PARENT), 15);
        t.exit_at(id, 1, 30);
        t.exit_at(other, 1, 35);
        let c = t.checkpoint_at(40);
        assert_eq!(
            (c.threads, c.open_frames, c.dropped, c.malformed),
            (2, 0, 0, 0)
        );
        assert_ne!(c.segments[0].thread, c.segments[1].thread);
        assert_eq!(
            c.segments
                .iter()
                .map(|s| s.end_ns - s.start_ns)
                .sum::<u64>(),
            40
        );
        // Their sum (40) exceeds the observed wall interval (25), intentionally.
        assert_eq!(c.segments[1].end_ns - c.segments[0].start_ns, 25);
    }
}
