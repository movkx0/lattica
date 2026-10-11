//! Pre-allocation allowance for the recorder's own storage, including dropped
//! intermediates and simultaneous growth arrays. Caller/AIR-owned allocations
//! and normalization have separate lifetimes. This is not a physical RSS bound.
use super::{CompileError, MAX_NODES};
use std::{cell::RefCell, mem::size_of, sync::Arc};

pub(super) const HOST_BYTES: usize = 64 << 20;
pub(super) const MAX_DEPTH: usize = 512;
const _: () = assert!(HOST_BYTES as u64 <= super::HOST_BYTES);

#[derive(Clone, Copy)]
struct State {
    limit: usize,
    bytes: usize,
    allocations: usize,
    arc_nodes: usize,
    depth: usize,
    failed: bool,
}

thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
}

pub(super) fn error() -> CompileError {
    CompileError::Shape("symbolic recording allowance")
}

pub(super) fn reject() -> bool {
    STATE.with(|state| {
        if let Some(state) = &mut *state.borrow_mut() {
            state.failed = true;
        }
    });
    false
}

pub(super) fn check() -> Result<(), CompileError> {
    if STATE.with(|state| state.borrow().as_ref().is_some_and(|s| s.failed)) {
        Err(error())
    } else {
        Ok(())
    }
}

fn reserve(bytes: usize, allocations: usize) -> bool {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        let Some(state) = state.as_mut() else {
            return true;
        };
        if state.failed {
            return false;
        }
        let Some(total) = state.bytes.checked_add(bytes).filter(|n| *n <= state.limit) else {
            state.failed = true;
            return false;
        };
        state.bytes = total;
        state.allocations += allocations;
        true
    })
}

pub(super) fn expression<T>(arcs: usize, depth: usize) -> bool {
    let active = STATE.with(|state| {
        let mut state = state.borrow_mut();
        let Some(state) = state.as_mut() else {
            return false;
        };
        if depth > MAX_DEPTH {
            state.failed = true;
        }
        state.depth = state.depth.max(depth);
        true
    });
    if !active {
        return true;
    } // Compatibility/test construction outside recording.
      // Arc's two counters and padding are covered conservatively; allocator
      // bookkeeping remains part of the enclosing process allowance.
    let Some(bytes) = size_of::<T>()
        .checked_add(4 * size_of::<usize>())
        .and_then(|n| n.checked_mul(arcs))
    else {
        return reject();
    };
    if !reserve(bytes, arcs) {
        return false;
    }
    STATE.with(|state| state.borrow_mut().as_mut().unwrap().arc_nodes += arcs);
    true
}

pub(super) fn vector<T>(
    count: usize,
    mut value: impl FnMut(usize) -> T,
) -> Result<Vec<T>, CompileError> {
    let bytes = count
        .checked_mul(size_of::<T>())
        .filter(|_| count <= MAX_NODES)
        .ok_or_else(|| {
            reject();
            error()
        })?;
    if !reserve(bytes, usize::from(count != 0)) {
        return Err(error());
    }
    let mut values = Vec::new();
    values.try_reserve_exact(count).map_err(|_| {
        reject();
        error()
    })?;
    if values.capacity() != count {
        reject();
        return Err(error());
    }
    for i in 0..count {
        values.push(value(i));
        check()?;
    }
    Ok(values)
}

pub(super) fn push<T>(values: &mut Vec<T>, value: T) -> Result<(), CompileError> {
    if check().is_err() || values.len() >= MAX_NODES {
        reject();
        return Err(error());
    }
    if values.len() == values.capacity() {
        let Some(count) = values
            .capacity()
            .checked_mul(2)
            .map(|n| n.max(4).min(MAX_NODES))
        else {
            reject();
            return Err(error());
        };
        let Some(bytes) = count.checked_mul(size_of::<T>()) else {
            reject();
            return Err(error());
        };
        if !reserve(bytes, 1) {
            return Err(error());
        }
        let mut next = Vec::new();
        if next.try_reserve_exact(count).is_err() || next.capacity() != count {
            reject();
            return Err(error());
        }
        next.append(values);
        *values = next;
    }
    values.push(value);
    Ok(())
}

pub(super) fn collect<T>(values: impl IntoIterator<Item = T>) -> Result<Vec<T>, CompileError> {
    check()?;
    let mut result = Vec::new();
    for value in values {
        push(&mut result, value)?;
    }
    Ok(result)
}

pub(super) fn shared<T>(values: Vec<T>) -> Result<Arc<Vec<T>>, CompileError> {
    if !reserve(size_of::<Vec<T>>() + 4 * size_of::<usize>(), 1) {
        return Err(error());
    }
    Ok(Arc::new(values))
}

pub(super) fn string(value: &str) -> Result<String, CompileError> {
    if value.len() > MAX_NODES || !reserve(value.len(), usize::from(!value.is_empty())) {
        reject();
        return Err(error());
    }
    let mut result = String::new();
    result.try_reserve_exact(value.len()).map_err(|_| {
        reject();
        error()
    })?;
    if result.capacity() != value.len() {
        reject();
        return Err(error());
    }
    result.push_str(value);
    Ok(result)
}

struct Scope {
    report: bool,
}
impl Drop for Scope {
    fn drop(&mut self) {
        let state = STATE.with(|state| state.borrow_mut().take()).unwrap();
        if self.report {
            eprintln!("bounded_symbolic_recording admitted_bytes={} allocations={} arc_nodes={} max_depth={} limit_bytes={} rejected={} unwinding={}",
                state.bytes, state.allocations, state.arc_nodes, state.depth, state.limit,
                state.failed, std::thread::panicking());
        }
    }
}

pub(super) fn scoped<T>(
    limit: usize,
    report: bool,
    body: impl FnOnce() -> Result<T, CompileError>,
) -> Result<T, CompileError> {
    if STATE.with(|state| state.borrow().is_some()) {
        reject();
        return Err(error());
    }
    STATE.with(|state| {
        *state.borrow_mut() = Some(State {
            limit,
            bytes: 0,
            allocations: 0,
            arc_nodes: 0,
            depth: 0,
            failed: false,
        })
    });
    let scope = Scope { report };
    let result = body();
    let admitted = check();
    drop(scope);
    admitted?;
    result
}

pub(super) fn run<T>(
    report: bool,
    body: impl FnOnce() -> Result<T, CompileError>,
) -> Result<T, CompileError> {
    scoped(HOST_BYTES, report, body)
}

#[cfg(test)]
mod tests;
