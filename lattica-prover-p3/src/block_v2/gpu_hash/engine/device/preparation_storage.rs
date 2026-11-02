//! Private workspace for one serial OperationContext. No cross-scope cache.
//! The full device geometry is checked together before the first allocation.
use super::*;
use super::random::SecretAllocation;
use crate::{block_v2::native_gpu::operations_arithmetic::ArithmeticOperationSpec,
    proving::{Backend, Run, Stage, preparation_profile as profile}};
use std::cell::RefCell;

const COUNTS: [usize; 8] = [1 << 17, 4096, 256, 256, 4096, 4096, 4096, 4096];
pub(crate) const DEVICE_BYTES: usize = (COUNTS[0] + COUNTS[1] + COUNTS[2] + COUNTS[3] + 4 * 4096) * 8;
// Pinned ocl 0.19: five kernels, <=10 argument types each and <=8 memory
// arguments per kernel. Bound every BTree node as an internal 11-entry node,
// with twice (entries+1) nodes, including clone/build overlap. ArgType contains
// only two small enums and bool (64 bytes is deliberately conservative).
const KERNEL_HEAP: usize = 5 * (2 * 9 * (32 + 11 * 32 + 12 * 8) + 3 * 16 * 64);
#[repr(C)]
struct ArcBacking<T> { strong: std::sync::atomic::AtomicUsize, weak: std::sync::atomic::AtomicUsize, value: T }
pub(crate) const HOST_BYTES: usize = 4 * 4096 * 8
    + 8 * (core::mem::size_of::<Workspace>() + KERNEL_HEAP
        + 8 * core::mem::size_of::<ArcBacking<Allocation>>()
        + 8 * core::mem::size_of::<MatrixSpec>() + 4096);

pub(crate) struct Workspace {
    // Drop kernels before the buffers their OpenCL memory arguments retain.
    kernels: Option<[compute::Kernel; 5]>,
    metadata: [Vec<u64>; 4],
    buffers: [SecretAllocation; 8],
    queue: compute::Queue,
    session: Arc<Session>,
}
impl Workspace {
    fn supports(counts: [usize; 4]) -> bool {
        counts.into_iter().zip(COUNTS).all(|(need, capacity)| need <= capacity)
    }
    fn scrub(&self, counts: [usize; 4]) {
        let _cleanup = profile::metric(profile::CLEANUP);
        for (buffer, count) in self.buffers.iter().zip(counts) {
            if count != 0 {
                if let Err(error) = buffer.buffer().cmd().fill(0u64, Some(count)).enq() {
                    super::super::fatal_cleanup("preparation_workspace_scrub", error);
                }
            }
        }
        if let Err(error) = self.queue.finish() {
            super::super::fatal_cleanup("preparation_workspace_scrub_drain", error);
        }
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        drop(self.kernels.take());
        let _cleanup = profile::metric(profile::CLEANUP);
        for buffer in &self.buffers {
            if let Err(error) = buffer.buffer().cmd().fill(0u64, None).enq() {
                super::super::fatal_cleanup("preparation_workspace_final_scrub", error);
            }
        }
        if let Err(error) = self.queue.finish() {
            super::super::fatal_cleanup("preparation_workspace_final_drain", error);
        }
        for buffer in &mut self.buffers { buffer.group_scrubbed(); }
    }
}
struct Use<'a> { workspace: &'a mut Workspace, counts: [usize; 4] }
impl Drop for Use<'_> { fn drop(&mut self) { self.workspace.scrub(self.counts); } }
impl Use<'_> {
    fn buffer(&self, i: usize) -> &compute::Buffer<u64> { self.workspace.buffers[i].buffer() }
    fn kernel(&self, i: usize) -> &compute::Kernel { &self.workspace.kernels.as_ref().unwrap()[i] }
    fn metadata(&mut self, spec: &ArithmeticOperationSpec) -> Result<(usize, bool), String> {
        let slot = match (spec.metadata[0], spec.metadata[1]) {
            (7, 167_770_241) => Some(0), (7, 3_489_661_057) => Some(1),
            (8, 167_770_241) => Some(2), (8, 3_489_661_057) => Some(3), _ => None,
        };
        if let Some(slot) = slot {
            let saved = &mut self.workspace.metadata[slot];
            if saved.is_empty() {
                // Capacity was admitted at scope creation. No replacement or
                // geometric growth can retain a second metadata allocation.
                *saved = spec.metadata.to_vec();
                self.workspace.buffers[4 + slot].buffer().write(saved.as_slice()).enq().map_err(|e| e.to_string())?;
                return Ok((4 + slot, true));
            }
            if saved == &spec.metadata { return Ok((4 + slot, false)); }
        }
        self.buffer(1).write(spec.metadata.as_slice()).enq().map_err(|e| e.to_string())?;
        Ok((1, true))
    }
}

impl DeviceSession {
    pub(crate) fn preparation_workspace(&self) -> Result<Workspace, String> {
        self.with_engine(|engine| {
            let shapes = COUNTS.map(|n| MatrixSpec::new(0, n, Extension::Base, RowOrder::Natural, 1))
                .into_iter().collect::<Result<Vec<_>, _>>()?;
            let _plan = Self::plan(engine, &shapes)?;
            // Partial initialization retains the ordinary scrub-on-drop path.
            let buffers: [SecretAllocation; 8] = COUNTS.into_iter().map(|n| SecretAllocation::new(engine, n))
                .collect::<Result<Vec<_>, _>>()?.try_into().map_err(|_| "workspace buffer count")?;
            let setup = profile::metric(profile::KERNEL);
            let mut node = engine.pq.kernel_builder("pq_operation_commit_node");
            node.arg(buffers[0].buffer()).arg(0u32).arg(167_770_241u64).arg(buffers[2].buffer());
            for constant in &engine.constants { node.arg(&constant.buffer); }
            let node = node.global_work_size(1).build().map_err(|e| e.to_string())?;
            let fields = engine.pq.kernel_builder("pq_operation_commit_fields")
                .arg(buffers[0].buffer()).arg(0u32).arg(0u32).arg(buffers[1].buffer()).arg(buffers[2].buffer())
                .arg(&engine.constants[0].buffer).arg(&engine.constants[1].buffer)
                .arg(&engine.constants[2].buffer).arg(&engine.constants[3].buffer)
                .global_work_size(1).build().map_err(|e| e.to_string())?;
            let arithmetic = engine.pq.kernel_builder("pq_graph_arithmetic")
                .arg(buffers[0].buffer()).arg(buffers[1].buffer()).arg(buffers[2].buffer()).arg(buffers[3].buffer())
                .global_work_size(1).build().map_err(|e| e.to_string())?;
            let node_batch = engine.pq.kernel_builder("pq_operation_commit_node_batch")
                .arg(buffers[0].buffer()).arg(0u32).arg(167_770_241u64).arg(0u32)
                .arg(buffers[2].buffer()).arg(buffers[3].buffer())
                .arg(&engine.constants[0].buffer).arg(&engine.constants[1].buffer)
                .arg(&engine.constants[2].buffer).arg(&engine.constants[3].buffer)
                .global_work_size(1).build().map_err(|e| e.to_string())?;
            let field_batch = engine.pq.kernel_builder("pq_operation_commit_fields_batch")
                .arg(buffers[0].buffer()).arg(buffers[1].buffer()).arg(0u32).arg(0u32)
                .arg(buffers[2].buffer()).arg(buffers[3].buffer())
                .arg(&engine.constants[0].buffer).arg(&engine.constants[1].buffer)
                .arg(&engine.constants[2].buffer).arg(&engine.constants[3].buffer)
                .global_work_size(1).build().map_err(|e| e.to_string())?;
            drop(setup);
            Ok(Workspace { kernels: Some([node, fields, arithmetic, node_batch, field_batch]), metadata: core::array::from_fn(|_| Vec::new()),
                buffers, queue: engine.pq.queue().clone(), session: self.session.clone() })
        })
    }
    fn with_prepared<T>(&self, workspace: &RefCell<Option<Workspace>>, counts: [usize; 4], family: usize,
        run: &Run, operation: impl FnOnce(&mut Use<'_>, &mut Engine) -> Result<T, String>) -> Option<Result<T, String>> {
        let mut owner = match workspace.try_borrow_mut() { Ok(owner) => owner,
            Err(_) => return Some(Err("reentrant raw preparation workspace".into())) };
        let workspace = owner.as_mut()?;
        if !Workspace::supports(counts) { return None; }
        let _operation = profile::operation(family);
        Some(self.with_engine(|engine| {
            run.check_device_stage(Stage::WitnessTrace, Backend::OpenCl).map_err(|e| e.to_string())?;
            if !Arc::ptr_eq(&workspace.session, &self.session) { return Err("foreign preparation workspace".into()); }
            let mut use_ = Use { workspace, counts };
            operation(&mut use_, engine)
        }))
    }
    fn prepared_event(&self, engine: &mut Engine, run: &Run, name: &'static str, event: &compute::Event) -> Result<(), String> {
        let wait = profile::metric(profile::DEVICE_WAIT);
        let ns = self.session.record_event(engine, Stage::WitnessTrace, name, event).map_err(|error| {
            run.observation_failed(); error
        })?;
        drop(wait);
        run.observe_device(Stage::WitnessTrace, Backend::OpenCl, 1, ns).map_err(|e| e.to_string())
    }
    fn prepared_transfer(&self, engine: &mut Engine, upload: u64, download: u64) {
        profile::transfer(upload, download);
        engine.stats.uploaded_bytes += upload; engine.stats.downloaded_bytes += download;
        let mut stats = self.session.stats.lock().unwrap();
        stats.uploaded_bytes += upload; stats.downloaded_bytes += download;
    }
    pub(crate) fn prepared_commit_node(&self, workspace: &RefCell<Option<Workspace>>, kind: u32,
        input: &[u64], modulus: u64, run: &Run) -> Option<Result<[u64; 4], String>> {
        self.with_prepared(workspace, [input.len(), 0, 5, 0], profile::NODE, run, |use_, engine| {
            let expected = match (kind, modulus) { (0, 167_770_241 | 3_489_661_057) | (1, 0) => 256,
                (2, 0) => 32, _ => return Err("raw node commitment kind or modulus".into()) };
            if input.len() != expected { return Err("raw node commitment input width".into()); }
            let mut result = [0u64; 5];
            let fence = engine.fence();
            let upload = profile::metric(profile::UPLOAD);
            use_.buffer(0).write(input).enq().map_err(|e| e.to_string())?;
            drop(upload);
            let setup = profile::metric(profile::KERNEL);
            let kernel = use_.kernel(0);
            kernel.set_arg(1, kind).map_err(|e| e.to_string())?;
            kernel.set_arg(2, modulus).map_err(|e| e.to_string())?;
            drop(setup);
            let mut event = compute::Event::empty();
            // SAFETY: the admitted fixed buffers outlive this drained operation;
            // the original kernel validates kind, residues and signed framing.
            unsafe { kernel.cmd().enew(&mut event).enq().map_err(|e| e.to_string())?; }
            self.prepared_event(engine, run, "pq_operation_commit_node", &event)?;
            let readback = profile::metric(profile::READBACK);
            use_.buffer(2).read(&mut result[..]).enq().map_err(|e| e.to_string())?;
            fence.finish()?; drop(readback);
            self.prepared_transfer(engine, (input.len() * 8) as u64, 40);
            if result[4] != 0 || result[..4].iter().any(|v| *v >= GOLDILOCKS_MODULUS) {
                return Err("GPU node commitment rejected input or noncanonical root".into());
            }
            Ok(result[..4].try_into().unwrap())
        })
    }
    pub(crate) fn prepared_commit_fields(&self, workspace: &RefCell<Option<Workspace>>, initial: [u64; 4],
        words: &[u64], run: &Run) -> Option<Result<[u64; 4], String>> {
        self.with_prepared(workspace, [words.len(), 4, 5, 0], profile::FIELDS, run, |use_, engine| {
            let mut result = [0u64; 5];
            let fence = engine.fence();
            let upload = profile::metric(profile::UPLOAD);
            if !words.is_empty() { use_.buffer(0).write(words).enq().map_err(|e| e.to_string())?; }
            use_.buffer(1).write(&initial[..]).enq().map_err(|e| e.to_string())?;
            drop(upload);
            let kernel = use_.kernel(1);
            for begin in (0..words.len().max(1)).step_by(4096) {
                let setup = profile::metric(profile::KERNEL);
                kernel.set_arg(1, words.len() as u32).map_err(|e| e.to_string())?;
                kernel.set_arg(2, begin as u32).map_err(|e| e.to_string())?;
                drop(setup);
                let mut event = compute::Event::empty();
                // SAFETY: original bounded serial hash kernel and unchanged tile
                // order; fixed state and source buffers remain owned by use_.
                unsafe { kernel.cmd().enew(&mut event).enq().map_err(|e| e.to_string())?; }
                self.prepared_event(engine, run, "pq_operation_commit_fields", &event)?;
            }
            let readback = profile::metric(profile::READBACK);
            use_.buffer(2).read(&mut result[..]).enq().map_err(|e| e.to_string())?;
            fence.finish()?; drop(readback);
            self.prepared_transfer(engine, ((words.len() + 4) * 8) as u64, 40);
            if result[4] != 0 || result[..4].iter().any(|v| *v >= GOLDILOCKS_MODULUS) {
                return Err("GPU field commitment rejected noncanonical input or root".into());
            }
            Ok(result[..4].try_into().unwrap())
        })
    }
    pub(crate) fn prepared_arithmetic(&self, workspace: &RefCell<Option<Workspace>>, spec: &ArithmeticOperationSpec,
        input: &[u64], run: &Run) -> Option<Result<Vec<u64>, String>> {
        self.with_prepared(workspace, [spec.input_words, spec.metadata.len(), spec.output_words, spec.work_items],
            profile::ARITHMETIC, run, |use_, engine| {
            if input.len() != spec.input_words { return Err("raw arithmetic input length mismatch".into()); }
            let mut invalid = [0u64; 256];
            let fence = engine.fence();
            let upload = profile::metric(profile::UPLOAD);
            use_.buffer(0).write(input).enq().map_err(|e| e.to_string())?;
            let (metadata, uploaded_metadata) = use_.metadata(spec)?;
            use_.buffer(3).cmd().fill(0u64, Some(spec.work_items)).enq().map_err(|e| e.to_string())?;
            drop(upload);
            let setup = profile::metric(profile::KERNEL);
            let kernel = use_.kernel(2);
            kernel.set_arg(1, use_.buffer(metadata)).map_err(|e| e.to_string())?;
            drop(setup);
            let mut event = compute::Event::empty();
            // SAFETY: the private ArithmeticOperationSpec admits indices and
            // counts. The kernel and exact status-before-output ordering match
            // the ordinary operation, with checked disjoint workspace prefixes.
            unsafe { kernel.cmd().global_work_size(spec.work_items).enew(&mut event).enq().map_err(|e| e.to_string())?; }
            self.prepared_event(engine, run, "pq_graph_arithmetic", &event)?;
            let readback = profile::metric(profile::READBACK);
            use_.buffer(3).read(&mut invalid[..spec.work_items]).enq().map_err(|e| e.to_string())?;
            fence.finish()?; drop(readback);
            let upload = (input.len() + if uploaded_metadata { spec.metadata.len() } else { 0 }) * 8;
            self.prepared_transfer(engine, upload as u64, (spec.work_items * 8) as u64);
            if let Some((index, code)) = invalid[..spec.work_items].iter().enumerate().find(|(_, value)| **value != 0) {
                return Err(format!("raw arithmetic opcode {} invalid input at work item {index}, status {code}", spec.metadata[0]));
            }
            let mut result = vec![0; spec.output_words];
            let fence = engine.fence();
            let readback = profile::metric(profile::READBACK);
            use_.buffer(2).read(result.as_mut_slice()).enq().map_err(|e| e.to_string())?;
            fence.finish()?; drop(readback);
            self.prepared_transfer(engine, 0, (spec.output_words * 8) as u64);
            Ok(result)
        })
    }
}

mod batches;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn workspace_bounds_cover_all_live_buffers_and_arc_backing() {
        assert_eq!(DEVICE_BYTES, COUNTS.iter().sum::<usize>() * 8);
        assert!(Workspace::supports([1 << 17, 4096, 256, 256]));
        for index in 0..4 {
            let mut counts = [0; 4]; counts[index] = COUNTS[index] + 1;
            assert!(!Workspace::supports(counts));
        }
        assert!(core::mem::size_of::<ArcBacking<Allocation>>() >=
            crate::block_v2::gpu_hash::cache_metadata::arc_bytes::<Allocation>());
        assert!(HOST_BYTES > 4 * 4096 * 8 + 8 * core::mem::size_of::<Workspace>());
    }
}
