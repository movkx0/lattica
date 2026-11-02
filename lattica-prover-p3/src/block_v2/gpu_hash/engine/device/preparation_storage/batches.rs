use super::*;

impl DeviceSession {
    // Status is read and checked before any roots are downloaded or published.
    fn batch_roots(&self, use_: &Use<'_>, engine: &mut Engine, count: usize) -> Result<Vec<[u64; 4]>, String> {
        let mut status = [0u64; 64];
        let fence = engine.fence();
        let readback = profile::metric(profile::READBACK);
        use_.buffer(3).read(&mut status[..count]).enq().map_err(|e| e.to_string())?;
        fence.finish()?;
        self.prepared_transfer(engine, 0, (count * 8) as u64);
        if status[..count].iter().any(|s| *s != 0) {
            return Err("GPU commitment batch rejected input".into());
        }
        let mut roots = [0u64; 256];
        let fence = engine.fence();
        use_.buffer(2).read(&mut roots[..count * 4]).enq().map_err(|e| e.to_string())?;
        fence.finish()?;
        drop(readback);
        self.prepared_transfer(engine, 0, (count * 32) as u64);
        if roots[..count * 4].iter().any(|v| *v >= GOLDILOCKS_MODULUS) {
            return Err("GPU commitment batch returned a noncanonical root".into());
        }
        Ok(roots[..count * 4].chunks_exact(4).map(|r| r.try_into().unwrap()).collect())
    }
    pub(crate) fn prepared_node_batch(&self, workspace: &RefCell<Option<Workspace>>, kind: u32,
        modulus: u64, count: usize, packed: &[u64], run: &Run) -> Option<Result<Vec<[u64; 4]>, String>> {
        if !(1..=64).contains(&count) { return Some(Err("invalid node batch count".into())); }
        self.with_prepared(workspace, [packed.len(), 0, count * 4, count], profile::NODE, run, |use_, engine| {
            profile::batch_hashes(count);
            let width = if kind == 2 { 32 } else { 256 };
            if kind > 2 || packed.len() != count * width { return Err("invalid node batch packing".into()); }
            let fence = engine.fence();
            let upload = profile::metric(profile::UPLOAD);
            use_.buffer(0).write(packed).enq().map_err(|e| e.to_string())?;
            drop(upload);
            let setup = profile::metric(profile::KERNEL);
            let kernel = use_.kernel(3);
            kernel.set_arg(1, kind).map_err(|e| e.to_string())?;
            kernel.set_arg(2, modulus).map_err(|e| e.to_string())?;
            kernel.set_arg(3, count as u32).map_err(|e| e.to_string())?;
            drop(setup);
            let mut event = compute::Event::empty();
            // SAFETY: validated count/packing, fixed disjoint root/status
            // prefixes, and unchanged per-node permutation/framing. The fence
            // drains all borrowed transfers before Use scrubs its buffers.
            unsafe { kernel.cmd().global_work_size(count).enew(&mut event).enq().map_err(|e| e.to_string())?; }
            self.prepared_event(engine, run, "pq_operation_commit_node_batch", &event)?;
            self.prepared_transfer(engine, (packed.len() * 8) as u64, 0);
            let roots = self.batch_roots(use_, engine, count)?;
            fence.finish()?;
            Ok(roots)
        })
    }
    pub(crate) fn prepared_field_batch(&self, workspace: &RefCell<Option<Workspace>>, count: usize,
        maximum: usize, packed: &[u64], descriptors: &[u64], run: &Run) -> Option<Result<Vec<[u64; 4]>, String>> {
        if !(1..=64).contains(&count) || descriptors.len() != 6 * count || maximum > packed.len() {
            return Some(Err("invalid field batch geometry".into()));
        }
        self.with_prepared(workspace, [packed.len(), descriptors.len(), count * 4, count], profile::FIELDS, run, |use_, engine| {
            profile::batch_hashes(count);
            let fence = engine.fence();
            let upload = profile::metric(profile::UPLOAD);
            if !packed.is_empty() { use_.buffer(0).write(packed).enq().map_err(|e| e.to_string())?; }
            use_.buffer(1).write(descriptors).enq().map_err(|e| e.to_string())?;
            drop(upload);
            let kernel = use_.kernel(4);
            for begin in (0..maximum.max(1)).step_by(4096) {
                let setup = profile::metric(profile::KERNEL);
                kernel.set_arg(2, count as u32).map_err(|e| e.to_string())?;
                kernel.set_arg(3, begin as u32).map_err(|e| e.to_string())?;
                drop(setup);
                let mut event = compute::Event::empty();
                // SAFETY: descriptors are packed by the checked public API;
                // the kernel also bounds every span. Independent streams use
                // separate state/status and ordered bounded tiles on one queue.
                unsafe { kernel.cmd().global_work_size(count).enew(&mut event).enq().map_err(|e| e.to_string())?; }
                self.prepared_event(engine, run, "pq_operation_commit_fields_batch", &event)?;
            }
            self.prepared_transfer(engine, ((packed.len() + descriptors.len()) * 8) as u64, 0);
            let roots = self.batch_roots(use_, engine, count)?;
            fence.finish()?;
            Ok(roots)
        })
    }
}
