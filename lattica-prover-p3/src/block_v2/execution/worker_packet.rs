//! Bounded local execution packets, not a network/consensus protocol or ABI.
//! Legacy CPU and typed registry families use distinct request/result formats.
//! A decoder never reconstructs a scheduler Assignment or a verification ticket.
//! Launch permission binds the exact packet; the owner independently verifies
//! result bytes against its original Job and current attempt before acceptance.
use super::*;
use crate::block_v2::{
    commitment::{self, Context, CAPACITY, DEPTH},
    execution::launch::{self, Token, WorkerGate},
    profile::MAX_PROOF_BYTES,
    recursive::WrapperConstruction,
};

const REQUEST_MAGIC: &[u8; 8] = b"LVCPUR01";
const RESULT_MAGIC: &[u8; 8] = b"LVCPUS01";
const TYPED_REQUEST_MAGIC: &[u8; 8] = b"LVTYPR01";
const TYPED_RESULT_MAGIC: &[u8; 8] = b"LVTYPS01";
pub const MAX_RESULT_BYTES: usize = MAX_PROOF_BYTES + 256;
const RESULT_HEADER_BYTES: usize = 181;

#[derive(Clone)]
pub(super) struct Child {
    pub(super) job: JobId,
    pub(super) operation: Operation,
    pub(super) start: u8,
    pub(super) expected: NodeSummary,
}
pub(super) struct Request<B = Arc<[u8]>> {
    pub(super) key: [u8; 32],
    pub(super) resources: Resources,
    pub(super) pin: RegistryPin,
    pub(super) job: JobId,
    pub(super) operation: Operation,
    pub(super) start: u8,
    pub(super) expected: NodeSummary,
    pub(super) children: Vec<Child>,
    pub(super) manifest: Vec<ArtifactRef>,
    pub(super) inputs: Vec<B>,
}

// Protocol-owned vectors are admitted before allocation. Capacity, including
// any allocator rounding visible to Vec, must stay within the exact request.
pub(super) fn storage_vec<T>(count: usize, limit: usize) -> Result<Vec<T>, Error> {
    if count > limit {
        return Err("packet storage element bound".into());
    }
    let mut values = Vec::new();
    values.try_reserve_exact(count)?;
    if std::mem::size_of::<T>() != 0 && values.capacity() != count {
        return Err("packet storage capacity differs from admitted count".into());
    }
    Ok(values)
}

/// Observation of a CPU-checked request, not scheduler eligibility/authority.
pub struct RequestInfo {
    pub process_key: [u8; 32],
    pub job: JobId,
    pub resources: Resources,
    pub expected: NodeSummary,
}

fn construction(pin: RegistryPin) -> u8 {
    if pin.is_typed() {
        return 3;
    }
    match pin.construction() {
        WrapperConstruction::SingleWallet => 1,
        WrapperConstruction::GroupedPair => 2,
    }
}
fn operation(code: u8) -> Result<Operation, Error> {
    Operation::from_code(code)
}
fn cpu_resources(value: Resources) -> Result<(), Error> {
    value.validate_legacy_capacity()?;
    if value.vram_bytes != 0 {
        return Err("CPU packet reserves VRAM".into());
    }
    Ok(())
}
fn put_resources(out: &mut Vec<u8>, value: Resources) {
    for v in [value.ram_bytes, value.vram_bytes, value.scratch_bytes] {
        out.extend(v.to_le_bytes());
    }
    out.extend(value.threads.to_le_bytes());
}
fn put_summary(out: &mut Vec<u8>, value: NodeSummary) -> Result<(), Error> {
    commitment::validate_summary(value)?;
    out.extend([value.level, value.count]);
    out.extend(commitment::digest_bytes(value.root)?);
    Ok(())
}
fn put_artifact(out: &mut Vec<u8>, value: ArtifactRef) {
    out.push(match value.kind() {
        ArtifactKind::Wallet => 1,
        ArtifactKind::Node => 2,
    });
    out.extend(value.byte_len().to_le_bytes());
    out.extend(value.digest_bytes());
}
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        let end = self
            .at
            .checked_add(count)
            .ok_or("CPU packet offset overflow")?;
        let bytes = self.bytes.get(self.at..end).ok_or("CPU packet truncated")?;
        self.at = end;
        Ok(bytes)
    }
    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into()?))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into()?))
    }
    fn array(&mut self) -> Result<[u8; 32], Error> {
        Ok(self.take(32)?.try_into()?)
    }
    fn job(&mut self) -> Result<JobId, Error> {
        JobId::from_bytes(self.array()?)
    }
    fn resources(&mut self) -> Result<Resources, Error> {
        let resources = Resources {
            ram_bytes: self.u64()?,
            vram_bytes: self.u64()?,
            scratch_bytes: self.u64()?,
            threads: self.u32()?,
        };
        resources.validate_capacity()?;
        Ok(resources)
    }
    fn summary(&mut self, context: Context) -> Result<NodeSummary, Error> {
        let value = NodeSummary {
            context,
            level: self.byte()?,
            count: self.byte()?,
            root: commitment::digest_from_bytes(self.take(32)?)?,
        };
        commitment::validate_summary(value)?;
        Ok(value)
    }
    fn artifact(&mut self) -> Result<ArtifactRef, Error> {
        let kind = match self.byte()? {
            1 => ArtifactKind::Wallet,
            2 => ArtifactKind::Node,
            _ => return Err("CPU packet artifact kind".into()),
        };
        ArtifactRef::from_descriptor(kind, self.u32()?, self.array()?)
    }
    fn done(&self) -> Result<(), Error> {
        if self.at != self.bytes.len() {
            return Err("CPU packet trailing bytes".into());
        }
        Ok(())
    }
}

fn shape(pin: RegistryPin, op: Operation, start: u8, expected: NodeSummary) -> Result<(), Error> {
    commitment::validate_summary(expected)?;
    if expected.context.profile_id != pin.profile() || expected.level > DEPTH {
        return Err("CPU packet statement profile/level".into());
    }
    let width = 1usize << expected.level;
    if start as usize % width != 0 || start as usize + width > CAPACITY {
        return Err("CPU packet statement range".into());
    }
    let valid = match op {
        Operation::Wrap => {
            !pin.is_typed()
                && pin.construction() == WrapperConstruction::SingleWallet
                && expected.level == 0
                && expected.count == 1
        }
        Operation::WrapPair => {
            !pin.is_typed()
                && pin.construction() == WrapperConstruction::GroupedPair
                && expected.level == 1
                && expected.count == 2
        }
        Operation::Empty => expected.count == 0,
        Operation::Merge => expected.level > 0,
        Operation::TypedPair { mode, padded } => {
            pin.is_typed()
                && crate::block_v2::machine::typed_pairs::leaf_modes(u64::from(mode)).is_ok()
                && expected.level == 1
                && expected.count == if padded { 1 } else { 2 }
        }
        Operation::Finalize => {
            pin.is_typed() && start == 0 && expected.level == DEPTH && expected.count > 0
        }
    };
    if !valid {
        return Err("CPU packet operation/statement shape".into());
    }
    Ok(())
}

impl<B: AsRef<[u8]>> Request<B> {
    pub(super) fn validate(&self) -> Result<(), Error> {
        if self.pin.is_typed() {
            self.resources.validate_capacity()?;
        } else {
            cpu_resources(self.resources)?;
        }
        commitment::digest_from_bytes(&self.key)?;
        shape(self.pin, self.operation, self.start, self.expected)?;
        let (wallets, children) = self.operation.arity();
        if children > 2
            || wallets + children > 2
            || self.children.len() != children
            || self.manifest.len() != wallets + children
            || self.inputs.len() != self.manifest.len()
        {
            return Err("CPU packet input arity".into());
        }
        for (identity, bytes) in self.manifest.iter().zip(&self.inputs) {
            let expected_kind = if children == 0 {
                ArtifactKind::Wallet
            } else {
                ArtifactKind::Node
            };
            if identity.kind() != expected_kind {
                return Err("CPU packet input kind".into());
            }
            identity.check_bytes(bytes.as_ref())?;
        }
        for child in &self.children {
            shape(self.pin, child.operation, child.start, child.expected)?;
            if child.expected.context != self.expected.context {
                return Err("CPU packet child context".into());
            }
        }
        if children == 2 {
            let [left, right] = [&self.children[0], &self.children[1]];
            if left.start != self.start
                || usize::from(left.start) + (1usize << left.expected.level)
                    != usize::from(right.start)
                || commitment::merge_nodes(left.expected, right.expected)? != self.expected
            {
                return Err("CPU packet ordered merge statement".into());
            }
        }
        if self.operation == Operation::Finalize {
            let child = &self.children[0];
            if child.start != 0
                || child.expected.level >= DEPTH
                || child.operation == Operation::Finalize
                || child.expected.count == 0
            {
                return Err("typed packet finalizer child geometry".into());
            }
            let mut expected = child.expected;
            while expected.level < DEPTH {
                expected = commitment::merge_nodes(
                    expected,
                    commitment::empty_subtree(expected.context, expected.level)?,
                )?;
            }
            if expected != self.expected {
                return Err("typed packet finalizer statement".into());
            }
        }
        if matches!(self.operation, Operation::TypedPair { padded: true, .. })
            && self.manifest[0] != self.manifest[1]
        {
            return Err("typed packet padding must repeat its verified wallet".into());
        }
        let mut deps = [self.job; 2];
        for (slot, child) in deps.iter_mut().zip(&self.children) {
            *slot = child.job;
        }
        if JobId::for_summary(
            self.pin,
            self.operation,
            self.start,
            self.expected,
            &deps[..children],
        )? != self.job
        {
            return Err("CPU packet semantic job identity".into());
        }
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        // Fixed header, child descriptors, artifact descriptors, then payloads.
        // validate() bounded all metadata counts and each proof's byte length.
        let mut size = 203 + 68 * self.children.len() + 37 * self.manifest.len();
        for bytes in &self.inputs {
            size = size
                .checked_add(bytes.as_ref().len())
                .ok_or("CPU packet size overflow")?;
        }
        let mut out = storage_vec(size, launch::MAX_REQUEST_BYTES)?;
        out.extend_from_slice(if self.pin.is_typed() {
            TYPED_REQUEST_MAGIC
        } else {
            REQUEST_MAGIC
        });
        out.extend(self.key);
        put_resources(&mut out, self.resources);
        out.extend(self.pin.profile());
        out.push(construction(self.pin));
        out.extend(self.expected.context.chain_id);
        out.extend(self.job.to_bytes());
        out.extend([self.operation.code() as u8, self.start]);
        put_summary(&mut out, self.expected)?;
        out.push(self.children.len() as u8);
        for child in &self.children {
            out.extend(child.job.to_bytes());
            out.extend([child.operation.code() as u8, child.start]);
            put_summary(&mut out, child.expected)?;
        }
        out.push(self.manifest.len() as u8);
        for (identity, bytes) in self.manifest.iter().zip(&self.inputs) {
            put_artifact(&mut out, *identity);
            out.extend_from_slice(bytes.as_ref());
        }
        if out.len() != size || out.capacity() != size {
            return Err("CPU packet encoded size differs from admission".into());
        }
        Ok(out)
    }

    pub(super) fn bind(&self, token: &Token, bytes: &[u8]) -> Result<(), Error> {
        token.check_request(bytes)?;
        if token.key() != self.key || token.resources() != self.resources {
            return Err("CPU packet launch key/resources".into());
        }
        Ok(())
    }
}

impl Request {
    pub(super) fn decode<'a>(
        bytes: &'a [u8],
        pin: RegistryPin,
        chain: [u8; 32],
    ) -> Result<Request<&'a [u8]>, Error> {
        if bytes.len() > launch::MAX_REQUEST_BYTES {
            return Err("CPU packet size".into());
        }
        let mut r = Reader { bytes, at: 0 };
        let magic = if pin.is_typed() {
            TYPED_REQUEST_MAGIC
        } else {
            REQUEST_MAGIC
        };
        if r.take(8)? != magic {
            return Err("CPU packet schema".into());
        }
        let key = r.array()?;
        commitment::digest_from_bytes(&key)?;
        let resources = r.resources()?;
        if r.array()? != pin.profile() || r.byte()? != construction(pin) || r.array()? != chain {
            return Err("CPU packet external profile/construction/chain".into());
        }
        let context = Context {
            profile_id: pin.profile(),
            chain_id: chain,
        };
        let job = r.job()?;
        let operation = operation(r.byte()?)?;
        let start = r.byte()?;
        let expected = r.summary(context)?;
        let count = r.byte()? as usize;
        if count > 2 {
            return Err("CPU packet child count".into());
        }
        let mut children = storage_vec(count, 2)?;
        for _ in 0..count {
            children.push(Child {
                job: r.job()?,
                operation: self::operation(r.byte()?)?,
                start: r.byte()?,
                expected: r.summary(context)?,
            });
        }
        let count = r.byte()? as usize;
        if count > 2 {
            return Err("CPU packet artifact count".into());
        }
        let mut manifest = storage_vec(count, 2)?;
        let mut inputs = storage_vec(count, 2)?;
        for _ in 0..count {
            let identity = r.artifact()?;
            // Proofs borrow the retained packet through validation/execution.
            let bytes = r.take(identity.byte_len() as usize)?;
            identity.check_bytes(bytes)?;
            manifest.push(identity);
            inputs.push(bytes);
        }
        r.done()?;
        let request = Request {
            key,
            resources,
            pin,
            job,
            operation,
            start,
            expected,
            children,
            manifest,
            inputs,
        };
        request.validate()?;
        Ok(request)
    }
}

/// Serialize a frozen scheduler assignment. Only public proof bytes are carried;
/// preprocessing keys come from separately pinned worker configuration.
pub fn encode_request(assignment: &Assignment) -> Result<Vec<u8>, Error> {
    assignment.validate()?;
    let mut children = storage_vec(assignment.dependencies.len(), 2)?;
    for child in &assignment.dependencies {
        children.push(Child {
            job: child.id(),
            operation: child.operation(),
            start: child.start(),
            expected: child.expected(),
        });
    }
    let mut manifest = storage_vec(assignment.manifest.len(), 2)?;
    manifest.extend_from_slice(&assignment.manifest);
    let mut inputs = storage_vec(assignment.inputs.len(), 2)?;
    inputs.extend(assignment.inputs.iter().map(AsRef::as_ref));
    Request {
        key: assignment.lease.process_key()?,
        resources: assignment.resources,
        pin: assignment.job.pin(),
        job: assignment.job.id(),
        operation: assignment.job.operation(),
        start: assignment.job.start(),
        expected: assignment.job.expected(),
        children,
        manifest,
        inputs,
    }
    .encode()
}

impl CpuWorker {
    fn prepare_packet<B: AsRef<[u8]>>(&self, request: &Request<B>) -> Result<Inputs, Error> {
        require_cpu_backend()?;
        request.validate()?;
        if request.pin != self.pin {
            return Err("CPU packet worker registry".into());
        }
        let chain = request.expected.context.chain_id;
        let wallet = |i: usize| -> Result<(VerifiedWallet, WalletProof), Error> {
            let bytes = request.inputs[i].as_ref();
            let ticket = VerifiedWallet::verify(self.pin, &self.registry, chain, bytes)?;
            Ok((ticket, codec::decode(&bytes[WALLET_MAGIC.len()..])?))
        };
        let (derived, inputs) = match request.operation {
            Operation::Wrap => {
                let (ticket, proof) = wallet(0)?;
                (
                    Some(Job::wrap(request.start, ticket)?),
                    Inputs::Wallet(proof),
                )
            }
            Operation::WrapPair => {
                let (left, lp) = wallet(0)?;
                let (right, rp) = wallet(1)?;
                (
                    Some(Job::wrap_pair(request.start, left, right)?),
                    Inputs::Pair([lp, rp]),
                )
            }
            Operation::Empty => (
                Some(Job::empty(
                    self.pin,
                    chain,
                    request.start,
                    request.expected.level,
                )?),
                Inputs::Empty,
            ),
            Operation::Merge => {
                let mut proofs = Vec::with_capacity(2);
                for (child, bytes) in request.children.iter().zip(&request.inputs) {
                    let proof = codec::decode_node(bytes.as_ref())?;
                    self.registry.verify(
                        self.pin.profile(),
                        &proof,
                        &programs::statement(child.expected, child.operation.proof_mode()),
                    )?;
                    proofs.push(proof);
                }
                let right = proofs.pop().unwrap();
                let left = proofs.pop().unwrap();
                (None, Inputs::Merge([left, right]))
            }
            Operation::TypedPair { .. } | Operation::Finalize => {
                return Err("legacy CPU packet rejects typed jobs".into())
            }
        };
        if let Some(job) = derived {
            if job.id() != request.job
                || job.expected() != request.expected
                || job.wallet_inputs() != request.manifest
            {
                return Err("CPU packet reconstructed wallet/empty job".into());
            }
        }
        Ok(inputs)
    }

    fn bound_packet<'a>(
        &self,
        gate: &WorkerGate,
        bytes: &'a [u8],
        chain: [u8; 32],
    ) -> Result<Request<&'a [u8]>, Error> {
        gate.token().check_request(bytes)?;
        let request = Request::decode(bytes, self.pin, chain)?;
        request.bind(gate.token(), bytes)?;
        Ok(request)
    }

    pub(super) fn check_assignment_gate(
        &self,
        gate: &WorkerGate,
        bytes: &[u8],
        chain: [u8; 32],
    ) -> Result<(), Error> {
        self.bound_packet(gate, bytes, chain)?;
        Ok(())
    }

    /// Verify the bounded request while its single-use process guard is held.
    /// This does not prove a new node or authorize owner-side completion.
    pub fn check_packet(
        &self,
        gate: &WorkerGate,
        bytes: &[u8],
        chain: [u8; 32],
    ) -> Result<RequestInfo, Error> {
        let request = self.bound_packet(gate, bytes, chain)?;
        self.prepare_packet(&request)?;
        Ok(RequestInfo {
            process_key: request.key,
            job: request.job,
            resources: request.resources,
            expected: request.expected,
        })
    }

    /// CPU-prove under the caller-held launch guard. The runtime must enforce
    /// physical resources and retain the guard through result publication/exit.
    pub fn execute_packet(
        &mut self,
        gate: &WorkerGate,
        bytes: &[u8],
        chain: [u8; 32],
    ) -> Result<Vec<u8>, Error> {
        let started = Instant::now();
        let request = self.bound_packet(gate, bytes, chain)?;
        crate::block_v2::recursive::storage::admit_startup(request.resources.ram_bytes)?;
        let inputs = self.prepare_packet(&request)?;
        let input_verification_ms = started.elapsed().as_millis();
        let (proof, proving_ms, serialization_ms, stats) = self.prove(
            inputs,
            request.expected,
            request.operation,
            request.resources.ram_bytes,
        )?;
        encode_result(
            request.key,
            request.job,
            launch::request_digest(bytes)?,
            &proof,
            Timings {
                input_verification_ms,
                proving_ms,
                serialization_ms,
            },
            stats,
        )
    }
}

/// Untrusted worker report. These bytes still require independent CPU verification
/// against the owner's original Job, plus current attempt/candidate fencing.
pub struct UnverifiedResult {
    bytes: Vec<u8>,
    timings: Timings,
    stats: CacheStats,
}
impl UnverifiedResult {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
    /// Worker-claimed telemetry, never an admission/stop/acceptance decision.
    pub fn timings(&self) -> Timings {
        self.timings
    }
    pub fn stats(&self) -> CacheStats {
        self.stats
    }
}
fn encode_result(
    key: [u8; 32],
    job: JobId,
    request: [u8; 32],
    proof: &[u8],
    timings: Timings,
    stats: CacheStats,
) -> Result<Vec<u8>, Error> {
    encode_result_for(false, key, job, request, proof, timings, stats)
}

pub(super) fn encode_result_for(
    typed: bool,
    key: [u8; 32],
    job: JobId,
    request: [u8; 32],
    proof: &[u8],
    timings: Timings,
    stats: CacheStats,
) -> Result<Vec<u8>, Error> {
    if proof.is_empty() || proof.len() > MAX_PROOF_BYTES {
        return Err("CPU result proof size".into());
    }
    let size = RESULT_HEADER_BYTES + proof.len();
    let mut bytes = storage_vec(size, MAX_RESULT_BYTES)?;
    bytes.resize(RESULT_HEADER_BYTES, 0);
    bytes.extend_from_slice(proof);
    ResultPacket {
        bytes,
        direct_node: false,
    }
    .finish(typed, key, job, request, timings, stats)
}

// An unfinished packet cannot escape as bytes until its proof identity and
// control header are filled. Node serialization writes directly into its tail.
pub(super) struct ResultPacket {
    bytes: Vec<u8>,
    direct_node: bool,
}

impl ResultPacket {
    pub(super) fn node(node: &NodeProof) -> Result<Self, Error> {
        let size = RESULT_HEADER_BYTES + MAX_PROOF_BYTES;
        let mut bytes = storage_vec(size, MAX_RESULT_BYTES)?;
        bytes.resize(size, 0);
        let proof_len = codec::encode_node_into(node, &mut bytes[RESULT_HEADER_BYTES..])?.len();
        bytes.truncate(RESULT_HEADER_BYTES + proof_len);
        Ok(Self {
            bytes,
            direct_node: true,
        })
    }

    pub(super) fn finish(
        mut self,
        typed: bool,
        key: [u8; 32],
        job: JobId,
        request: [u8; 32],
        timings: Timings,
        stats: CacheStats,
    ) -> Result<Vec<u8>, Error> {
        let proof = &self.bytes[RESULT_HEADER_BYTES..];
        let identity = ArtifactRef::from_bytes(ArtifactKind::Node, proof)?;
        let header = result_header(typed, key, job, request, identity, timings, stats)?;
        self.bytes[..RESULT_HEADER_BYTES].copy_from_slice(&header);
        eprintln!("bounded_result_packet proof_bytes={} packet_bytes={} capacity_bytes={} capacity_limit_bytes={} direct_node={}",
            identity.byte_len(), self.bytes.len(), self.bytes.capacity(), MAX_RESULT_BYTES, self.direct_node);
        Ok(self.bytes)
    }
}

fn result_header(
    typed: bool,
    key: [u8; 32],
    job: JobId,
    request: [u8; 32],
    identity: ArtifactRef,
    timings: Timings,
    stats: CacheStats,
) -> Result<[u8; RESULT_HEADER_BYTES], Error> {
    use std::io::Write;
    let mut header = [0; RESULT_HEADER_BYTES];
    let mut out = std::io::Cursor::new(&mut header[..]);
    out.write_all(if typed {
        TYPED_RESULT_MAGIC
    } else {
        RESULT_MAGIC
    })?;
    out.write_all(&key)?;
    out.write_all(&job.to_bytes())?;
    out.write_all(&request)?;
    for ms in [
        timings.input_verification_ms,
        timings.proving_ms,
        timings.serialization_ms,
    ] {
        out.write_all(&u64::try_from(ms)?.to_le_bytes())?;
    }
    out.write_all(&stats.setups.to_le_bytes())?;
    out.write_all(&stats.hits.to_le_bytes())?;
    out.write_all(&[2])?; // Node artifact.
    out.write_all(&identity.byte_len().to_le_bytes())?;
    out.write_all(&identity.digest_bytes())?;
    if out.position() as usize != RESULT_HEADER_BYTES {
        return Err("CPU result header size".into());
    }
    Ok(header)
}

fn check_assignment_request(assignment: &Assignment, bytes: &[u8]) -> Result<(), Error> {
    assignment.validate()?;
    let job = &assignment.job;
    let request = Request::decode(bytes, job.pin(), job.expected().context.chain_id)?;
    // Compare every canonical field and the exact proof bytes against the
    // original assignment without materializing a second encoded request.
    if request.key != assignment.lease.process_key()?
        || request.resources != assignment.resources
        || request.job != job.id()
        || request.operation != job.operation()
        || request.start != job.start()
        || request.expected != job.expected()
        || request.manifest != assignment.manifest
        || request.children.len() != assignment.dependencies.len()
        || request.inputs.len() != assignment.inputs.len()
        || !request
            .children
            .iter()
            .zip(&assignment.dependencies)
            .all(|(child, job)| {
                child.job == job.id()
                    && child.operation == job.operation()
                    && child.start == job.start()
                    && child.expected == job.expected()
            })
        || !request
            .inputs
            .iter()
            .zip(&assignment.inputs)
            .all(|(a, b)| *a == b.as_ref())
    {
        return Err("CPU result original request binding".into());
    }
    Ok(())
}

/// Bind a report to the exact original assignment and packet, not worker-supplied
/// expected statements. This is bounded decoding, not cryptographic acceptance.
pub fn decode_result(
    assignment: &Assignment,
    request: &[u8],
    bytes: &[u8],
) -> Result<UnverifiedResult, Error> {
    let (range, timings, stats) =
        parse_result(assignment, launch::RequestBinding::Bytes(request), bytes)?;
    let mut proof = storage_vec(range.len(), MAX_PROOF_BYTES)?;
    proof.extend_from_slice(&bytes[range]);
    Ok(UnverifiedResult {
        bytes: proof,
        timings,
        stats,
    })
}

/// Consume an admitted response buffer and compact its proof in place. The
/// containing frame capacity stays charged while the returned proof is live.
pub(super) fn decode_result_owned(
    assignment: &Assignment,
    request: &[u8],
    bytes: Vec<u8>,
) -> Result<UnverifiedResult, Error> {
    decode_result_owned_inner(assignment, launch::RequestBinding::Bytes(request), bytes)
}

/// The original locally owned request supplies its identity, never the worker.
/// Assignment binding and artifact validation remain identical to raw decoding.
pub(super) fn decode_result_prepared_owned(
    assignment: &Assignment,
    request: &launch::PreparedRequest,
    bytes: Vec<u8>,
) -> Result<UnverifiedResult, Error> {
    decode_result_owned_inner(assignment, launch::RequestBinding::Prepared(request), bytes)
}

fn decode_result_owned_inner(
    assignment: &Assignment,
    request: launch::RequestBinding<'_>,
    mut bytes: Vec<u8>,
) -> Result<UnverifiedResult, Error> {
    if bytes.capacity() > MAX_RESULT_BYTES {
        return Err("CPU result owned capacity".into());
    }
    let (range, timings, stats) = parse_result(assignment, request, &bytes)?;
    let proof_len = range.len();
    bytes.copy_within(range, 0);
    bytes.truncate(proof_len);
    eprintln!("reused_result_packet proof_bytes={} capacity_bytes={} capacity_limit_bytes={} new_allocations=0",
        bytes.len(), bytes.capacity(), MAX_RESULT_BYTES);
    Ok(UnverifiedResult {
        bytes,
        timings,
        stats,
    })
}

fn parse_result(
    assignment: &Assignment,
    request: launch::RequestBinding<'_>,
    bytes: &[u8],
) -> Result<(std::ops::Range<usize>, Timings, CacheStats), Error> {
    if bytes.len() > MAX_RESULT_BYTES || request.bytes().len() > launch::MAX_REQUEST_BYTES {
        return Err("CPU result/request size".into());
    }
    check_assignment_request(assignment, request.bytes())?;
    let mut r = Reader { bytes, at: 0 };
    let magic = if assignment.job.pin().is_typed() {
        TYPED_RESULT_MAGIC
    } else {
        RESULT_MAGIC
    };
    if r.take(8)? != magic
        || r.array()? != assignment.lease.process_key()?
        || r.job()? != assignment.job.id()
        || r.array()? != request.digest()?
    {
        return Err("CPU result assignment/request identity".into());
    }
    let timings = Timings {
        input_verification_ms: r.u64()?.into(),
        proving_ms: r.u64()?.into(),
        serialization_ms: r.u64()?.into(),
    };
    let stats = CacheStats {
        setups: r.u64()?,
        hits: r.u64()?,
    };
    let identity = r.artifact()?;
    if identity.kind() != ArtifactKind::Node {
        return Err("CPU result artifact kind".into());
    }
    let start = r.at;
    let proof = r.take(identity.byte_len() as usize)?;
    identity.check_bytes(proof)?;
    r.done()?;
    Ok((start..r.at, timings, stats))
}

#[cfg(test)]
#[path = "worker_packet_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "worker_typed_packet_tests.rs"]
mod typed_tests;
