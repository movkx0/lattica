//! Bounded local CPU-worker packets, not a network/consensus protocol or ABI.
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
pub const MAX_RESULT_BYTES: usize = MAX_PROOF_BYTES + 256;

#[derive(Clone)]
struct Child {
    job: JobId,
    operation: Operation,
    start: u8,
    expected: NodeSummary,
}
struct Request {
    key: [u8; 32],
    resources: Resources,
    pin: RegistryPin,
    job: JobId,
    operation: Operation,
    start: u8,
    expected: NodeSummary,
    children: Vec<Child>,
    manifest: Vec<ArtifactRef>,
    inputs: Vec<Arc<[u8]>>,
}

/// Observation of a CPU-checked request, not scheduler eligibility/authority.
pub struct RequestInfo {
    pub process_key: [u8; 32],
    pub job: JobId,
    pub resources: Resources,
    pub expected: NodeSummary,
}

fn construction(pin: RegistryPin) -> u8 {
    match pin.construction() {
        WrapperConstruction::SingleWallet => 1,
        WrapperConstruction::GroupedPair => 2,
    }
}
fn operation(code: u8) -> Result<Operation, Error> {
    match code {
        1 => Ok(Operation::Wrap),
        2 => Ok(Operation::WrapPair),
        3 => Ok(Operation::Empty),
        4 => Ok(Operation::Merge),
        _ => Err("CPU packet operation".into()),
    }
}
fn cpu_resources(value: Resources) -> Result<(), Error> {
    value.validate_capacity()?;
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
        cpu_resources(resources)?;
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
            pin.construction() == WrapperConstruction::SingleWallet
                && expected.level == 0
                && expected.count == 1
        }
        Operation::WrapPair => {
            pin.construction() == WrapperConstruction::GroupedPair
                && expected.level == 1
                && expected.count == 2
        }
        Operation::Empty => expected.count == 0,
        Operation::Merge => expected.level > 0,
    };
    if !valid {
        return Err("CPU packet operation/statement shape".into());
    }
    Ok(())
}

impl Request {
    fn validate(&self) -> Result<(), Error> {
        cpu_resources(self.resources)?;
        commitment::digest_from_bytes(&self.key)?;
        shape(self.pin, self.operation, self.start, self.expected)?;
        let (wallets, children) = match self.operation {
            Operation::Wrap => (1, 0),
            Operation::WrapPair => (2, 0),
            Operation::Empty => (0, 0),
            Operation::Merge => (0, 2),
        };
        if self.children.len() != children
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
            identity.check_bytes(bytes)?;
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
        let deps: Vec<_> = self.children.iter().map(|c| c.job).collect();
        if JobId::for_summary(self.pin, self.operation, self.start, self.expected, &deps)?
            != self.job
        {
            return Err("CPU packet semantic job identity".into());
        }
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut out = REQUEST_MAGIC.to_vec();
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
            out.extend_from_slice(bytes);
        }
        if out.len() > launch::MAX_REQUEST_BYTES {
            return Err("CPU packet size".into());
        }
        Ok(out)
    }

    fn decode(bytes: &[u8], pin: RegistryPin, chain: [u8; 32]) -> Result<Self, Error> {
        if bytes.len() > launch::MAX_REQUEST_BYTES {
            return Err("CPU packet size".into());
        }
        let mut r = Reader { bytes, at: 0 };
        if r.take(8)? != REQUEST_MAGIC {
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
        let mut children = Vec::with_capacity(count);
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
        let mut manifest = Vec::with_capacity(count);
        let mut inputs = Vec::with_capacity(count);
        for _ in 0..count {
            let identity = r.artifact()?;
            // Bounds and availability are checked before copying proof bytes.
            let bytes = r.take(identity.byte_len() as usize)?;
            identity.check_bytes(bytes)?;
            manifest.push(identity);
            inputs.push(Arc::from(bytes));
        }
        r.done()?;
        let request = Self {
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

    fn bind(&self, token: &Token, bytes: &[u8]) -> Result<(), Error> {
        token.check_request(bytes)?;
        if token.key() != self.key || token.resources() != self.resources {
            return Err("CPU packet launch key/resources".into());
        }
        Ok(())
    }
}

/// Serialize a frozen scheduler assignment. Only public proof bytes are carried;
/// preprocessing keys come from separately pinned worker configuration.
pub fn encode_request(assignment: &Assignment) -> Result<Vec<u8>, Error> {
    assignment.validate()?;
    Request {
        key: assignment.lease.process_key()?,
        resources: assignment.resources,
        pin: assignment.job.pin(),
        job: assignment.job.id(),
        operation: assignment.job.operation(),
        start: assignment.job.start(),
        expected: assignment.job.expected(),
        children: assignment
            .dependencies
            .iter()
            .map(|child| Child {
                job: child.id(),
                operation: child.operation(),
                start: child.start(),
                expected: child.expected(),
            })
            .collect(),
        manifest: assignment.manifest.clone(),
        inputs: assignment.inputs.clone(),
    }
    .encode()
}

impl CpuWorker {
    fn prepare_packet(&self, request: &Request) -> Result<Inputs, Error> {
        require_cpu_backend()?;
        request.validate()?;
        if request.pin != self.pin {
            return Err("CPU packet worker registry".into());
        }
        let chain = request.expected.context.chain_id;
        let wallet = |i: usize| -> Result<(VerifiedWallet, WalletProof), Error> {
            let bytes = &request.inputs[i];
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
                    let proof = codec::decode_node(bytes)?;
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

    fn bound_packet(
        &self,
        gate: &WorkerGate,
        bytes: &[u8],
        chain: [u8; 32],
    ) -> Result<Request, Error> {
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
        let inputs = self.prepare_packet(&request)?;
        let input_verification_ms = started.elapsed().as_millis();
        let (proof, proving_ms, serialization_ms, stats) =
            self.prove(inputs, request.expected, request.operation)?;
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
    let identity = ArtifactRef::from_bytes(ArtifactKind::Node, proof)?;
    let mut out = RESULT_MAGIC.to_vec();
    out.extend(key);
    out.extend(job.to_bytes());
    out.extend(request);
    for ms in [
        timings.input_verification_ms,
        timings.proving_ms,
        timings.serialization_ms,
    ] {
        out.extend(u64::try_from(ms)?.to_le_bytes());
    }
    out.extend(stats.setups.to_le_bytes());
    out.extend(stats.hits.to_le_bytes());
    put_artifact(&mut out, identity);
    out.extend(proof);
    if out.len() > MAX_RESULT_BYTES {
        return Err("CPU result size".into());
    }
    Ok(out)
}

/// Bind a report to the exact original assignment and packet, not worker-supplied
/// expected statements. This is bounded decoding, not cryptographic acceptance.
pub fn decode_result(
    assignment: &Assignment,
    request: &[u8],
    bytes: &[u8],
) -> Result<UnverifiedResult, Error> {
    if bytes.len() > MAX_RESULT_BYTES || request.len() > launch::MAX_REQUEST_BYTES {
        return Err("CPU result/request size".into());
    }
    if encode_request(assignment)?.as_slice() != request {
        return Err("CPU result original request binding".into());
    }
    let mut r = Reader { bytes, at: 0 };
    if r.take(8)? != RESULT_MAGIC
        || r.array()? != assignment.lease.process_key()?
        || r.job()? != assignment.job.id()
        || r.array()? != launch::request_digest(request)?
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
    let proof = r.take(identity.byte_len() as usize)?;
    identity.check_bytes(proof)?;
    r.done()?;
    Ok(UnverifiedResult {
        bytes: proof.to_vec(),
        timings,
        stats,
    })
}

#[cfg(test)]
#[path = "worker_packet_tests.rs"]
mod tests;
