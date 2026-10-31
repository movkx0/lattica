//! Research wrapper around the unchanged production join-split AIR. It does
//! not alter consensus acceptance and is a different ledger/key construction
//! from MatRiCT. Proofs are fresh CPU proofs, not RingCT/GPU throughput claims.
use crate::{amounts, context_binding, cpu_request, Context, Error, Profile, GOLDILOCKS_MODULUS};
use lattica_prover_p3::joinsplit_air as js;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks as Val;
use serde::Serialize;
use std::time::Instant;

pub use js::Witness;
const MAX_PROOF_BYTES: usize = 64 << 20;
const MAGIC: &[u8; 8] = b"PQNOTE1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Statement {
    pub profile: Profile,
    pub context: Context,
    pub public: Vec<u64>,
}
impl Statement {
    pub fn admit(&self, expected: Context) -> Result<Vec<Val>, Error> {
        if self.profile != Profile::PrivateNoteDirectV1 {
            return Err(Error::Profile);
        }
        if self.context != expected {
            return Err(Error::Context);
        }
        if self.public.len() != js::N_PUBLIC {
            return Err(Error::Geometry);
        }
        if self.public.iter().any(|&x| x >= GOLDILOCKS_MODULUS) {
            return Err(Error::NonCanonical);
        }
        if self.public[js::PI_FEE] != 0 || self.public[js::PI_MINT] != 0 {
            return Err(Error::UnsupportedIssuance);
        }
        if self.public[js::PI_NF..js::PI_NF + 4] == self.public[js::PI_NF + 4..js::PI_NF + 8] {
            return Err(Error::DuplicateSpend);
        }
        let public: Vec<_> = self.public.iter().copied().map(Val::from_u64).collect();
        if public[js::PI_TXBIND..js::PI_TXBIND + 4] != context_binding(self.profile, expected) {
            return Err(Error::Context);
        }
        Ok(public)
    }
}

fn derive(w: &Witness, expected: Context) -> Result<Vec<Val>, Error> {
    if (js::N_IN, js::M_OUT, js::BITS, js::DEPTH) != (2, 2, 52, 32) {
        return Err(Error::Geometry);
    }
    if w.fee != 0 || w.mint != 0 {
        return Err(Error::UnsupportedIssuance);
    }
    if w.tx_binding != context_binding(Profile::PrivateNoteDirectV1, expected) {
        return Err(Error::Context);
    }
    amounts(
        w.inputs.each_ref().map(|i| i.value),
        w.outputs.each_ref().map(|o| o.value),
    )?;
    if w.inputs
        .iter()
        .flat_map(|i| i.nk)
        .any(|x| x >= GOLDILOCKS_MODULUS)
    {
        return Err(Error::NonCanonical);
    }
    let asset = w.inputs[0].asset;
    if w.inputs.iter().any(|i| i.asset != asset) || w.outputs.iter().any(|o| o.asset != asset) {
        return Err(Error::Asset);
    }
    let mut public = vec![Val::ZERO; js::N_PUBLIC];
    for (i, input) in w.inputs.iter().enumerate() {
        let [nk0, nk1] = input.nk.map(Val::from_u64);
        let owner = js::recipient_of(nk0, nk1, input.div);
        let cm = js::commit(
            owner,
            Val::from_u64(input.value),
            input.rho,
            input.rcm,
            input.asset,
        );
        let anchor = js::fold(cm, &input.sib, &input.bits);
        if i == 0 {
            public[js::PI_ANCHOR..js::PI_ANCHOR + 4].copy_from_slice(&anchor);
        } else if public[js::PI_ANCHOR..js::PI_ANCHOR + 4] != anchor {
            return Err(Error::Membership);
        }
        let nf = js::nullifier(nk0, nk1, input.rho, js::pos_of(&input.bits));
        public[js::PI_NF + 4 * i..js::PI_NF + 4 * (i + 1)].copy_from_slice(&nf);
    }
    if public[js::PI_NF..js::PI_NF + 4] == public[js::PI_NF + 4..js::PI_NF + 8] {
        return Err(Error::DuplicateSpend);
    }
    for (i, output) in w.outputs.iter().enumerate() {
        let cm = js::commit(
            output.recipient,
            Val::from_u64(output.value),
            output.rho,
            output.rcm,
            output.asset,
        );
        public[js::PI_OUTCM + 4 * i..js::PI_OUTCM + 4 * (i + 1)].copy_from_slice(&cm);
    }
    public[js::PI_TXBIND..js::PI_TXBIND + 4].copy_from_slice(&w.tx_binding);
    Ok(public)
}

/// Host differential oracle only; verification requires [`verify`].
pub fn check_relation(s: &Statement, w: &Witness, expected: Context) -> Result<(), Error> {
    let public = s.admit(expected)?;
    if derive(w, expected)? != public {
        return Err(Error::Membership);
    }
    Ok(())
}

pub fn statement(w: &Witness, context: Context) -> Result<Statement, Error> {
    Ok(Statement {
        profile: Profile::PrivateNoteDirectV1,
        context,
        public: derive(w, context)?
            .into_iter()
            .map(|v| v.as_canonical_u64())
            .collect(),
    })
}

/// Public deterministic fixture only, retaining the reference depth and range.
pub fn fixture(context: Context) -> Result<(Statement, Witness), Error> {
    let mut w = js::demo_witness();
    // Reference fixture pays a 100-unit fee; this comparison profile has no fee.
    w.outputs[1].value += w.fee;
    w.fee = 0;
    w.tx_binding = context_binding(Profile::PrivateNoteDirectV1, context);
    Ok((statement(&w, context)?, w))
}

#[derive(Clone)]
pub struct Artifact {
    statement: Statement,
    proof: Vec<u8>,
}

impl Artifact {
    pub fn proof_bytes(&self) -> usize {
        self.proof.len()
    }
    pub fn statement(&self) -> &Statement {
        &self.statement
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(48 + 8 * js::N_PUBLIC + self.proof.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.statement.context.0);
        for &v in &self.statement.public {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.extend_from_slice(&(self.proof.len() as u64).to_le_bytes());
        out.extend_from_slice(&self.proof);
        out
    }
    pub fn decode(bytes: &[u8], expected: &Statement, context: Context) -> Result<Self, Error> {
        expected.admit(context)?;
        let head = 48 + 8 * js::N_PUBLIC;
        if bytes.len() < head || bytes.len() > head + MAX_PROOF_BYTES || &bytes[..8] != MAGIC {
            return Err(Error::Geometry);
        }
        let encoded_context = Context(bytes[8..40].try_into().unwrap());
        if encoded_context != context {
            return Err(Error::Context);
        }
        let mut public = Vec::with_capacity(js::N_PUBLIC);
        for chunk in bytes[40..40 + 8 * js::N_PUBLIC].chunks_exact(8) {
            public.push(u64::from_le_bytes(chunk.try_into().unwrap()));
        }
        let count = u64::from_le_bytes(bytes[head - 8..head].try_into().unwrap());
        if count != (bytes.len() - head) as u64 || count == 0 {
            return Err(Error::Geometry);
        }
        let statement = Statement {
            profile: Profile::PrivateNoteDirectV1,
            context,
            public,
        };
        statement.admit(context)?;
        if &statement != expected {
            return Err(Error::ProofRejected);
        }
        Ok(Self {
            statement,
            proof: bytes[head..].to_vec(),
        })
    }
}

#[derive(Debug, Serialize)]
pub struct Measurement {
    pub profile: Profile,
    pub backend: &'static str,
    pub fresh_proof: bool,
    pub input_count: usize,
    pub output_count: usize,
    pub value_bits: usize,
    pub native_proof_count: usize,
    pub recursive_proof_count: usize,
    pub active_rows: Option<usize>,
    pub padded_rows: usize,
    pub proving_including_setup_ns: u128,
    pub cpu_verification_ns: u128,
    pub artifact_roundtrip_ns: u128,
    pub profile_prove_verify_roundtrip_ns: u128,
    pub complete_workflow_ns: Option<u128>,
    pub setup_ns: Option<u128>,
    pub host_peak_bytes: Option<usize>,
    pub gpu_peak_bytes: Option<usize>,
    pub proof_bytes: usize,
    pub matched_ringct_workflow: bool,
    pub security_review: &'static str,
}

/// Fresh proof plus independent CPU verification and artifact round trip. The
/// timer covers this research profile only; no RingCT aggregate is implied.
pub fn prove(
    s: &Statement,
    w: &Witness,
    context: Context,
) -> Result<(Artifact, Measurement), Error> {
    let workflow = Instant::now();
    check_relation(s, w, context)?;
    let start = Instant::now();
    let (proof, _) = js::prove_to_bytes_with_request(w, cpu_request())
        .map_err(|e| Error::Backend(e.to_string()))?;
    let proving_ns = start.elapsed().as_nanos();
    if proof.is_empty() || proof.len() > MAX_PROOF_BYTES {
        return Err(Error::ResourceLimit);
    }
    let artifact = Artifact {
        statement: s.clone(),
        proof,
    };
    let start = Instant::now();
    verify(&artifact, s, context)?;
    let verification_ns = start.elapsed().as_nanos();
    let start = Instant::now();
    let encoded = artifact.encode();
    let restored = Artifact::decode(&encoded, s, context)?;
    verify(&restored, s, context)?;
    let roundtrip_ns = start.elapsed().as_nanos();
    let measurement = Measurement {
        profile: Profile::PrivateNoteDirectV1,
        backend: "cpu_required",
        fresh_proof: true,
        input_count: 2,
        output_count: 2,
        value_bits: 52,
        native_proof_count: 1,
        recursive_proof_count: 0,
        active_rows: Some((2 * (4 + 32) + 2 * 2 + 2 + 2) * 32),
        padded_rows: js::HEIGHT,
        proving_including_setup_ns: proving_ns,
        cpu_verification_ns: verification_ns,
        artifact_roundtrip_ns: roundtrip_ns,
        profile_prove_verify_roundtrip_ns: workflow.elapsed().as_nanos(),
        complete_workflow_ns: None,
        setup_ns: None,
        host_peak_bytes: None,
        gpu_peak_bytes: None,
        proof_bytes: artifact.proof.len(),
        matched_ringct_workflow: false,
        security_review: "required_before_adoption",
    };
    Ok((artifact, measurement))
}

pub fn verify(artifact: &Artifact, expected: &Statement, context: Context) -> Result<(), Error> {
    let public = expected.admit(context)?;
    if &artifact.statement != expected
        || artifact.proof.is_empty()
        || artifact.proof.len() > MAX_PROOF_BYTES
    {
        return Err(Error::ProofRejected);
    }
    if !js::verify_bytes(&artifact.proof, &public) {
        return Err(Error::ProofRejected);
    }
    Ok(())
}
