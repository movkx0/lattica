//! Ordered manifest for the currently implemented cryptographic obligations.
//!
//! This is deliberately a crypto-subset manifest, not complete MatRiCT
//! acceptance. New linear/range/transcript relations need their own typed proof
//! adapters before a transaction coordinator can claim complete coverage.
//! ComponentManifest keeps verified records inside one borrowed builder, so a
//! purported verified Wire from another program cannot be replayed as a token.
use crate::rust_verify::constraints_crypto::{CryptoObligations, PendingAes, PendingShake};
use lattica_prover_p3::block_v2::machine::{
    program::{ScopedProgramBuilder, Val, Wire},
    verifier::ProofInputs,
};
use p3_field::PrimeCharacteristicRing;

pub const DOMAIN: u64 = 0x4d4154525f4f4231;
const VERSION: u64 = 1;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error(pub String);
type Result<T> = std::result::Result<T, Error>;
fn err(e: impl std::fmt::Debug) -> Error {
    Error(format!("{e:?}"))
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CryptoShape {
    Shake {
        index: u32,
        input_len: usize,
        output_len: usize,
    },
    Aes {
        index: u32,
        domain: u64,
        start_counter: u32,
        output_len: usize,
    },
    Ntt {
        index: u32,
        modulus: u64,
    },
    Mul {
        index: u32,
        modulus: u64,
    },
}
impl CryptoShape {
    fn tag(&self) -> u64 {
        match self {
            Self::Shake { .. } => 1,
            Self::Aes { .. } => 2,
            Self::Ntt { .. } => 3,
            Self::Mul { .. } => 4,
        }
    }
    fn index(&self) -> u32 {
        match *self {
            Self::Shake { index, .. }
            | Self::Aes { index, .. }
            | Self::Ntt { index, .. }
            | Self::Mul { index, .. } => index,
        }
    }
    fn roots(&self) -> usize {
        if matches!(self, Self::Mul { .. }) {
            3
        } else {
            2
        }
    }
    fn descriptor(&self) -> Result<Vec<u64>> {
        let values = match *self {
            Self::Shake {
                input_len,
                output_len,
                ..
            } => {
                crate::shake_air::Descriptor {
                    input_len,
                    output_len,
                }
                .permutations()
                .map_err(err)?;
                vec![input_len as u64, output_len as u64]
            }
            Self::Aes {
                domain,
                start_counter,
                output_len,
                ..
            } => {
                crate::aes_lane_air::AesLaneAir::new(crate::aes_lane_air::Descriptor {
                    domain,
                    start_counter,
                    output_len,
                })
                .map_err(err)?;
                vec![
                    domain & 0xffff_ffff,
                    domain >> 32,
                    u64::from(start_counter),
                    output_len as u64,
                ]
            }
            Self::Ntt { modulus, .. } | Self::Mul { modulus, .. } => {
                if ![crate::rust_verify::Q, crate::rust_verify::QHAT].contains(&modulus) {
                    return Err(Error("unsupported polynomial modulus".into()));
                }
                vec![modulus]
            }
        };
        if values
            .iter()
            .any(|&x| x >= lattica_prover_p3::block_v2::commitment::MODULUS)
        {
            return Err(Error("noncanonical descriptor field".into()));
        }
        Ok(values)
    }
    fn shake(index: u32, p: &PendingShake) -> Self {
        Self::Shake {
            index,
            input_len: p.input.len(),
            output_len: p.output.len(),
        }
    }
    fn aes(index: u32, p: &PendingAes) -> Self {
        Self::Aes {
            index,
            domain: p.domain,
            start_counter: p.start_counter,
            output_len: p.output.len(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CryptoPlan {
    shapes: Vec<CryptoShape>,
}
impl CryptoPlan {
    /// Canonical family order SHAKE/AES/NTT/Mul, dense zero-based indices.
    /// An arithmetic proof must authenticate this exact complete crypto plan.
    pub fn new(shapes: Vec<CryptoShape>) -> Result<Self> {
        let mut counts = [0_u32; 4];
        let mut last = 0;
        for shape in &shapes {
            shape.descriptor()?;
            let tag = shape.tag();
            let kind = (tag - 1) as usize;
            if tag < last || shape.index() != counts[kind] {
                return Err(Error(
                    "manifest order/index is missing, duplicate or noncanonical".into(),
                ));
            }
            counts[kind] = counts[kind]
                .checked_add(1)
                .ok_or_else(|| Error("manifest index overflow".into()))?;
            last = tag;
        }
        Ok(Self { shapes })
    }
    pub fn shapes(&self) -> &[CryptoShape] {
        &self.shapes
    }
    pub fn len(&self) -> usize {
        self.shapes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.shapes.is_empty()
    }
}
#[derive(Clone, Copy, Debug)]
pub struct ManifestRoot([Wire; 4]);
impl ManifestRoot {
    pub fn wires(self) -> [Wire; 4] {
        self.0
    }
}
fn commit(
    b: &mut ScopedProgramBuilder<'_>,
    plan: &CryptoPlan,
    roots: &[Vec<[Wire; 4]>],
) -> Result<ManifestRoot> {
    if plan.shapes.len() != roots.len() {
        return Err(Error("manifest record count".into()));
    }
    let mut fields = vec![
        b.constant(Val::from_u64(VERSION)),
        b.constant(Val::from_usize(roots.len())),
    ];
    for (ordinal, (shape, record)) in plan.shapes.iter().zip(roots).enumerate() {
        if record.len() != shape.roots() {
            return Err(Error("manifest record root count".into()));
        }
        let descriptor = shape.descriptor()?;
        for value in [
            ordinal as u64,
            shape.tag(),
            u64::from(shape.index()),
            descriptor.len() as u64,
        ] {
            fields.push(b.constant(Val::from_u64(value)));
        }
        fields.extend(
            descriptor
                .into_iter()
                .map(|value| b.constant(Val::from_u64(value))),
        );
        fields.push(b.constant(Val::from_usize(record.len())));
        fields.extend(record.iter().flatten().copied());
    }
    Ok(ManifestRoot(b.hash_fields(DOMAIN, &fields)))
}

/// Computes a commitment from the arithmetic compiler's own pending root
/// wires. It does not discharge those obligations or create a verified leaf.
pub fn arithmetic_crypto_manifest(
    b: &mut ScopedProgramBuilder<'_>,
    pending: &CryptoObligations,
) -> Result<(CryptoPlan, ManifestRoot)> {
    // Deliberately exhaustive: adding an obligation field must force this
    // compiler to add coverage or explicitly reject it, never silently omit it.
    let CryptoObligations {
        fixed_setup_seed: _,
        shake,
        aes,
        ntt,
        mul,
        polynomial_commitments: _,
    } = pending;
    let mut shapes = Vec::new();
    let mut roots = Vec::new();
    for (i, p) in shake.iter().enumerate() {
        shapes.push(CryptoShape::shake(u32::try_from(i).map_err(err)?, p));
        roots.push(vec![p.input_commitment, p.output_commitment]);
    }
    for (i, p) in aes.iter().enumerate() {
        shapes.push(CryptoShape::aes(u32::try_from(i).map_err(err)?, p));
        roots.push(vec![p.input_commitment, p.output_commitment]);
    }
    for (i, p) in ntt.iter().enumerate() {
        shapes.push(CryptoShape::Ntt {
            index: u32::try_from(i).map_err(err)?,
            modulus: p.modulus,
        });
        roots.push(vec![p.input_commitment, p.output_commitment]);
    }
    for (i, p) in mul.iter().enumerate() {
        shapes.push(CryptoShape::Mul {
            index: u32::try_from(i).map_err(err)?,
            modulus: p.modulus,
        });
        roots.push(vec![
            p.left_commitment,
            p.right_commitment,
            p.output_commitment,
        ]);
    }
    let plan = CryptoPlan::new(shapes)?;
    let root = commit(b, &plan, &roots)?;
    Ok((plan, root))
}

/// The expected transaction context comes from a separately constrained and
/// authenticated arithmetic/statement proof in this same builder.
pub struct ContextWires {
    pub profile: [Wire; 8],
    pub context: [Wire; 8],
    pub statement: [Wire; 4],
}
pub struct ComponentManifest<'a, 'scope> {
    b: &'a mut ScopedProgramBuilder<'scope>,
    inputs: &'a mut ProofInputs,
    plan: &'a CryptoPlan,
    records: Vec<Vec<[Wire; 4]>>,
}
impl<'a, 'scope> ComponentManifest<'a, 'scope> {
    pub fn new(
        b: &'a mut ScopedProgramBuilder<'scope>,
        inputs: &'a mut ProofInputs,
        plan: &'a CryptoPlan,
    ) -> Self {
        Self {
            b,
            inputs,
            plan,
            records: Vec::new(),
        }
    }
    fn expect(&self, shapes: &[CryptoShape]) -> Result<()> {
        let start = self.records.len();
        let end = start
            .checked_add(shapes.len())
            .ok_or_else(|| Error("manifest record overflow".into()))?;
        if self.plan.shapes.get(start..end) != Some(shapes) {
            return Err(Error(
                "missing, extra, reordered or substituted component record".into(),
            ));
        }
        Ok(())
    }
    pub fn verify_shake(
        &mut self,
        index: u32,
        request: &PendingShake,
        partition: &crate::shake_air::lane::batch::ShakeBatchPartition,
        proofs: &[crate::shake_air::lane::LaneShakeProof],
    ) -> Result<()> {
        self.expect(&[CryptoShape::shake(index, request)])?;
        crate::shake_air::lane::batch::verify_batched_request(
            self.b,
            self.inputs,
            request,
            partition,
            proofs,
        )
        .map_err(err)?;
        self.records
            .push(vec![request.input_commitment, request.output_commitment]);
        Ok(())
    }
    pub fn verify_aes(
        &mut self,
        index: u32,
        request: &PendingAes,
        partition: &crate::aes_lane_air::join::AesLanePartition,
        proofs: &[crate::aes_lane_air::join::AesLaneSegmentProof],
    ) -> Result<()> {
        self.expect(&[CryptoShape::aes(index, request)])?;
        crate::aes_lane_air::join::verify_request(self.b, self.inputs, request, partition, proofs)
            .map_err(err)?;
        self.records
            .push(vec![request.input_commitment, request.output_commitment]);
        Ok(())
    }
    pub fn verify_ntt_batch(
        &mut self,
        first_index: u32,
        requests: &[&crate::rust_verify::constraints_ntt::PendingNtt],
        registered: &crate::ntt_air::RegisteredNttAir,
        proof: &crate::ntt_air::NttBatchProof,
    ) -> Result<()> {
        if requests.is_empty() {
            return Err(Error("empty NTT manifest batch".into()));
        }
        let shapes = requests
            .iter()
            .enumerate()
            .map(|(i, p)| {
                Ok(CryptoShape::Ntt {
                    index: first_index
                        .checked_add(u32::try_from(i).map_err(err)?)
                        .ok_or_else(|| Error("NTT manifest index overflow".into()))?,
                    modulus: p.modulus,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        self.expect(&shapes)?;
        registered
            .compile_join(self.b, self.inputs, requests, proof)
            .map_err(err)?;
        self.records.extend(
            requests
                .iter()
                .map(|p| vec![p.input_commitment, p.output_commitment]),
        );
        Ok(())
    }
    pub fn verify_mul_batch(
        &mut self,
        first_index: u32,
        requests: &[&crate::rust_verify::constraints_poly::PendingMul],
        registered: &crate::poly_air::RegisteredMulAir,
        proof: &crate::poly_air::MulBatchProof,
    ) -> Result<()> {
        if requests.is_empty() {
            return Err(Error("empty product manifest batch".into()));
        }
        let shapes = requests
            .iter()
            .enumerate()
            .map(|(i, p)| {
                Ok(CryptoShape::Mul {
                    index: first_index
                        .checked_add(u32::try_from(i).map_err(err)?)
                        .ok_or_else(|| Error("product manifest index overflow".into()))?,
                    modulus: p.modulus,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        self.expect(&shapes)?;
        registered
            .compile_join(self.b, self.inputs, requests, proof)
            .map_err(err)?;
        self.records.extend(
            requests
                .iter()
                .map(|p| vec![p.left_commitment, p.right_commitment, p.output_commitment]),
        );
        Ok(())
    }
    pub fn verify_request_tree(
        &mut self,
        key: &crate::component_tree::NodeKey,
        proof: &crate::component_tree::NodeProof,
        context: &ContextWires,
    ) -> Result<()> {
        self.expect(&[key.manifest_shape().map_err(err)?])?;
        let roots = key
            .compile_manifest_record(self.b, self.inputs, proof, context)
            .map_err(err)?;
        self.records.push(roots.to_vec());
        Ok(())
    }
    pub fn finish(self) -> Result<ManifestRoot> {
        if self.records.len() != self.plan.shapes.len() {
            return Err(Error("undischarged component obligations".into()));
        }
        commit(self.b, self.plan, &self.records)
    }
    /// Final equality must use the manifest root authenticated by the arithmetic
    /// proof, not an unconstrained native digest hint.
    pub fn finish_equal(self, expected: [Wire; 4]) -> Result<()> {
        if self.records.len() != self.plan.shapes.len() {
            return Err(Error("undischarged component obligations".into()));
        }
        let actual = commit(self.b, self.plan, &self.records)?;
        for i in 0..4 {
            self.b.assert_equal(actual.0[i], expected[i]);
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests;
