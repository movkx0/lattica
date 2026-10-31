//! Encoded and decoded generated sources keep their original generation claim.
//! No copied numeric receipt, allocation census or source view releases credit.
use crate::{
    execution::retained_resources::{Bytes, Category, Ledger, Requirements, Reservation},
    native::declared_footprint::DeclaredNativeFootprint,
    native_packet::{PROOF_BYTES, STATEMENT_BYTES},
    rust_verify::{committed_backend::source_graph::InitialSourceFootprint, Proof, Statement},
    spend_pipeline::full_workflow::InitialNativeSource,
};
use core::mem::size_of;
use lattica_prover_p3::block_v2::native_gpu::private_spend::PrivateSpendOutput;

type Result<T> = core::result::Result<T, &'static str>;
fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or("generation input census overflow")
}
fn host(category: Category, bytes: usize) -> Result<Requirements> {
    Ok(Requirements::single(category, Bytes {
        host: u64::try_from(bytes).map_err(|_| "generation input census width")?, device: 0,
    }))
}

pub(super) struct InputPlan {
    output: Requirements,
    scratch: Requirements,
}
impl InputPlan {
    pub(super) fn new(native: DeclaredNativeFootprint) -> Result<Self> {
        let source = InitialSourceFootprint::fixed()?;
        // Output keys coexist with encoded output until this owner wipes them.
        // N10 emits exactly two nine-polynomial commitment keys. The private
        // key owner itself lives in PrivateSpendOutput's inline census.
        let keys = 2 * 9 * 256 * size_of::<i64>();
        let encoded = add(STATEMENT_BYTES, PROOF_BYTES)?;
        let payload = add(add(encoded, source.decoded_bytes())?, keys)?;
        let output = host(Category::NativeProof,
            add(payload, 4 * size_of::<FreshNativeInput>() + 4 * size_of::<VerifiedInput>() + 4 * size_of::<PrivateSpendOutput>())?)?;
        let scratch = host(Category::IndependentVerifier,
            add(usize::try_from(native.verifier_bytes()).map_err(|_| "native verifier census width")?,
                add(source.decode_temporary_bytes(),
                    4 * size_of::<GeneratedInputSlot>() + 4 * size_of::<Result<FreshNativeInput>>()
                        + InitialNativeSource::inspection_frame_bytes())?)?)?;
        Ok(Self { output, scratch })
    }
    pub(super) fn output_requirements(&self) -> Requirements { self.output }
    pub(super) fn scratch_requirements(&self) -> Requirements { self.scratch }

    /// Takes both originals before the GPU creates any output. The enclosing
    /// generator preissues all N slots and the shared operation/runtime claims.
    pub(super) fn bind(&self, output: Reservation, scratch: Reservation, ledger: &Ledger)
        -> Result<GeneratedInputSlot>
    {
        if !output.belongs_to(ledger) || !scratch.belongs_to(ledger)
            || output.requirements() != self.output || scratch.requirements() != self.scratch
        {
            return Err("generation input original claim mismatch");
        }
        Ok(GeneratedInputSlot { output, scratch })
    }
}

pub(super) struct GeneratedInputSlot {
    output: Reservation,
    scratch: Reservation,
}
impl GeneratedInputSlot {
    pub(super) fn original(&self) -> &Reservation { &self.output }

    /// Called only by the concrete fresh-generation loop after its GPU method
    /// returns. Actual native verification precedes decode/source construction.
    pub(super) fn finish(&self, output: PrivateSpendOutput, setup_seed: [u8; 32], context: [u8; 32])
        -> Result<VerifiedInput>
    {
        let PrivateSpendOutput { statement: statement_bytes, proof: proof_bytes, output_keys } = output;
        drop(output_keys); // Existing key owner performs its volatile wipe.
        if statement_bytes.len() != STATEMENT_BYTES || statement_bytes.capacity() != STATEMENT_BYTES
            || proof_bytes.len() != PROOF_BYTES || proof_bytes.capacity() != PROOF_BYTES
        {
            return Err("generated native output differs from preissued source geometry");
        }
        if !crate::native::verify(&context, &statement_bytes, &proof_bytes)
            .map_err(|_| "generated native independent verifier failed")?
        {
            return Err("generated native independent verifier rejected");
        }
        let statement = Statement::decode(&statement_bytes).map_err(|_| "generated statement decoding failed")?;
        let proof = Proof::decode(&proof_bytes).map_err(|_| "generated proof decoding failed")?;
        if statement.seed != setup_seed { return Err("generated setup seed mismatch"); }
        let source = InitialNativeSource::new(setup_seed, context,
            &statement_bytes, &proof_bytes, &statement, &proof)?;
        let actual = u64::try_from(source.retained_bytes()).map_err(|_| "generated source width")?;
        if actual > self.output.requirements().get(Category::NativeProof).host {
            return Err("generated retained source exceeds its original claim");
        }
        // Keep the original slot, including verifier scratch, in the generation
        // frame until the caller obtains authenticated runtime retirement.
        Ok(VerifiedInput { statement_bytes, proof_bytes, statement, proof, setup_seed, context })
    }
    pub(super) fn attach_after_retirement(self, payload: VerifiedInput) -> FreshNativeInput {
        drop(self.scratch);
        FreshNativeInput { payload, original: self.output }
    }
}

pub(super) struct VerifiedInput {
    statement_bytes: Vec<u8>,
    proof_bytes: Vec<u8>,
    statement: Statement,
    proof: Proof,
    setup_seed: [u8; 32],
    context: [u8; 32],
}
pub(super) struct FreshNativeInput {
    // Payload destruction precedes the same original reservation's release.
    payload: VerifiedInput,
    original: Reservation,
}
impl FreshNativeInput {
    pub(super) fn view(&self) -> Result<InitialNativeSource<'_>> {
        let value = &self.payload;
        InitialNativeSource::new(value.setup_seed, value.context, &value.statement_bytes,
            &value.proof_bytes, &value.statement, &value.proof)
    }
    pub(super) fn belongs_to(&self, ledger: &Ledger) -> bool { self.original.belongs_to(ledger) }
    pub(super) fn original_requirements(&self) -> Requirements { self.original.requirements() }
}
