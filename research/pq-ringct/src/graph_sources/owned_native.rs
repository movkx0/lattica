//! Concrete Statement/PrivateProof recording and native production.
//! The returned object is explicitly unverified. The coordinator must retain
//! original runtime/phase claims through actual retirement, then perform the
//! separately admitted independent verifier before recursive consumption.
use super::SourceFactory;
use super::verification_memory::{self, Plan as VerificationPlan, SourceAir, VerificationReceipt};
use crate::{proof_air::ProofAir, statement_air::StatementAir};
use core::mem::size_of;
use lattica_prover_p3::{
    block_v2::{
        gpu_hash::device::ringct_runtime::Runtime,
        native_gpu::{
            graph_source_output::{GraphSourceOutputPlan, OwnedGraphSourceProof},
            graph_source_preparation::{GraphSourceKind, GraphSourcePreparationPlan},
            graph_source_recording::{GraphSourceRecorder, PreparedGraphSource},
            owned_graph_source::{GraphSourceInput, NativeGraphSourcePhase},
        },
        native_graph_source_proof::NativeGraphSourceProof,
    },
    ringct_research_quota::{Ledger, Reservation},
};
use p3_air::{Air, BaseAir};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SourceNativeFailure { Geometry, Preparation, Production, Resource, VerificationBudget }
type Result<T> = core::result::Result<T, SourceNativeFailure>;

/// Pure source metadata. Exact source membership, closure ownership and all
/// original claims remain obligations of the coordinator's source issuer.
pub(crate) struct SourceNativePlan<'factory, 'graph> {
    factory: &'factory SourceFactory<'graph>,
    preparation: GraphSourcePreparationPlan,
    output: GraphSourceOutputPlan,
}

fn source_input<'factory>(factory: &'factory SourceFactory<'_>, kind: GraphSourceKind)
    -> Result<GraphSourceInput<'factory>>
{
    match kind {
        GraphSourceKind::Statement => Ok(GraphSourceInput::Statement {
            bytes: factory.statement.try_into().map_err(|_| SourceNativeFailure::Geometry)?,
            setup_seed: &factory.setup_seed,
        }),
        GraphSourceKind::PrivateProof => Ok(GraphSourceInput::PrivateProof {
            polynomials: factory.private.polynomials.as_slice().try_into()
                .map_err(|_| SourceNativeFailure::Geometry)?,
            alpha: &factory.private.alpha,
        }),
    }
}

fn source_air_geometry(factory: &SourceFactory<'_>, kind: GraphSourceKind)
    -> (usize, usize, usize, Option<usize>)
{
    match kind {
        GraphSourceKind::Statement => {
            let air = StatementAir { setup_seed: factory.setup_seed };
            (air.width(), air.num_public_values(), air.num_periodic_columns(), air.max_constraint_degree())
        }
        GraphSourceKind::PrivateProof => {
            let air = ProofAir;
            (air.width(), air.num_public_values(), air.num_periodic_columns(), air.max_constraint_degree())
        }
    }
}

impl<'factory, 'graph> SourceNativePlan<'factory, 'graph> {
    pub(crate) fn new(factory: &'factory SourceFactory<'graph>, kind: GraphSourceKind) -> Result<Self> {
        let preparation = GraphSourcePreparationPlan::new(kind).map_err(|_| SourceNativeFailure::Resource)?;
        let geometry = preparation.geometry();
        let _ = source_input(factory, kind)?;
        if source_air_geometry(factory, kind)
            != (geometry.width(), geometry.public_values(), geometry.periodic_columns(), None)
            || match kind {
                GraphSourceKind::Statement => crate::statement_air::HEIGHT,
                GraphSourceKind::PrivateProof => crate::proof_air::HEIGHT,
            } != geometry.rows()
        { return Err(SourceNativeFailure::Geometry); }
        let output = GraphSourceOutputPlan::new(preparation).map_err(|_| SourceNativeFailure::Resource)?;
        Ok(Self { factory, preparation, output })
    }

    pub(crate) fn source(&self) -> &'factory SourceFactory<'graph> { self.factory }
    pub(crate) fn preparation(&self) -> GraphSourcePreparationPlan { self.preparation }
    pub(crate) fn output_plan(&self) -> GraphSourceOutputPlan { self.output }

    /// Charge before any plan/recording/production helper is constructed. This
    /// excludes the actual source owner, symbolic graph, core output and phase
    /// payload, which each retain their independent original reservations.
    pub(crate) fn caller_host_bytes() -> Result<usize> {
        [size_of::<Self>(), size_of::<Result<Self>>(),
            size_of::<PreparedSource<'static, 'static, 'static>>(),
            size_of::<Result<PreparedSource<'static, 'static, 'static>>>(),
            size_of::<UnverifiedSourceProof<'static, 'static>>(),
            size_of::<Result<UnverifiedSourceProof<'static, 'static>>>(),
            size_of::<StatementAir>(), size_of::<ProofAir>(), size_of::<SourceAir>(),
            size_of::<VerificationPlan>(), size_of::<VerificationReceipt>(),
            size_of::<VerifiedSourceProof<'static, 'static>>(),
            size_of::<VerificationOutcome<'static, 'static>>(),
            size_of::<SourceVerificationFailure>(),
            size_of::<GraphSourceInput<'static>>(), size_of::<GraphSourceOutputPlan>(),
            size_of::<GraphSourcePreparationPlan>(), size_of::<[usize; 8]>()]
            .into_iter().try_fold(VerificationPlan::retaining_original_caller_host_bytes()
                .map_err(|_| SourceNativeFailure::Resource)?, |sum, part|
                part.checked_mul(8).and_then(|part| sum.checked_add(part))
                    .ok_or(SourceNativeFailure::Resource))
    }

    pub(crate) fn record<'claim>(&self, original: &'claim mut Reservation, ledger: &'claim Ledger)
        -> Result<PreparedSource<'factory, 'graph, 'claim>>
    {
        let mut recorder = GraphSourceRecorder::begin(self.preparation, original, ledger)
            .map_err(|_| SourceNativeFailure::Preparation)?;
        match self.preparation.geometry().kind() {
            GraphSourceKind::Statement =>
                StatementAir { setup_seed: self.factory.setup_seed }.eval(recorder.builder_mut()),
            GraphSourceKind::PrivateProof => ProofAir.eval(recorder.builder_mut()),
        }
        let recorded = recorder.finish().map_err(|_| SourceNativeFailure::Preparation)?;
        let air = SourceAir::new(self.preparation.geometry().kind(), self.factory.setup_seed);
        let verification = VerificationPlan::for_recorded(&air, recorded.symbolic_replay_census())
            .map_err(|_| SourceNativeFailure::VerificationBudget)?;
        Ok(PreparedSource { factory: self.factory, recorded, verification })
    }
}

/// The original preparation token stays exclusively borrowed until the fixed
/// core producer consumes the exact recording. No arbitrary AIR callback exists.
pub(crate) struct PreparedSource<'factory, 'graph, 'claim> {
    factory: &'factory SourceFactory<'graph>,
    recorded: PreparedGraphSource<'claim>,
    verification: VerificationPlan,
}

impl<'factory, 'graph> PreparedSource<'factory, 'graph, '_> {
    pub(crate) fn source(&self) -> &'factory SourceFactory<'graph> { self.factory }
    pub(crate) fn preparation(&self) -> GraphSourcePreparationPlan { self.recorded.census() }
    pub(crate) fn recorded(&self) -> &PreparedGraphSource<'_> { &self.recorded }
    pub(crate) fn verification_plan(&self) -> VerificationPlan { self.verification }

    /// # Safety
    /// The closed whole-workflow issuer established all original claims before
    /// proof0 and retains the immutable process/selection guard and exact phase
    /// through actual retirement of this Runtime. No retry/fallback is allowed.
    pub(crate) unsafe fn produce(self, phase: &mut NativeGraphSourcePhase,
        runtime: &Runtime, runtime_owner: &Reservation, verifier: &Reservation)
        -> Result<UnverifiedSourceProof<'factory, 'graph>>
    {
        let kind = self.recorded.census().geometry().kind();
        let input = source_input(self.factory, kind)?;
        // SAFETY: the caller's closed original-owner contract is forwarded.
        let owned = unsafe { phase.produce(self.recorded, input, runtime, runtime_owner, verifier) }
            .map_err(|_| SourceNativeFailure::Production)?;
        Ok(UnverifiedSourceProof { factory: self.factory, owned, verification: self.verification })
    }
}

/// This object makes no independent-verification claim. Its original output
/// claims remain attached through all moves; only read-only borrows are exposed.
pub(crate) struct UnverifiedSourceProof<'factory, 'graph> {
    factory: &'factory SourceFactory<'graph>,
    owned: OwnedGraphSourceProof,
    verification: VerificationPlan,
}

impl<'factory, 'graph> UnverifiedSourceProof<'factory, 'graph> {
    pub(crate) fn source(&self) -> &'factory SourceFactory<'graph> { self.factory }
    pub(crate) fn artifact(&self) -> &NativeGraphSourceProof { self.owned.artifact() }
    pub(crate) fn owned(&self) -> &OwnedGraphSourceProof { &self.owned }
    pub(crate) fn belongs_to(&self, ledger: &Ledger) -> bool { self.owned.belongs_to(ledger) }
    pub(crate) fn into_originals(self) -> (Reservation, Reservation) { self.owned.into_originals() }

    fn verify_borrowed_preserving(&self, original: Reservation, ledger: &Ledger)
        -> core::result::Result<(VerificationReceipt, Reservation), (SourceVerificationFailure, Reservation)>
    {
        let artifact = self.owned.artifact();
        let correct_public = match artifact {
            NativeGraphSourceProof::Statement(proof) => proof.public_values == self.factory.expected_statement,
            NativeGraphSourceProof::PrivateProof(proof) => proof.public_values == self.factory.expected_private,
        };
        if !self.owned.belongs_to(ledger) || !correct_public {
            return Err((SourceVerificationFailure::Source, original));
        }
        let air = SourceAir::new(self.owned.geometry().kind(), self.factory.setup_seed);
        let admission = match self.verification.admit_pre_reserved_preserving(
            &air, artifact.proof(), artifact.public_values(), self.owned.proof_reservation(),
            original, ledger,
        ) {
            Ok(admission) => admission,
            Err((error, original)) => return Err((SourceVerificationFailure::Admission(error), original)),
        };
        admission.verify_retaining_original()
            .map_err(|(error, original)| (SourceVerificationFailure::Proof(error), original))
    }

    /// Numerical verification only. The enclosing closed lifecycle driver must
    /// retire this proof's actual Runtime before this call; this return value
    /// is not a cleanup receipt or an authority to dispatch another operation.
    /// Every branch returns the exact original verifier and source-proof owners.
    pub(crate) fn verify_retaining(self, original: Reservation, ledger: &Ledger)
        -> VerificationOutcome<'factory, 'graph>
    {
        match self.verify_borrowed_preserving(original, ledger) {
            Ok((receipt, original)) => Ok((VerifiedSourceProof { original: self, receipt }, original)),
            Err((failure, original)) => Err((failure, self, original)),
        }
    }
}

#[derive(Debug)]
pub(crate) enum SourceVerificationFailure {
    Source,
    Admission(&'static str),
    Proof(verification_memory::VerificationFailure),
}
type VerificationOutcome<'factory, 'graph> = core::result::Result<
    (VerifiedSourceProof<'factory, 'graph>, Reservation),
    (SourceVerificationFailure, UnverifiedSourceProof<'factory, 'graph>, Reservation),
>;

/// Cryptographic verification of the exact retained native source. Original
/// source/proof claims remain inseparable; graph/final closure is still separate.
pub(crate) struct VerifiedSourceProof<'factory, 'graph> {
    original: UnverifiedSourceProof<'factory, 'graph>,
    receipt: VerificationReceipt,
}
impl<'factory, 'graph> VerifiedSourceProof<'factory, 'graph> {
    pub(crate) fn source(&self) -> &'factory SourceFactory<'graph> { self.original.source() }
    pub(crate) fn artifact(&self) -> &NativeGraphSourceProof { self.original.artifact() }
    pub(crate) fn owned(&self) -> &OwnedGraphSourceProof { self.original.owned() }
    pub(crate) fn receipt(&self) -> &VerificationReceipt { &self.receipt }
    pub(crate) fn into_originals(self) -> (Reservation, Reservation) { self.original.into_originals() }
}
