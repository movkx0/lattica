//! Internal single-use continuation of the exact prepared note. Every original
//! quota owner follows normalization, private witness/proof, serialization and
//! report retirement. There is no externally reachable dispatch entry; runtime
//! construction/cleanup and the outer packet/verifier owner remain prerequisites.
use super::super::{
    config::NoteConfiguration, selection::NoteSelection, OpeningHostResources,
    PreopeningHostResources,
};
use super::*;
use crate::block_v2::{pcs_field::ProvingConfig, wallet_output};
use crate::config::Challenge;
use crate::gpu_device::bounded;
use crate::proving::{
    note_storage::{NoteReportResources, NoteRun},
    Backend, Report, Stage,
};
use core::mem::size_of;
use p3_uni_stark::StarkGenericConfig;

type Proof = p3_uni_stark::Proof<ProvingConfig<Challenge>>;
type ReportResult = Result<Report, crate::proving::Error>;

// Same native payload ceiling as the research PQNOTE1 decoder. This is a
// preceding output reservation, not a larger cryptographic/workflow parameter.
const ENCODED_PROOF_BYTES: usize = 64 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::block_v2::legacy_wallet::note_admission) struct OperationResources {
    preopening_bytes: usize,
    opening_bytes: usize,
    report_bytes: usize,
    encoded_proof_bytes: usize,
    inline_owner_bytes: usize,
    output_host_allowance: usize,
    required_host_bytes: usize,
}

impl OperationResources {
    pub(in crate::block_v2::legacy_wallet::note_admission) fn new() -> Result<Self, Error> {
        let preopening = PreopeningHostResources::new()?;
        let opening = OpeningHostResources::new()?;
        let report = NoteReportResources::new().map_err(|_| Error::ResourceLimit)?;
        let preopening_bytes = preopening.requested_payload_bytes();
        let opening_bytes = opening.required_host_bytes();
        let report_bytes = report.required_host_bytes;
        let inline_owner_bytes = add(
            size_of::<NoteAttempt<'static>>(),
            size_of::<NoteCompletion<'static>>(),
        )?;
        #[cfg(all(
            feature = "note-gpu-proving-experiment",
            target_os = "linux",
            target_arch = "x86_64"
        ))]
        let inline_owner_bytes = add(
            inline_owner_bytes,
            add(
                size_of::<RetiringPayloads>(),
                add(
                    size_of::<EncodedPayload>(),
                    size_of::<super::super::runtime::OwnedEncodedNote>(),
                )?,
            )?,
        )?;
        let output_host_allowance = add(
            add(preopening_bytes, opening.raw_proof_capacity_ceiling_bytes())?,
            ENCODED_PROOF_BYTES,
        )?;
        let required_host_bytes = add(
            add(add(preopening_bytes, opening_bytes)?, report_bytes)?,
            add(ENCODED_PROOF_BYTES, inline_owner_bytes)?,
        )?;
        Ok(Self {
            preopening_bytes,
            opening_bytes,
            report_bytes,
            encoded_proof_bytes: ENCODED_PROOF_BYTES,
            inline_owner_bytes,
            output_host_allowance,
            required_host_bytes,
        })
    }

    pub(in crate::block_v2::legacy_wallet::note_admission) fn required_host_bytes(self) -> usize {
        self.required_host_bytes
    }

    fn check_reservation(self, token: &Reservation, anchor: &Reservation) -> Result<(), Error> {
        if self != Self::new()?
            || token.reserved_bytes() < self.required_host_bytes
            || !token.same_ledger(anchor)
        {
            return Err(Error::ResourceLimit);
        }
        Ok(())
    }
}

/// Payload fields precede every retained token. The original preparation
/// reservation remains even once its public recording/compiled program has
/// retired. A failure cannot release it before partial report publication.
pub(in crate::block_v2::legacy_wallet::note_admission) struct NoteAttempt<'w> {
    recorded: Option<uni::Prepared>,
    proof: Option<Proof>,
    public: Vec<Val>,
    encoded: Vec<u8>,
    witness: &'w js::Witness,
    expected_public: [Val; 26],
    resources: OperationResources,
    operation_host_allowance: usize,
    run: Option<NoteRun>,
    configuration: NoteConfiguration,
    selection: NoteSelection,
    request: bounded::Request,
    preparation_reservation: Reservation,
    operation_reservation: Reservation,
}

/// Both successful and failed completions retain their owners. Error coverage
/// vectors/report tables drop before the proof/configuration and shared charges.
/// No Clone, owned proof/configuration/encoding extraction or retry exists.
pub(in crate::block_v2::legacy_wallet::note_admission) struct NoteCompletion<'w> {
    report: ReportResult,
    result: Result<(), Error>,
    attempt: NoteAttempt<'w>,
}

/// The original operation reservation moves with its own encoded allocation.
/// The whole charge is retained conservatively, including phases that have
/// finished. No caller can construct this owner or replace its ledger token.
#[cfg(all(
    feature = "note-gpu-proving-experiment",
    target_os = "linux",
    target_arch = "x86_64"
))]
pub(in crate::block_v2::legacy_wallet::note_admission) struct EncodedPayload {
    pub(in crate::block_v2::legacy_wallet::note_admission) encoded: Vec<u8>,
    pub(in crate::block_v2::legacy_wallet::note_admission) public: [Val; 26],
    pub(in crate::block_v2::legacy_wallet::note_admission) proof_scope_ns: u128,
    pub(in crate::block_v2::legacy_wallet::note_admission) reservation: Reservation,
}

#[cfg(all(
    feature = "note-gpu-proving-experiment",
    target_os = "linux",
    target_arch = "x86_64"
))]
type RetiringPayloads = (
    ReportResult,
    Option<uni::Prepared>,
    Option<Proof>,
    Vec<Val>,
    Option<NoteRun>,
    NoteConfiguration,
    NoteSelection,
    Reservation,
);

impl<'w> PreparedNote<'w> {
    /// Existing source-built owners only. The extra token is admitted before
    /// NoteRun construction or public normalization; all owners must share the
    /// original preparation ledger. This method does not initialize a runtime.
    pub(in crate::block_v2::legacy_wallet::note_admission) fn into_attempt(
        self,
        configuration: NoteConfiguration,
        mut selection: NoteSelection,
        request: bounded::Request,
        operation_reservation: Reservation,
    ) -> Result<NoteAttempt<'w>, Error> {
        let resources = OperationResources::new()?;
        resources.check_reservation(&operation_reservation, &self.reservation)?;
        if !selection.same_ledger(&operation_reservation) {
            return Err(Error::ResourceLimit);
        }
        let operation_host_allowance = self.operation_host_allowance()?;
        configuration.checked_config(&self)?;
        selection.recheck(request)?;
        let run = NoteRun::new(resources.report_bytes, selection.policy())
            .map_err(|_| Error::Configuration)?;
        Ok(NoteAttempt {
            recorded: Some(self.prepared),
            proof: None,
            public: Vec::new(),
            encoded: Vec::new(),
            witness: self.witness,
            expected_public: self.expected_public,
            resources,
            operation_host_allowance,
            run: Some(run),
            configuration,
            selection,
            request,
            preparation_reservation: self.reservation,
            operation_reservation,
        })
    }
}

impl<'w> NoteAttempt<'w> {
    fn recheck(&mut self) -> Result<(), Error> {
        self.resources
            .check_reservation(&self.operation_reservation, &self.preparation_reservation)?;
        if !self.selection.same_ledger(&self.operation_reservation) {
            return Err(Error::ResourceLimit);
        }
        self.selection.recheck(self.request)?;
        self.configuration.checked_reserved_config(
            &self.preparation_reservation,
            self.operation_host_allowance,
        )?;
        Ok(())
    }

    fn execute(&mut self) -> Result<(), Error> {
        self.recheck()?;
        let geometry = Geometry::pinned()?;
        let normalized = {
            let configuration = self.configuration.checked_reserved_config(
                &self.preparation_reservation,
                self.operation_host_allowance,
            )?;
            self.recorded
                .take()
                .ok_or(Error::Preparation)?
                .normalize_for_profile(
                    configuration,
                    &js::JoinSplitAir,
                    self.run.as_ref().ok_or(Error::Preparation)?.run(),
                    geometry.quotient_chunks,
                )
                .map_err(|_| Error::Preparation)?
        };
        if normalized.quotient_chunks() != geometry.quotient_chunks
            || normalized.operation_host_allowance() != self.operation_host_allowance
        {
            return Err(Error::Geometry);
        }
        // The actual normalized degree is closed before the first private
        // witness operation. The source and original token remain one owner.
        self.recheck()?;
        let configuration = self.configuration.checked_reserved_config(
            &self.preparation_reservation,
            self.operation_host_allowance,
        )?;
        let session = configuration
            .pcs()
            .quotient_session()
            .map_err(|_| Error::Configuration)?;
        let run = self.run.as_ref().ok_or(Error::Preparation)?.run();
        let frame = session
            .joinsplit_witness(self.witness, self.operation_host_allowance, run)
            .map_err(|_| Error::Preparation)?;
        let downloaded = session.stats().downloaded_bytes;
        let (trace, public) = frame
            .into_proving_parts(&session, self.operation_host_allowance)
            .map_err(|_| Error::Preparation)?;
        let readback = session
            .stats()
            .downloaded_bytes
            .checked_sub(downloaded)
            .ok_or(Error::Preparation)?;
        validate_readback(&public, readback, &self.expected_public)?;
        self.public = public.into_iter().map(Val::from_u64).collect();
        self.recheck()?;
        let configuration = self.configuration.checked_reserved_config(
            &self.preparation_reservation,
            self.operation_host_allowance,
        )?;
        let run = self.run.as_ref().ok_or(Error::Preparation)?.run();
        self.proof = Some(
            uni::prove_normalized(
                configuration,
                &js::JoinSplitAir,
                trace,
                &self.public,
                run,
                normalized,
            )
            .map_err(|_| Error::Preparation)?,
        );
        self.recheck()?;
        let run = self.run.as_ref().ok_or(Error::Preparation)?.run();
        self.encoded = run
            .measure(Stage::Serialization, Backend::Cpu, || {
                wallet_output::serialize(
                    self.proof.as_ref().ok_or(wallet_output::Error::Encoding)?,
                    &[&self.public],
                    &[],
                    self.resources.encoded_proof_bytes,
                    self.resources.output_host_allowance,
                )
            })
            .map_err(|_| Error::Preparation)?
            .map_err(|_| Error::Preparation)?;
        self.recheck()
    }

    /// Single-use private continuation. Public dispatch remains refused. The
    /// caller must first close startup/runtime construction and cleanup under
    /// the same ledger, including A's wrapper census and the trusted reserve.
    pub(in crate::block_v2::legacy_wallet::note_admission) fn prove(
        mut self,
    ) -> NoteCompletion<'w> {
        let result = self.execute();
        // Finish while every owner is still live. During panic unwinding the
        // NoteRun field's Drop publishes failure before these tokens release.
        let report = self
            .run
            .take()
            .expect("private single-use note run")
            .finish(result.is_ok());
        NoteCompletion {
            report,
            result,
            attempt: self,
        }
    }
}

fn validate_readback(public: &[u64], readback: u64, expected: &[Val; 26]) -> Result<(), Error> {
    if public.len() != 26
        || readback != 26 * 8
        || public
            .iter()
            .zip(expected)
            .any(|(&word, expected)| word >= Val::ORDER_U64 || word != expected.as_canonical_u64())
    {
        return Err(Error::Statement);
    }
    Ok(())
}

impl NoteCompletion<'_> {
    #[cfg(all(
        feature = "note-gpu-proving-experiment",
        target_os = "linux",
        target_arch = "x86_64"
    ))]
    pub(in crate::block_v2::legacy_wallet::note_admission) fn into_encoded(
        self,
    ) -> Result<EncodedPayload, Error> {
        self.status()?;
        let proof_scope_ns = self
            .report
            .as_ref()
            .map_err(|_| Error::Preparation)?
            .elapsed_ns;
        let Self {
            report, attempt, ..
        } = self;
        let NoteAttempt {
            recorded,
            proof,
            public,
            encoded,
            expected_public,
            run,
            configuration,
            selection,
            preparation_reservation,
            operation_reservation,
            ..
        } = attempt;
        let retired: RetiringPayloads = (
            report,
            recorded,
            proof,
            public,
            run,
            configuration,
            selection,
            preparation_reservation,
        );
        let output = EncodedPayload {
            encoded,
            public: expected_public,
            proof_scope_ns,
            reservation: operation_reservation,
        };
        // Tuple fields retire in this order, including during unwinding of a
        // field destructor. The encoded output's original operation token is
        // still held in `output`; Engine shutdown belongs to the outer owner.
        drop(retired);
        Ok(output)
    }

    pub(in crate::block_v2::legacy_wallet::note_admission) fn status(&self) -> Result<(), Error> {
        self.result?;
        let report = self.report.as_ref().map_err(|_| Error::Preparation)?;
        if !report.succeeded || !report.stage_coverage_complete || report.completion_rejected {
            return Err(Error::Preparation);
        }
        Ok(())
    }

    pub(in crate::block_v2::legacy_wallet::note_admission) fn encoded(
        &self,
    ) -> Result<&[u8], Error> {
        self.status()?;
        Ok(&self.attempt.encoded)
    }

    pub(in crate::block_v2::legacy_wallet::note_admission) fn public(
        &self,
    ) -> Result<&[Val; 26], Error> {
        self.status()?;
        Ok(&self.attempt.expected_public)
    }

    pub(in crate::block_v2::legacy_wallet::note_admission) fn same_ledger(
        &self,
        token: &Reservation,
    ) -> bool {
        self.attempt.operation_reservation.same_ledger(token)
    }
}

#[cfg(all(test, not(debug_assertions)))]
mod tests;
