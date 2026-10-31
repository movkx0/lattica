//! Test-only opt-in transfer from construction ceilings to immutable backing.
//!
//! Call only on the returned compiled owner: compiler locals/children and actual
//! phase cleanup have already completed. No runtime path invokes this module.
//! Full construction tokens stay live through scanning and both splits. The
//! same payload receives replacement tokens before any surplus charge retires.

use super::{
    requirement, Bytes, Category, GroupCompilePlan, Ledger, OwnedCompiledShake, Requirements,
    Reservation, Val, HEADER, MAX_ROWS,
};
use core::mem::size_of;
use lattica_prover_p3::block_v2::machine::program::MAX_WIRES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Authority,
    Geometry,
    Overflow,
    Source,
    Capacity,
    ScanAdmission,
    Transfer,
}

/// Fixed-size requested-backing evidence. This is neither RSS nor admission for
/// a future phase. The receipt remains owned and charged beside the payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Receipt {
    pub(super) construction_program_host: u64,
    pub(super) construction_input_host: u64,
    pub(super) source_program_host: u64,
    pub(super) source_input_host: u64,
    pub(super) retained_program_host: u64,
    pub(super) retained_input_host: u64,
    pub(super) scan_scratch_host: u64,
    pub(super) ledger_host_before: u64,
    pub(super) ledger_host_after: u64,
}

/// The original request, program, inputs, report and linear tokens move together.
/// No mutable output, raw program, token extraction or proving API is exposed.
pub(super) struct ExactRetainedShake<'request> {
    output: OwnedCompiledShake<'request>,
    receipt: Receipt,
}

impl ExactRetainedShake<'_> {
    pub(super) fn output(&self) -> &OwnedCompiledShake<'_> {
        &self.output
    }

    pub(super) fn receipt(&self) -> Receipt {
        self.receipt
    }
}

// Program's read-only source scan uses no heap on success. Its checked-error
// paths can create one of these short Strings before returning a fixed error.
const SOURCE_ERROR_BYTES: usize =
    4 * "machine source Arc layout overflow".len() + 2 * size_of::<String>();
const SCAN_SCRATCH_BYTES: usize = SOURCE_ERROR_BYTES
    + 2 * size_of::<Transfer<'static>>()
    + 2 * size_of::<Plan>()
    + 2 * size_of::<Receipt>()
    + 2 * size_of::<crate::execution::retained_resources::Snapshot>()
    + 2 * size_of::<Reservation>();

// Before scan admission, the original compiler charge still includes its plan
// header. It also covers the small rejection/transfer header around this owner.
const _: () = assert!(
    size_of::<Failure<'static>>()
        <= size_of::<OwnedCompiledShake<'static>>() + size_of::<GroupCompilePlan<'static>>()
);

fn scan_requirement() -> Requirements {
    requirement(Category::PhaseScratch, SCAN_SCRATCH_BYTES).expect("fixed scan scratch fits u64")
}

fn input_bytes(public_capacity: usize, witness_capacity: usize) -> Result<u64, Error> {
    public_capacity
        .checked_add(witness_capacity)
        .and_then(|n| n.checked_mul(size_of::<Val>()))
        .and_then(|n| u64::try_from(n).ok())
        .ok_or(Error::Overflow)
}

fn program_bytes(source: usize) -> Result<u64, Error> {
    source
        .checked_add(size_of::<ExactRetainedShake<'static>>())
        .and_then(|n| u64::try_from(n).ok())
        .ok_or(Error::Overflow)
}

fn category_bytes(token: &Reservation, category: Category) -> Result<u64, Error> {
    let requested = token.requirements();
    let bytes = requested.get(category);
    if bytes.device != 0 || requested != Requirements::single(category, bytes) {
        return Err(Error::Authority);
    }
    Ok(bytes.host)
}

fn authority(output: &OwnedCompiledShake<'_>, ledger: &Ledger) -> Result<(), Error> {
    let allowance = ledger.snapshot().allowance;
    if !crate::host_memory_profile::HostMemoryProfile::valid_worker_ceiling(allowance.host)
        || allowance.device != 0
        || !output._program.belongs_to(ledger)
        || !output._inputs.belongs_to(ledger)
        || !output.report.belongs_to(ledger)
    {
        return Err(Error::Authority);
    }
    category_bytes(&output._program, Category::SymbolicCompiler)?;
    category_bytes(&output._inputs, Category::CompilerInputs)?;
    Ok(())
}

struct Plan {
    program: Requirements,
    inputs: Requirements,
    receipt: Receipt,
}

impl Plan {
    fn scan(output: &OwnedCompiledShake<'_>, ledger_host_before: u64) -> Result<Self, Error> {
        let program = &output.compiled.program;
        let summary = output.summary;
        if !(8..=MAX_ROWS).contains(&program.height())
            || !program.height().is_power_of_two()
            || program.wire_count() > MAX_WIRES
            || program.public_values() != HEADER + 8
            || program.height() != summary.padded_rows
            || program.active_rows() != summary.active_rows
            || program.wire_count() != summary.wires
            || program.witness_values() != summary.input_values
            || output.compiled.public.len() != program.public_values()
            || output.compiled.witness.len() != program.witness_values()
            || !(1..=2).contains(&summary.span.segment_count)
            || summary.independent_native_verifications != summary.span.segment_count
        {
            return Err(Error::Geometry);
        }
        let source_program_host = program.retained_host_bytes().map_err(|_| Error::Source)?;
        let source_input_host = input_bytes(
            output.compiled.public.capacity(),
            output.compiled.witness.capacity(),
        )?;
        let retained_program_host = program_bytes(source_program_host)?;
        let construction_program_host =
            category_bytes(&output._program, Category::SymbolicCompiler)?;
        let construction_input_host = category_bytes(&output._inputs, Category::CompilerInputs)?;
        if retained_program_host > construction_program_host
            || source_input_host > construction_input_host
        {
            return Err(Error::Capacity);
        }
        Ok(Self {
            program: Requirements::single(
                Category::SymbolicCompiler,
                Bytes {
                    host: retained_program_host,
                    device: 0,
                },
            ),
            inputs: Requirements::single(
                Category::CompilerInputs,
                Bytes {
                    host: source_input_host,
                    device: 0,
                },
            ),
            receipt: Receipt {
                construction_program_host,
                construction_input_host,
                source_program_host: source_program_host as u64,
                source_input_host,
                retained_program_host,
                retained_input_host: source_input_host,
                scan_scratch_host: SCAN_SCRATCH_BYTES as u64,
                ledger_host_before,
                ledger_host_after: 0,
            },
        })
    }
}

/// Drop order is essential: payload first, then any detached exact tokens,
/// then scan/report scratch. A failed second split cannot release the first
/// split's backing while the original payload remains live.
struct Transfer<'request> {
    output: Option<OwnedCompiledShake<'request>>,
    program: Option<Reservation>,
    inputs: Option<Reservation>,
    scratch: Option<Reservation>,
}

impl<'request> Transfer<'request> {
    fn new(output: OwnedCompiledShake<'request>) -> Self {
        Self {
            output: Some(output),
            program: None,
            inputs: None,
            scratch: None,
        }
    }

    fn split(&mut self, plan: &Plan) -> Result<(), Error> {
        let output = self
            .output
            .as_mut()
            .expect("transfer retains exact payload");
        self.program = Some(
            output
                ._program
                .split(plan.program)
                .map_err(|_| Error::Transfer)?,
        );
        self.inputs = Some(
            output
                ._inputs
                .split(plan.inputs)
                .map_err(|_| Error::Transfer)?,
        );
        Ok(())
    }

    fn finish(mut self, plan: Plan, ledger: &Ledger) -> ExactRetainedShake<'request> {
        let mut output = self.output.take().expect("transfer retains exact payload");
        // Both replacements exist before either original remainder can drop.
        let program_remainder = core::mem::replace(
            &mut output._program,
            self.program.take().expect("exact program split"),
        );
        let input_remainder = core::mem::replace(
            &mut output._inputs,
            self.inputs.take().expect("exact input split"),
        );
        let mut retained = ExactRetainedShake {
            output,
            receipt: plan.receipt,
        };
        drop(program_remainder);
        drop(input_remainder);
        drop(self); // Scan and transient receipt scratch retire last.
        retained.receipt.ledger_host_after = ledger.snapshot().current.host;
        retained
    }
}

pub(super) struct Failure<'request> {
    transfer: Transfer<'request>,
    error: Error,
}

impl Failure<'_> {
    pub(super) fn error(&self) -> Error {
        self.error
    }
}

impl core::fmt::Debug for Failure<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExactRetentionFailure")
            .field("error", &self.error)
            .finish()
    }
}

/// Explicit qualification selection only. Existing constructors and default
/// behavior keep their original conservative construction-ceiling charges.
pub(super) fn retain_exact<'request>(
    output: OwnedCompiledShake<'request>,
    ledger: &Ledger,
) -> Result<ExactRetainedShake<'request>, Failure<'request>> {
    let mut transfer = Transfer::new(output);
    let attempt = (|| {
        let output = transfer
            .output
            .as_ref()
            .expect("transfer retains exact payload");
        authority(output, ledger)?;
        let before = ledger.snapshot().current.host;
        transfer.scratch = Some(
            ledger
                .admit_phase(scan_requirement())
                .map_err(|_| Error::ScanAdmission)?,
        );
        let plan = Plan::scan(output, before)?;
        transfer.split(&plan)?;
        Ok(plan)
    })();
    match attempt {
        Ok(plan) => Ok(transfer.finish(plan, ledger)),
        Err(error) => Err(Failure { transfer, error }),
    }
}

mod tests;
