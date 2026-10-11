//! CPU verification metadata through the bounded symbolic implementation.
//! These are graph-storage limits, not a complete verifier/RSS reservation.
use super::*;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    pub recording: usize,
    pub normalization: usize,
    pub packing: usize,
    pub retained: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            recording: 64 << 20,
            normalization: 64 << 20,
            packing: 64 << 20,
            retained: 64 << 20,
        }
    }
}

impl Limits {
    pub(crate) fn validate(self) -> Result<(), CompileError> {
        if [
            self.recording,
            self.normalization,
            self.packing,
            self.retained,
        ]
        .iter()
        .any(|&n| n > 64 << 20)
        {
            return Err(CompileError::Shape(
                "verifier metadata allowance exceeds ceiling",
            ));
        }
        Ok(())
    }

    // Unpacked lookups coexist with recording and normalization of the batch
    // graph. That graph drops before packing coexists with the input lookups.
    pub(crate) fn workspace(self) -> usize {
        (self.recording + 2 * self.normalization).max(self.normalization + self.packing)
    }
}

pub(crate) fn prepare<A: BaseAir<Val> + Air<Builder>>(
    air: &A,
    limits: Limits,
) -> Result<LookupLayout, CompileError> {
    limits.validate()?;
    let constants = Constants::cpu();
    let layout = AirLayout::from_air::<Val>(air);
    let unpacked = {
        let builder = recording::scoped(limits.recording, false, || {
            let mut builder = Builder::new(layout)?;
            air.eval(&mut builder);
            Ok(builder)
        })?;
        let storage = normalize::Storage::limited(limits.normalization, false);
        lookups_from_builder(&builder, constants, &storage)?
    };
    let gadget = LogUpGadget::new();
    let degree = {
        let layout = batch_layout(layout, &unpacked, &gadget)?;
        let builder = recording::scoped(limits.recording, false, || {
            let mut builder = Builder::new(layout)?;
            gadget.eval_air_and_lookups(air, &mut builder, &unpacked);
            Ok(builder)
        })?;
        let storage = normalize::Storage::limited(limits.normalization, false);
        finish_with_storage(&builder, constants, &storage)?.max_degree()
    };
    let degree = if let Some(hint) = air.max_constraint_degree() {
        let hinted = unpacked.iter().try_fold(hint, |degree, lookup| {
            Ok::<_, CompileError>(degree.max(lookup::degree(lookup)?))
        })?;
        if hinted < degree {
            return Err(CompileError::Shape("symbolic degree hint"));
        }
        hinted
    } else {
        degree
    };
    let log_chunks = log_chunks(degree);
    if log_chunks > crate::block_v2::profile::LOG_BLOWUP {
        return Err(CompileError::Shape("symbolic quotient degree"));
    }
    let count = unpacked.len();
    let (lookups, bytes) =
        lookup::pack_limited(unpacked, 1 << log_chunks, limits.packing, limits.retained)?;
    eprintln!("bounded_verifier_metadata unpacked={} packed={} log_chunks={} retained_bytes={} recording_limit_bytes={} normalization_limit_bytes={} packing_limit_bytes={} retained_limit_bytes={} graph_workspace_limit_bytes={}",
        count, lookups.len(), log_chunks, bytes, limits.recording, limits.normalization, limits.packing, limits.retained, limits.workspace());
    Ok(LookupLayout {
        lookups,
        log_chunks,
    })
}

/// Registry identity needs the final ordered constraints as well as lookups.
/// The first recording/normalization and packing phases finish in `prepare`;
/// only its checked retained lookup payload overlaps this final graph pass.
pub(crate) fn prepare_registry(
    air: &super::super::MachineAir,
    limits: Limits,
) -> Result<Prepared, CompileError> {
    let selected = prepare(air, limits)?;
    let gadget = LogUpGadget::new();
    let layout = batch_layout(AirLayout::from_air::<Val>(air), &selected.lookups, &gadget)?;
    let builder = recording::scoped(limits.recording, false, || {
        let mut builder = Builder::new(layout)?;
        gadget.eval_air_and_lookups(air, &mut builder, &selected.lookups);
        Ok(builder)
    })?;
    let storage = normalize::Storage::limited(limits.normalization, false);
    let constraints = finish_with_storage(&builder, Constants::cpu(), &storage)?;
    Ok(Prepared {
        lookups: selected.lookups,
        constraints,
        log_chunks: selected.log_chunks,
    })
}

#[cfg(test)]
mod tests;
