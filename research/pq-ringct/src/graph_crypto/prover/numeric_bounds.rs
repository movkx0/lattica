//! Resolve only descriptor lookups on the coordinator before numeric workers
//! begin. Topology and hash calculation remain in the ordinary numeric planner.
use crate::component_tree::paired_runtime::{source, ComponentSourceFacts, PairedFailure};
use crate::execution::retained_resources::{Ledger, Reservation};
use crate::graph_crypto::{Request, RequestDescriptor, ShakeWrapperLayout};

pub(crate) fn warm_request_bounds(request: &Request, layout: ShakeWrapperLayout,
    scratch: &Reservation, ledger: &Ledger) -> Result<(), PairedFailure>
{
    warm(request, layout, Some((scratch, ledger)))
}
/// Early readiness owns numeric frames, not a compiler reservation. Both
/// lookup guards reject missing entries before any compiler can be entered.
pub(super) fn warm_cached_request_bounds(request: &Request, layout: ShakeWrapperLayout) -> Result<(), PairedFailure> {
    crate::component_tree::native_shape::cache::lookup_only(||
        lattica_prover_p3::block_v2::machine::verifier::batch::shape::HeightEnvelopeCacheScope::lookup_only(||
            warm(request, layout, None)))
}
fn warm(request: &Request, layout: ShakeWrapperLayout, backing: Option<(&Reservation, &Ledger)>) -> Result<(), PairedFailure> {
    let mut carry = [None; usize::BITS as usize];
    let mut push = |mut fact: ComponentSourceFacts| -> Result<(), PairedFailure> {
        for slot in &mut carry {
            match slot.take() {
                None => { *slot = Some(fact); return Ok(()); }
                Some(left) => fact = source::parent_source(left.maximum_padded_rows, fact.maximum_padded_rows)?,
            }
        }
        Err(PairedFailure::Overflow)
    };
    match request.descriptor() {
        RequestDescriptor::Shake(_) => {
            for span in request.shake_wrapper_schedule(layout).map_err(|_| PairedFailure::Coverage)?.groups() {
                push(source::GroupBlueprint::new(request, span)?.inspect()?)?;
            }
        }
        RequestDescriptor::Aes(_) => {
            if backing.is_none() {
                for index in 0..request.segments().len() { push(source::AesBlueprint::new(request, index)?.inspect()?)?; }
            } else {
            let (scratch, ledger) = backing.ok_or(PairedFailure::Source)?;
            use crate::component_tree::native_shape::cohort;
            let mut index = 0;
            while index < request.segments().len() {
                let count = cohort::MAX.min(request.segments().len() - index);
                let first = source::AesBlueprint::new(request, index)?;
                let mut requests = [first.metadata_request(); cohort::MAX];
                for (offset, slot) in requests[..count].iter_mut().enumerate() {
                    *slot = source::AesBlueprint::new(request, index + offset)?.metadata_request();
                }
                let mut bounds = cohort::bounds_exact_in_ledger(&requests[..count], source::construction(), scratch, ledger)
                    .map_err(|_| PairedFailure::Source)?;
                for offset in 0..count {
                    push(source::AesBlueprint::new(request, index + offset)?.inspect_bound(
                        bounds[offset].take().ok_or(PairedFailure::SourceDrift)?)?)?;
                }
                index += count;
            }
            }
        }
    }
    let mut right: Option<ComponentSourceFacts> = None;
    for left in carry.into_iter().flatten() {
        right = Some(match right {
            None => left,
            Some(right) => source::parent_source(left.maximum_padded_rows, right.maximum_padded_rows)?,
        });
    }
    right.ok_or(PairedFailure::Coverage).map(|_| ())
}
