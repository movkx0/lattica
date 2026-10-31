//! Pinned P3 0.6.1 / Rust 1.96 x86_64 numerical-verifier allocation census.
//! Adapted from the core wallet verifier census to quadratic challenges,
//! 96 queries, no chain wrapper, and every admitted FRI arity up to sixteen.
//! All temporary requests are summed, so sequential release is never assumed.
use super::*;
use p3_field::ExtensionField;
use p3_matrix::Dimensions;
use p3_uni_stark::Domain;

type Ext = Challenge;
type Point = (Ext, Vec<Ext>);
type Matrix = (Domain<MyConfig>, Vec<Point>);
type Round = (Cap, Vec<Matrix>);
type SortedDimension = (usize, &'static Dimensions);
type Packed = <Ext as ExtensionField<Val>>::ExtensionPacking;
const MAX_TEMPORARY_BYTES: usize = 64 << 20;

#[derive(Clone, Copy, Default)]
struct Ledger(usize);
impl Ledger {
    fn bytes(&mut self, bytes: usize) -> Result<(), Error> {
        self.0 = add(self.0, bytes)?;
        Ok(())
    }
    fn exact<T>(&mut self, count: usize) -> Result<(), Error> {
        self.bytes(mul(count, core::mem::size_of::<T>())?)
    }
    fn growing<T>(&mut self, count: usize) -> Result<(), Error> {
        if count == 0 {
            return Ok(());
        }
        // All replaced RawVec buffers plus the final buffer under pinned
        // geometric growth; the minimum nonzero capacity is at most eight.
        self.exact::<T>(mul(4, count.max(8))?)
    }
    fn repeat(&mut self, other: Self, count: usize) -> Result<(), Error> {
        self.bytes(mul(other.0, count)?)
    }
}

fn tree(heap: &mut Ledger, matrices: usize, log_height: usize) -> Result<(), Error> {
    // Stable dimension sorting and its scratch, plus the Merkle arity walk.
    // Every input batch here has one height, so no remaining-height heap grows.
    for _ in 0..2 {
        heap.growing::<SortedDimension>(matrices)?;
        heap.exact::<SortedDimension>(matrices)?;
    }
    heap.growing::<usize>(log_height)
}
fn hiding_tree(
    heap: &mut Ledger,
    matrices: usize,
    width: usize,
    log_height: usize,
) -> Result<(), Error> {
    heap.growing::<Vec<Val>>(matrices)?;
    let mut row = Ledger::default();
    row.growing::<Val>(add(width, 4)?)?;
    heap.repeat(row, matrices)?;
    heap.growing::<Dimensions>(matrices)?;
    tree(heap, matrices, log_height)
}

fn configuration() -> Result<usize, Error> {
    // One original challenger permutation, two hash/compressor permutations,
    // and their two FRI-MMCS clones. Each has 2*4*8+22 field constants.
    let permutations = 5 * (2 * 4 * 8 + 22) * core::mem::size_of::<Val>();
    #[repr(C)]
    struct Cache {
        _lock: std::sync::atomic::AtomicUsize,
        _map: std::collections::BTreeMap<usize, usize>,
    }
    #[repr(C)]
    struct ArcInner<T> {
        _strong: std::sync::atomic::AtomicUsize,
        _weak: std::sync::atomic::AtomicUsize,
        _value: T,
    }
    // config::Dft is exactly Radix2DitParallel, with three empty Arc cache roots.
    // CPU verification does not populate them. ChaCha/Mutex state stays inline.
    add(permutations, 3 * core::mem::size_of::<ArcInner<Cache>>())
}

#[derive(Clone, Copy)]
struct Periodic {
    construction: usize,
    retained: usize,
    peak: usize,
    cumulative: usize,
}
fn periodic(g: Geometry) -> Result<Periodic, Error> {
    let values = 11 * 32 + (g.periodic_columns - 11) * g.padded_rows;
    let mut construction = Ledger::default();
    construction.exact::<Val>(values)?;
    construction.exact::<Vec<Val>>(8)?;
    construction.growing::<Vec<Val>>(g.periodic_columns)?;
    // joinsplit_air::periodic: each index vector including all growing range
    // windows and membership rows; output field columns are exact-sized.
    for count in [2, 2, 2, 4, 4, 2 * 32, 2, 2, 2, 6, 6, 6 * 52, 6] {
        construction.growing::<usize>(count)?;
    }
    let mut retained = Ledger::default();
    retained.exact::<Val>(values)?;
    retained.exact::<Vec<Val>>(2 * g.periodic_columns.max(8))?;
    let small = interpolation(32)?;
    let large = interpolation(g.padded_rows)?;
    Ok(Periodic {
        construction: construction.0,
        retained: retained.0,
        peak: small.max(large),
        cumulative: add(mul(11, small)?, mul(g.periodic_columns - 11, large)?)?,
    })
}
fn interpolation(period: usize) -> Result<usize, Error> {
    let mut heap = Ledger::default();
    heap.exact::<Val>(period)?; // domain-owned copy of the periodic column
    heap.growing::<Val>(period)?; // interpolation coset collection
    for _ in 0..3 {
        heap.exact::<Ext>(period)?;
    } // differences, inverses, weights
      // Indexed Rayon fold/reduce creates at most two identities per leaf and
      // at most period leaves. This covers all workers, not just the caller.
    heap.exact::<Packed>(mul(2, period)?)?;
    heap.growing::<Ext>(1)?; // collection or on-coset one-element early result
    Ok(heap.0)
}

pub(super) fn build() -> Result<VerificationPlan, Error> {
    let g = Geometry::pinned()?;
    if 2 * super::air::DEGREE.next_power_of_two() != g.quotient_chunks {
        return Err(Error::Geometry);
    }
    let roots = 1 << g.cap_height;
    let matrices = [1, 1, g.quotient_chunks];
    let widths = [g.challenge_degree, g.trace_columns, g.challenge_degree];
    let log_lde = g.degree_bits + g.log_blowup;
    let periodic = periodic(g)?;
    let mut uni = Ledger::default();
    for _ in 0..2 {
        uni.growing::<Domain<MyConfig>>(g.quotient_chunks)?;
    }
    uni.growing::<usize>(g.trace_columns)?; // main-next-row metadata
    uni.growing::<Round>(3)?; // random round, temporary extension, final rounds
    for (round, points) in [1, 2, 1].into_iter().enumerate() {
        uni.growing::<Matrix>(matrices[round])?;
        let mut matrix = Ledger::default();
        matrix.growing::<Point>(points)?;
        for _ in 0..points {
            matrix.exact::<Ext>(widths[round])?;
            matrix.exact::<Ext>(2 * (widths[round] + g.random_codewords))?;
        }
        uni.repeat(matrix, matrices[round])?;
    }
    uni.exact::<[Val; 4]>(6 * roots)?; // transcript and PCS cap clones
    uni.growing::<Ext>(g.quotient_chunks)?;
    uni.growing::<Ext>(g.periodic_columns)?;

    let mut transcript = Ledger::default();
    transcript.exact::<[Val; 8]>(8)?;
    transcript.exact::<Val>(22)?; // cloned challenger permutation constants
    for _ in 0..2 {
        transcript.growing::<Val>(4)?;
    } // input/output sponge buffers
    let mut air = Ledger::default();
    for count in [
        g.public_values,
        g.trace_columns,
        g.trace_columns,
        g.periodic_columns,
        8,
    ] {
        air.growing::<Ext>(count)?;
    }

    let mut fri = Ledger::default();
    let mut arities = Ledger::default();
    arities.growing::<usize>(g.degree_bits)?;
    fri.repeat(arities, g.queries)?;
    fri.growing::<Ext>(g.degree_bits)?;
    fri.exact::<[Val; 4]>(g.degree_bits * roots)?;
    let mut query = Ledger::default();
    // Reduced openings has one common LDE height, hence one BTreeMap leaf.
    // Pinned Rust B=6 stores eleven key/value slots; eight words overbound its
    // node header/alignment. All roots are iterated before the FRI fold walk.
    query.bytes(
        8 * core::mem::size_of::<usize>()
            + 11 * (core::mem::size_of::<usize>() + core::mem::size_of::<(Ext, Ext)>()),
    )?;
    query.growing::<(usize, Ext)>(1)?;
    for round in 0..3 {
        query.growing::<usize>(matrices[round])?;
        query.growing::<Dimensions>(matrices[round])?;
        hiding_tree(
            &mut query,
            matrices[round],
            widths[round] + g.random_codewords,
            log_lde,
        )?;
    }
    let arity = 1 << g.max_log_fri_arity;
    let mut step = Ledger::default();
    for _ in 0..3 {
        step.exact::<Ext>(arity)?;
    } // reconstruction, two MMCS clones
    step.growing::<Val>(arity * g.challenge_degree)?;
    step.growing::<Vec<Val>>(1)?;
    step.growing::<Dimensions>(1)?;
    hiding_tree(&mut step, 1, arity * g.challenge_degree, log_lde - 1)?;
    step.growing::<Ext>(arity)?; // fold-row collection
    step.growing::<Val>(arity)?; // interpolation coset
    step.growing::<Ext>(arity)?; // denominators
    step.exact::<Ext>(arity)?; // batch inverses
                               // Simultaneously maximal steps and arities overcount every allowed
                               // schedule; no untrusted schedule can request more than this ceiling.
    query.repeat(step, g.degree_bits)?;
    fri.repeat(query, g.queries)?;
    let config = configuration()?;
    let mut total = Ledger::default();
    for bytes in [
        config,
        uni.0,
        transcript.0,
        air.0,
        fri.0,
        periodic.construction,
        periodic.cumulative,
        1024 + core::mem::size_of::<String>(),
        core::mem::size_of::<super::super::codec::ScratchGuard<'static>>(),
    ] {
        total.bytes(bytes)?;
    }
    if total.0 > MAX_TEMPORARY_BYTES {
        return Err(Error::ResourceLimit);
    }
    Ok(VerificationPlan {
        configuration_bytes: config,
        uni_stark_bytes: uni.0,
        transcript_bytes: transcript.0,
        air_bytes: air.0,
        fri_bytes: fri.0,
        periodic_construction_bytes: periodic.construction,
        periodic_retained_bytes: periodic.retained,
        periodic_evaluation_peak_bytes: periodic.peak,
        periodic_evaluation_cumulative_bytes: periodic.cumulative,
        cumulative_requested_bytes: total.0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn census_is_finite_and_checks_arithmetic() {
        let plan = build().unwrap();
        assert!(plan.cumulative_requested_bytes <= MAX_TEMPORARY_BYTES);
        assert!(plan.periodic_evaluation_cumulative_bytes >= plan.periodic_evaluation_peak_bytes);
        assert!(plan.periodic_construction_bytes >= plan.periodic_retained_bytes);
        assert!(Ledger::default().growing::<Ext>(usize::MAX).is_err());
        assert!(Ledger(usize::MAX).bytes(1).is_err());
        assert!(Ledger::default().repeat(Ledger(usize::MAX), 2).is_err());
    }
}
