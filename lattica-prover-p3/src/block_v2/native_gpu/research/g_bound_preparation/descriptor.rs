//! Exact public transform schedule for the two maintained GBound predicates.
use super::*;
use p3_field::{Field, PrimeField64, TwoAdicField};
pub const HEIGHT: usize = 4096;
pub const WIDTH: usize = 850;
pub const PUBLIC_VALUES: usize = 8;
pub const PERIOD: usize = 128;
pub const PERIODIC_COLUMNS: usize = 39;
const D: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct GBoundDescriptor { f_bound: u32, g_bound: u32 }
impl GBoundDescriptor {
    pub fn new(g_bound: u32) -> Result<Self> {
        let f_bound = match g_bound { 6_825_771 => 5086, 1_137_628 => 565,
            _ => return Err(Error::UnsupportedProfile) };
        let maximum = D as u128 * u128::from(f_bound) * (u128::from(f_bound) + 1)
            + u128::from(g_bound);
        if maximum >= 0xffff_ffff_0000_0001 { return Err(Error::UnsupportedProfile); }
        Ok(Self { f_bound, g_bound })
    }
    pub fn f_bound(self) -> u32 { self.f_bound }
    pub fn g_bound(self) -> u32 { self.g_bound }
    pub fn count(self) -> usize { 1 }
    pub fn geometry_tuple(self) -> (usize, usize, usize, usize) {
        (HEIGHT, WIDTH, PUBLIC_VALUES, PERIODIC_COLUMNS)
    }
    pub fn maximum_integer_difference(self) -> u64 {
        D as u64 * u64::from(self.f_bound) * (u64::from(self.f_bound) + 1) + u64::from(self.g_bound)
    }
    pub fn psi_128(self) -> u64 { Val::two_adic_generator(9).exp_u64(128).as_canonical_u64() }
    pub fn inverse_psi_128(self) -> u64 { Val::two_adic_generator(9).inverse().exp_u64(128).as_canonical_u64() }
    pub fn schedule(self) -> [u64; PERIODIC_COLUMNS * PERIOD] {
        let geometry = GBoundGeometry::for_kind(self);
        core::array::from_fn(|i| geometry.periodic_value(i / PERIOD, i % PERIOD)
            .expect("fixed GBound schedule index").as_canonical_u64())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct GBoundGeometry { kind: GBoundDescriptor }
impl GBoundGeometry {
    pub fn for_kind(kind: GBoundDescriptor) -> Self { Self { kind } }
    pub fn kind(self) -> GBoundDescriptor { self.kind }
    pub fn rows(self) -> usize { HEIGHT }
    pub fn width(self) -> usize { WIDTH }
    pub fn public_values(self) -> usize { PUBLIC_VALUES }
    pub fn periodic_columns(self) -> usize { PERIODIC_COLUMNS }
    pub fn period(self) -> usize { PERIOD }
    pub fn periodic_length(self) -> usize { PERIOD }
    pub fn raw_words(self) -> usize { 2 * D }
    pub fn geometry_words(self) -> usize { 32 + PERIODIC_COLUMNS * PERIOD }
    pub fn endpoint_words(self) -> usize { PUBLIC_VALUES }
    pub fn periodic_value(self, index: usize, row: usize) -> Result<Val> {
        if index >= PERIODIC_COLUMNS || row >= PERIOD { return Err(Error::UnsupportedProfile); }
        let psi = Val::two_adic_generator(9);
        if index < 32 {
            let stage = index % 8;
            let size = D >> stage;
            let half = size / 2;
            let j = row % half;
            let a = (row / half) * size + j;
            Ok(match index / 8 {
                0 => Val::from_usize(a),
                1 => Val::from_usize(a + half),
                2 => psi.square().exp_u64((j * D / size) as u64),
                _ => psi.square().inverse().exp_u64((j * D / size) as u64),
            })
        } else {
            Ok(match index {
                32 => psi.exp_u64(row as u64),
                33 => psi.inverse().exp_u64(row as u64) * Val::from_usize(D).inverse(),
                34 => Val::from_usize(row),
                35 => Val::from_usize(4 * (row % 64)),
                36 => Val::from_bool(row < 64),
                37 => Val::from_bool(row == 63),
                38 => Val::from_bool(row == 127),
                _ => return Err(Error::UnsupportedProfile),
            })
        }
    }
}
