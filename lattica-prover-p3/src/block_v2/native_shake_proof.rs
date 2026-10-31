//! Native SHAKE proof data shared with the isolated research implementation.
//! This schema supplies no verification, transaction acceptance or ownership.
use super::profile::Config;
use crate::config::Val;

pub const PUBLIC_VALUES: usize = 216;

pub struct NativeShakeProof {
    pub public_values: [Val; PUBLIC_VALUES],
    pub proof: p3_uni_stark::Proof<Config>,
}
