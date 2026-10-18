//! The OpenCL and CUDA samplers share the same allocation-free byte planner.
pub(crate) use crate::gpu_random::FieldStoragePlan;

#[cfg(test)]
mod tests;
