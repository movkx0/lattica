//! Retained private device prefixes and bounded public preprocessing backing.
//! Commitment dimensions are recorded independently of host LDE storage.
use super::*;
use device::{DeviceMatrix, DeviceSession, PublicMatrix};

pub struct OwnedInputs {
    storage: Storage,
    dimensions: Vec<Dimensions>,
}
enum Storage {
    Private(Vec<DeviceMatrix>),
    Public(Vec<PublicMatrix>),
}

impl OwnedInputs {
    pub(super) fn retained_host_backing(&self) -> Result<usize, String> {
        use super::cache_metadata::{add, capacity};
        let mut bytes = capacity::<Dimensions>(self.dimensions.capacity())?;
        match &self.storage {
            Storage::Private(matrices) => {
                bytes = add(bytes, capacity::<DeviceMatrix>(matrices.capacity())?)?;
                for matrix in matrices {
                    bytes = add(bytes, matrix.retained_host_backing())?;
                }
            }
            Storage::Public(matrices) => {
                bytes = add(bytes, capacity::<PublicMatrix>(matrices.capacity())?)?;
                for matrix in matrices {
                    bytes = add(bytes, matrix.cached_host_backing())?;
                }
            }
        }
        Ok(bytes)
    }

    pub(super) fn cached_public_backing(
        &self,
        height: usize,
        count: usize,
    ) -> Result<usize, String> {
        use super::cache_metadata::{add, capacity};
        let Storage::Public(matrices) = &self.storage else {
            return Err("private PCS prefixes cannot enter preprocessing cache".into());
        };
        if matrices.len() != count
            || self.dimensions.len() != count
            || self.dimensions.iter().any(|d| d.height != height)
        {
            return Err("cached PCS prefix geometry".into());
        }
        let mut bytes = add(
            capacity::<PublicMatrix>(matrices.capacity())?,
            capacity::<Dimensions>(self.dimensions.capacity())?,
        )?;
        for matrix in matrices {
            bytes = add(bytes, matrix.cached_host_backing())?;
        }
        Ok(bytes)
    }
    pub(crate) fn new(matrices: Vec<DeviceMatrix>, preprocessing: bool, height: usize) -> Self {
        let heights = vec![height; matrices.len()];
        Self::new_with_heights(matrices, preprocessing, &heights)
    }
    pub(crate) fn new_with_heights(
        matrices: Vec<DeviceMatrix>,
        preprocessing: bool,
        heights: &[usize],
    ) -> Self {
        assert_eq!(matrices.len(), heights.len());
        assert!(!matrices.is_empty());
        let dimensions = matrices
            .iter()
            .zip(heights)
            .map(|(m, &height)| {
                assert!(height.is_power_of_two() && m.spec().rows() <= height);
                Dimensions {
                    width: m.spec().columns(),
                    height,
                }
            })
            .collect();
        let storage = if preprocessing {
            Storage::Public(
                matrices
                    .into_iter()
                    .map(DeviceMatrix::into_public_preprocessing)
                    .collect(),
            )
        } else {
            Storage::Private(matrices)
        };
        Self {
            storage,
            dimensions,
        }
    }

    fn matrix(&self, session: &DeviceSession, index: usize) -> Result<DeviceMatrix, String> {
        match &self.storage {
            Storage::Private(m) => {
                session.alias_private(m.get(index).ok_or("private LDE index out of range")?)
            }
            Storage::Public(m) => session
                .import_preprocessing(m.get(index).ok_or("preprocessed LDE index out of range")?),
        }
    }

    fn is_private(&self) -> bool {
        matches!(self.storage, Storage::Private(_))
    }
}

#[cfg(all(test, feature = "stream"))]
#[test]
fn retained_prefix_spare_capacity_matches_allocator_requests() {
    use crate::spill_alloc::allocation_requests::measure;
    for public in [false, true] {
        let (inputs, allocated) = measure(|| OwnedInputs {
            storage: if public {
                Storage::Public(Vec::with_capacity(3))
            } else {
                Storage::Private(Vec::with_capacity(3))
            },
            dimensions: Vec::with_capacity(7),
        });
        let (bytes, census) = measure(|| inputs.retained_host_backing().unwrap());
        assert_eq!(bytes, allocated.bytes);
        assert_eq!(allocated.calls, 2);
        assert_eq!(census.calls, 0);
        assert!(!allocated.overflow && !census.overflow);
    }
}

impl<M> ProverData<M> {
    pub(crate) fn park_public_salts(
        &mut self,
        session: &DeviceSession,
        allowance: usize,
    ) -> Result<usize, String> {
        let Self::DeviceOnly { salts, .. } = self else {
            return Err("owned public salt storage required".into());
        };
        salts.park_public(session, allowance)
    }

    pub(crate) fn public_salt_upload_bytes(&self) -> Result<usize, String> {
        if let Self::DeviceOnly { salts, .. } = self {
            salts.public_upload_bytes()
        } else {
            Ok(0)
        }
    }
    pub(crate) fn park_public_prefixes(
        &mut self,
        session: &DeviceSession,
        allowance: usize,
    ) -> Result<usize, String> {
        let owned = match self {
            Self::DeviceOnly { owned, .. } => owned,
            Self::GpuRetained {
                owned: Some(owned), ..
            } => owned,
            Self::Compact(data) => data.owned.as_mut().ok_or("missing public prefixes")?,
            _ => return Err("public prefix storage required".into()),
        };
        let Storage::Public(matrices) = &mut owned.storage else {
            return Err("private prefixes cannot enter public host storage".into());
        };
        let required = matrices
            .iter()
            .try_fold(0usize, |sum, m| sum.checked_add(m.host_bound()))
            .ok_or("public prefix size overflow")?;
        if required > allowance {
            return Err("public prefix host admission".into());
        }
        let mut bytes = 0usize;
        for matrix in matrices {
            bytes = bytes
                .checked_add(matrix.park(session, allowance - bytes)?)
                .ok_or("public prefix host size overflow")?;
        }
        Ok(bytes)
    }
    fn owned_inputs(&self) -> Result<&OwnedInputs, String> {
        match self {
            Self::DeviceOnly { owned, .. } => Some(owned),
            Self::GpuRetained { owned, .. } => owned.as_ref(),
            Self::Compact(data) => data.owned.as_ref(),
            _ => None,
        }
        .ok_or_else(|| "PCS data has no owned GPU input; no silent fallback".into())
    }

    pub(crate) fn owned_dimensions(&self) -> Result<&[Dimensions], String> {
        Ok(&self.owned_inputs()?.dimensions)
    }
    /// Validate ownership and shape without uploading a host-backed public prefix.
    pub(crate) fn owned_matrix_spec(
        &self,
        session: &DeviceSession,
        index: usize,
    ) -> Result<device::MatrixSpec, String> {
        match &self.owned_inputs()?.storage {
            Storage::Private(m) => {
                let matrix = m.get(index).ok_or("private LDE index out of range")?;
                matrix.check_session(session)?;
                Ok(matrix.spec())
            }
            Storage::Public(m) => m
                .get(index)
                .ok_or("public LDE index out of range")?
                .checked_spec(session),
        }
    }
    pub(crate) fn public_prefix_upload_bytes(&self) -> Result<usize, String> {
        match &self.owned_inputs()?.storage {
            Storage::Private(_) => Ok(0),
            Storage::Public(m) => m
                .iter()
                .try_fold(0usize, |sum, matrix| sum.checked_add(matrix.parked_bytes()))
                .ok_or_else(|| "public prefix upload size overflow".into()),
        }
    }

    pub(crate) fn owned_matrix(
        &self,
        session: &DeviceSession,
        index: usize,
    ) -> Result<DeviceMatrix, String> {
        self.owned_inputs()?.matrix(session, index)
    }

    pub(crate) fn release_private_owned(&mut self) {
        let slot = match self {
            Self::GpuRetained { owned, .. } => owned,
            Self::Compact(data) => &mut data.owned,
            _ => return,
        };
        if slot.as_ref().is_some_and(OwnedInputs::is_private) {
            *slot = None;
        }
    }
}
