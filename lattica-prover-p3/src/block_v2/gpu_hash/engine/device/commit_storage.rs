//! Shared admission for commitment-input samples and parameter buffers.
//! Existing device samples are already charged in `live`; uploaded samples are
//! pending. This is a storage snapshot, not a reservation or a host/RSS budget.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SampleLocation {
    Uploaded,
    Resident,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CommitInputStorage {
    pub allocation_bytes: [usize; 3],
    pub sample_bytes: usize,
    pub pending_bytes: usize,
    pub peak_bytes: usize,
    pub location: SampleLocation,
}

impl CommitInputStorage {
    pub(super) fn new(
        samples: [usize; 2],
        parameter_words: usize,
        location: SampleLocation,
        live: usize,
        managed: usize,
        max_allocation: usize,
    ) -> Result<Self, String> {
        let mut allocation_bytes = [0; 3];
        for (bytes, words) in
            allocation_bytes
                .iter_mut()
                .zip([samples[0], samples[1], parameter_words])
        {
            *bytes = words
                .checked_mul(8)
                .ok_or("commitment input size overflow")?;
            if *bytes > max_allocation {
                return Err("commitment input exceeds device allocation limit".into());
            }
        }
        if parameter_words == 0 {
            return Err("commitment input requires parameters".into());
        }
        let sample_bytes = allocation_bytes[0]
            .checked_add(allocation_bytes[1])
            .ok_or("commitment sample size overflow")?;
        if location == SampleLocation::Resident && live < sample_bytes {
            return Err("resident commitment samples exceed live storage".into());
        }
        let pending_bytes = allocation_bytes[2]
            .checked_add(if location == SampleLocation::Resident {
                0
            } else {
                sample_bytes
            })
            .ok_or("commitment pending storage overflow")?;
        let peak_bytes = live
            .checked_add(pending_bytes)
            .filter(|&n| n <= managed)
            .ok_or("commitment input exceeds managed capacity")?;
        Ok(Self {
            allocation_bytes,
            sample_bytes,
            pending_bytes,
            peak_bytes,
            location,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Extension, MatrixSpec, QuotientCommitShape, RowOrder, TraceCommitShape};
    use super::*;

    #[test]
    fn commitment_input_storage_counts_uploaded_and_resident_samples_once() {
        for extension in [Extension::Base, Extension::Quadratic, Extension::Cubic] {
            let spec = MatrixSpec::new(4, 3, extension, RowOrder::Natural, 1).unwrap();
            let shape = TraceCommitShape::new(spec, 4).unwrap();
            let sample = shape.random_words * 8;
            for location in [SampleLocation::Uploaded, SampleLocation::Resident] {
                let live = 64
                    + if location == SampleLocation::Resident {
                        sample
                    } else {
                        0
                    };
                let peak = 64 + sample + 8;
                assert!(shape
                    .storage_plan(location, live, peak - 1, sample)
                    .is_err());
                assert!(shape
                    .storage_plan(location, live, peak, sample - 1)
                    .is_err());
                let plan = shape.storage_plan(location, live, peak, sample).unwrap();
                assert_eq!(plan.peak_bytes, peak);
                assert_eq!(plan.pending_bytes, peak - live);
                assert_eq!(plan.allocation_bytes, [sample, 0, 8]);
            }
        }
    }

    #[test]
    fn quotient_input_storage_checks_each_mask_and_parameter_allocation() {
        for extension in [Extension::Quadratic, Extension::Cubic] {
            for chunks in [2, 4, 8, 16, 32] {
                let spec = MatrixSpec::new(10, 1, extension, RowOrder::Natural, 7).unwrap();
                let shape = QuotientCommitShape::new(spec, chunks, 4).unwrap();
                let bytes = shape.allocation_words().map(|n| n * 8);
                let max = *bytes.iter().max().unwrap();
                for location in [SampleLocation::Uploaded, SampleLocation::Resident] {
                    let live = 64
                        + if location == SampleLocation::Resident {
                            bytes[0] + bytes[1]
                        } else {
                            0
                        };
                    let peak = 64 + shape.bytes().unwrap();
                    assert!(shape.storage_plan(location, live, peak - 1, max).is_err());
                    assert!(shape.storage_plan(location, live, peak, max - 1).is_err());
                    let plan = shape.storage_plan(location, live, peak, max).unwrap();
                    assert_eq!(plan.allocation_bytes, bytes);
                    assert_eq!(plan.pending_bytes, peak - live);
                    assert_eq!(plan.peak_bytes, peak);
                }
            }
        }
    }

    #[test]
    fn commitment_input_storage_rejects_overflow_and_inconsistent_residency() {
        for (samples, parameters, location, live) in [
            ([usize::MAX, 0], 1, SampleLocation::Uploaded, 0),
            (
                [usize::MAX / 8, usize::MAX / 8],
                1,
                SampleLocation::Uploaded,
                0,
            ),
            ([0, 0], 1, SampleLocation::Uploaded, usize::MAX),
            ([1, 2], 1, SampleLocation::Resident, 23),
            ([0, 0], 0, SampleLocation::Resident, 0),
        ] {
            assert!(CommitInputStorage::new(
                samples,
                parameters,
                location,
                live,
                usize::MAX,
                usize::MAX
            )
            .is_err());
        }
        let preprocessing = TraceCommitShape::preprocessing(
            MatrixSpec::new(4, 3, Extension::Base, RowOrder::Natural, 1).unwrap(),
        )
        .unwrap();
        assert!(preprocessing
            .storage_plan(SampleLocation::Uploaded, 0, 8, 7)
            .is_err());
        assert_eq!(
            preprocessing
                .storage_plan(SampleLocation::Uploaded, 0, 8, 8)
                .unwrap()
                .pending_bytes,
            8
        );
        assert!(CommitInputStorage::new([1, 1], 3, SampleLocation::Resident, 16, 40, 23).is_err());
        assert_eq!(
            CommitInputStorage::new([1, 1], 3, SampleLocation::Resident, 16, 40, 24)
                .unwrap()
                .peak_bytes,
            40
        );
    }

    #[test]
    fn evaluation_input_shape_and_parameter_admission_share_runtime_bounds() {
        use super::super::EvaluationShape;
        for spec in [
            MatrixSpec::new(0, 1, Extension::Base, RowOrder::Natural, 1).unwrap(),
            MatrixSpec::new(26, 1, Extension::Base, RowOrder::Natural, 1).unwrap(),
            MatrixSpec::new(4, 4097, Extension::Base, RowOrder::Natural, 1).unwrap(),
            MatrixSpec::new(4, 1, Extension::Cubic, RowOrder::Natural, 1).unwrap(),
            MatrixSpec::new(4, 1, Extension::Base, RowOrder::BitReversed, 1).unwrap(),
        ] {
            assert!(EvaluationShape::new(spec).is_err());
        }
        let shape = EvaluationShape::new(
            MatrixSpec::new(4, 7, Extension::Base, RowOrder::Natural, 11).unwrap(),
        )
        .unwrap();
        assert!(shape.storage_plan(64, 79, 16).is_err());
        assert!(shape.storage_plan(64, 80, 15).is_err());
        let plan = shape.storage_plan(64, 80, 16).unwrap();
        assert_eq!(plan.allocation_bytes, [0, 0, 16]);
        assert_eq!(plan.peak_bytes, 80);
        let lde = shape.lde_shape(21).unwrap();
        assert_eq!((lde.height, lde.width, lde.added_bits), (16, 7, 21));
        assert!(shape.lde_shape(22).is_err());
        assert!(shape.lde_shape(usize::MAX).is_err());
    }
}
