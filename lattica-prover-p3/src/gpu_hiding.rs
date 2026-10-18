//! Protocol geometry shared by OpenCL/Metal and native CUDA polynomial hiding.
use crate::gpu_matrix::{Extension, MatrixSpec, RowOrder};

#[derive(Clone, Copy, Debug)]
pub(crate) struct TraceCommitShape {
    pub height: usize,
    pub width: usize,
    pub trace_width: usize,
    pub random_columns: usize,
    pub random_words: usize,
}
impl TraceCommitShape {
    pub(crate) fn new(spec: MatrixSpec, random_columns: usize) -> Result<Self, String> {
        Self::plan(spec, random_columns, false)
    }
    pub(crate) fn preprocessing(spec: MatrixSpec) -> Result<Self, String> {
        Self::plan(spec, 0, true)
    }
    fn plan(spec: MatrixSpec, random_columns: usize, preprocessing: bool) -> Result<Self, String> {
        if (preprocessing && spec.extension != Extension::Base)
            || spec.order != RowOrder::Natural
            || spec.shift != 1
            || spec.log_rows >= 31
            || random_columns
                != if preprocessing {
                    0
                } else {
                    crate::block_v2::profile::NUM_RANDOM_CODEWORDS
                }
        {
            return Err("unsupported device trace commitment geometry".into());
        }
        let trace_width = spec
            .columns
            .checked_mul(spec.extension.degree())
            .ok_or("trace width overflow")?;
        let width = trace_width
            .checked_add(random_columns)
            .filter(|n| *n <= u32::MAX as usize)
            .ok_or("hidden trace width overflow")?;
        let random_words = if preprocessing {
            0
        } else {
            trace_width
                .checked_add(2 * random_columns)
                .filter(|n| *n <= u32::MAX as usize)
                .and_then(|n| n.checked_mul(spec.rows()))
                .filter(|n| n.checked_mul(8).is_some())
                .ok_or("trace hiding samples overflow")?
        };
        let height = spec.rows() * 2;
        MatrixSpec::new(
            spec.log_rows + 1,
            width,
            Extension::Base,
            RowOrder::Natural,
            1,
        )?;
        Ok(Self {
            height,
            width,
            trace_width,
            random_columns,
            random_words,
        })
    }
    pub(crate) fn allocation_bytes(self) -> [usize; 2] {
        [self.random_words * 8, 8]
    }
}

#[cfg(test)]
mod trace_commit_tests {
    use super::*;
    #[test]
    fn trace_commit_layout_accounts_for_reference_hiding_and_rejects_bad_geometry() {
        let spec = MatrixSpec::new(10, 17, Extension::Cubic, RowOrder::Natural, 1).unwrap();
        let shape = TraceCommitShape::new(spec, 4).unwrap();
        assert_eq!(
            (shape.height, shape.width, shape.trace_width),
            (2048, 55, 51)
        );
        assert_eq!(shape.random_words, 1024 * (51 + 8));
        assert_eq!(shape.allocation_bytes(), [1024 * 59 * 8, 8]);
        let quadratic = TraceCommitShape::new(
            MatrixSpec {
                extension: Extension::Quadratic,
                ..spec
            },
            4,
        )
        .unwrap();
        assert_eq!(
            (quadratic.height, quadratic.width, quadratic.trace_width),
            (2048, 38, 34)
        );
        assert_eq!(quadratic.random_words, 1024 * 42);
        assert_eq!(quadratic.allocation_bytes(), [1024 * 42 * 8, 8]);
        for invalid in [
            MatrixSpec {
                order: RowOrder::BitReversed,
                ..spec
            },
            MatrixSpec { shift: 7, ..spec },
            MatrixSpec {
                log_rows: 31,
                ..spec
            },
        ] {
            assert!(TraceCommitShape::new(invalid, 4).is_err());
        }
        let base = TraceCommitShape::new(
            MatrixSpec::new(10, 17, Extension::Base, RowOrder::Natural, 1).unwrap(),
            4,
        )
        .unwrap();
        assert_eq!((base.height, base.width, base.trace_width), (2048, 21, 17));
        assert_eq!(base.random_words, 1024 * 25);
        assert_eq!(base.allocation_bytes(), [1024 * 25 * 8, 8]);
        let preprocessing = TraceCommitShape::preprocessing(
            MatrixSpec::new(10, 17, Extension::Base, RowOrder::Natural, 1).unwrap(),
        )
        .unwrap();
        assert_eq!((preprocessing.height, preprocessing.width), (2048, 17));
        assert_eq!(preprocessing.random_columns, 0);
        assert_eq!(preprocessing.random_words, 0);
        assert_eq!(preprocessing.allocation_bytes(), [0, 8]);
        assert!(TraceCommitShape::preprocessing(spec).is_err());
        for random_columns in [0, 3, 5, usize::MAX] {
            assert!(TraceCommitShape::new(spec, random_columns).is_err());
        }
        assert!(TraceCommitShape::new(
            MatrixSpec::new(0, u32::MAX as usize, Extension::Cubic, RowOrder::Natural, 1).unwrap(),
            4
        )
        .is_err());
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct QuotientCommitShape {
    pub degree: usize,
    pub chunks: usize,
    pub height: usize,
    pub width: usize,
    pub random_columns: usize,
    pub random_words: usize,
    pub mask_words: usize,
}
impl QuotientCommitShape {
    pub(crate) fn new(
        spec: MatrixSpec,
        chunks: usize,
        random_columns: usize,
    ) -> Result<Self, String> {
        let max_chunks = crate::block_v2::profile::MAX_QUOTIENT_CHUNKS;
        if spec.extension == Extension::Base
            || spec.columns != 1
            || spec.order != RowOrder::Natural
            || spec.log_rows > 31
            || chunks < 2
            || chunks > max_chunks
            || !chunks.is_power_of_two()
            || spec.rows() / chunks < 2
            || random_columns != crate::block_v2::profile::NUM_RANDOM_CODEWORDS
        {
            return Err(format!("unsupported owned quotient commitment geometry: spec={spec:?} chunks={chunks} random_columns={random_columns}"));
        }
        let height = spec.rows() / chunks;
        let width = spec
            .extension
            .degree()
            .checked_add(random_columns)
            .ok_or("quotient width overflow")?;
        let random_words = spec
            .rows()
            .checked_mul(random_columns)
            .ok_or("quotient random column overflow")?;
        let mask_words = height
            .checked_mul(width)
            .and_then(|n| n.checked_mul(chunks - 1))
            .ok_or("quotient hiding mask overflow")?;
        let result = Self {
            degree: spec.extension.degree(),
            chunks,
            height,
            width,
            random_columns,
            random_words,
            mask_words,
        };
        result.bytes()?;
        Ok(result)
    }
    pub(crate) fn allocation_words(self) -> [usize; 3] {
        [self.random_words, self.mask_words, self.chunks * 3]
    }
    pub(crate) fn bytes(self) -> Result<usize, String> {
        self.allocation_words()
            .into_iter()
            .try_fold(0usize, |total, n| {
                n.checked_mul(8)
                    .and_then(|n| total.checked_add(n))
                    .ok_or_else(|| "quotient sample storage overflow".into())
            })
    }
}

#[cfg(test)]
mod quotient_commit_tests {
    use super::*;
    use crate::config::Val;
    use p3_commit::PolynomialSpace;
    use p3_field::{coset::TwoAdicMultiplicativeCoset as Domain, PrimeCharacteristicRing};

    #[test]
    fn quotient_commit_shape_counts_raw_samples_and_rejects_noncanonical_partitions() {
        let spec = MatrixSpec::new(11, 1, Extension::Cubic, RowOrder::Natural, 7).unwrap();
        let shape = QuotientCommitShape::new(spec, 16, 4).unwrap();
        assert_eq!(
            (
                shape.height,
                shape.width,
                shape.random_words,
                shape.mask_words
            ),
            (128, 7, 8192, 13440)
        );
        assert_eq!(shape.bytes().unwrap(), 173440);
        let quadratic = MatrixSpec::new(11, 1, Extension::Quadratic, RowOrder::Natural, 7).unwrap();
        let quadratic = QuotientCommitShape::new(quadratic, 16, 4).unwrap();
        assert_eq!(
            (
                quadratic.degree,
                quadratic.width,
                quadratic.random_words,
                quadratic.mask_words
            ),
            (2, 6, 8192, 11520)
        );
        assert_eq!(quadratic.bytes().unwrap(), 158080);
        assert!(QuotientCommitShape::new(spec, 32, 4).is_ok());
        assert!(QuotientCommitShape::new(
            MatrixSpec::new(11, 1, Extension::Quadratic, RowOrder::Natural, 7).unwrap(),
            32,
            4
        )
        .is_ok());
        for chunks in [0, 1, 3, 64, 2048] {
            assert!(QuotientCommitShape::new(spec, chunks, 4).is_err());
        }
        for random_columns in [0, 1, 3, 5] {
            assert!(QuotientCommitShape::new(spec, 16, random_columns).is_err());
        }
        for invalid in [
            MatrixSpec::new(11, 1, Extension::Cubic, RowOrder::BitReversed, 7).unwrap(),
            MatrixSpec::new(11, 3, Extension::Base, RowOrder::Natural, 7).unwrap(),
            MatrixSpec::new(11, 2, Extension::Cubic, RowOrder::Natural, 7).unwrap(),
            MatrixSpec::new(4, 1, Extension::Cubic, RowOrder::Natural, 7).unwrap(),
        ] {
            assert!(QuotientCommitShape::new(invalid, 16, 4).is_err());
        }
    }

    #[test]
    fn uniform_partition_has_equal_reference_normalized_vanishing_weights() {
        for shift in [7, 11] {
            for log_height in [1, 3, 13] {
                for log_chunks in [1, 2, 4, 5] {
                    let chunks = 1usize << log_chunks;
                    let domain =
                        Domain::new(Val::from_u64(shift), log_height + log_chunks).unwrap();
                    let parts = domain.split_domains(chunks);
                    for (i, part) in parts.iter().enumerate() {
                        let denominator: Val = parts
                            .iter()
                            .enumerate()
                            .filter(|(j, _)| *j != i)
                            .map(|(_, other)| other.vanishing_poly_at_point(part.first_point()))
                            .product();
                        assert_eq!(denominator, -Val::from_usize(chunks));
                    }
                }
            }
        }
    }
}
