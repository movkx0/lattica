//! Shape-limited NTT schedules. Storage includes padding and every table.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Ntt {
    Baseline,
    Powers,
    Split8,
    #[default]
    SmallTile,
    Padded,
    Local48,
}
impl Ntt {
    pub fn parse(value: &str) -> Result<Self, String> {
        Ok(match value {
            "baseline" => Self::Baseline,
            "powers" => Self::Powers,
            "split8" => Self::Split8,
            "smalltile" => Self::SmallTile,
            "padded" => Self::Padded,
            "local48" => Self::Local48,
            _ => return Err("unknown aggregation NTT schedule".into()),
        })
    }
    pub fn admitted(self, height: usize, width: usize) -> bool {
        self != Self::Baseline
            && height.is_power_of_two()
            && matches!(height.trailing_zeros(), 18 | 19 | 22 | 23 | 24)
            && matches!(width, 1 | 3 | 4 | 7 | 8 | 16)
    }
    pub fn geometry(self, baseline_columns: usize) -> (usize, usize) {
        match self {
            Self::Split8 | Self::Padded => (3, 12),
            Self::SmallTile => (3, 11),
            Self::Local48 => (4, 12),
            _ => (baseline_columns, 12),
        }
    }
    pub fn storage(
        self,
        stages: usize,
        columns: usize,
        scaled: bool,
        device_local: usize,
    ) -> Option<(usize, usize)> {
        if !(1..=12).contains(&stages) || columns > 4 {
            return None;
        }
        let rows = 1usize << stages;
        let elements = rows << columns;
        let tile = elements
            + if self == Self::Padded {
                (elements - 1) / 32
            } else {
                0
            };
        let powers = rows / 2 + stages + if scaled { rows } else { 0 };
        let limit = device_local.min(if self == Self::Local48 {
            48 << 10
        } else {
            32 << 10
        });
        ((tile + powers) * 8 <= limit).then_some((tile, powers))
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Poseidon {
    #[default]
    Baseline,
    Square,
    SquareUnroll,
}
impl Poseidon {
    pub fn parse(value: &str) -> Result<Self, String> {
        Ok(match value {
            "baseline" => Self::Baseline,
            "square" => Self::Square,
            "square-unroll" => Self::SquareUnroll,
            _ => return Err("unknown aggregation Poseidon schedule".into()),
        })
    }
    pub fn defines(self) -> &'static str {
        match self {
            Self::Baseline => "",
            Self::Square => "#define LATTICA_POSEIDON_SQUARE 1\n",
            Self::SquareUnroll => {
                "#define LATTICA_POSEIDON_SQUARE 1\n#define LATTICA_POSEIDON_UNROLL 1\n"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cache_accounts_for_padding_powers_and_scale() {
        assert!(Ntt::Powers.storage(8, 4, false, 49152).is_none());
        assert!(Ntt::Split8.storage(8, 3, true, 32768).is_some());
        let (tile, powers) = Ntt::Padded.storage(8, 3, true, 32768).unwrap();
        assert_eq!(tile, 2048 + 63);
        assert_eq!(powers, 128 + 8 + 256);
        assert!(Ntt::Local48.storage(8, 4, true, 49152).is_some());
        assert!(Ntt::Local48.storage(8, 4, true, 32768).is_none());
        for profile in [
            Ntt::Powers,
            Ntt::Split8,
            Ntt::SmallTile,
            Ntt::Padded,
            Ntt::Local48,
        ] {
            assert!(profile.admitted(1 << 24, 16));
            assert!(!profile.admitted(1 << 25, 16));
            assert!(!profile.admitted(1 << 24, 32));
            assert!(profile.storage(usize::MAX, 4, true, usize::MAX).is_none());
        }
    }
}
