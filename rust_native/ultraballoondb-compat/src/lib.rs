pub const COMPATIBILITY_SUITE_VERSION: &str =
    "V00R3B4_CRASH_CONSISTENCY_AND_FORMAT_COMPATIBILITY_SUITE_R01";
pub const CONTROLLED_HARD_EXIT_CODE: i32 = 86;
pub const FORMAT_MAJOR_V1: u16 = 1;
pub const WAL_HEADER_BYTES_V1: usize = 96;
pub const VERSIONED_FILE_HEADER_BYTES_V1: usize = 80;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrashScenario {
    Uncommitted,
    CommittedNoCheckpoint,
    Checkpointed,
    PartialWalTail,
}

impl CrashScenario {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Uncommitted => "UNCOMMITTED",
            Self::CommittedNoCheckpoint => "COMMITTED_NO_CHECKPOINT",
            Self::Checkpointed => "CHECKPOINTED",
            Self::PartialWalTail => "PARTIAL_WAL_TAIL",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "UNCOMMITTED" => Some(Self::Uncommitted),
            "COMMITTED_NO_CHECKPOINT" => Some(Self::CommittedNoCheckpoint),
            "CHECKPOINTED" => Some(Self::Checkpointed),
            "PARTIAL_WAL_TAIL" => Some(Self::PartialWalTail),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scenario_names_roundtrip() {
        for scenario in [
            CrashScenario::Uncommitted,
            CrashScenario::CommittedNoCheckpoint,
            CrashScenario::Checkpointed,
            CrashScenario::PartialWalTail,
        ] {
            assert_eq!(
                CrashScenario::parse(scenario.name()),
                Some(scenario)
            );
        }
    }

    #[test]
    fn frozen_header_sizes() {
        assert_eq!(WAL_HEADER_BYTES_V1, 96);
        assert_eq!(VERSIONED_FILE_HEADER_BYTES_V1, 80);
        assert_eq!(FORMAT_MAJOR_V1, 1);
    }
}
