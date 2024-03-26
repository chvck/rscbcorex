#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum DurabilityLevel {
    Majority,
    MajorityAndPersistToActive,
    PersistToMajority,
}

impl Into<u8> for DurabilityLevel {
    fn into(self) -> u8 {
        match self {
            DurabilityLevel::Majority => 1,
            DurabilityLevel::MajorityAndPersistToActive => 2,
            DurabilityLevel::PersistToMajority => 3,
        }
    }
}
