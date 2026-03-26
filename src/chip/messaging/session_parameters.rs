#[repr(u32)]
#[derive(Eq, PartialEq, Clone, Copy)]
pub enum Tag {
    KSessionIdleInterval      = 1,
    KSessionActiveInterval    = 2,
    KSessionActiveThreshold   = 3,
    KDataModelRevision        = 4,
    KInteractionModelRevision = 5,
    KSpecificationVersion     = 6,
    KMaxPathsPerInvoke        = 7,
}

pub struct SessionParameters {
}

impl SessionParameters {
}
