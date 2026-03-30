use crate::{ChipError, ChipErrorResult};

pub type Seconds32 = core::time::Duration;
pub type Milliseconds16 = core::time::Duration;
pub type Milliseconds32 = core::time::Duration;
pub type Milliseconds = core::time::Duration;
pub type Micsoseconds = core::time::Duration;
pub type Timeout = core::time::Duration;
pub type Timestamp = core::time::Duration;

/*
pub trait ClockBase {
    fn get_monotonic_timestamp(&self) -> Timestamp;
    fn get_clock_realtime(&self) -> Result<Micsoseconds, ChipError>;
    fn set_clock_realtime(&self, a_new_cur_time: Micsoseconds) -> ChipErrorReslut;
}
*/

mod internal {
    // no specific platform, a test-able system clock is set up.
    mod no_op {
        use super::super::*;
        use core::cell::OnceCell;
        use core::time::Duration;
        use core::sync::atomic::AtomicU64;

        static CLOCK: Clock = Clock::new();

        pub struct Clock {
            m_system_time: AtomicU64,
            m_real_time: AtomicU64,
        }

        impl Clock {
            const fn new() -> Self {
                Self {
                    m_system_time: AtomicU64::new(0),
                    m_real_time: AtomicU64::new(0),
                }
            }
        }

        pub fn init() { }

        pub fn get_monotonic_timestamp() -> Timestamp {
            Duration::ZERO
        }
    }

    pub use no_op::{init, get_monotonic_timestamp};
}// end of internal

pub use internal::{init, get_monotonic_timestamp};
