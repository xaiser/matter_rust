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
        use crate::{chip_ok, ChipError, ChipErrorResult};
        use super::super::*;
        use core::time::Duration;
        use core::sync::atomic::{AtomicU64, Ordering};

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
            let ms = CLOCK.m_system_time.load(Ordering::Relaxed);

            Duration::from_millis(ms)
        }

        pub fn get_clock_realtime() -> Result<Micsoseconds, ChipError> {
            let ms = CLOCK.m_real_time.load(Ordering::Relaxed);

            Ok(Duration::from_millis(ms))
        }

        pub fn set_clock_realtime(a_new_cur_time: Micsoseconds) -> ChipErrorResult {
            CLOCK.m_real_time.store(a_new_cur_time.as_millis() as u64, Ordering::Relaxed);

            chip_ok!()
        }
    }

    pub use no_op::{init, get_monotonic_timestamp, get_clock_realtime, set_clock_realtime};
}// end of internal

pub use internal::{init, get_monotonic_timestamp, get_clock_realtime, set_clock_realtime};
