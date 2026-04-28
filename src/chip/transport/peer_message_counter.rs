use crate::{
    chip::{
        chip_lib::{
            core::chip_config::CHIP_CONFIG_MESSAGE_COUNTER_WINDOW_SIZE,
        },
    },
    ChipErrorResult,
    ChipError,
    chip_ok,
    chip_sdk_error,
    chip_core_error,
    chip_error_incorrect_state,
    chip_error_invalid_argument,
    chip_error_duplicate_message_received,
    verify_or_die,
    verify_or_return_error,
    verify_or_return_value,
};
mod peer_message_counter {
    use crate::{
        chip::{
            chip_lib::{
                support::bitset::Bitset,
                core::chip_config::CHIP_CONFIG_MESSAGE_COUNTER_WINDOW_SIZE,
            },
        },
    };

    // Counter position indicator with respect to our current
    // mSynced.mMaxCounter.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(super) enum Position
    {
        BeforeWindow,
        InWindow,
        MaxCounter,
        FutureCounter,
    }

    pub(super) enum Status {
        NotSynced,     // No state associated
        SyncInProcess(SyncInProcess), // mSyncInProcess will be active
        Synced(Synced),        // mSynced will be active
    }

    impl Status {
        pub fn reset(&mut self) {
            match self {
                Status::SyncInProcess(sip) => {
                    sip.m_challenge.fill(0);
                },
                Status::Synced(s) => {
                    s.m_max_counter = 0;
                    s.m_window.reset();
                },
                _ => {
                }
            }
        }

        pub fn challenge_mut(&mut self) -> Option<&mut [u8]> {
            match self {
                Status::SyncInProcess(sip) => {
                    sip.m_challenge.get_mut(..)
                },
                _ => {
                    None
                }
            }
        }

        pub fn challenge(&self) -> Option<&[u8]> {
            match self {
                Status::SyncInProcess(sip) => {
                    sip.m_challenge.get(..)
                },
                _ => {
                    None
                }
            }
        }

        pub fn max_counter_mut(&mut self) -> Option<&mut u32> {
            match self {
                Status::Synced(s) => {
                    Some(&mut s.m_max_counter)
                },
                _ => {
                    None
                }
            }
        }

        pub fn max_counter(&self) -> Option<u32> {
            match self {
                Status::Synced(s) => {
                    Some(s.m_max_counter)
                },
                _ => {
                    None
                }
            }
        }

        pub fn window_mut(&mut self) -> Option<&mut Window> {
            match self {
                Status::Synced(s) => {
                    Some(&mut s.m_window)
                },
                _ => {
                    None
                }
            }
        }

        pub fn window(&self) -> Option<&Window> {
            match self {
                Status::Synced(s) => {
                    Some(&s.m_window)
                },
                _ => {
                    None
                }
            }
        }

        pub fn synced_mut(&mut self) -> Option<&mut Synced> {
            match self {
                Status::Synced(s) => {
                    Some(s)
                },
                _ => {
                    None
                }
            }
        }

        pub fn synced(&self) -> Option<&Synced> {
            match self {
                Status::Synced(s) => {
                    Some(s)
                },
                _ => {
                    None
                }
            }
        }
    }

    #[derive(Default)]
    pub(super) struct SyncInProcess {
        pub m_challenge: super::Challenge,
    }

    type Window = Bitset<CHIP_CONFIG_MESSAGE_COUNTER_WINDOW_SIZE>;

    #[derive(Default)]
    pub(super) struct Synced {
        pub m_max_counter: u32,
        pub m_window: Window,
    }

    /*
    enum PeerSync {
        SyncInProcess(SyncInProcess),
        Synced(Synced),
    }
    */
}

use peer_message_counter::{Status, Synced, SyncInProcess, Position};

pub type Challenge = [u8; PeerMessageCounter::K_CHALLENGE_SIZE];

pub struct PeerMessageCounter {
    //m_sync: PeerSync,
    m_status: Status,
}

impl PeerMessageCounter {
    pub const K_CHALLENGE_SIZE: usize = 8;
    pub const K_INITIAL_SYNC_VALUE: u32 = 0;

    pub const fn new() -> Self {
        Self {
            m_status: Status::NotSynced,
        }
    }

    pub fn reset(&mut self) {
        self.m_status.reset();
        self.m_status = Status::NotSynced;
    }

    #[inline]
    pub fn is_synchronizing(&self) -> bool {
        matches!(self.m_status, Status::SyncInProcess(_))
    }

    #[inline]
    pub fn is_synchronized(&self) -> bool {
        matches!(self.m_status, Status::Synced(_))
    }

    pub fn sync_starting(&mut self, challenge: &Challenge) {
        verify_or_die!(matches!(self.m_status, Status::NotSynced));
        self.m_status = Status::SyncInProcess(SyncInProcess::default());
        if let Some(c) = self.m_status.challenge_mut() {
            c.copy_from_slice(&challenge[..]);
        } else {
            // should never reach here
            verify_or_die!(false);
        }
    }

    pub fn sync_failed(&mut self) {
        self.reset();
    }

    pub fn verify_challeng(&mut self, counter: u32, challenge: &Challenge) -> ChipErrorResult {
        if let Some(c) = self.m_status.challenge() {
            if c != challenge {
                return Err(chip_error_invalid_argument!());
            }
        } else {
            return Err(chip_error_incorrect_state!());
        }

        self.m_status.reset();
        self.m_status = Status::Synced(Synced::default());

        if let Some(sync) = self.m_status.synced_mut() {
            sync.m_max_counter = counter;
            sync.m_window.reset();
        } else {
            return Err(chip_error_incorrect_state!());
        }

        chip_ok!()
    }

    /*
     * Classify an incoming counter value's position for the cases when counters
     * are allowed to roll over.  Must be used only if mStatus is
     * Status::Synced.
     *
     * This can be used as the basis for implementing section 4.5.4.2 in the
     * spec:
     *
     * For encrypted messages of Group Session Type, any arriving message with a counter in the range
     * [(max_message_counter + 1) to (max_message_counter + 2^31 - 1)] (modulo 2^32) SHALL be considered
     * new, and cause the max_message_counter value to be updated. Messages with counters from
     * [(max_message_counter - 2^31) to (max_message_counter - MSG_COUNTER_WINDOW_SIZE - 1)] (modulo 2^
     * 32) SHALL be considered duplicate. Message counters within the range of the bitmap SHALL be
     * considered duplicate if the corresponding bit offset is set to true.
     */
    fn classify_with_rollover(&self, counter: u32) -> Option<Position> {
        let current_max_count = self.m_status.max_counter()?;
        //let counter_increase = counter - current_max_count;
        let (counter_increase, _) = counter.overflowing_sub(current_max_count);
        const future_counter_window: u32 = (1 << 31) - 1;

        if counter_increase >= 1 && counter_increase <= future_counter_window {
            return Some(Position::FutureCounter);
        }

        self.classify_non_future_counter(counter)
    }


    /*
     * Classify a counter that's known to not be future counter.  This works
     * identically whether we are doing rollover or not.
     */
    fn classify_non_future_counter(&self, counter: u32) -> Option<Position> {
        let current_max_count = self.m_status.max_counter()?;

        if counter == current_max_count {
            return Some(Position::MaxCounter);
        }

        let (offset, is_overflow) = current_max_count.overflowing_sub(counter);
        if !is_overflow && offset <= CHIP_CONFIG_MESSAGE_COUNTER_WINDOW_SIZE as u32 {
            return Some(Position::InWindow);
        }

        Some(Position::BeforeWindow)
    }

    /*
     * Given an encrypted (group or unicast) counter position and the counter
     * value, verify whether we should accept it.
     */
    fn verify_position_encrypted(&self, position: Position, counter: u32) -> ChipErrorResult {
        match position {
            Position::FutureCounter => {
                chip_ok!()
            },
            Position::InWindow => {
                if let Some(synced) = self.m_status.synced() {
                    let (offset, _) = synced.m_max_counter.overflowing_sub(counter);
                    if synced.m_window.test((offset - 1) as usize) {
                        return Err(chip_error_duplicate_message_received!());
                    }
                    chip_ok!()
                } else {
                    Err(chip_error_incorrect_state!())
                }
            },
            _ => {
                Err(chip_error_duplicate_message_received!())
            }
        }
    }
}

impl Drop for PeerMessageCounter {
    fn drop(&mut self) {
        self.reset();
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init() {
        let counter = PeerMessageCounter::new();
        assert!(!counter.is_synchronizing());
    }

    #[test]
    fn start_sync() {
        let mut counter = PeerMessageCounter::new();
        let challenge = [0u8; PeerMessageCounter::K_CHALLENGE_SIZE];
        counter.sync_starting(&challenge);
        assert!(counter.is_synchronizing());
    }

    #[test]
    fn verify_challenge_successfully() {
        let mut counter = PeerMessageCounter::new();
        let challenge = [0u8; PeerMessageCounter::K_CHALLENGE_SIZE];
        counter.sync_starting(&challenge);
        assert!(counter.is_synchronizing());
        assert!(counter.verify_challeng(0, &challenge).is_ok());
    }

    #[test]
    fn verify_challenge_incorrect_state() {
        let mut counter = PeerMessageCounter::new();
        let challenge = [0u8; PeerMessageCounter::K_CHALLENGE_SIZE];
        assert!(counter.verify_challeng(0, &challenge).is_err_and(|e| e == chip_error_incorrect_state!()));
    }

    #[test]
    fn verify_challenge_incorrect_challenge() {
        let mut counter = PeerMessageCounter::new();
        let challenge = [0u8; PeerMessageCounter::K_CHALLENGE_SIZE];
        counter.sync_starting(&challenge);
        assert!(counter.is_synchronizing());
        let challenge_wrong = [1u8; PeerMessageCounter::K_CHALLENGE_SIZE];
        assert!(counter.verify_challeng(0, &challenge_wrong).is_err_and(|e| e == chip_error_invalid_argument!()));
    }

    #[test]
    fn classify_with_rollover_future() {
        let mut counter = PeerMessageCounter::new();
        let challenge = [0u8; PeerMessageCounter::K_CHALLENGE_SIZE];
        counter.sync_starting(&challenge);
        assert!(counter.is_synchronizing());
        assert!(counter.verify_challeng(0, &challenge).is_ok());
        assert!(counter.classify_with_rollover(1).is_some_and(|p| p == Position::FutureCounter));
    }

    #[test]
    fn classify_with_rollover_farest_future() {
        let mut counter = PeerMessageCounter::new();
        let challenge = [0u8; PeerMessageCounter::K_CHALLENGE_SIZE];
        counter.sync_starting(&challenge);
        assert!(counter.is_synchronizing());
        assert!(counter.verify_challeng(0, &challenge).is_ok());
        assert!(counter.classify_with_rollover(0 + ((1 << 31) -1)).is_some_and(|p| p == Position::FutureCounter));
    }

    #[test]
    fn classify_with_rollover_future_overflow() {
        let mut counter = PeerMessageCounter::new();
        let challenge = [0u8; PeerMessageCounter::K_CHALLENGE_SIZE];
        counter.sync_starting(&challenge);
        assert!(counter.is_synchronizing());
        assert!(counter.verify_challeng(0, &challenge).is_ok());
        assert!(counter.classify_with_rollover(1 + ((1 << 31) -1)).is_some_and(|p| p == Position::BeforeWindow));
    }

    #[test]
    fn classify_max_counter() {
        let mut counter = PeerMessageCounter::new();
        let challenge = [0u8; PeerMessageCounter::K_CHALLENGE_SIZE];
        counter.sync_starting(&challenge);
        assert!(counter.is_synchronizing());
        assert!(counter.verify_challeng(0, &challenge).is_ok());
        assert!(counter.classify_with_rollover(0).is_some_and(|p| p == Position::MaxCounter));
    }

    #[test]
    fn classify_in_oldest_window() {
        let mut counter = PeerMessageCounter::new();
        let challenge = [0u8; PeerMessageCounter::K_CHALLENGE_SIZE];
        counter.sync_starting(&challenge);
        assert!(counter.is_synchronizing());
        assert!(counter.verify_challeng(32, &challenge).is_ok());
        assert!(counter.classify_with_rollover(0).is_some_and(|p| p == Position::InWindow));
    }

    #[test]
    fn classify_in_latest_window() {
        let mut counter = PeerMessageCounter::new();
        let challenge = [0u8; PeerMessageCounter::K_CHALLENGE_SIZE];
        counter.sync_starting(&challenge);
        assert!(counter.is_synchronizing());
        assert!(counter.verify_challeng(32, &challenge).is_ok());
        assert!(counter.classify_with_rollover(31).is_some_and(|p| p == Position::InWindow));
    }

    #[test]
    fn classify_before_window() {
        let mut counter = PeerMessageCounter::new();
        let challenge = [0u8; PeerMessageCounter::K_CHALLENGE_SIZE];
        counter.sync_starting(&challenge);
        assert!(counter.is_synchronizing());
        assert!(counter.verify_challeng(33, &challenge).is_ok());
        assert!(counter.classify_with_rollover(0).is_some_and(|p| p == Position::BeforeWindow));
    }

    #[test]
    fn classify_with_rollover_incorect_state() {
        let mut counter = PeerMessageCounter::new();
        assert!(counter.classify_with_rollover(1).is_none());
    }
} // end of tests
