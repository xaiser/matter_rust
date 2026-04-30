use crate::{
    chip::{
        chip_lib::{
            core::chip_config::CHIP_CONFIG_MESSAGE_COUNTER_WINDOW_SIZE,
        },
    },
    ChipErrorResult,
    //ChipError,
    chip_ok,
    chip_sdk_error,
    chip_core_error,
    chip_error_incorrect_state,
    chip_error_invalid_argument,
    chip_error_duplicate_message_received,
    chip_error_internal,
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
        pub fn new_synced_counter(counter: u32) -> Self {
            let mut inner = Synced { m_max_counter: counter, m_window: Window::default() };
            inner.m_window.reset();

            Status::Synced(inner)
        }

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

        #[allow(dead_code)]
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

        #[allow(dead_code)]
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

        #[allow(dead_code)]
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

use peer_message_counter::{Status, SyncInProcess, Position};

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
        self.m_status = Status::new_synced_counter(counter);

        chip_ok!()
    }

    pub fn verify_grop(&self, counter: u32) -> ChipErrorResult {
        let pos = self.classify_with_rollover(counter).ok_or(chip_error_incorrect_state!())?;

        self.verify_position_encrypted(pos, counter)
    }

    pub fn verify_or_trust_first_group(&mut self, counter: u32) -> ChipErrorResult {
        match self.m_status {
            Status::NotSynced => {
                self.set_counter(counter);
                return chip_ok!();
            }, 
            Status::Synced(_) => {
                return self.verify_grop(counter);
            },
            _ => {
                verify_or_die!(false);
                return Err(chip_error_internal!());
            }
        }
    }

    pub fn commit_group(&mut self, counter: u32) -> ChipErrorResult {
        self.commit_with_rollover(counter)
    }

    pub fn verify_encrypted_unicast(&self, counter: u32) -> ChipErrorResult {
        verify_or_return_error!(matches!(self.m_status, Status::Synced(_)), Err(chip_error_incorrect_state!()));

        let pos = self.classify_without_rollover(counter).ok_or(chip_error_incorrect_state!())?;

        self.verify_position_encrypted(pos, counter)
    }

    pub fn commit_encrypted_unicast(&mut self, counter: u32) -> ChipErrorResult {
        self.commit_without_rollover(counter)
    }

    pub fn verify_uncrypted(&mut self, counter: u32) -> ChipErrorResult {
        match self.m_status {
            Status::NotSynced => {
                self.set_counter(counter);
                chip_ok!()
            },
            Status::Synced(_) => {
                let pos = self.classify_with_rollover(counter).ok_or(chip_error_incorrect_state!())?;
                self.verify_position_unencrypted(pos, counter)
            },
            _ => {
                verify_or_die!(false);
                Err(chip_error_internal!())
            }
        }
    }

    pub fn commit_unencrypted(&mut self, counter: u32) -> ChipErrorResult {
        self.commit_with_rollover(counter)
    }

    pub fn set_counter(&mut self, value: u32) {
        self.reset();
        self.m_status = Status::new_synced_counter(value);
    }

    pub fn get_counter(&self) -> Option<u32> {
        self.m_status.max_counter()
    }

    fn classify_without_rollover(&self, counter: u32) -> Option<Position> {
        if counter > self.m_status.max_counter()? {
            return Some(Position::FutureCounter);
        }

        self.classify_non_future_counter(counter)
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
        const FUTURE_COUNTER_WINDOW: u32 = (1 << 31) - 1;

        if counter_increase >= 1 && counter_increase <= FUTURE_COUNTER_WINDOW {
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
                    // this will return false if overflow
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
    fn verify_position_unencrypted(&self, position: Position, counter: u32) -> ChipErrorResult {
        match position {
            Position::MaxCounter => {
                Err(chip_error_duplicate_message_received!())
            },
            Position::InWindow => {
                if let Some(synced) = self.m_status.synced() {
                    let (offset, _) = synced.m_max_counter.overflowing_sub(counter);
                    // this will return false if overflow
                    if synced.m_window.test((offset - 1) as usize) {
                        return Err(chip_error_duplicate_message_received!());
                    }
                    chip_ok!()
                } else {
                    Err(chip_error_incorrect_state!())
                }
            },
            _ => {
                chip_ok!()
            }
        }
    }

    fn commit_with_rollover(&mut self, counter: u32) -> ChipErrorResult {
        let pos = self.classify_with_rollover(counter).ok_or(chip_error_incorrect_state!())?;

        self.commit_with_position(pos, counter)
    }

    fn commit_without_rollover(&mut self, counter: u32) -> ChipErrorResult {
        let pos = self.classify_without_rollover(counter).ok_or(chip_error_incorrect_state!())?;

        self.commit_with_position(pos, counter)
    }

    fn commit_with_position(&mut self, position: Position, counter: u32) -> ChipErrorResult {
        match position {
            Position::InWindow => {
                let synced = self.m_status.synced_mut().ok_or(chip_error_incorrect_state!())?;
                let (offset, _) = synced.m_max_counter.overflowing_sub(counter);
                synced.m_window.set((offset - 1) as usize);
            },
            Position::MaxCounter => {
                // do nothing
            },
            _ => {
                let synced = self.m_status.synced_mut().ok_or(chip_error_incorrect_state!())?;
                let (shift, _) = counter.overflowing_sub(synced.m_max_counter);
                synced.m_max_counter = counter;
                let shift = shift as usize;
                if shift > CHIP_CONFIG_MESSAGE_COUNTER_WINDOW_SIZE {
                    synced.m_window.reset();
                } else {
                    synced.m_window <<= shift;
                    synced.m_window.set(shift - 1);
                }
            }
        }
        chip_ok!()
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

    #[test]
    fn verify_position_encrypt_future() {
        let mut counter = PeerMessageCounter::new();
        let challenge = [0u8; PeerMessageCounter::K_CHALLENGE_SIZE];
        counter.sync_starting(&challenge);
        assert!(counter.is_synchronizing());
        assert!(counter.verify_challeng(0, &challenge).is_ok());
        assert!(counter.verify_position_encrypted(Position::FutureCounter, 1).is_ok());
    }

    // TODO: wait for window movement implementation
    /*
    #[test]
    fn verify_position_encrypt_in_window() {
        let mut counter = PeerMessageCounter::new();
        let challenge = [0u8; PeerMessageCounter::K_CHALLENGE_SIZE];
        counter.sync_starting(&challenge);
        assert!(counter.is_synchronizing());
        assert!(counter.verify_challeng(1, &challenge).is_ok());
        assert!(counter.verify_position_encrypted(Position::FutureCounter, 1).is_ok());
    }
    */
    #[test]
    fn verify_position_encrypt_not_in_window() {
        let mut counter = PeerMessageCounter::new();
        let challenge = [0u8; PeerMessageCounter::K_CHALLENGE_SIZE];
        counter.sync_starting(&challenge);
        assert!(counter.is_synchronizing());
        assert!(counter.verify_challeng(0, &challenge).is_ok());
        assert!(counter.verify_position_encrypted(Position::InWindow, u32::MAX).is_ok());
    }

    #[test]
    fn verify_position_encrypt_before() {
        let mut counter = PeerMessageCounter::new();
        let challenge = [0u8; PeerMessageCounter::K_CHALLENGE_SIZE];
        counter.sync_starting(&challenge);
        assert!(counter.is_synchronizing());
        assert!(counter.verify_challeng(0, &challenge).is_ok());
        assert!(counter.verify_position_encrypted(Position::BeforeWindow, 0).is_err_and(|e| e == chip_error_duplicate_message_received!()));
    }

    #[test]
    fn verify_or_trust_first_group_not_syncd() {
        let mut counter = PeerMessageCounter::new();
        assert!(counter.verify_or_trust_first_group(1).is_ok());
        assert!(counter.is_synchronized());
    }

    #[test]
    #[should_panic]
    fn verify_or_trust_first_group_syncing() {
        let mut counter = PeerMessageCounter::new();
        let challenge = [0u8; PeerMessageCounter::K_CHALLENGE_SIZE];
        counter.sync_starting(&challenge);
        assert!(counter.is_synchronizing());
        assert!(counter.verify_or_trust_first_group(1).is_err());
    }

    #[test]
    fn verify_or_trust_first_group_synced() {
        let mut counter = PeerMessageCounter::new();
        let challenge = [0u8; PeerMessageCounter::K_CHALLENGE_SIZE];
        counter.sync_starting(&challenge);
        assert!(counter.is_synchronizing());
        assert!(counter.verify_challeng(0, &challenge).is_ok());
        assert!(counter.verify_or_trust_first_group(1).is_ok());
    }

    #[test]
    fn commit_with_pos_in_window_successfully() {
        let mut counter = PeerMessageCounter::new();
        let challenge = [0u8; PeerMessageCounter::K_CHALLENGE_SIZE];
        counter.sync_starting(&challenge);
        assert!(counter.is_synchronizing());
        assert!(counter.verify_challeng(1, &challenge).is_ok());
        assert!(counter.commit_with_position(Position::InWindow, 0).is_ok());
    }

    #[test]
    fn commit_with_pos_in_window_incorrect_state() {
        let mut counter = PeerMessageCounter::new();
        let challenge = [0u8; PeerMessageCounter::K_CHALLENGE_SIZE];
        counter.sync_starting(&challenge);
        assert!(counter.commit_with_position(Position::InWindow, 0).is_err_and(|e| e == chip_error_incorrect_state!()));
    }

    #[test]
    fn commit_with_pos_max_counter() {
        let mut counter = PeerMessageCounter::new();
        assert!(counter.commit_with_position(Position::MaxCounter, 0).is_ok());
    }

    #[test]
    fn commit_with_pos_far_future_successfully() {
        let mut counter = PeerMessageCounter::new();
        let challenge = [0u8; PeerMessageCounter::K_CHALLENGE_SIZE];
        counter.sync_starting(&challenge);
        assert!(counter.is_synchronizing());
        assert!(counter.verify_challeng(1, &challenge).is_ok());
        assert!(counter.commit_with_position(Position::FutureCounter, (CHIP_CONFIG_MESSAGE_COUNTER_WINDOW_SIZE + 2) as u32).is_ok());
        assert!(counter.m_status.synced().is_some_and(
                |s| s.m_max_counter == ((CHIP_CONFIG_MESSAGE_COUNTER_WINDOW_SIZE + 2) as u32) && s.m_window.none()));
    }

    #[test]
    fn commit_with_pos_near_future_successfully() {
        let mut counter = PeerMessageCounter::new();
        let challenge = [0u8; PeerMessageCounter::K_CHALLENGE_SIZE];
        counter.sync_starting(&challenge);
        assert!(counter.is_synchronizing());
        assert!(counter.verify_challeng(1, &challenge).is_ok());
        assert!(counter.commit_with_position(Position::FutureCounter, 2 as u32).is_ok());
        assert!(counter.m_status.synced().is_some_and(
                |s| s.m_max_counter == 2 && s.m_window.test(0)));
    }

    #[test]
    fn verify_position_unencrypt_max_counter() {
        let mut counter = PeerMessageCounter::new();
        assert!(counter.verify_position_unencrypted(Position::MaxCounter, 0).is_err_and(|e| e == chip_error_duplicate_message_received!()));
    }

    #[test]
    fn verify_position_unencrypt_future() {
        let mut counter = PeerMessageCounter::new();
        assert!(counter.verify_position_encrypted(Position::FutureCounter, 1).is_ok());
    }
} // end of tests
