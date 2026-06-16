/*
 * MessageCounter represents a local message counter. There are 2 types of message counter
 *
 * 1. Global unencrypted message counter
 * 2. Secure session message counter
 *
 * There will be separate implementations for each type
 */
use crate::{
    ChipError,
    chip_sdk_error,
    chip_core_error,
    chip_error_message_counter_exhausted,
};

pub enum Type {
    GlobalUnencrypted,
    Session,
}

pub trait MessageCounterBase {
    fn get_type(&self) -> Type;
    fn advance_and_consume(&mut self) -> Result<u32, ChipError>;
}

pub struct GlobalUnencrypted {
    m_last_used_value: u32,
}

impl GlobalUnencrypted {
    pub const fn new() -> Self {
        Self {
            m_last_used_value: 0,
        }
    }
}

pub struct Session {
    m_last_used_value: u32,
}

impl Session {
    pub const K_MESSAGE_COUNTER_MAX: u32 = 0xFFFFFFFF;
    pub const fn new() -> Self {
        Self {
            m_last_used_value: 0,
        }
    }
}

pub enum MessageCounter {
    GlobalUnencrypted(GlobalUnencrypted),
    Session(Session),
}

impl MessageCounter {
    pub const KMESSAGE_COUNTER_RANDOM_INIT_MASK: u32 = 0x0FFFFFFF;

    pub const fn new_global_unencrypted() -> Self {
        MessageCounter::GlobalUnencrypted(GlobalUnencrypted::new())
    }

    pub const fn new_session() -> Self {
        MessageCounter::Session(Session::new())
    }

    pub fn init(&mut self) {
        match self {
            MessageCounter::GlobalUnencrypted(counter) => {
                counter.m_last_used_value = MessageCounter::get_default_initial_value_predecessor();
            },
            MessageCounter::Session(counter) => {
                counter.m_last_used_value = MessageCounter::get_default_initial_value_predecessor();
            },
        }
    }

    pub fn get_default_initial_value_predecessor() -> u32 {
        crate::chip::crypto::get_rand_u32() & Self::KMESSAGE_COUNTER_RANDOM_INIT_MASK
    }
}

impl MessageCounterBase for MessageCounter {
    fn get_type(&self) -> Type {
        match self {
            MessageCounter::GlobalUnencrypted(_) => {
                Type::GlobalUnencrypted
            },
            MessageCounter::Session(_) => {
                Type::Session
            },
        }
    }

    fn advance_and_consume(&mut self) -> Result<u32, ChipError> {
        match self {
            MessageCounter::GlobalUnencrypted(counter) => {
                counter.m_last_used_value += 1;
                Ok(counter.m_last_used_value)
            },
            MessageCounter::Session(counter) => {
                if counter.m_last_used_value == Session::K_MESSAGE_COUNTER_MAX {
                    return Err(chip_error_message_counter_exhausted!());
                }
                counter.m_last_used_value += 1;
                Ok(counter.m_last_used_value)
            },
        }
    }
}

