use crate::{
    chip::{
        messaging::{
            reliable_message_mgr::{
                SharedReliableMessageMgr, ReliableMessageMgr,
            },
        },
    },
};

pub struct ExchangeManager {
    m_reliable_message_mgr: ReliableMessageMgr,
}

impl ExchangeManager {
    pub const fn new() -> Self {
        Self {
            m_reliable_message_mgr: ReliableMessageMgr::new(),
        }
    }

    pub fn get_reliable_message_mgr(&self) -> SharedReliableMessageMgr {
        self.m_reliable_message_mgr.shared()
    }
}
