use crate::{
    chip::{
        messaging::{
            reliable_message_mgr::{
                SharedReliableMessageMgr, ReliableMessageMgr,
            },
        },
        transport::session_mgr::{
            //SessionManagerGetter,
            SessionManagerTrait,
        },
    },
};

use core::ptr::NonNull;

pub struct ExchangeManager<'a> {
    m_reliable_message_mgr: ReliableMessageMgr,
    m_session_mgr: Option<NonNull<dyn SessionManagerTrait + 'a>>,
}

impl ExchangeManager<'_> {
    pub const fn new() -> Self {
        Self {
            m_reliable_message_mgr: ReliableMessageMgr::new(),
            m_session_mgr: None,
        }
    }

    pub fn get_reliable_message_mgr(&self) -> SharedReliableMessageMgr {
        self.m_reliable_message_mgr.shared()
    }

    pub fn get_session_manager(&self) -> Option<&mut dyn SessionManagerTrait> {
        unsafe {
            self.m_session_mgr.map(|mut ptr| ptr.as_mut())
        }
    }
}
