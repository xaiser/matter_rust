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
    ChipErrorResult,
    chip_core_error, chip_sdk_error,
    chip_ok,
};

use core::ptr::NonNull;

pub struct ExchangeManager<'a> {
    m_reliable_message_mgr: ReliableMessageMgr,
    m_session_mgr: Option<NonNull<dyn SessionManagerTrait + 'a>>,
}

impl<'a> ExchangeManager<'a> {
    pub const fn new() -> Self {
        Self {
            m_reliable_message_mgr: ReliableMessageMgr::new(),
            m_session_mgr: None,
        }
    }

    /*
     *  Initialize the ExchangeManager object. Within the lifetime
     *  of this instance, this method is invoked once after object
     *  construction until a call to Shutdown is made to terminate the
     *  instance.
     *
     */
    pub fn init(&mut self, session_mgr: NonNull<dyn SessionManagerTrait + 'a>) -> ChipErrorResult {
        self.m_session_mgr = Some(session_mgr);

        //TODO: not implement all yet

        chip_ok!()
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
