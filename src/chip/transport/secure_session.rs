#![allow(dead_code)]
use crate::chip::transport::session::{
    SessionType, SessionHolderList, SessionBase, 
    new_session_holder_list, SessionBasePrivate};

pub trait AsMut {
    fn as_mut(&mut self) -> Option<&mut SecureSession>;
}

pub trait AsRef {
    fn as_ref(&self) -> Option<&SecureSession>;
}

pub struct SecureSession {
    m_holders: SessionHolderList,
}

impl SessionBasePrivate for SecureSession {
    fn holders(&mut self) -> &mut SessionHolderList {
        &mut self.m_holders
    }
}

impl SessionBase for SecureSession {
    fn get_session_type(&self) -> SessionType {
        SessionType::KSecure
    }

    /*
    fn holders(&mut self) -> &mut SessionHolderList {
        &mut self.m_holders
    }
    */

    fn is_active_session(&self) -> bool {
        // TODO: this is just a stub return value
        true
    }
    /*
    fn add_holder(&mut self, holder: SessionHolderHandle) {
        self.m_holders.push_back(holder);
    }

    fn remove_holder(&mut self, holder: SessionHolderHandle) {
        unsafe {
            let mut cur_mut = self.m_holders.cursor_mut_from_ptr(SessionHolderHandle::into_raw(holder));
            cur_mut.remove();
        }
    }
    */
}

impl SecureSession {
    pub const fn new() -> Self {
        Self {
            m_holders: new_session_holder_list(),
        }
    }

    pub fn is_establishing(&self) -> bool {
        // TODO: this is just a stub return
        true
    }
}
