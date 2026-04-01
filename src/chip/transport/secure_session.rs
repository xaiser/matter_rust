use crate::chip::transport::session::{SessionType, SessionHolderHandle, SessionHolder, SessionHolderList, SessionBase};

pub trait AsMut {
    fn as_mut(&mut self) -> Option<&mut SecureSession>;
}

pub struct SecureSession {
    m_holders: SessionHolderList,
}

impl SessionBase for SecureSession {
    fn get_session_type(&self) -> SessionType {
        SessionType::KSecure
    }

    fn holders(&mut self) -> &mut SessionHolderList {
        &mut self.m_holders
    }

    fn is_active_session(&self) -> bool {
        // TODO: this is just a stub return value
        false
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
