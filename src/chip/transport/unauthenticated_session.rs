use crate::chip::transport::session::{SessionType, SessionHolderHandle, SessionHolder, SessionHolderList, SessionBase};

pub trait AsMut {
    fn as_mut(&mut self) -> Option<&mut UnauthenticatedSession>;
}

pub struct UnauthenticatedSession {
    m_holders: SessionHolderList,
}

impl SessionBase for UnauthenticatedSession {
    fn get_session_type(&self) -> SessionType {
        SessionType::KUnauthenticated
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

#[cfg(test)]
mod tests {
    mod holder {
        use super::super::*;
        use crate::chip::transport::session::{SessionType, SessionHolderHandle, SessionHolder, SessionHolderList, SessionBase};

        struct Holder {
            m_session: SessionHolder,
        }
    }
} // end of tests
