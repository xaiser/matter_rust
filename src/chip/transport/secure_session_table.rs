use crate::{
    chip::transport::{
        session::SharedSession,
        secure_session::SecureSession,
    },
};

pub struct SecureSessionTable;

impl SecureSessionTable {
    pub fn retain(&mut self) {
    }

    pub fn newer_session_available(&mut self, session: &SecureSession) {
    }
}
