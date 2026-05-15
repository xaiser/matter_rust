use crate::{
    chip::{
        chip_lib::{
            core::{
                node_id::KUNDEFINED_NODE_ID,
                data_model_types::KUNDEFINED_FABRIC_INDEX,
            },
            support::{
                pool::{size_guard, ObjectPool, BitMapObjectPool},
            },
        },
        transport::{
            session::{
                SessionType, SessionHolderList, SessionBase, new_session_holder_list, SessionBasePrivate,
                SharedSession, Alloactor as Pool, ALLOACTOR_CAP as POOL_SIZE, SessionHandle,
                Session, new_session_alloactor, new_shared_session, notify_shared_session_released,
            },
            secure_session::SecureSession,
        },
    },
    verify_or_die,
};

const K_MAX_SESSION_ID: u16 = u16::MAX;
const K_UNSECURED_SESSION_ID: u16 = 0;

pub struct SecureSessionTable {
    m_running_eviction_logic: bool,
    m_entries: [Option<SharedSession>; POOL_SIZE],
    m_entries_pool: Pool,
    m_next_session_id: u16,
}

impl Drop for SecureSessionTable {
    fn drop(&mut self) {
        for session in self.m_entries.iter_mut().filter(|s| s.is_some()) {
            {
                let session_ref = session.as_mut().unwrap();
                notify_shared_session_released(session_ref);
                verify_or_die!(SharedSession::is_unique(session_ref));
            }
            // drop the least one
            *session = None;
        }
    }
}

impl SecureSessionTable {
    pub const fn new() -> Self {
        SecureSessionTable {
            m_running_eviction_logic: false,
            m_entries: [const { None }; POOL_SIZE],
            m_entries_pool: new_session_alloactor(),
            m_next_session_id: K_UNSECURED_SESSION_ID,
        }
    }

    pub fn init(&mut self) {
        self.m_next_session_id = crate::chip::crypto::get_rand_u16();
    }

    pub fn for_each_session<F>(&mut self, mut f: F)
        where
            F: FnOnce(&SharedSession) + FnMut(&SharedSession)
    {
        for session in self.m_entries.iter_mut().filter(|s| s.is_some()) {
            {
                let session_ref = session.as_mut().unwrap();
                f(session_ref);
            }
        }
    }

    pub fn retain(&mut self, session_handle: &SessionHandle) {
    }

    pub fn release(&mut self, _secure_session: &SecureSession) {
    }

    pub fn newer_session_available(&mut self, session: &mut SessionHandle) {
        for session in self.m_entries.iter_mut().filter(|s| s.is_some()) {
            {
                let session_ref = session.as_mut().unwrap();
            }
        }
    }
}
