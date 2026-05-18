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
            secure_session::{self, SecureSession, AsMut, AsRef},
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

    pub fn retain(&mut self, _session_handle: &SessionHandle) {
    }

    pub fn release(&mut self, _secure_session: &SessionHandle) {
    }

    pub fn newer_session_available(&mut self, target_session_handle: &mut SessionHandle) {
        for session in self.m_entries.iter_mut().filter(|s| s.is_some()) {
            let old_session_handle = SessionHandle::new_with(session.as_mut().unwrap());

            if SessionHandle::eq(&old_session_handle, target_session_handle) {
                continue;
            }

            let is_renew = {
                if let Ok(old_session) = old_session_handle.try_ref() {
                    if let Some(old_secure_session) = old_session.as_ref() {
                        if let Ok(target_session) = target_session_handle.try_ref() {
                            if let Some(target_secure_session) = target_session.as_ref() {
                                if old_secure_session.get_secure_session_type() == secure_session::Type::Kcase && old_secure_session.get_peer() == target_secure_session.get_peer() &&
                                    old_secure_session.get_peer_cats() == target_secure_session.get_peer_cats()
                                {
                                    true;
                                } else {
                                    false;
                                }
                            } else {
                                false;
                            }
                        } else {
                            false;
                        }
                    } else {
                        false;
                    }
                } else {
                    false;
                }
            };
            // This will give all SessionHolders pointing to oldSession a chance to switch to the provided session
            //
            // See documentation for SessionDelegate::GetNewSessionHandlingPolicy about how session auto-shifting works, and how
            // to disable it for a specific SessionHolder in a specific scenario.
            if is_renew {
                let handle = SessionHandle::new_with(old_session_handle);
                secure_session::newer_session_available(handle, target_session_handle);
            }
        }
    }
}
