use crate::{
    chip::{
        chip_lib::{
            core::{
                node_id::KUNDEFINED_NODE_ID,
                data_model_types::KUNDEFINED_FABRIC_INDEX,
                case_auth_tag::CATValues,
            },
            support::{
                iterators::Loop,
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
        messaging::reliable_message_protocol_config::ReliableMessageProtocolConfig,
        NodeId, FabricIndex, ScopedNodeId,
    },
    verify_or_die,
    chip_static_assert,
};

use crate::chip_internal_log;
use crate::chip_internal_log_impl;
use crate::chip_log_error;
use crate::chip_log_progress;
use core::str::FromStr;

use core::ptr;
use core::cell::Cell;

const K_MAX_SESSION_ID: u16 = u16::MAX;
const K_UNSECURED_SESSION_ID: u16 = 0;

struct SortableSession {
    m_session: SessionHandle,
    m_num_matching_on_fabric: u16,
    m_num_matching_on_peer: u16,
}

impl SortableSession {
    const fn new(session: SessionHandle) -> Self {
        chip_static_assert!(POOL_SIZE <= u16::MAX as usize);
        Self {
            m_session: session,
            m_num_matching_on_fabric: 0,
            m_num_matching_on_peer: 0,
        }
    }

    fn get_num_matching_on_fabric(&self) -> u16 {
        self.m_num_matching_on_fabric
    }

    fn get_num_matching_on_peer(&self) -> u16 {
        self.m_num_matching_on_peer
    }
}

struct EvictionPoilcyContext<'a> {
    m_session_list: &'a mut [SortableSession],
    m_session_eviction_hint: ScopedNodeId,
}

impl<'a> EvictionPoilcyContext<'a> {
    const fn new(session_list: &'a mut [SortableSession], session_eviction_hint: ScopedNodeId) -> Self {
        Self {
            m_session_list: session_list,
            m_session_eviction_hint: session_eviction_hint,
        }
    }
}

pub struct SecureSessionTable {
    m_running_eviction_logic: Cell<bool>,
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
            m_running_eviction_logic: Cell::new(false),
            m_entries: [const { None }; POOL_SIZE],
            m_entries_pool: new_session_alloactor(),
            m_next_session_id: K_UNSECURED_SESSION_ID,
        }
    }

    pub fn init(&mut self) {
        self.m_next_session_id = crate::chip::crypto::get_rand_u16();
    }

    pub fn create_new_secure_session_for_test(&mut self, secure_session_type: secure_session::Type, local_session_id: u16, local_node_id: NodeId,
        peer_node_id: NodeId, peer_cats: CATValues, peer_session_id: u16, fabric_index: FabricIndex, config: &ReliableMessageProtocolConfig) -> Option<SharedSession>
    {
        match secure_session_type {
            secure_session::Type::Kcase => {
                if (fabric_index == KUNDEFINED_FABRIC_INDEX) || (local_node_id == KUNDEFINED_NODE_ID) || (peer_node_id == KUNDEFINED_NODE_ID) {
                    return None;
                }
            },
            secure_session::Type::Kpase => {
                if (fabric_index != KUNDEFINED_FABRIC_INDEX) || (local_node_id != KUNDEFINED_NODE_ID) || (peer_node_id != KUNDEFINED_NODE_ID) {
                    verify_or_die!(false);
                    return None;
                }
            },
        }

        let shared_session = new_shared_session(Session::new_secure_with(SecureSession::new_with_test(ptr::addr_of_mut!(*self), secure_session_type,
            local_session_id, local_node_id, peer_node_id, peer_cats, peer_session_id, fabric_index, config)), ptr::addr_of_mut!(self.m_entries_pool)).ok()?;

        for session in self.m_entries.iter_mut().filter(|s| s.is_none()) {
            *session = Some(shared_session.clone());
            break;
        }

        Some(shared_session)
    }

    /*
    pub fn create_new_secure_session(&mut self, secure_session_type: secure_session::Type, session_eviction_hint: ScopeNodeid) -> Option<SharedSession>
    {
    }
    */

    pub fn for_each_session<F>(&mut self, mut f: F) -> Loop
        where
            F: FnOnce(&SharedSession) -> Loop + FnMut(&SharedSession) -> Loop
    {
        for session in self.m_entries.iter_mut().filter(|s| s.is_some()) {
            let session_ref = session.as_mut().unwrap();
            if f(session_ref) == Loop::Break {
                return Loop::Break;
            }
        }

        Loop::Finish
    }

    pub fn for_each_session_const<F>(&self, mut f: F) -> Loop
        where
            F: FnOnce(&SharedSession) -> Loop + FnMut(&SharedSession) -> Loop
    {
        for session in self.m_entries.iter().filter(|s| s.is_some()) {
            let session_ref = session.as_ref().unwrap();
            if f(session_ref) == Loop::Break {
                return Loop::Break;
            }
        }

        Loop::Finish
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
                let is_renew: bool;
                if let Ok(old_session) = old_session_handle.try_ref() {
                    if let Some(old_secure_session) = old_session.as_ref() {
                        if let Ok(target_session) = target_session_handle.try_ref() {
                            if let Some(target_secure_session) = target_session.as_ref() {
                                if old_secure_session.get_secure_session_type() == secure_session::Type::Kcase && old_secure_session.get_peer() == target_secure_session.get_peer() &&
                                    *old_secure_session.get_peer_cats() == *target_secure_session.get_peer_cats()
                                {
                                    is_renew = true;
                                } else {
                                    is_renew = false;
                                }
                            } else {
                                is_renew = false;
                            }
                        } else {
                            is_renew = false;
                        }
                    } else {
                        is_renew = false;
                    }
                } else {
                    is_renew = false;
                }

                is_renew
            };
            // This will give all SessionHolders pointing to oldSession a chance to switch to the provided session
            //
            // See documentation for SessionDelegate::GetNewSessionHandlingPolicy about how session auto-shifting works, and how
            // to disable it for a specific SessionHolder in a specific scenario.
            if is_renew {
                secure_session::newer_session_available(old_session_handle, target_session_handle);
            }
        }
    }

    fn default_eviction_policy(a: &SortableSession, b: &SortableSession) -> core::cmp::Ordering {
        if let Ok(a_borrow) = a.m_session.try_ref() &&
            let Ok(b_borrow) = b.m_session.try_ref() &&
                let Some(a_secure) = a_borrow.as_ref() &&
                let Some(b_secure) = b_borrow.as_ref()
        {
            if a.m_num_matching_on_fabric != b.m_num_matching_on_fabric {
                return a.m_num_matching_on_fabric.cmp(&b.m_num_matching_on_fabric);
            }

            core::cmp::Ordering::Equal
        } else {
            core::cmp::Ordering::Equal
        }
    }

    fn evict_and_allocate(&mut self, local_session_id: u16, secure_session_type: secure_session::Type, session_eviction_hint: &ScopedNodeId) -> Option<SharedSession> {
        // TODO: add verify_or_die_with_msg
        // TODO: ensure no re-enter from more high level
        chip_log_progress!(SecureChannel, "evicting a slot for session with LSID {}, type {}", local_session_id, secure_session_type as u8);

        // TODO why do we need this?
        //verify_or_die!(self.allocated() <= POOL_SIZE);

        let mut sortable_sessions: [Option<SortableSession>; POOL_SIZE] = [const { None }; POOL_SIZE];
        let mut index = 0usize;

        self.for_each_session_const(|session| {
            let mut sortable_session = SortableSession::new(SessionHandle::new_with(session));

            self.for_each_session_const(|other_session| {
                if !SharedSession::ptr_eq(session, other_session) {
                    if let Ok(a_borrow) = session.try_borrow() &&
                        let Ok(b_borrow) = other_session.try_borrow() &&
                            let Some(a_s) = a_borrow.as_ref() &&
                            let Some(b_s) = b_borrow.as_ref()
                    {
                        if a_s.get_fabric_index() == b_s.get_fabric_index() {
                            sortable_session.m_num_matching_on_fabric += 1;
                            if a_s.get_peer_node_id() == b_s.get_peer_node_id() {
                                sortable_session.m_num_matching_on_peer += 1;
                            }
                        }
                    }
                }
                Loop::Continue
            });
            sortable_sessions[index] = Some(sortable_session);
            index += 1;
            Loop::Continue
        });

        None
    }

    fn allocated(&self) -> usize {
        let mut count = 0usize;

        self.for_each_session_const(|session| { count += 1; Loop::Continue } );

        count
    }

    fn find_unused_session_id(&self) -> Option<u16> {
        let mut candidate_base = 0u16;
        let mut candidate_mask = 0u64;

        for i in (0..=K_MAX_SESSION_ID).step_by(64) {
            // candidate_base is the base session ID we are searching from.
            // We have a 64-bit mask anchored at this ID and iterate over the
            // whole session table, setting bits in the mask for in-use IDs.
            // If we can iterate through the entire session table and have
            // any bits clear in the mask, we have available session IDs.
            candidate_base = (i as u32 + self.m_next_session_id as u32) as u16;
            candidate_mask = 0;
            let shift = K_UNSECURED_SESSION_ID.wrapping_sub(candidate_base);
            if shift <= 63 {
                candidate_mask |= 1 << shift;
            }

            self.for_each_session_const(|session| {
                if let Ok(s_ref) = session.try_borrow() &&
                  let Some(ss) = s_ref.as_ref() 
                {
                    //let shift = (session.get_local_session_id() - candidate_base) as u16;
                    let shift = ss.get_local_session_id().wrapping_sub(candidate_base);
                    if shift <= 63 {
                        candidate_mask |= 1 << shift;
                    }
                    if candidate_mask == u64::MAX {
                        return Loop::Break;
                    }
                    
                    Loop::Continue
                } else {
                    verify_or_die!(false);
                    return Loop::Break;
                }
            });

            if u64::from(candidate_base) != u64::MAX {
                break;
            }
        }

        if u64::from(candidate_mask) != u64::MAX {
            let mut offset = 0u16;
            while 1 == (candidate_mask & 1) {
                candidate_mask >>= 1;
                offset += 1;
            }

            return Some(candidate_base.wrapping_add(offset));
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_one_session_successfully() {
        let mut table = SecureSessionTable::new();
        table.init();

        let cat = CATValues::new();
        let config = ReliableMessageProtocolConfig::new();

        assert!(table.create_new_secure_session_for_test(secure_session::Type::Kcase, 0, KUNDEFINED_NODE_ID + 1, KUNDEFINED_NODE_ID + 1,
                cat, 1, KUNDEFINED_FABRIC_INDEX + 1, &config).is_some());
    }

    #[test]
    fn new_two_session_successfully() {
        let mut table = SecureSessionTable::new();
        table.init();

        let cat = CATValues::new();
        let config = ReliableMessageProtocolConfig::new();

        assert!(table.create_new_secure_session_for_test(secure_session::Type::Kcase, 0, KUNDEFINED_NODE_ID + 1, KUNDEFINED_NODE_ID + 1,
                cat, 1, KUNDEFINED_FABRIC_INDEX + 1, &config).is_some());

        assert!(table.create_new_secure_session_for_test(secure_session::Type::Kcase, 1, KUNDEFINED_NODE_ID + 2, KUNDEFINED_NODE_ID + 2,
                cat, 3, KUNDEFINED_FABRIC_INDEX + 2, &config).is_some());
    }

    #[test]
    fn next_unused_session_id_from_0() {
        let mut table = SecureSessionTable::new();
        table.init();
        table.m_next_session_id = K_UNSECURED_SESSION_ID;

        assert!(table.find_unused_session_id().is_some_and(|id| id == K_UNSECURED_SESSION_ID + 1));
    }

    #[test]
    fn next_unused_session_id_from_1() {
        let mut table = SecureSessionTable::new();
        table.init();

        let cat = CATValues::new();
        let config = ReliableMessageProtocolConfig::new();

        // to simulate a session with id = 65535
        assert!(table.create_new_secure_session_for_test(secure_session::Type::Kcase, 1, KUNDEFINED_NODE_ID + 1, KUNDEFINED_NODE_ID + 1,
                cat, 1, KUNDEFINED_FABRIC_INDEX + 1, &config).is_some());
        table.m_next_session_id = 1;

        assert!(table.find_unused_session_id().is_some_and(|id| id == 2));
    }

    #[test]
    fn next_unused_session_id_from_max() {
        let mut table = SecureSessionTable::new();
        table.init();

        let cat = CATValues::new();
        let config = ReliableMessageProtocolConfig::new();

        // to simulate a session with id = 65535
        assert!(table.create_new_secure_session_for_test(secure_session::Type::Kcase, u16::MAX, KUNDEFINED_NODE_ID + 1, KUNDEFINED_NODE_ID + 1,
                cat, 1, KUNDEFINED_FABRIC_INDEX + 1, &config).is_some());
        table.m_next_session_id = u16::MAX;

        assert!(table.find_unused_session_id().is_some_and(|id| id == K_UNSECURED_SESSION_ID + 1));
    }
} // end of tests
