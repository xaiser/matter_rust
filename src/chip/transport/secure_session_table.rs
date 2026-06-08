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
                //pool::{size_guard, ObjectPool, BitMapObjectPool},
            },
        },
        transport::{
            session::{
                SessionBase,
                SharedSession, Alloactor as Pool, ALLOACTOR_CAP as POOL_SIZE, SessionHandle,
                Session, new_session_alloactor, new_shared_session, notify_shared_session_released,
            },
            secure_session::{self, SecureSession, AsRef},
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
use crate::chip_log_detail;
use core::str::FromStr;

use core::ptr;
//use core::cell::Cell;

const K_MAX_SESSION_ID: u16 = u16::MAX;
const K_UNSECURED_SESSION_ID: u16 = 0;

#[derive(Clone)]
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

    #[allow(dead_code)]
    fn get_num_matching_on_fabric(&self) -> u16 {
        self.m_num_matching_on_fabric
    }

    #[allow(dead_code)]
    fn get_num_matching_on_peer(&self) -> u16 {
        self.m_num_matching_on_peer
    }
}

struct EvictionPoilcyContext<'a> {
    m_session_list: &'a mut [Option<SortableSession>],
    m_session_eviction_hint: ScopedNodeId,
}

impl<'a> EvictionPoilcyContext<'a> {
    const fn new(session_list: &'a mut [Option<SortableSession>], session_eviction_hint: ScopedNodeId) -> Self {
        Self {
            m_session_list: session_list,
            m_session_eviction_hint: session_eviction_hint,
        }
    }

    fn get_session_eviction_hint(&self) -> &ScopedNodeId {
        &self.m_session_eviction_hint
    }
}

pub struct SecureSessionTable {
    //m_running_eviction_logic: Cell<bool>,
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
            //m_running_eviction_logic: Cell::new(false),
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

        self.inner_retain(&shared_session);

        Some(shared_session)
    }

    pub fn create_new_secure_session(&mut self, secure_session_type: secure_session::Type, session_eviction_hint: ScopedNodeId) -> Option<SessionHandle>
    {
        let session_id = self.find_unused_session_id()?;

        let shared_session = if self.allocated() < POOL_SIZE {
            let ss = new_shared_session(Session::new_secure_with(SecureSession::new_with(ptr::addr_of_mut!(*self), secure_session_type,
            session_id)), ptr::addr_of_mut!(self.m_entries_pool)).ok()?;

            self.inner_retain(&ss);

            ss
        } else {
            self.evict_and_allocate(session_id, secure_session_type, &session_eviction_hint)?
        };

        self.m_next_session_id = if session_id == K_MAX_SESSION_ID {
            (K_UNSECURED_SESSION_ID + 1) as u16
        } else {
            session_id + 1
        };

        Some(SessionHandle::new_with(&shared_session))
    }

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

    pub fn find_secure_session_by_local_key(&self, local_session_id: u16) -> Option<SessionHandle> {
        let mut result: Option<SessionHandle> = None;
        self.for_each_session_const(|s| {
            if let Ok(borrow) = s.try_borrow() {
                if let Some(ss) = borrow.as_ref() {
                    if ss.get_local_session_id() == local_session_id {
                        result = Some(SessionHandle::new_with(s));
                        return Loop::Break;
                    }
                }
            }
            Loop::Continue
        });

        result
    }

    pub fn retain(&mut self, _session_handle: &SessionHandle) {
        // TODO: find a way to implement this
        /*
        for session in self.m_entries.iter_mut().filter(|s| s.is_some()) {
            let handle = SessionHandle::new_with(session.as_ref().unwrap());
            if SessionHandle::eq(&handle, secure_session) {
                *session = None;
                break;
            }
        }
        */
    }

    pub fn release(&mut self, _secure_session: &SessionHandle) {
        // TODO: find a way to implement this
        /*
        for session in self.m_entries.iter_mut().filter(|s| s.is_some()) {
            let handle = SessionHandle::new_with(session.as_ref().unwrap());
            if SessionHandle::eq(&handle, secure_session) {
                *session = None;
                break;
            }
        }
        */
    }

    fn inner_retain(&mut self, ss: &SharedSession) {
        for session in self.m_entries.iter_mut().filter(|s| s.is_none()) {
            *session = Some(ss.clone());
            break;
        }
    }

    fn inner_release(&mut self, secure_session: &SessionHandle) {
        for session in self.m_entries.iter_mut().filter(|s| s.is_some()) {
            let handle = SessionHandle::new_with(session.as_ref().unwrap());
            if SessionHandle::eq(&handle, secure_session) {
                *session = None;
                break;
            }
        }
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

        let mut policy_context = EvictionPoilcyContext::new(&mut sortable_sessions[..index], session_eviction_hint.clone());
        Self::default_eviction_policy(&mut policy_context);
        chip_log_progress!(SecureChannel, "Sorted sessions for eviction...");

        #[cfg(feature = "chip_detail_logging")]
        {
            //let num_sessions = self.allocated();
            chip_log_detail!(SecureChannel, "Sorted Eviction Candidates (ranked from best candidate to worst):");
            for (index, ss) in sortable_sessions.iter().enumerate().filter(|(_, s)| s.is_some()) {
                if let Some(sort_session) = ss &&
                    let Ok(session) = sort_session.m_session.try_ref() &&
                        let Some(secure_session) = session.as_ref()
                {
                    chip_log_detail!(SecureChannel, "\t {}: [{:p}] -- Peer: [{}:{}] State: '{}', NumMatchingOnFabric {} NumMatchingOnPeer: {} ActivityTime: {}",
                        index, sort_session, secure_session.get_peer().get_fabric_index(), secure_session.get_peer().get_node_id(),
                        secure_session.get_state(), sort_session.m_num_matching_on_fabric, sort_session.m_num_matching_on_peer,
                        secure_session.get_last_activity_time().as_millis()
                    );
                }
            }
        }

        for option_ss in &mut sortable_sessions[..index] {
            let prev_count = self.allocated();

            if let Some(ss) = option_ss.as_ref() &&
                let Ok(session) = ss.m_session.try_ref() &&
                    let Some(secure_session) = session.as_ref()
            {
                if secure_session.is_pending_eviction() {
                    continue;
                }

                chip_log_progress!(SecureChannel, "Candidate Session {:p} - Attempting to evict...", secure_session);
            } else {
                continue;
            }

            let sortable_session = option_ss.take().unwrap();

            secure_session::inner_mark_for_evication(sortable_session.m_session.clone(), None);
            self.inner_release(&sortable_session.m_session);

            // now this should be very last one handle that hold the to-be-deleted session
            // consume the session with check
            verify_or_die!(sortable_session.m_session.is_unique());
            drop(sortable_session);

            let new_count = self.allocated();

            if new_count < prev_count {
                chip_log_progress!(SecureChannel, "Successfully evicted a session!");

                let shared_session = new_shared_session(Session::new_secure_with(SecureSession::new_with(ptr::addr_of_mut!(*self), secure_session_type,
                    local_session_id)), ptr::addr_of_mut!(self.m_entries_pool));

                verify_or_die!(shared_session.is_ok());

                let shared_session = shared_session.unwrap();
                self.inner_retain(&shared_session);

                return Some(shared_session);
            }
        } // end of sortable sessions walk

        chip_log_error!(SecureChannel, "We couldn't find any session to evict at all, something's wrong!");
        verify_or_die!(false);
        None
    }

    fn allocated(&self) -> usize {
        let mut count = 0usize;

        self.for_each_session_const(|_| { count += 1; Loop::Continue } );

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

    fn default_eviction_policy(eviction_context: &mut EvictionPoilcyContext) {
        let eviction_hint_index = eviction_context.get_session_eviction_hint().get_fabric_index();
        let eviction_hint_id = eviction_context.get_session_eviction_hint().clone();
        eviction_context.m_session_list.sort_by(|option_a, option_b| {
            if option_a.is_none() || option_b.is_none() {
                chip_log_error!(SecureChannel, "invalid sortable session");
                verify_or_die!(false);
            }
            if let Some(a) = option_a.as_ref() &&
                let Some(b) = option_b.as_ref() &&
                let Ok(session_a) = a.m_session.try_ref() &&
                let Ok(session_b) = b.m_session.try_ref() &&
                    let Some(sa) = session_a.as_ref() &&
                    let Some(sb) = session_b.as_ref()
            {
                // Sorting on Key1
                //
                if a.m_num_matching_on_fabric != b.m_num_matching_on_fabric {
                    return b.m_num_matching_on_fabric.cmp(&a.m_num_matching_on_fabric);
                }

                let does_a_match_session_hint_fabric = sa.get_peer().get_fabric_index() == eviction_hint_index;
                let does_b_match_session_hint_fabric = sb.get_peer().get_fabric_index() == eviction_hint_index;


                //
                // Sorting on Key2
                //
                if does_a_match_session_hint_fabric != does_b_match_session_hint_fabric {
                    return does_b_match_session_hint_fabric.cmp(&does_a_match_session_hint_fabric);
                }

                //
                // Sorting on Key3
                //
                if a.m_num_matching_on_peer != b.m_num_matching_on_peer {
                    return b.m_num_matching_on_peer.cmp(&a.m_num_matching_on_peer);
                }

                // We have an evicton hint in two cases:
                //
                // 1) When we just established CASE as a responder, the hint is the node
                //    we just established CASE to.
                // 2) When starting to establish CASE as an initiator, the hint is the
                //    node we are going to establish CASE to.
                //
                // In case 2, we should not end up here if there is an active session to
                // the peer at all (because that session should have been used instead
                // of establishing a new one).
                //
                // In case 1, we know we have a session matching the hint, but we don't
                // want to pick that one for eviction, because we just established it.
                // So we should not consider a session as matching a hint if it's active
                // and is the only session to our peer.
                //
                // Checking for the "active" state in addition to the "only session to
                // peer" state allows us to prioritize evicting defuct sessions that
                // match the hint against other defunct sessions.

                fn session_matches_eviction_hint(hint: &ScopedNodeId, session: &SecureSession, matching_on_peer: u16) -> bool {
                    if session.get_peer() != *hint {
                        return false;
                    }
                    let is_only_active_session_to_peer = session.is_active_session() && matching_on_peer == 0;
                    return !is_only_active_session_to_peer;
                }
                let does_a_match_session_hint = session_matches_eviction_hint(&eviction_hint_id, sa, a.m_num_matching_on_peer);
                let does_b_match_session_hint = session_matches_eviction_hint(&eviction_hint_id, sb, b.m_num_matching_on_peer);

                //
                // Sorting on Key4
                //
                if does_a_match_session_hint != does_b_match_session_hint {
                    return does_b_match_session_hint.cmp(&does_a_match_session_hint);
                }


                let mut a_state_score = 0u32;
                let mut b_state_score = 0u32;
                fn assign_state_score(score: &mut u32, session: &SecureSession) {
                    if session.is_defunct() {
                        *score = 2;
                    } else if session.is_active_session() {
                        *score = 1;
                    } else {
                        *score = 0;
                    }
                }

                assign_state_score(&mut a_state_score, sa);
                assign_state_score(&mut b_state_score, sb);

                //
                // Sorting on Key5
                //
                if a_state_score != b_state_score {
                    return b_state_score.cmp(&a_state_score);
                }

                //
                // Sorting on Key6
                //
                sa.get_last_activity_time().cmp(&sb.get_last_activity_time())
            } else {
                // should not reach here
                chip_log_error!(SecureChannel, "cannot convert to secure session");
                verify_or_die!(false);

                core::cmp::Ordering::Equal
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chip::system::system_clock::{set_monotonic_timestamp, Timestamp, get_monotonic_timestamp};
    use crate::chip::transport::secure_session::AsMut;

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

    #[test]
    fn sort_session_with_key_1() {
        let mut table = SecureSessionTable::new();
        table.init();

        let cat = CATValues::new();
        let config = ReliableMessageProtocolConfig::new();
        let a_fabric_index = KUNDEFINED_FABRIC_INDEX + 1;
        let b_fabric_index = KUNDEFINED_FABRIC_INDEX + 2;

        let a = table.create_new_secure_session_for_test(secure_session::Type::Kcase, u16::MAX, KUNDEFINED_NODE_ID + 1,
            KUNDEFINED_NODE_ID + 1, cat, 1, a_fabric_index, &config);
        assert!(a.is_some());
        let a = a.unwrap();

        let a_copy = SessionHandle::new_with(&a);

        let b = table.create_new_secure_session_for_test(secure_session::Type::Kcase, u16::MAX, KUNDEFINED_NODE_ID + 1,
            KUNDEFINED_NODE_ID + 1, cat, 1, b_fabric_index, &config);
        assert!(b.is_some());
        let b = b.unwrap();

        let sort_a = SortableSession::new(SessionHandle::new_with(&a));
        let mut sort_b = SortableSession::new(SessionHandle::new_with(&b));
        // to simulate different number of matching fabric
        sort_b.m_num_matching_on_fabric += 1;

        let mut sortable_sessions = [Some(sort_a), Some(sort_b)];

        let mut eviction_context = EvictionPoilcyContext::new(&mut sortable_sessions[..], ScopedNodeId::default());

        SecureSessionTable::default_eviction_policy(&mut eviction_context);

        // "a" matches less fabric, so it got swappwd
        assert!(SessionHandle::eq(&a_copy, &sortable_sessions[1].as_ref().unwrap().m_session));
    }

    #[test]
    fn sort_session_with_key_2() {
        let mut table = SecureSessionTable::new();
        table.init();

        let cat = CATValues::new();
        let config = ReliableMessageProtocolConfig::new();
        let a_fabric_index = KUNDEFINED_FABRIC_INDEX + 1;
        let b_fabric_index = KUNDEFINED_FABRIC_INDEX + 2;

        let a = table.create_new_secure_session_for_test(secure_session::Type::Kcase, u16::MAX, KUNDEFINED_NODE_ID + 1,
            KUNDEFINED_NODE_ID + 1, cat, 1, a_fabric_index, &config);
        assert!(a.is_some());
        let a = a.unwrap();

        let a_copy = SessionHandle::new_with(&a);

        let b = table.create_new_secure_session_for_test(secure_session::Type::Kcase, u16::MAX, KUNDEFINED_NODE_ID + 1,
            KUNDEFINED_NODE_ID + 1, cat, 1, b_fabric_index, &config);
        assert!(b.is_some());
        let b = b.unwrap();

        let sort_a = SortableSession::new(SessionHandle::new_with(&a));
        let sort_b = SortableSession::new(SessionHandle::new_with(&b));

        let mut sortable_sessions = [Some(sort_a), Some(sort_b)];

        // "a" is the hint
        let mut eviction_context = EvictionPoilcyContext::new(&mut sortable_sessions[..], ScopedNodeId::default_with_ids(KUNDEFINED_NODE_ID + 1, a_fabric_index));

        SecureSessionTable::default_eviction_policy(&mut eviction_context);

        // "a" is prefer to evict
        assert!(SessionHandle::eq(&a_copy, &sortable_sessions[0].as_ref().unwrap().m_session));
    }

    #[test]
    fn sort_session_with_key_3() {
        let mut table = SecureSessionTable::new();
        table.init();

        let cat = CATValues::new();
        let config = ReliableMessageProtocolConfig::new();
        let a_fabric_index = KUNDEFINED_FABRIC_INDEX + 1;
        let b_fabric_index = KUNDEFINED_FABRIC_INDEX + 2;

        let a = table.create_new_secure_session_for_test(secure_session::Type::Kcase, u16::MAX, KUNDEFINED_NODE_ID + 1,
            KUNDEFINED_NODE_ID + 1, cat, 1, a_fabric_index, &config);
        assert!(a.is_some());
        let a = a.unwrap();

        let a_copy = SessionHandle::new_with(&a);

        let b = table.create_new_secure_session_for_test(secure_session::Type::Kcase, u16::MAX, KUNDEFINED_NODE_ID + 1,
            KUNDEFINED_NODE_ID + 1, cat, 1, b_fabric_index, &config);
        assert!(b.is_some());
        let b = b.unwrap();

        let sort_a = SortableSession::new(SessionHandle::new_with(&a));
        let mut sort_b = SortableSession::new(SessionHandle::new_with(&b));
        // to simulate different number of matching fabric
        sort_b.m_num_matching_on_peer += 1;

        let mut sortable_sessions = [Some(sort_a), Some(sort_b)];

        let mut eviction_context = EvictionPoilcyContext::new(&mut sortable_sessions[..], ScopedNodeId::default());

        SecureSessionTable::default_eviction_policy(&mut eviction_context);

        // "a" has less peer thus got swapped
        assert!(SessionHandle::eq(&a_copy, &sortable_sessions[1].as_ref().unwrap().m_session));
    }

    #[test]
    fn sort_session_with_key_4() {
        let mut table = SecureSessionTable::new();
        table.init();

        let cat = CATValues::new();
        let config = ReliableMessageProtocolConfig::new();
        let a_fabric_index = KUNDEFINED_FABRIC_INDEX + 1;
        let b_fabric_index = a_fabric_index;

        let a = table.create_new_secure_session_for_test(secure_session::Type::Kcase, 10, KUNDEFINED_NODE_ID + 1,
            KUNDEFINED_NODE_ID + 2, cat, 1, a_fabric_index, &config);
        assert!(a.is_some());
        let a = a.unwrap();

        let a_copy = SessionHandle::new_with(&a);

        let b = table.create_new_secure_session_for_test(secure_session::Type::Kcase, 20, KUNDEFINED_NODE_ID + 1,
            KUNDEFINED_NODE_ID + 3, cat, 1, b_fabric_index, &config);
        assert!(b.is_some());
        let b = b.unwrap();

        let mut sort_a = SortableSession::new(SessionHandle::new_with(&a));
        let mut sort_b = SortableSession::new(SessionHandle::new_with(&b));
        // to simulate "a" and "b" are not the only session for the peer
        sort_a.m_num_matching_on_peer += 1;
        sort_b.m_num_matching_on_peer += 1;

        let mut sortable_sessions = [Some(sort_a), Some(sort_b)];

        // "a" match hint id
        let mut eviction_context = EvictionPoilcyContext::new(&mut sortable_sessions[..], ScopedNodeId::default_with_ids(KUNDEFINED_NODE_ID + 2, a_fabric_index));

        SecureSessionTable::default_eviction_policy(&mut eviction_context);

        // "a" is prefered to evit
        assert!(SessionHandle::eq(&a_copy, &sortable_sessions[0].as_ref().unwrap().m_session));
    }

    #[test]
    fn sort_session_with_key_5() {
        let mut table = SecureSessionTable::new();
        table.init();

        let cat = CATValues::new();
        let config = ReliableMessageProtocolConfig::new();
        let a_fabric_index = KUNDEFINED_FABRIC_INDEX + 1;
        let b_fabric_index = KUNDEFINED_FABRIC_INDEX + 2;

        let a = table.create_new_secure_session_for_test(secure_session::Type::Kcase, 10, KUNDEFINED_NODE_ID + 1,
            KUNDEFINED_NODE_ID + 2, cat, 1, a_fabric_index, &config);
        assert!(a.is_some());
        let a = a.unwrap();

        let a_copy = SessionHandle::new_with(&a);

        let b = table.create_new_secure_session_for_test(secure_session::Type::Kcase, 20, KUNDEFINED_NODE_ID + 1,
            KUNDEFINED_NODE_ID + 3, cat, 1, b_fabric_index, &config);
        assert!(b.is_some());
        let b = b.unwrap();
        // mark b as defunct so a will have higher score
        if let Ok(mut mb) = b.try_borrow_mut() &&
            let Some(smb) = mb.as_mut() {
                smb.mark_as_defunct();
        } else {
            assert!(false);
        }


        let sort_a = SortableSession::new(SessionHandle::new_with(&a));
        let sort_b = SortableSession::new(SessionHandle::new_with(&b));

        let mut sortable_sessions = [Some(sort_a), Some(sort_b)];

        let mut eviction_context = EvictionPoilcyContext::new(&mut sortable_sessions[..], ScopedNodeId::default());

        SecureSessionTable::default_eviction_policy(&mut eviction_context);

        assert!(SessionHandle::eq(&a_copy, &sortable_sessions[1].as_ref().unwrap().m_session));
    }

    #[test]
    fn sort_session_with_key_6() {
        let mut table = SecureSessionTable::new();
        table.init();

        let cat = CATValues::new();
        let config = ReliableMessageProtocolConfig::new();
        let a_fabric_index = KUNDEFINED_FABRIC_INDEX + 1;
        let b_fabric_index = KUNDEFINED_FABRIC_INDEX + 2;

        let a = table.create_new_secure_session_for_test(secure_session::Type::Kcase, 10, KUNDEFINED_NODE_ID + 1,
            KUNDEFINED_NODE_ID + 2, cat, 1, a_fabric_index, &config);
        assert!(a.is_some());
        let a = a.unwrap();

        let a_copy = SessionHandle::new_with(&a);

        let b = table.create_new_secure_session_for_test(secure_session::Type::Kcase, 20, KUNDEFINED_NODE_ID + 1,
            KUNDEFINED_NODE_ID + 3, cat, 1, b_fabric_index, &config);
        assert!(b.is_some());
        let b = b.unwrap();

        // mark a as later activated
        let _ = set_monotonic_timestamp(Timestamp::from_secs(2));
        if let Ok(mut ma) = a.try_borrow_mut() &&
            let Some(sma) = ma.as_mut() {
                sma.mark_active();
        } else {
            assert!(false);
        }


        let sort_a = SortableSession::new(SessionHandle::new_with(&a));
        let sort_b = SortableSession::new(SessionHandle::new_with(&b));

        let mut sortable_sessions = [Some(sort_a), Some(sort_b)];

        let mut eviction_context = EvictionPoilcyContext::new(&mut sortable_sessions[..], ScopedNodeId::default());

        SecureSessionTable::default_eviction_policy(&mut eviction_context);

        assert!(SessionHandle::eq(&a_copy, &sortable_sessions[1].as_ref().unwrap().m_session));
    }

    #[test]
    fn evict_one() {
        let mut table = SecureSessionTable::new();
        table.init();

        let cat = CATValues::new();
        let config = ReliableMessageProtocolConfig::new();
        let a_fabric_index = KUNDEFINED_FABRIC_INDEX + 1;

        assert!(table.create_new_secure_session_for_test(secure_session::Type::Kcase, 10, KUNDEFINED_NODE_ID + 1,
            KUNDEFINED_NODE_ID + 2, cat, 1, a_fabric_index, &config).is_some());

        assert_eq!(1, table.allocated());
        let hint = ScopedNodeId::default();

        assert!(table.evict_and_allocate(11, secure_session::Type::Kcase, &hint).is_some());
        assert_eq!(1, table.allocated());
    }

    #[test]
    fn evict_twice() {
        let mut table = SecureSessionTable::new();
        table.init();

        let cat = CATValues::new();
        let config = ReliableMessageProtocolConfig::new();
        let a_fabric_index = KUNDEFINED_FABRIC_INDEX + 1;

        assert!(table.create_new_secure_session_for_test(secure_session::Type::Kcase, 10, KUNDEFINED_NODE_ID + 1,
            KUNDEFINED_NODE_ID + 2, cat, 1, a_fabric_index, &config).is_some());

        assert!(table.create_new_secure_session_for_test(secure_session::Type::Kcase, 11, KUNDEFINED_NODE_ID + 2,
            KUNDEFINED_NODE_ID + 3, cat, 2, a_fabric_index + 1, &config).is_some());

        assert_eq!(2, table.allocated());
        let hint = ScopedNodeId::default();

        assert!(table.evict_and_allocate(13, secure_session::Type::Kcase, &hint).is_some());
        assert_eq!(2, table.allocated());
        assert!(table.evict_and_allocate(14, secure_session::Type::Kcase, &hint).is_some());
        assert_eq!(2, table.allocated());
    }

    #[test]
    #[should_panic]
    fn evict_none() {
        let mut table = SecureSessionTable::new();
        table.init();

        let hint = ScopedNodeId::default();

        assert!(table.evict_and_allocate(11, secure_session::Type::Kcase, &hint).is_none());
    }

    #[test]
    fn create_one_session() {
        let mut table = SecureSessionTable::new();
        table.init();

        assert!(table.create_new_secure_session(secure_session::Type::Kcase, ScopedNodeId::default()).is_some());
    }

    #[test]
    fn create_two_session() {
        let mut table = SecureSessionTable::new();
        table.init();

        assert!(table.create_new_secure_session(secure_session::Type::Kcase, ScopedNodeId::default()).is_some());

        assert!(table.create_new_secure_session(secure_session::Type::Kcase, ScopedNodeId::default()).is_some());
    }

    #[test]
    fn create_more_than_pool_size() {
        let mut table = SecureSessionTable::new();
        table.init();

        for _i in 0..=POOL_SIZE {
            assert!(table.create_new_secure_session(secure_session::Type::Kcase, ScopedNodeId::default()).is_some());
        }
    }
} // end of tests
