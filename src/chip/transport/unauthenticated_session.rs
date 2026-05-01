#![allow(dead_code)]
use crate::chip::{
    access::subject_descriptor::SubjectDescriptor,
    ble::ble_config::BTP_ACK_TIMEOUT_MS,
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
        peer_message_counter::PeerMessageCounter,
        session::{
            SessionType, SessionHolderList, SessionBase, new_session_holder_list, SessionBasePrivate,
            SharedSession, Alloactor as Pool, ALLOACTOR_CAP as POOL_SIZE, SessionHandle,
            Session, new_session_alloactor, new_shared_session,
        },
        raw::peer_address::{self, PeerAddress},
    },
    messaging::{
        session_parameters::SessionParameters,
        reliable_message_protocol_config::ReliableMessageProtocolConfig,
    },
    system::system_clock::{Timestamp, Seconds, Milliseconds, get_monotonic_timestamp},
    ScopedNodeId, NodeId, FabricIndex,
};

use crate::{
    ChipErrorResult,
    ChipError,
    chip_ok,
    chip_sdk_error,
    chip_core_error,
    chip_error_no_memory,
    //chip_error_incorrect_state,
    //chip_error_invalid_argument,
    //chip_error_duplicate_message_received,
    chip_error_internal,
    //verify_or_die,
    //verify_or_return_error,
    //verify_or_return_value,
};

use core::{
    ptr::{self, NonNull},
    cell::OnceCell,
};

pub trait AsRef {
    fn as_ref(&self) -> Option<&UnauthenticatedSession>;
}

pub trait AsMut {
    fn as_mut(&mut self) -> Option<&mut UnauthenticatedSession>;
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum SessionRole {
    Kinitiator,
    Kresponder,
}

pub struct UnauthenticatedSession {
    m_holders: SessionHolderList,
    m_peer_address: PeerAddress,
    m_remote_session_params: SessionParameters,
    m_last_peer_activity_time: Timestamp,
    m_last_activity_time: Timestamp,
    m_fabric_index: FabricIndex,
    m_session_role: OnceCell<SessionRole>,
    m_ephemeral_initiator_node_id: OnceCell<NodeId>,
    m_peer_message_counter: PeerMessageCounter,
}

impl SessionBasePrivate for UnauthenticatedSession {
    fn holders(&mut self) -> &mut SessionHolderList {
        &mut self.m_holders
    }
}

impl SessionBase for UnauthenticatedSession {
    fn get_session_type(&self) -> SessionType {
        SessionType::KUnauthenticated
    }

    fn is_active_session(&self) -> bool {
        true
    }

    fn get_ack_timeout(&self, is_first_message_on_exchange: bool) -> Milliseconds {
        match self.m_peer_address.get_transport_type() {
            peer_address::Type::KUdp => {
                let remote_mrp_config = self.m_remote_session_params.get_mrp_config();

                ReliableMessageProtocolConfig::get_retransmission_timeout(remote_mrp_config.m_active_retrans_timeout, remote_mrp_config.m_idle_retrans_timeout,
                    self.get_last_peer_activity_time(), remote_mrp_config.m_active_threshold_time,
                    is_first_message_on_exchange)
            },
            peer_address::Type::KTcp => {
                Seconds::from_secs(30)
            },
            peer_address::Type::KBle => {
                Milliseconds::from_millis(BTP_ACK_TIMEOUT_MS)
            },
            _ => {
                Milliseconds::ZERO
            }
        }
    }

    fn get_message_receipt_timeout(&self, our_last_activity: Timestamp, is_first_message_on_exchange: bool) -> Milliseconds {
        match self.m_peer_address.get_transport_type() {
            peer_address::Type::KUdp => {
                let local_mrp_config = ReliableMessageProtocolConfig::get_local_mrp_config().unwrap_or(ReliableMessageProtocolConfig::get_default_mrp_config());

                ReliableMessageProtocolConfig::get_retransmission_timeout(local_mrp_config.m_active_retrans_timeout, local_mrp_config.m_idle_retrans_timeout,
                    our_last_activity, local_mrp_config.m_active_threshold_time,
                    is_first_message_on_exchange)
            },
            peer_address::Type::KTcp => {
                Seconds::from_secs(30)
            },
            peer_address::Type::KBle => {
                Milliseconds::from_millis(BTP_ACK_TIMEOUT_MS)
            },
            _ => {
                Milliseconds::ZERO
            }
        }
    }

    fn get_peer(&self) -> ScopedNodeId {
        ScopedNodeId::default_with_ids(self.get_peer_node_id(), KUNDEFINED_FABRIC_INDEX)
    }

    fn get_fabric_index(&self) -> FabricIndex {
        self.m_fabric_index
    }

    fn get_subject_descriptor(&self) -> SubjectDescriptor {
        SubjectDescriptor::new()
    }

    fn allows_mrp(&self) -> bool {
        self.m_peer_address.get_transport_type() == peer_address::Type::KUdp
    }

    fn allow_large_payload(&self) -> bool {
        self.m_peer_address.get_transport_type() == peer_address::Type::KTcp
    }

    fn get_remote_session_parameters(&self) -> &SessionParameters {
        &self.m_remote_session_params
    }

    fn get_mrp_base_timeout(&self) -> Timestamp {
        if self.is_peer_active() {
            self.get_remote_mrp_config().m_active_retrans_timeout
        } else {
            self.get_remote_mrp_config().m_idle_retrans_timeout
        }
    }

    fn set_fabric_index(&mut self, fabric_index: FabricIndex) {
        self.m_fabric_index = fabric_index
    }

    // no used
    fn session_id_for_logging(&self) -> u16 { 0 }

    fn get_local_scoped_node_id(&self) -> ScopedNodeId {
        ScopedNodeId::const_default()
    }
}

impl UnauthenticatedSession {
    pub const fn new() -> Self {
        Self {
            m_holders: new_session_holder_list(),
            m_peer_address: PeerAddress::new(),
            m_remote_session_params: SessionParameters::new(),
            m_last_peer_activity_time: Timestamp::ZERO,
            m_last_activity_time: Timestamp::ZERO,
            m_fabric_index: KUNDEFINED_FABRIC_INDEX,
            m_session_role: OnceCell::new(),
            m_ephemeral_initiator_node_id: OnceCell::new(),
            m_peer_message_counter: PeerMessageCounter::new(),
        }
    }

    pub fn new_with(session_role: SessionRole, ephemeral_initiator_node_id: NodeId, peer_address: &PeerAddress,
        config: &ReliableMessageProtocolConfig) -> Self
    {
        let s = Self {
            m_holders: new_session_holder_list(),
            m_peer_address: peer_address.clone(),
            m_remote_session_params: SessionParameters::new_with(config.clone()),
            m_last_peer_activity_time: Timestamp::ZERO,
            m_last_activity_time: get_monotonic_timestamp(),
            m_fabric_index: KUNDEFINED_FABRIC_INDEX,
            //m_session_role: OnceCell::with_value(session_role),
            m_session_role: OnceCell::new(),
            //m_ephemeral_initiator_node_id: OnceCell::with_value(ephemeral_initiator_node_id),
            m_ephemeral_initiator_node_id: OnceCell::new(),
            m_peer_message_counter: PeerMessageCounter::new(),
        };
        let _ = s.m_session_role.set(session_role);
        let _ = s.m_ephemeral_initiator_node_id.set(ephemeral_initiator_node_id);

        s
    }

    fn get_last_peer_activity_time(&self) -> Timestamp { self.m_last_peer_activity_time }

    #[inline]
    fn get_session_role(&self) -> SessionRole {
        *(self.m_session_role.get_or_init(|| SessionRole::Kinitiator))
    }

    #[inline]
    fn get_ephemeral_initiator_node_id(&self) -> NodeId {
        *(self.m_ephemeral_initiator_node_id.get_or_init(|| KUNDEFINED_NODE_ID))
    }

    fn get_peer_node_id(&self) -> NodeId {
        if self.get_session_role() == SessionRole::Kinitiator {
            return KUNDEFINED_NODE_ID;
        }

        self.get_ephemeral_initiator_node_id()
    }

    fn is_peer_active(&self) -> bool {
        if let Some(diff) = get_monotonic_timestamp().checked_sub(self.get_last_peer_activity_time()) {
            return diff < self.get_remote_mrp_config().m_active_threshold_time;
        }

        false
    }

    pub fn get_last_activity_time(&self) -> Timestamp { self.m_last_activity_time }

    pub fn mark_active(&mut self) {
        self.m_last_activity_time = get_monotonic_timestamp();
    }

    pub fn mark_active_rx(&mut self) {
        self.m_last_peer_activity_time = get_monotonic_timestamp();
        self.mark_active();
    }

    pub fn get_peer_address(&self) -> &PeerAddress {
        &self.m_peer_address
    }

    pub fn set_peer_address(&mut self, address: PeerAddress) {
        self.m_peer_address = address;
    }

    pub fn set_remote_session_parameters(&mut self, session_params: SessionParameters) {
        self.m_remote_session_params = session_params;
    }

    pub fn get_peer_message_counter(&self) -> &PeerMessageCounter {
        &self.m_peer_message_counter
    }
}

type EntryType = SharedSession;

pub struct UnauthenticatedSessionTable
{
    m_entries: [Option<SharedSession>; POOL_SIZE],
    m_entries_pool: Pool,
}

impl UnauthenticatedSessionTable
{
    pub const fn new() -> Self {
        Self {
            m_entries: [const { None }; POOL_SIZE],
            m_entries_pool: new_session_alloactor(),
        }
    }

    fn alloc_entry(&mut self, session_role: SessionRole, ephemeral_initiator_node_id: NodeId, peer_address: &PeerAddress,
        config: &ReliableMessageProtocolConfig) -> Result<&SharedSession, ChipError>
    {
        let available_entry_index: Option<usize> = {
            let mut result: Option<usize> = None;
            for (index, s) in self.m_entries.iter().enumerate() {
                if s.is_none() {
                    result = Some(index);
                    break;
                }
            }

            result
        };

        if available_entry_index.is_some() && !self.m_entries_pool.exhausted() {
            // we have avaiable entry in table and have some space in pool
            if let Ok(ss) = new_shared_session(Session::new_unauthenticated_with(UnauthenticatedSession::new_with(
                        session_role, ephemeral_initiator_node_id, peer_address, config)), ptr::addr_of_mut!(self.m_entries_pool)) {
                // we are safe to do this 
                let entry = self.m_entries.get_mut(available_entry_index.unwrap()).unwrap();
                *entry = Some(ss);
                return Ok(entry.as_ref().unwrap());
            } else {
                // should reach here
                return Err(chip_error_internal!());
            }
        }

        // we run out of entry, try to find least used one
        let least_useed_entry_index = self.find_least_recent_used_entry().ok_or(chip_error_no_memory!())?;
        let least_used_entry = self.m_entries.get_mut(least_useed_entry_index).unwrap();
        // since this is the unique rc, this drop will trigger the release in the pool
        *least_used_entry = None;

        if let Ok(ss) = new_shared_session(Session::new_unauthenticated_with(UnauthenticatedSession::new_with(
                    session_role, ephemeral_initiator_node_id, peer_address, config)), ptr::addr_of_mut!(self.m_entries_pool)) {
            // we are safe to do this 
            *least_used_entry = Some(ss);
            return Ok(least_used_entry.as_ref().unwrap());
        } else {
            // should reach here
            return Err(chip_error_internal!());
        }
    }

    fn find_entry(&self, session_role: SessionRole, ephemeral_initiator_node_id: NodeId, peer_address: &PeerAddress) -> Option<&SharedSession> {
        for s in (&self.m_entries).into_iter().filter(|s| s.as_ref().is_some_and(|rc| rc.try_borrow().is_ok())) {
            let rc = s.as_ref().unwrap();
            // we have checked if we can borrow, just go with it
            let session_borrow = rc.borrow();
            let us = session_borrow.as_ref().unwrap();
            if us.get_session_role() == session_role && us.get_ephemeral_initiator_node_id() == ephemeral_initiator_node_id &&
                us.get_peer_address().get_transport_type() == peer_address.get_transport_type() {
                    return Some(rc);
            }
        }

        None
    }

    fn find_least_recent_used_entry(&self) -> Option<usize> {
        let mut result = None;
        let mut oldest_time = Timestamp::MAX;

        for (index, s) in self.m_entries.iter().enumerate().filter(|(index, s)| s.is_some()) {
            let rc = s.as_ref().unwrap();
            if EntryType::is_unique(rc) {
                // we are the only owner, just borrow, no need for check
                let session_borrow = rc.borrow();
                let session = session_borrow.as_ref().unwrap();
                if session.get_last_activity_time() < oldest_time {
                    result = Some(index);
                    oldest_time = session.get_last_activity_time();
                }
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    #[test]
    fn find_least_recent_successfully() {
        let mut table = UnauthenticatedSessionTable::new();
        // create a session
        let session = new_shared_session(Session::new_unauthenticated(), ptr::addr_of_mut!(table.m_entries_pool));
        assert!(session.is_ok());
        let session = session.unwrap();
        table.m_entries[0] = Some(session);
        assert!(table.find_least_recent_used_entry().is_some());
    }

    #[test]
    fn find_least_recent_none() {
        let table = UnauthenticatedSessionTable::new();
        assert!(table.find_least_recent_used_entry().is_none());
    }

    #[test]
    fn find_least_recent_none_no_unique() {
        let mut table = UnauthenticatedSessionTable::new();
        // create a session
        let session = new_shared_session(Session::new_unauthenticated(), ptr::addr_of_mut!(table.m_entries_pool));
        assert!(session.is_ok());
        let session = session.unwrap();
        let _copy = session.clone();
        table.m_entries[0] = Some(session);
        assert!(table.find_least_recent_used_entry().is_none());
    }

    #[test]
    fn find_entry_successfully() {
        let mut table = UnauthenticatedSessionTable::new();
        // create a session
        let session = new_shared_session(Session::new_unauthenticated(), ptr::addr_of_mut!(table.m_entries_pool));
        assert!(session.is_ok());
        let session = session.unwrap();
        let role;
        let e_id;
        let peer_address;
        {
            let session_borrow = session.borrow();
            let us: &UnauthenticatedSession = session_borrow.as_ref().unwrap();
            role = us.get_session_role();
            e_id = us.get_ephemeral_initiator_node_id();
            peer_address = us.get_peer_address().clone();
        }
        table.m_entries[0] = Some(session);
        assert!(table.find_entry(role, e_id, &peer_address).is_some());
    }

    #[test]
    fn find_entry_none_not_matched() {
        let mut table = UnauthenticatedSessionTable::new();
        // create a session
        let session = new_shared_session(Session::new_unauthenticated(), ptr::addr_of_mut!(table.m_entries_pool));
        assert!(session.is_ok());
        let session = session.unwrap();
        let role;
        let e_id;
        let peer_address;
        {
            let session_borrow = session.borrow();
            let us: &UnauthenticatedSession = session_borrow.as_ref().unwrap();
            role = us.get_session_role();
            e_id = us.get_ephemeral_initiator_node_id();
            peer_address = us.get_peer_address().clone();
        }
        table.m_entries[0] = Some(session);
        assert!(table.find_entry(role, e_id + 1, &peer_address).is_none());
    }

    #[test]
    fn find_entry_none_no_entry() {
        let table = UnauthenticatedSessionTable::new();
        let peer_address = PeerAddress::new();
        assert!(table.find_entry(SessionRole::Kinitiator, 0, &peer_address).is_none());
    }

    #[test]
    fn alloc_one_successfully() {
        let mut table = UnauthenticatedSessionTable::new();
        let config = ReliableMessageProtocolConfig::new();
        let peer_address = PeerAddress::new();
        assert!(table.alloc_entry(SessionRole::Kinitiator, 0, &peer_address, &config).is_ok());
    }

    need more test here
} // end of tests
