#![allow(dead_code)]
use crate::chip::{
    access::subject_descriptor::SubjectDescriptor,
    ble::ble_config::BTP_ACK_TIMEOUT_MS,
    chip_lib::core::{
        node_id::KUNDEFINED_NODE_ID,
        data_model_types::KUNDEFINED_FABRIC_INDEX,
    },
    transport::{
        session::{
            SessionType, SessionHolderList, SessionBase, new_session_holder_list, SessionBasePrivate
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

use core::cell::OnceCell;

pub trait AsRef {
    fn as_ref(&self) -> Option<&UnauthenticatedSession>;
}

pub trait AsMut {
    fn as_mut(&mut self) -> Option<&mut UnauthenticatedSession>;
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum SessionRole {
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
        }
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
}
