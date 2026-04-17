#![allow(dead_code)]
use crate::{
    verify_or_die,
    chip::{
        access::{self, subject_descriptor::SubjectDescriptor},
        ble::ble_config::BTP_ACK_TIMEOUT_MS,
        chip_lib::core::{
            case_auth_tag::CATValues,
            node_id::{KUNDEFINED_NODE_ID, is_operational_node_id, is_pake_key_id},
            data_model_types::KUNDEFINED_FABRIC_INDEX,
        },
        transport::{
            session::{
                SessionType, SessionHolderList, SessionBase, new_session_holder_list, SessionBasePrivate
            },
            raw::peer_address::{self, PeerAddress},
            crypto_context::CryptoContext,
        },
        messaging::{
            session_parameters::SessionParameters,
            reliable_message_protocol_config::ReliableMessageProtocolConfig,
        },
        system::system_clock::{Timestamp, Seconds, Milliseconds, get_monotonic_timestamp},
        ScopedNodeId, NodeId, FabricIndex,
    },
};

use core::cell::OnceCell;

pub trait AsMut {
    fn as_mut(&mut self) -> Option<&mut SecureSession>;
}

pub trait AsRef {
    fn as_ref(&self) -> Option<&SecureSession>;
}

#[derive(PartialEq, Eq, Copy, Clone)]
enum Type {
    Kpase = 1,
    Kcase = 2,
}

pub struct SecureSession {
    m_holders: SessionHolderList,
    m_peer_address: PeerAddress,
    m_remote_session_params: SessionParameters,
    m_last_peer_activity_time: Timestamp,
    m_local_session_id: OnceCell<u16>,
    m_peer_node_id: NodeId,
    m_fabric_index: FabricIndex,
    m_local_node_id: NodeId,
    m_secure_session_type: Type,
    m_is_case_commissioning_session: bool,
    m_peer_cats: CATValues,
    m_crypto_context: CryptoContext,
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

    fn is_active_session(&self) -> bool {
        // TODO: this is just a stub return value
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
        ScopedNodeId::default_with_ids(self.m_peer_node_id, self.get_fabric_index())
    }

    fn get_fabric_index(&self) -> FabricIndex {
        self.m_fabric_index
    }

    fn get_local_scoped_node_id(&self) -> ScopedNodeId {
        ScopedNodeId::default_with_ids(self.m_local_node_id, self.get_fabric_index())
    }

    fn get_subject_descriptor(&self) -> SubjectDescriptor {
        let mut subject_descriptor = SubjectDescriptor::new();

        if is_operational_node_id(self.m_peer_node_id) {
            subject_descriptor.fabric_index = self.get_fabric_index();
            subject_descriptor.auth_mode = access::auth_mode::AuthMode::KCase;
            subject_descriptor.subject = self.m_peer_node_id;
            subject_descriptor.cats = self.m_peer_cats;
            subject_descriptor.is_commissioning = self.is_commissioning_session();
        } else if is_pake_key_id(self.m_peer_node_id) {
            if self.m_crypto_context.is_responder() {
                subject_descriptor.auth_mode = access::auth_mode::AuthMode::KPase;
                subject_descriptor.subject = self.m_peer_node_id;
                subject_descriptor.fabric_index = self.get_fabric_index();
                subject_descriptor.is_commissioning = self.is_commissioning_session();
            }
        } else {
            verify_or_die!(false);
        }

        subject_descriptor
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

    fn is_commissioning_session(&self) -> bool {
        if self.is_pase_session() {
            return true;
        }

        // CASE session is a commissioning session if it was marked as such.
        // The SessionManager is what keeps track.
        if self.is_case_session() && self.m_is_case_commissioning_session {
            return true;
        }

        false
    }

    fn set_fabric_index(&mut self, fabric_index: FabricIndex) {
        self.m_fabric_index = fabric_index
    }

    // no used
    fn session_id_for_logging(&self) -> u16 { 0 }
}

impl SecureSession {
    pub const fn new() -> Self {
        Self {
            m_holders: new_session_holder_list(),
            m_peer_address: PeerAddress::new(),
            m_remote_session_params: SessionParameters::new(),
            m_last_peer_activity_time: Timestamp::ZERO,
            m_local_session_id: OnceCell::new(),
            m_peer_node_id: KUNDEFINED_NODE_ID,
            m_fabric_index: KUNDEFINED_FABRIC_INDEX,
            m_local_node_id: KUNDEFINED_NODE_ID,
            m_secure_session_type: Type::Kpase,
            m_is_case_commissioning_session: false,
            m_peer_cats: CATValues::new(),
            m_crypto_context: CryptoContext::new(),
        }
    }

    pub fn is_establishing(&self) -> bool {
        // TODO: this is just a stub return
        true
    }

    fn get_last_peer_activity_time(&self) -> Timestamp { self.m_last_peer_activity_time }

    pub fn get_local_session_id(&self) -> u16 {
        *(self.m_local_session_id.get_or_init(|| 0))
    }

    #[inline]
    fn get_secure_session_type(&self) -> Type {
        self.m_secure_session_type
    }

    #[inline]
    fn is_case_session(&self) -> bool {
        self.get_secure_session_type() == Type::Kcase
    }

    #[inline]
    fn is_pase_session(&self) -> bool {
        self.get_secure_session_type() == Type::Kpase
    }

    fn is_peer_active(&self) -> bool {
        let now = get_monotonic_timestamp();
        if let Some(diff) = now.checked_sub(self.get_last_peer_activity_time()) {
            return diff < self.get_remote_mrp_config().m_active_threshold_time;
        }

        false
    }
}
