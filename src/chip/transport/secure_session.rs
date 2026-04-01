#![allow(dead_code)]
use crate::chip::{
    ble::ble_config::BTP_ACK_TIMEOUT_MS,
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
    system::system_clock::{Timestamp, Seconds, Milliseconds},
};

pub trait AsMut {
    fn as_mut(&mut self) -> Option<&mut SecureSession>;
}

pub trait AsRef {
    fn as_ref(&self) -> Option<&SecureSession>;
}

pub struct SecureSession {
    m_holders: SessionHolderList,
    m_peer_address: PeerAddress,
    m_remote_session_params: SessionParameters,
    m_last_peer_activity_time: Timestamp,
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
}

impl SecureSession {
    pub const fn new() -> Self {
        Self {
            m_holders: new_session_holder_list(),
            m_peer_address: PeerAddress::new(),
            m_remote_session_params: SessionParameters::new(),
            m_last_peer_activity_time: Timestamp::ZERO,
        }
    }

    pub fn is_establishing(&self) -> bool {
        // TODO: this is just a stub return
        true
    }

    fn get_last_peer_activity_time(&self) -> Timestamp { self.m_last_peer_activity_time }
}
