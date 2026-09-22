use crate::{
    chip::{
        messaging::{
            flags::MessageFlagValues,
        },
        system::{
            system_clock::Timestamp,
        },
    },
};

use bitflags::bitflags;

bitflags! {
    #[derive(Copy, Clone)]
    struct MessageFlags: u16 {
        // When set, signifies that this context is the initiator of the exchange.
        const KflagInitiator = (1u16 << 0);

        // When set, signifies that a response is expected for a message that is being sent.
        const KflagResponseExpected = (1u16 << 1);

        // When set, automatically request an acknowledgment whenever a message is sent via UDP.
        const KflagAutoRequestAck = (1u16 << 2);

        // When set, signifies the reliable message context is waiting for an
        // ack: a message that needs an ack has been sent, no ack has been
        // received, and we have not yet run out of MRP retries.
        const KflagWaitingForAck = (1u16 << 3);

        // When set, signifies that there is an acknowledgment pending to be sent back.
        const KflagAckPending = (1u16 << 4);

        // When set, signifies that mPendingPeerAckMessageCounter is valid.
        // The counter is valid once we receive a message which requests an ack.
        // Once mPendingPeerAckMessageCounter is valid, it never stops being valid.
        const KflagAckMessageCounterIsValid = (1u16 << 5);

        // When set, signifies that this exchange is waiting for a call to SendMessage.
        const KflagWillSendMessage = (1u16 << 6);

        // When set, we have had Close() or Abort() called on us already.
        const KflagClosed = (1u16 << 7);

        // When set, signifies that the exchange created sorely for replying a StandaloneAck
        const KflagEphemeralExchange = (1u16 << 8);

        // When set, ignore session being released, because we are releasing it ourselves.
        const KflagIgnoreSessionRelease = (1u16 << 9);

        // This flag is used to determine if the peer (receiver) should be considered active or not.
        // When set, sender knows it has received at least one application-level message
        // from the peer and can assume the peer (receiver) is active.
        // If the flag is not set, we don't know if the peer (receiver) is active or not.
        const KflagReceivedAtLeastOneMessage = (1u16 << 10);

        // When set:
        //
        // (1) We sent a message that expected a response (hence
        //     IsResponseExpected() is true).
        // (2) We have received neither a response nor an ack for that message.
        const KflagWaitingForResponseOrAck = (1u16 << 11);
    }
}

pub trait ReliableMessageContext {
    fn base(&self) -> &BaseReliableMessageContext;
    fn base_mut(&self) -> &mut BaseReliableMessageContext;
}

pub struct BaseReliableMessageContext {
    m_flags: MessageFlags,
    // Next time for triggering Solo Ack
    m_next_ack_time: Timestamp,
    m_pending_peer_ack_message_counter: u32,
}

impl BaseReliableMessageContext {
    pub const fn new() -> Self {
        Self {
            m_flags: MessageFlags::KflagInitiator,
            m_next_ack_time: Timestamp::from_secs(0),
            m_pending_peer_ack_message_counter: 0,
        }
    }

    pub fn take_pending_peer_ack_message_counter(&mut self) -> u32 {
        self.set_ack_pending(false);

        self.m_pending_peer_ack_message_counter
    }

    #[inline]
    pub fn auto_request_ack(&self) -> bool {
        self.m_flags.intersects(MessageFlags::KflagAutoRequestAck)
    }

    #[inline]
    pub fn is_ack_pending(&self) -> bool {
        self.m_flags.intersects(MessageFlags::KflagAckPending)
    }

    #[inline]
    pub fn is_waiting_for_ack(&self) -> bool {
        self.m_flags.intersects(MessageFlags::KflagWaitingForAck)
    }

    #[inline]
    pub fn has_piggyback_ack_pending(&self) -> bool {
        self.m_flags.intersects(MessageFlags::KflagAckMessageCounterIsValid)
    }

    #[inline]
    pub fn set_auto_request_ack(&mut self, auto_req_ack: bool) {
        self.m_flags.set(MessageFlags::KflagAutoRequestAck, auto_req_ack)
    }

    #[inline]
    pub fn set_ack_pending(&mut self, in_ack_pending: bool) {
        self.m_flags.set(MessageFlags::KflagAckPending, in_ack_pending)
    }

    #[inline]
    pub fn is_ephemeral_exchange(&self) -> bool {
        self.m_flags.intersects(MessageFlags::KflagEphemeralExchange)
    }

    #[inline]
    pub fn waiting_for_response_or_ack(&self) -> bool {
        self.m_flags.intersects(MessageFlags::KflagWaitingForResponseOrAck)
    }

    #[inline]
    pub fn set_waiting_for_response_or_ack(&mut self, waiting_for_response_or_ack: bool) {
        self.m_flags.set(MessageFlags::KflagWaitingForResponseOrAck, waiting_for_response_or_ack)
    }
}
