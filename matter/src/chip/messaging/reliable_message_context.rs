use crate::{
    chip::{
        chip_lib::{
            support::{
                logging::text_only_logging::chip_log_value_exchange,
            },
        },
        messaging::{
            exchange_context::ExchangeContext,
            reliable_message_mgr::SharedReliableMessageMgr,
            reliable_message_protocol_config::CHIP_CONFIG_RMP_DEFAULT_ACK_TIMEOUT,
            flags::MessageFlagValues,
        },
        system::{
            system_clock::Timestamp,
            system_packet_buffer::PacketBufferHandle,
        },
    },
    ChipErrorResult, chip_ok,

    chip_internal_log,
    chip_internal_log_impl,
    chip_log_detail,
    //chip_log_error,
};

use core::str::FromStr;
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

    /*
     * Flush the pending Ack for current exchange.
     *
     */
    fn flush_acks(&mut self) -> ChipErrorResult {
        if self.is_ack_pending() {
            self.send_standalone_ack_message()?;

            chip_log_detail!(ExchangeManager, "Flushed pending ack for MessageCounter:{} on exchange {:p}",
                self.base().m_pending_peer_ack_message_counter, self.get_exchange_context_const());
        }

        chip_ok!()
    }

    /*
     * Take the pending peer ack message counter from the context.  This must
     * only be called when HasPiggybackAckPending() is true.  After this call,
     * IsAckPending() will be false; it's the caller's responsibility to send
     * the ack.
     */
    fn take_pending_peer_ack_message_counter(&mut self) -> u32 {
        self.base_mut().set_ack_pending(false);

        self.base().m_pending_peer_ack_message_counter
    }

    /*
     * Check whether we have a mPendingPeerAckMessageCounter. The counter is
     * valid once we receive a message which requests an ack. Once
     * mPendingPeerAckMessageCounter is valid, it never stops being valid.
     */
    fn has_piggyback_ack_pending(&self) -> bool;

    /*
     *  Send a SecureChannel::StandaloneAck message.
     *
     *  @note  When sent via UDP, the null message is sent *without* requesting an acknowledgment,
     *  even in the case where the auto-request acknowledgment feature has been enabled on the
     *  exchange.
     */
    fn send_standalone_ack_message(&mut self) -> ChipErrorResult;

    /*
     *  Determine whether an acknowledgment will be requested whenever a message is sent for the exchange.
     *
     *  @return Returns 'true' an acknowledgment will be requested whenever a message is sent, else 'false'.
     */
    fn auto_request_ack(&self) -> bool {
        self.base().auto_request_ack()
    }

    /*
     * Set whether an acknowledgment should be requested whenever a message is sent.
     *
     * @param[in] autoReqAck            A Boolean indicating whether or not an
     *                                  acknowledgment should be requested whenever a
     *                                  message is sent.
     */
    fn set_auto_request_ack(&mut self, auto_req_ack: bool) {
        self.base_mut().set_auto_request_ack(auto_req_ack)
    }

    /*
     *  Determine whether there is already an acknowledgment pending to be sent to the peer on this exchange.
     *
     *  @return Returns 'true' if there is already an acknowledgment pending  on this exchange, else 'false'.
     */
    fn is_ack_pending(&self) -> bool {
        self.base().is_ack_pending()
    }

    // Determine whether the reliable message context is waiting for an ack.
    fn is_waiting_for_ack(&self) -> bool {
        self.base().is_waiting_for_ack()
    }

    // Set whether the reliable message context is waiting for an ack.
    fn set_waiting_for_ack(&mut self, waiting_for_ack: bool) {
        self.base_mut().set_waiting_ack(waiting_for_ack)
    }

    // Set if this exchange is requesting Sleepy End Device active mode
    fn set_requesting_active_mode(&mut self, active_mode: bool);

    // Determine whether this exchange is a EphemeralExchange for replying a StandaloneAck
    fn is_ephemeral_exchange(&self) -> bool {
        self.base().is_ephemeral_exchange()
    }

    /*
     * Get the reliable message manager that corresponds to this reliable
     * message context.
     */
    fn get_reliable_message_mgr(&self) -> SharedReliableMessageMgr;

    fn get_exchange_context(&mut self) -> &mut ExchangeContext;

    fn get_exchange_context_const(&self) -> &ExchangeContext;

    fn handle_rcvd_ack(&mut self, ack_message_counter: u32) 
        where
            Self: Sized,
    {
        let mgr = self.get_reliable_message_mgr();
        if mgr.get_mut().check_and_rem_retrans_table(self, ack_message_counter) {
            self.base_mut().set_waiting_for_response_or_ack(false);
        } else {
            // This can happen quite easily due to a packet with a piggyback ack
            // being lost and retransmitted.
            chip_log_detail!(ExchangeManager, "CHIP MessageCounter:{} not in RetransTable on exchange {}",
                ack_message_counter, chip_log_value_exchange(self.get_exchange_context_const()));
        }
    }

    fn handle_needs_ack(&mut self, message_counter: u32, message_flags: MessageFlagValues) -> ChipErrorResult {
        let result = self.handle_needs_ack_inner(message_counter, message_flags);

        // Schedule next physical wakeup on function exit
        let mgr = self.get_reliable_message_mgr();
        mgr.get_mut().start_timer();

        result
    }

    fn handle_needs_ack_inner(&mut self, message_counter: u32, message_flags: MessageFlagValues) -> ChipErrorResult {
        // If the message IS a duplicate there will never be a response to it, so we
        // should not wait for one and just immediately send a standalone ack.
        if message_flags.intersects(MessageFlagValues::KduplicateMessage) {
            chip_log_detail!(ExchangeManager,
                "Forcing tx of solitary ack for duplicate MessageCounter: {} on exchange {}",
                message_counter, chip_log_value_exchange(self.get_exchange_context()));

            let was_ack_pending = self.is_ack_pending() && self.base().m_pending_peer_ack_message_counter != message_counter;
            let message_counter_was_valid = self.has_piggyback_ack_pending();
            // Temporary store currently pending ack message counter (even if there is none).
            let temp_ack_message_counter = self.base().m_pending_peer_ack_message_counter;

            self.set_pending_peer_ack_message_counter(message_counter);
            let err = self.send_standalone_ack_message();

            if was_ack_pending {
                // Restore previously pending ack message counter.
                self.set_pending_peer_ack_message_counter(temp_ack_message_counter);
            } else if message_counter_was_valid {
                // Restore the previous value, so later piggybacks will pick it up,
                // but don't set out "ack is pending" state, because we didn't use
                // to have it set.
                self.base_mut().m_pending_peer_ack_message_counter = temp_ack_message_counter;
            }

            // Otherwise don't restore the invalid old mPendingPeerAckMessageCounter
            // value, so we preserve the invariant that once we have had an ack
            // pending we always have a valid mPendingPeerAckMessageCounter.
            return err;
        }
        // Otherwise, the message IS NOT a duplicate.
        if self.is_ack_pending() {
            chip_log_detail!(ExchangeManager,
                "Pending ack queue full; forcing tx of solitary ack for MessageCounter: {} on exchange {}",
                self.base().m_pending_peer_ack_message_counter, chip_log_value_exchange(self.get_exchange_context_const()));
            // Send the Ack for the currently pending Ack in a SecureChannel::StandaloneAck message.
            self.send_standalone_ack_message()?;
        }

        // Replace the Pending ack message counter.
        self.set_pending_peer_ack_message_counter(message_counter);
        self.base_mut().m_next_ack_time = crate::chip::system::system_clock::get_monotonic_timestamp().saturating_add(
            CHIP_CONFIG_RMP_DEFAULT_ACK_TIMEOUT);

        chip_ok!()
    }

    fn set_pending_peer_ack_message_counter(&mut self, peer_ack_message_counter: u32) {
        self.base_mut().set_pending_peer_ack_message_counter(peer_ack_message_counter)
    }
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

    fn set_pending_peer_ack_message_counter(&mut self, peer_ack_message_counter: u32) {
        self.m_pending_peer_ack_message_counter = peer_ack_message_counter;
        self.set_ack_pending(true);
        self.m_flags.insert(MessageFlags::KflagAckMessageCounterIsValid);
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

    #[inline]
    pub fn set_waiting_ack(&mut self, waiting_for_ack: bool) {
        self.m_flags.set(MessageFlags::KflagWaitingForAck, waiting_for_ack)
    }
}
