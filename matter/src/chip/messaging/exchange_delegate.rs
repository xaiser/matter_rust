use crate::{
    chip::{
        messaging::{
            exchange_context::exchange_context::ExchangeContext,
            exchange_message_dispatch::ExchangeMessageDispatchHandle,
        },
        transport::{
            session::SessionHandle,
            raw::{
                message_header::PayloadHeader,
            },
        },
        system::system_packet_buffer::PacketBufferHandle,
    },
    ChipErrorResult,
    chip_error_not_implemented,
    chip_core_error,
    chip_sdk_error,
};

pub trait ExchangeDelegate {
    /*
     * @brief
     *   This function is the protocol callback for handling a received CHIP
     *   message.
     *
     *   After calling this method an exchange will close itself unless one of
     *   two things happens:
     *
     *   1) A call to SendMessage on the exchange with the kExpectResponse flag
     *      set.
     *   2) A call to WillSendMessage on the exchange.
     *
     *   Consumers that don't do one of those things MUST NOT retain a pointer
     *   to the exchange.
     */
    fn on_message_received(&mut self, ec: &mut ExchangeContext, payload_header: &PayloadHeader, payload: PacketBufferHandle) -> ChipErrorResult;

    /*
     * @brief
     *   This function is the protocol callback to invoke when the timeout for the receipt
     *   of a response message has expired.
     *
     *   After calling this method an exchange will close itself unless one of
     *   two things happens:
     *
     *   1) A call to SendMessage on the exchange with the kExpectResponse flag
     *      set.
     *   2) A call to WillSendMessage on the exchange.
     *
     *   Consumers that don't do one of those things MUST NOT retain a pointer
     *   to the exchange.
     */
    fn on_response_timeout(&mut self, ec: &mut ExchangeContext);

    /*
     * @brief
     *   This function is the protocol callback to invoke when the associated
     *   exchange context is being closed.
     *
     *   If the exchange was in a state where it was expecting a message to be
     *   sent due to an earlier WillSendMessage call or because the exchange has
     *   just been created as an initiator, the consumer is holding a reference
     *   to the exchange and it's the consumer's responsibility to call
     *   Release() on the exchange at some point.  The usual way this happens is
     *   that the consumer tries to send its message, that fails, and the
     *   consumer calls Close() on the exchange.  Calling Close() after an
     *   OnExchangeClosing() notification is allowed in this situation.
     *
     */
    fn on_exchange_closing(&mut self, ec: &mut ExchangeContext);

    fn get_message_dispatch(&self) -> ExchangeMessageDispatchHandle;
}

pub trait UnsolicatedMessageHandler {
    /*
     * @brief
     *   This function handles an unsolicited CHIP message.
     *
     *   If the implementation returns CHIP_NO_ERROR, it is expected to set newDelegate to the delegate to use for the exchange
     *   handling the message.  The message layer will handle creating the exchange with this delegate.
     *
     *   If the implementation returns an error, message processing will be aborted for this message.
     */
    fn on_unsolicated_message_session_received<D: ExchangeDelegate>(&mut self, payload_header: &PayloadHeader, _session: &SessionHandle,
        new_delegate: &mut &mut D) -> ChipErrorResult
    {
        self.on_unsolicated_message_received(payload_header, new_delegate)
    }

    fn on_unsolicated_message_received<D: ExchangeDelegate>(&mut self, _payload_header: &PayloadHeader, _new_delegate: &mut &mut D) -> ChipErrorResult {
        Err(chip_error_not_implemented!())
    }

    /*
     * @brief
     *   This function is called when OnUnsolicitedMessageReceived successfully returns a new delegate, but the session manager
     *   fails to assign the delegate to a new exchange.  It can be used to free the delegate as needed.
     *
     *   Once an exchange is created with the delegate, the OnExchangeClosing notification can be used to free the delegate as
     *   needed.
     */
    fn on_exchange_creation_failed<D: ExchangeDelegate>(&mut self, _delegate: &mut D) {}
}
