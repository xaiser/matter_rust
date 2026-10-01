pub mod delegate {
    use crate::{
        chip::{
            messaging::{
                exchange_context::ExchangeContext,
                exchange_message_dispatch::ExchangeMessageDispatchHandle,
            },
            transport::{
                raw::{
                    message_header::PayloadHeader,
                },
            },
            system::system_packet_buffer::PacketBufferHandle,
        },
        ChipErrorResult,
    };

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
    pub type OnMessageReceived = fn(&mut ExchangeContext, &PayloadHeader, PacketBufferHandle) -> ChipErrorResult;

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
    pub type OnResponseTimeout = fn(&mut ExchangeContext);

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
    pub type OnExchangeClosing = fn(&mut ExchangeContext);

    pub type GetMessageDispatch = fn() -> ExchangeMessageDispatchHandle;
}

use delegate::{OnMessageReceived, OnResponseTimeout, OnExchangeClosing, GetMessageDispatch};

pub type ExchangeDelegateContext = *mut u8;

fn default_on_exchange_closing(_ec: &mut ExchangeContext) {}

pub struct ExchangeDelegate {
    pub(super) on_message_receive: OnMessageReceived,
    pub(super) on_response_timeout: OnResponseTimeout,
    pub(super) on_exchange_closing: OnExchangeClosing,
    pub(super) get_message_dispatch: GetMessageDispatch,
    pub(super) context: ExchangeDelegateContext,
}

impl ExchangeDelegate {
    pub fn new(on_message_receive: OnMessageReceived, on_response_timeout: OnResponseTimeout,
        on_exchange_closing: OnExchangeClosing, get_message_dispatch: GetMessageDispatch,
        context: ExchangeDelegateContext) -> Self
    {
        Self {
            on_message_receive,
            on_response_timeout,
            on_exchange_closing,
            get_message_dispatch,
            context,
        }
    }
}

