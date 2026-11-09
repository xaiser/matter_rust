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

macro_rules! call_on_all_variants {
    ($self:expr, $method:ident $(, $args:expr)*) => {
        match $self {
            ExchangeDelegate::Tmp(tmp) => tmp.$method($($args),*),
        }
    };
}

pub trait ExchangeDelegateTrait {
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
    fn on_message_received(&mut self, ec: *mut ExchangeContext, payload_header: &PayloadHeader, payload: PacketBufferHandle) -> ChipErrorResult;

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
    fn on_response_timeout(&mut self, ec: *mut ExchangeContext);

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
    fn on_exchange_closing(&mut self, ec: *mut ExchangeContext);

    fn get_message_dispatch(&self) -> ExchangeMessageDispatchHandle;
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub struct TestDelegate {
        pub delegate: Box<dyn ExchangeDelegateTrait>,
    }

    impl TestDelegate {
        pub fn new(delegate: impl ExchangeDelegateTrait) -> Self {
            Self {
                delegate: Box::new(delegate),
            }
        }
    }

    impl ExchangeDelegateTrait for TestDelegate {
        fn on_message_received(&mut self, ec: *mut ExchangeContext, payload_header: &PayloadHeader, payload: PacketBufferHandle) -> ChipErrorResult {
            self.delegate.on_message_received(ec, payload_header, payload)
        }

        fn on_response_timeout(&mut self, ec: *mut ExchangeContext) {
            self.delegate.on_response_timeout(ec)
        }

        fn on_exchange_closing(&mut self, _ec: *mut ExchangeContext) {
            self.delegate.on_exchange_closing(ec)
        }

        fn get_message_dispatch(&self) -> ExchangeMessageDispatchHandle {
            self.delegate.get_message_dispatch()
        }
    }
}

pub struct Tmp;

impl ExchangeDelegateTrait for Tmp {
    fn on_message_received(&mut self, _ec: *mut ExchangeContext, _payload_header: &PayloadHeader, _payload: PacketBufferHandle) -> ChipErrorResult {
        chip_ok!()
    }

    fn on_response_timeout(&mut self, _ec: *mut ExchangeContext) {}

    fn on_exchange_closing(&mut self, _ec: *mut ExchangeContext) {}

    fn get_message_dispatch(&self) -> ExchangeMessageDispatchHandle {
        ExchangeMessageDispatchHandle::new_application_exchange_dispatch()
    }
}

pub enum ExchangeDelegate {
    Tmp(Tmp),
    #[cfg(test)]
    Test(tests::TestDelegate),
}

impl ExchangeDelegate {
    pub const fn new_tmp() -> Self {
        ExchangeDelegate::Tmp(Tmp)
    }

    #[cfg(test)]
    pub fn new_test(delegate: impl ExchangeDelegateTrait) -> Self {
        ExchangeDelegate::Test(tests::TestDelegate::new(delegate))
    }

    pub fn dump_to_log(&self) -> &'static str{
        match self {
            ExchangeDelegate::Tmp => "Tmp",
        }
    }
}

impl ExchangeDelegateTrait for ExchangeDelegate {
    fn on_message_received(&mut self, ec: *mut ExchangeContext, payload_header: &PayloadHeader, payload: PacketBufferHandle) -> ChipErrorResult {
        call_on_all_variants!(self, on_message_received)
    }

    fn on_response_timeout(&mut self, ec: *mut ExchangeContext) {
        call_on_all_variants!(self, on_response_timeout)
    }

    fn on_exchange_closing(&mut self, ec: *mut ExchangeContext) {
        call_on_all_variants!(self, on_exchange_closing)
    }

    fn get_message_dispatch(&self) -> ExchangeMessageDispatchHandle {
        call_on_all_variants!(self, get_message_dispatch)
    }
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
    fn on_unsolicated_message_session_received<D: ExchangeDelegateTrait>(&mut self, payload_header: &PayloadHeader, _session: &SessionHandle,
        new_delegate: &mut &mut D) -> ChipErrorResult
    {
        self.on_unsolicated_message_received(payload_header, new_delegate)
    }

    fn on_unsolicated_message_received<D: ExchangeDelegateTrait>(&mut self, _payload_header: &PayloadHeader, _new_delegate: &mut &mut D) -> ChipErrorResult {
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
    fn on_exchange_creation_failed<D: ExchangeDelegateTrait>(&mut self, _delegate: &mut D) {}
}
