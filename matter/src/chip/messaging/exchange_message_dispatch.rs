use crate::{
    chip::{
        transport::{
            session_mgr::{
                SessionManagerTrait,
            },
            session::{
                SessionHandle,
            },
        },
        messaging::{
            reliable_message_context::ReliableMessageContext,
        },
        system::{
            system_packet_buffer::PacketBufferHandle,
        },
        protocols,
    },
    ChipErrorResult, chip_ok,
    chip_error_internal,
    chip_core_error,
    chip_sdk_error,
};

pub trait ExchangeMessageDispatch {
    fn is_encryption_required(&self) -> bool {
        true
    }

    fn send_message<'a, 'b>(&mut self, session_manager: &mut dyn SessionManagerTrait, session: &SessionHandle, exchange_id: u16,
        is_initiator: bool, reliable_message_context: &mut impl ReliableMessageContext<'a, 'b>, is_reliable_transmission: bool,
        protocol: protocols::Id, msg_type: u8, message: PacketBufferHandle) -> ChipErrorResult;
}

mod inner {
    use crate::{
        chip::{
            messaging::{
                application_exchange_dispatch::ApplicationExchangeDispatch,
                ephemeral_exchange_dispatch::EphemeralExchangeDispatch,
            },
        },
    };

    pub enum ExchangeMessageDispatch {
        Ephemeral(EphemeralExchangeDispatch),
        Application(ApplicationExchangeDispatch),
    }

    impl ExchangeMessageDispatch {
        pub const fn new_application_exchange_dispatch() -> Self {
            ExchangeMessageDispatch::Application(ApplicationExchangeDispatch::new())
        }

        pub const fn new_ephemeral_exchange_dispatch() -> Self {
            ExchangeMessageDispatch::Ephemeral(EphemeralExchangeDispatch::new())
        }
    }
}

pub struct ExchangeMessageDispatchHandle {
    dispatch: inner::ExchangeMessageDispatch,
}

impl ExchangeMessageDispatchHandle {
    pub const fn new_application_exchange_dispatch() -> Self {
        Self {
            dispatch: inner::ExchangeMessageDispatch::new_application_exchange_dispatch(),
        }
    }

    pub const fn new_ephemeral_exchange_dispatch() -> Self {
        Self {
            dispatch: inner::ExchangeMessageDispatch::new_ephemeral_exchange_dispatch(),
        }
    }
}

impl ExchangeMessageDispatch for ExchangeMessageDispatchHandle {
    fn send_message<'a, 'b>(&mut self, session_manager: &mut dyn SessionManagerTrait, session: &SessionHandle, exchange_id: u16,
        is_initiator: bool, reliable_message_context: &mut impl ReliableMessageContext<'a, 'b>, is_reliable_transmission: bool,
        protocol: protocols::Id, msg_type: u8, message: PacketBufferHandle) -> ChipErrorResult
    {
        Err(chip_error_internal!())
    }
}
