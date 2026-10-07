pub trait ExchangeMessageDispatch {
    fn is_encryption_required(&self) -> bool {
        true
    }
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
}
