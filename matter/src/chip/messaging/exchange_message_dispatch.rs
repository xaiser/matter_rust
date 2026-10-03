pub trait ExchangeMessageDispatch {
    fn is_encryption_required(&self) -> bool {
        true
    }
}

pub struct ExchangeMessageDispatchHandle;

impl ExchangeMessageDispatchHandle {
    pub const fn new() -> Self {
        ExchangeMessageDispatchHandle
    }
}

impl ExchangeMessageDispatch for ExchangeMessageDispatchHandle {
}
