pub trait ExchangeMessageDispatch {}

pub struct ExchangeMessageDispatchHandle;

impl ExchangeMessageDispatchHandle {
    pub const fn new() -> Self {
        ExchangeMessageDispatchHandle
    }
}
