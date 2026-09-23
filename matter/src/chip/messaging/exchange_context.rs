pub struct ExchangeContext;

impl ExchangeContext {
    pub fn get_exchange_id(&self) -> u16 {
        0
    }

    pub fn is_initiator(&self) -> bool {
        false
    }
}
