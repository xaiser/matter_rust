use crate::{
    chip::{
        system::system_clock::Timeout,
    },
    ChipError,
};

pub type TimerCompleteCallback = fn(*mut u8, TimerCallbackContext);
pub type TimerCallbackContext = *mut u8;

pub trait Layer {
    fn init(&mut self) -> ChipError;
    fn shutdown(&mut self);
    fn is_initialized(&self) -> bool;
    fn start_timer(&self, delay: Timeout, complete: TimerCompleteCallback, app_state: TimerCallbackContext);
}
