use crate::{
    chip::{
        system::{
            system_clock::Timeout,
        },
    },
    ChipErrorResult,
};

pub type TimerCompleteCallback = fn(*mut u8, TimerCallbackContext);
pub type TimerCallbackContext = *mut u8;

pub trait Layer {
    fn init(&mut self) -> ChipErrorResult;
    fn shutdown(&mut self);
    fn is_initialized(&self) -> bool;
    fn start_timer(&mut self, delay: Timeout, complete: TimerCompleteCallback, app_state: TimerCallbackContext);
    fn cancel_timer(&mut self, complete: TimerCompleteCallback, app_state: TimerCallbackContext);
}
