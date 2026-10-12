use crate::{
    chip::{
        system::system_clock::Timeout,
    },
    ChipError,
};

pub type TimerCompleteCallback<S: Layer> = fn(&mut S, TimerCallbackContext);
pub type TimerCallbackContext = *mut u8;

pub trait Layer {
    fn init(&mut self) -> ChipError;
    fn shutdown(&mut self);
    fn is_initialized(&self) -> bool;
    fn start_timer<S: Layer>(&self, delay: Timeout, complete: TimerCompleteCallback<S>, app_state: TimerCallbackContext);
    fn cancel_timer<S: Layer>(&self, complete: TimerCompleteCallback<S>, app_state: TimerCallbackContext);
}
