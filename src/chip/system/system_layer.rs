use crate::ChipError;

pub trait Layer {
    fn init(&mut self) -> ChipError;
    fn shutdown(&mut self);
    fn is_initialized(&self) -> bool;
}


