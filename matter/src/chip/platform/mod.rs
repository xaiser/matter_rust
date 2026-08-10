pub mod dummy;
pub mod global;
pub mod linux;
mod lock_tracker;

pub use lock_tracker::assert_chip_stack_locked_by_current_thread;

#[cfg(test)]
pub use linux::logging::log_v;

#[cfg(not(test))]
pub use dummy::logging::log_v;
