pub mod global;
pub mod linux;
pub mod dummy;

#[cfg(test)]
pub use linux::logging::log_v;

#[cfg(not(test))]
pub use dummy::logging::log_v;
