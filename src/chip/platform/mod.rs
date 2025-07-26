pub mod dummy;
pub mod global;
pub mod linux;

#[cfg(test)]
pub use linux::logging::log_v;

#[cfg(not(test))]
pub use dummy::logging::log_v;
