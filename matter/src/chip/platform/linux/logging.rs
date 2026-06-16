#[cfg(test)]
use crate::chip::logging::LogCategory;

#[cfg(test)]
use std::*;

#[cfg(test)]
pub fn log_v(module_name: &str, category: LogCategory, args: fmt::Arguments) {
    println!("[{}] {} {}", module_name, category, args);
}
