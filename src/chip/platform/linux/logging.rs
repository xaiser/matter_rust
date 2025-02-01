#[cfg(test)]
use std::*;

#[cfg(test)]
pub fn log_v(module_name: &str, category: u8, args: fmt::Arguments) {
    println!("[{}] {} {}", module_name, category, args);
}
