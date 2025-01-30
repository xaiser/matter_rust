#![cfg_attr(test, allow(unused_imports))]
#![cfg_attr(not(test), no_std)]

#[cfg(all(not(test), feature = "panic_handler"))]
use core::panic::PanicInfo;

#[cfg(all(not(test), feature = "panic_handler"))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {} // Infinite loop to prevent the program from returning (no std available)
}

pub mod chip;
pub use chip::chip_lib::core::chip_error::ChipError;
pub use chip::chip_lib::core::chip_error;
