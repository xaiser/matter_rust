#[cfg(feature = "chip_stack_lock_tracking_enabled")]
pub fn assert_chip_stack_locked_by_current_thread() {
}

#[cfg(not(feature = "chip_stack_lock_tracking_enabled"))]
pub fn assert_chip_stack_locked_by_current_thread() {
}
