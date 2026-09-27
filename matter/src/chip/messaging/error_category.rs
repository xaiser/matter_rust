use crate::{
    ChipError,
    chip_core_error,
    chip_sdk_error,
    chip_error_not_implemented,
    chip_error_outbound_message_too_big,
    chip_error_message_too_long,
    chip_error_no_memory,
    chip_config_is_platform_error_non_critical,
};

/*
 *  Checks if error, while sending, is critical enough to report to the application.
 *
 */
pub fn is_send_error_non_critical(err: ChipError) -> bool {
    return err == chip_error_not_implemented!() || err == chip_error_outbound_message_too_big!() || err == chip_error_message_too_long!() ||
        err == chip_error_no_memory!() || chip_config_is_platform_error_non_critical!(err);
}
