use crate::chip::{
    chip_lib::{
        support::{
            default_string::DefaultString,
        },
    },
    messaging::{
        exchange_context::exchange_context::ExchangeContext,
    },
    transport::{
        raw::{
            message_header::PayloadHeader,
        },
    },
    protocols,
};

use core::fmt::Write;
use core::ptr::NonNull;

const EXCHANGED_ID_MAX_LENGTH: usize = 8;
const OPTION_NONNULL_MAX_LENGTH: usize = 16;
const PROTOCOL_ID_MAX_LENGTH: usize = 16;

pub fn chip_log_value_exchange_id(id: u16, is_initiator: bool) -> DefaultString<EXCHANGED_ID_MAX_LENGTH> {
    let mut string = DefaultString::<EXCHANGED_ID_MAX_LENGTH>::new();
    if is_initiator {
        let _ = write!(&mut string, "{}{}", id, "i");
    } else {
        let _ = write!(&mut string, "{}{}", id, "r");
    }

    string
}

pub fn chip_log_value_exchange_id_from_received_header(payload_header: &PayloadHeader) -> DefaultString<EXCHANGED_ID_MAX_LENGTH> {
    /*
    let mut string = DefaultString::<EXCHANGED_ID_MAX_LENGTH>::new();
    if payload_header.is_initiator() {
        let _ = write!(&mut string, "{}{}", payload_header.get_exchange_id(), "i");
    } else {
        let _ = write!(&mut string, "{}{}", payload_header.get_exchange_id(), "r");
    }

    string
    */
    chip_log_value_exchange_id(payload_header.get_exchange_id(), payload_header.is_initiator())
}

pub fn chip_log_value_exchange(ec: &ExchangeContext) -> DefaultString<EXCHANGED_ID_MAX_LENGTH>{
    chip_log_value_exchange_id(ec.get_exchange_id(), ec.is_initiator())
}

pub fn chip_log_option_non_null<T: ?Sized>(op: Option<NonNull<T>>) -> DefaultString<OPTION_NONNULL_MAX_LENGTH> {
    let mut string = DefaultString::<OPTION_NONNULL_MAX_LENGTH>::new();
    if let Some(p) = op {
        let _ = write!(&mut string, "{:p}", p.as_ptr());
    } else {
        let _ = write!(&mut string, "None");
    }

    string
}

pub fn chip_log_value_protocol_id(id: &protocols::Id) -> DefaultString<PROTOCOL_ID_MAX_LENGTH> {
    let mut string = DefaultString::<OPTION_NONNULL_MAX_LENGTH>::new();
    let _ = write!(&mut string, "({} {})", id.get_vendor_id(), id.get_protocol_id());

    string
}
