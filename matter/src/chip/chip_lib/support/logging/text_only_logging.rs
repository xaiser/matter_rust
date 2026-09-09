use crate::chip::{
    chip_lib::{
        support::{
            default_string::DefaultString,
        },
    },
    transport::{
        raw::{
            message_header::PayloadHeader,
        },
    },
};

use core::fmt::Write;

const EXCHANGED_ID_MAX_LENGTH: usize = 8;

pub fn chip_log_value_exchange_id_from_received_header(payload_header: &PayloadHeader) -> DefaultString<EXCHANGED_ID_MAX_LENGTH> {
    let mut string = DefaultString::<EXCHANGED_ID_MAX_LENGTH>::new();
    if payload_header.is_initiator() {
        let _ = write!(&mut string, "{}{}", payload_header.get_exchange_id(), "i");
    } else {
        let _ = write!(&mut string, "{}{}", payload_header.get_exchange_id(), "r");
    }

    string
}
