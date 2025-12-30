use crate::{
    chip:: {
        chip_lib::support::default_string::DefaultString,
    },
    ChipErrorResult,
    chip_ok,
    chip_core_error,
    chip_sdk_error,
    chip_error_buffer_too_small,
    chip_error_invalid_argument,
};

use core::{
    fmt::Write,
    mem::size_of,
};
use bitflags::{bitflags, Flags};

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct HexFlags: u32 {
        const Knone = 0u32;
        // Use uppercase A-F if set otherwise, lowercase a-f
        const Kuppercase = (1u32 << 0);
        // Null-terminate buffer
        const KnullTerminate = (1u32 << 1);
        // Both use uppercase and null-termination.
        // Separately stated to avoid casts for common case.
        const KuppercaseAndNullTerminate = ((1u32 << 0) | (1u32 << 1));
    }
}

/*
 * Encode a buffer of bytes into hexadecimal, with or without null-termination
 * and using either lowercase or uppercase hex. The input bytes are assumed to be
 * in a big-engian order. The output is also in a big-endian order.
 *
 * Default is lowercase output, not null-terminated.
 *
 * If `flags` has `HexFlags::kNullTerminate` set, treat `dest_hex` as a
 * null-terminated string buffer. The function returns CHIP_ERROR_BUFFER_TOO_SMALL
 * if `dest_size_max` can't fit the entire encoded buffer, and the
 * null-terminator if enabled. This function will never output truncated data.
 * The result either fits and is written, or does not fit and nothing is written
 * to `dest_hex`.
 *
 * On success, number of bytes written to destination is always:
 *   output_size = (src_size * 2) + ((flags & HexFlags::kNullTerminate) ? 1 : 0);
 *
 * @param src_bytes Pointer to buffer to convert.  Only allowed to be null if
 *                  src_size is 0.
 * @param [out] dest_hex Destination buffer to receive hex encoding
 *                      including null-terminator if needed.
 * @param flags Flags from `HexFlags` for formatting options
 *
 * @return CHIP_ERROR_BUFFER_TOO_SMALL on dest_max_size too small to fit output
 * @return CHIP_ERROR_INVALID_ARGUMENT if either src_bytes or dest_hex is
 *                                     nullptr without the corresponding size
 *                                     being 0.
 * @return CHIP_NO_ERROR on success
 */

pub fn bytes_to_hex(src: &[u8], dest: &mut [u8], flags: HexFlags) -> ChipErrorResult {
    /*
    let mut tmp = DefaultString::<10>::const_default();

    if let Ok(hex_str) = write!(&mut tmp, "0x{:x}", dest) {
    }
    */
    chip_ok!()
}

pub fn uint64_to_hex(src: u64, dest: &mut [u8], flags: HexFlags) -> ChipErrorResult {
    const MAX_LEN: usize = size_of::<u64>() + 1;
    let mut tmp = DefaultString::<MAX_LEN>::const_default();

    if write!(&mut tmp, "{:x}", src).is_ok() {
        if dest.len() >= tmp.len() {
            dest[..tmp.len()].copy_from_slice(tmp.const_bytes());
        } else {
            return Err(chip_error_buffer_too_small!());
        }
    } else {
        return Err(chip_error_invalid_argument!());
    }

    if flags.intersects(HexFlags::KnullTerminate) {
        if dest.len() >= (tmp.len() + 1) {
            dest[tmp.len()] = b'\0';
        } else {
            return Err(chip_error_buffer_too_small!());
        }
    }

    chip_ok!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn uint64_to_hex_correctlly() {
        let mut buf = [0u8; 32];
        let value = 0x1u64;
        const SIZE: usize = size_of::<u64>();
        let mut expected_output = [b'0'; SIZE];
        expected_output[SIZE - 1] = b'1';
        assert!(uint64_to_hex(value, &mut buf, HexFlags::Knone).is_ok());
        assert_eq!(expected_output[..SIZE], buf[..SIZE]);
    }
} // end of tests
