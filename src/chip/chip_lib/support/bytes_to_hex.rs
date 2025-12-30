use crate::{
    ChipErrorResult,
    chip_ok,
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
 * If `src_bytes` and `dest_hex` overlap, the results may be incorrect, depending
 * on overlap, but only the core validity checks are done and it's possible to
 * get CHIP_NO_ERROR with erroneous output.
 *
 * On success, number of bytes written to destination is always:
 *   output_size = (src_size * 2) + ((flags & HexFlags::kNullTerminate) ? 1 : 0);
 *
 * @param src_bytes Pointer to buffer to convert.  Only allowed to be null if
 *                  src_size is 0.
 * @param src_size Number of bytes to convert from src_bytes
 * @param [out] dest_hex Destination buffer to receive hex encoding
 * @param dest_size_max Maximum buffer size for the hex encoded `dest_hex` buffer
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
    chip_ok!()
}

