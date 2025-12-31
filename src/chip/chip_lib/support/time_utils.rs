mod base {
    pub(super) const K_YEARS_PER_CENTURY: u8 = 100;
    pub(super) const K_LEAP_YEAR_INTERVAL: u8 = 4;
    pub(super) const K_DAYS_PER_STANDARD_YEAR: u16 = 365;
    pub(super) const K_HOURS_PER_DAY: u8 = 24;
    pub(super) const K_MINUTES_PER_HOUR: u8 = 60;
    pub(super) const K_SECONDS_PER_MINUTE: u8 = 60;
    pub(super) const K_SECONDS_PER_HOUR: u16 = K_SECONDS_PER_MINUTE as u16 * K_MINUTES_PER_HOUR as u16;
    pub(super) const K_SECONDS_PER_DAY: u32 = K_SECONDS_PER_HOUR as u32 * K_HOURS_PER_DAY as u32;
}

mod chip_epoch {
    pub(super) const K_BASE_YEAR: u16 = 2000;
    pub(super) const K_MAX_YEAR: u16 = 2135;
    pub(super) const K_DAYS_SINCE_UNIX_EPOCH: u16 = 10957;
    pub(super) const K_SECONDS_SINCE_UNIX_EPOCH: u64 = K_DAYS_SINCE_UNIX_EPOCH as u64 * super::base::K_SECONDS_PER_DAY as u64;
}

mod internal {
    // Number of years in a Gregorian "cycle", where a cycle is the 400-year period
    // over which the Gregorian calendar repeats.
    pub(super) const K_YEARS_PER_CYCLE: u16 = 400;
    // Total number of days within cycle.
    pub(super) const K_DAYS_PER_CYCLE: u32 = 146097;
    // Total number of days between 0000/03/01 and 1970/01/01.
    pub(super) const K_EPOCH_OFFSET_DAYS: u32 = 719468;
}

#[derive(PartialEq, Eq)]
enum Month {
    Kjanuary   = 1,
    Kfebruary  = 2,
    Kmarch     = 3,
    Kapril     = 4,
    Kmay       = 5,
    Kjune      = 6,
    Kjuly      = 7,
    Kaugust    = 8,
    Kseptember = 9,
    Koctober   = 10,
    Knovember  = 11,
    Kdecember  = 12
}

/* Converts a March-based month number (0=March, 1=April, etc.) to a March-1st based day of year (0=March 1st, 1=March 2nd, etc.).
 *
 * NOTE: This is based on the math described in http://howardhinnant.github.io/date_algorithms.html.
 */
fn march_based_month_to_day_of_year(month: u8) -> u16 {
    ((153 * month + 2) / 5) as u16
}

/* Converts a March-1st based day of year (0=March 1st, 1=March 2nd, etc.) to a March-based month number (0=March, 1=April, etc.).
 */
fn march_based_day_of_year_to_month(day_of_year: u16) -> u8 {
    // This assumes dayOfYear is not using the full uint16_t range, so the cast
    // to uint8_t doesn't overflow.
    ((5 * day_of_year + 2) / 153) as u8
}

/*
 *  @def DaysSinceUnixEpochToCalendarDate
 *
 *  @brief
 *    Convert the number of days since 1970-01-01 to a calendar date.
 *
 *  @param daysSinceEpoch
 *    Number of days since 1970-01-01.
 *
 *  @param year
 *    [OUTPUT] Gregorian calendar year.
 *
 *  @param month
 *    [OUTPUT] Month in standard form (1=January ... 12=December).
 *
 *  @param dayOfMonth
 *    [OUTPUT] Day-of-month in standard form (1=1st, 2=2nd, etc.).
 *
 *  @return
 *     True if the conversion was successful.  False if the year would not fit
 *     in uint16_t.
 */
pub fn days_since_unix_epoch_to_calendar_date(mut days_since_epoch: u32) -> Result<(u16, u8, u8), ()> {
    // NOTE: This algorithm is based on the logic described in http://howardhinnant.github.io/date_algorithms.html.
    if days_since_epoch / base::K_DAYS_PER_STANDARD_YEAR as u32 + 1 > u16::MAX as u32 {
        return Err(());
    }

    // Adjust days value to be relative to 0000-03-01.
    days_since_epoch += internal::K_EPOCH_OFFSET_DAYS;

    // Compute the 400-year Gregorian cycle in which the given day resides.
    let cycle: u32 = days_since_epoch / internal::K_DAYS_PER_CYCLE;

    // Compute the relative day within the cycle.
    let day_of_cycle: u32 = days_since_epoch - (cycle * internal::K_DAYS_PER_CYCLE);

    // Compute the relative year within the cycle, adjusting for leap-years.
    let year_of_cycle: u16 = ((day_of_cycle - day_of_cycle / 1460 + day_of_cycle / 36524 - day_of_cycle / 146906) / base::K_DAYS_PER_STANDARD_YEAR as u32) as u16;

    // Compute the relative day with the year.
    let day_of_year: u16 = (day_of_cycle - (year_of_cycle * base::K_DAYS_PER_STANDARD_YEAR + year_of_cycle / (base::K_LEAP_YEAR_INTERVAL as u16) - year_of_cycle / (base::K_YEARS_PER_CENTURY as u16)) as u32) as u16;

    // Compute a March-based month number (i.e. 0=March...11=February) from the day of year.
    let month = march_based_day_of_year_to_month(day_of_year);

    // Compute the days from March 1st to the start of the corresponding month.
    let days_from_march_1_to_start_of_month = march_based_month_to_day_of_year(month);

    // Compute the day of month in standard form (1=1st, 2=2nd, etc.).
    let day_of_month: u8 = (day_of_year - days_from_march_1_to_start_of_month + 1) as u8;

    // Convert the month number to standard form (1=January...12=December).
    let month: u8 = (month as i16 + { if month < 10 { 3i16 } else { -9i16 } }) as u8;

    // Compute the year, adjusting for the standard start of year (January).
    let mut year: u16 = (year_of_cycle as u32 + cycle * internal::K_YEARS_PER_CYCLE as u32) as u16;
    if month <= (Month::Kfebruary as u8) {
        year += 1;
    }

    Ok((year, month, day_of_month))
}

/*
 *  @brief
 *    Convert the number of seconds since 1970-01-01 00:00:00 UTC to a calendar date and time.
 *
 *  @note
 *    If secondsSinceEpoch is large enough this function will generate bad result. The way it is
 *    used in this file the generated result should be valid. Specifically, the largest
 *    possible value of secondsSinceEpoch input is (UINT32_MAX + kChipEpochSecondsSinceUnixEpoch),
 *    when it is called from ChipEpochToCalendarTime().
 */
fn seconds_since_unix_epoch_to_calendar_time(seconds_since_epoch: u64) -> (u16, u8, u8, u8, u8, u8) {
    (0, 0, 0, 0, 0, 0)
}

pub fn chip_epoch_to_calender_time(chip_epoch_time: u32) -> (u16, u8, u8, u8, u8, u8) {
    return seconds_since_unix_epoch_to_calendar_time(chip_epoch_time as u64 + chip_epoch::K_SECONDS_SINCE_UNIX_EPOCH);
}
