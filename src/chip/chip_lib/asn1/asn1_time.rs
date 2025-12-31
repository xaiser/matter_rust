use crate::{
    chip::{
        chip_lib::{
            support::default_string::DefaultString,
        },
    },
    ChipError,
};

use core::fmt::Write;

pub const K_ASN1_GENERALIZED_TIME_STRING_LENGTH: usize = 15;
pub const K_ASN1_UTC_TIME_STRING_LENGTH: usize = 13;

pub type Asn1UniversalTimeString = DefaultString<K_ASN1_GENERALIZED_TIME_STRING_LENGTH>;

pub struct Asn1UniversalTime {
    pub year: u16,  /*< Year component. Legal interval is 0..9999. */
    pub month: u8,  /*< Month component. Legal interval is 1..12. */
    pub day: u8,    /*< Day of month component. Legal interval is 1..31. */
    pub hour: u8,   /*< Hour component. Legal interval is 0..23. */
    pub minute: u8, /*< Minute component. Legal interval is 0..59. */
    pub second: u8, /*< Second component. Legal interval is 0..59. */
}

impl Default for Asn1UniversalTime {
    fn default() -> Self {
        Asn1UniversalTime::new()
    }
}

impl Asn1UniversalTime {
    pub const fn new() -> Self {
        Self {
            year: 0,
            month: 1,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0
        }
    }

    pub fn export_to_asn1_time_string(&self) -> Result<Asn1UniversalTimeString, ChipError> {
        // X.509/RFC5280 mandates that times before 2050 UTC must be encoded as ASN.1 UTCTime values, while
        // times equal or greater than 2050 must be encoded as GeneralizedTime values.  The only difference
        // (in the context of X.509 DER) is that GeneralizedTimes are encoded with a 4 digit year, while
        // UTCTimes are encoded with a two-digit year.
        let mut time_string = Asn1UniversalTimeString::default();
        if self.year < 1950 || self.year >= 2050 {
            write!(&mut time_string, "{:04}{:02}{:02}{:02}{:02}{:02}Z", self.year, self.month, self.day, self.hour, self.minute, self.second);
        } else {
            write!(&mut time_string, "{:02}{:02}{:02}{:02}{:02}{:02}Z", self.year % 100, self.month, self.day, self.hour, self.minute, self.second);
        }

        return Ok(time_string);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_1949_string() {
        let mut time = Asn1UniversalTime::default();
        time.year = 1949;
        
        assert!(time.export_to_asn1_time_string().is_ok_and(|ts| ts.str().is_some_and(|s| s == "19490101000000Z")));
    }

    #[test]
    fn export_1950_string() {
        let mut time = Asn1UniversalTime::default();
        time.year = 1950;
        
        //assert!(time.export_to_asn1_time_string().is_ok_and(|ts| ts.str().is_some()));
        assert!(time.export_to_asn1_time_string().is_ok_and(|ts| ts.str().is_some_and(|s| {
            return s == "500101000000Z";
        })));
    }

    #[test]
    fn export_2049_string() {
        let mut time = Asn1UniversalTime::default();
        time.year = 2049;
        
        //assert!(time.export_to_asn1_time_string().is_ok_and(|ts| ts.str().is_some()));
        assert!(time.export_to_asn1_time_string().is_ok_and(|ts| ts.str().is_some_and(|s| {
            return s == "490101000000Z";
        })));
    }

    #[test]
    fn export_2050_string() {
        let mut time = Asn1UniversalTime::default();
        time.year = 2050;
        
        assert!(time.export_to_asn1_time_string().is_ok_and(|ts| ts.str().is_some_and(|s| s == "20500101000000Z")));
    }
} // end of tests
