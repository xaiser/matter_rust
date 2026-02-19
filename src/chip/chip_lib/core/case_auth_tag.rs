use crate::chip::NodeId;

pub struct CatValues(u8);

pub type CaseAuthTag = u32;

const KtagVersionMask: NodeId = 0x0000_0000_0000_FFFF;
const K_MAX_SUBJECT_CAT_ATTRIBUTE_COUNT: usize = crate::chip::chip_lib::core::chip_config::CHIP_CONFIG_CERT_MAX_RDN_ATTRIBUTES - 2;
const K_UNDEFINED_CAT: CaseAuthTag = 0;
const K_TAG_IDENTIFIER_MASK: NodeId = 0x0000_0000_FFFF_0000;
const K_TAG_IDENTIFIER_SHIFT: u32 = 16;
const K_TAG_VERSION_MASK: NodeId = 0x0000_0000_0000_FFFF;

pub fn is_valid_case_auth_tag(a_cat: CaseAuthTag) -> bool {
    (a_cat & (KtagVersionMask as CaseAuthTag)) > 0
}

pub const fn get_case_auth_tag_identifier(a_cat: CaseAuthTag) -> u16 {
    ((a_cat & (K_TAG_IDENTIFIER_MASK as CaseAuthTag)) >> K_TAG_IDENTIFIER_SHIFT) as u16
}

pub fn case_auth_tag_from_node_id(node_id: NodeId) -> CaseAuthTag {
    use crate::chip::chip_lib::core::node_id::K_MASK_CASE_AUTH_TAG;

    return (node_id & K_MASK_CASE_AUTH_TAG) as CaseAuthTag;
}

pub fn get_case_auth_tag_version(a_cat: CaseAuthTag) -> u16 {
    (a_cat & (K_TAG_VERSION_MASK as CaseAuthTag)) as u16
}

mod case_auth_tag {
    use super::*;
    use crate::{
        ChipError,
        ChipErrorResult,
        chip_core_error,
        chip_error_no_memory,
        chip_error_internal,
        chip_no_error,
        chip_ok,
        chip_sdk_error,
        verify_or_die,
        verify_or_return_error,
        verify_or_return_value,
        chip::chip_lib::core::{
            node_id::{is_case_auth_tag, NodeId},
            chip_encoding,
        },
    };

    static K_SERIALIZED_LENGTH: usize = K_MAX_SUBJECT_CAT_ATTRIBUTE_COUNT * core::mem::size_of::<CaseAuthTag>();
    static K_UNDEFINED_CATS: CATValues = CATValues::new();

    pub type Serialized = [u8; K_SERIALIZED_LENGTH];

    pub struct CATValues {
        pub values: [CaseAuthTag; K_MAX_SUBJECT_CAT_ATTRIBUTE_COUNT],
    }

    impl CATValues {
        pub const fn new() -> Self {
            Self {
                values: [K_UNDEFINED_CAT; K_MAX_SUBJECT_CAT_ATTRIBUTE_COUNT],
            }
        }
        pub const fn size() -> usize {
            K_MAX_SUBJECT_CAT_ATTRIBUTE_COUNT
        }

        pub fn get_num_tags_present(&self) -> usize {
            self.values.iter().take_while(|cat| **cat != K_UNDEFINED_CAT).count()
        }

        pub fn contains(&self, tag: CaseAuthTag) -> bool {
            /*
            for _ in self.values.iter().take_while(|cat| **cat != K_UNDEFINED_CAT && **cat == tag) {
                return true;
            }
            */
            self.values.iter().any(|cat| *cat != K_UNDEFINED_CAT && *cat == tag)
        }

        pub fn are_valid(&self) -> bool {
            for (index, candidate) in self.values.iter().enumerate() {
                if *candidate == K_UNDEFINED_CAT {
                    continue;
                }

                if !is_valid_case_auth_tag(*candidate) {
                    return false;
                }

                for (index_other, other) in self.values.iter().enumerate() {
                    if index_other == index {
                        continue;
                    }
                    if *other == K_UNDEFINED_CAT {
                        continue;
                    }

                    let other_id = get_case_auth_tag_identifier(*other);
                    let candidate_id = get_case_auth_tag_identifier(*candidate);
                    if other_id == candidate_id {
                        return false;
                    }
                }
            }

            true
        }

        pub fn contains_identifier(&self, identifier: u16) -> bool {
            self.values.iter().any(|cat| *cat != K_UNDEFINED_CAT && get_case_auth_tag_identifier(*cat) == identifier)
        }

        pub fn check_subject_against_cats(&self, subject: NodeId) -> bool {
            verify_or_return_value!(is_case_auth_tag(subject), false);
            let cat_from_subject = case_auth_tag_from_node_id(subject);

            self.values.iter().any(|cat| {
                let cat_from_noc = *cat;
                if (cat_from_noc != K_UNDEFINED_CAT) &&
                    (get_case_auth_tag_identifier(cat_from_noc) == get_case_auth_tag_identifier(cat_from_subject)) &&
                        (get_case_auth_tag_version(cat_from_subject) > 0) &&
                        (get_case_auth_tag_version(cat_from_noc) >= get_case_auth_tag_version(cat_from_subject))
                {
                    return true;
                }
                false
            })
        }

        pub fn serialize(&self, out_serialized: &mut [u8]) -> ChipErrorResult {
            let mut rest = out_serialized;
            for v in self.values {
                if let Some((current, next_rest)) = rest.split_at_mut_checked(core::mem::size_of::<CaseAuthTag>()) {
                    chip_encoding::little_endian::put_u32(current, v);
                    rest = next_rest;
                } else {
                    return Err(chip_error_no_memory!());
                }
            }

            chip_ok!()
        }

        pub fn deserialize(&mut self, in_serialized: &[u8]) -> ChipErrorResult {
            let mut rest = in_serialized;
            for v in &mut self.values {
                if let Some((current, next_rest)) = rest.split_at_checked(core::mem::size_of::<CaseAuthTag>()) {
                    *v = CaseAuthTag::from_le_bytes(current.try_into().map_err(|_| chip_error_no_memory!())?);
                    rest = next_rest;
                } else {
                    return Err(chip_error_no_memory!());
                }
            }

            chip_ok!()
        }
    }

    impl PartialEq for CATValues {
        fn eq(&self, other: &Self) -> bool {
            // Two sets of CATs confer equal permissions if the sets are exactly equal
            // and the sets are valid.
            // Ignoring kUndefinedCAT values, evaluate this.
            if self.get_num_tags_present() != other.get_num_tags_present() {
                return false;
            }
            if !self.are_valid() || !other.are_valid() {
                return false;
            }

            if self.values.iter().any(|c| {
                let cat = *c;
                if cat == K_UNDEFINED_CAT {
                    return false;
                }
                if !other.contains(cat) {
                    return true;
                }
                false
            }) 
            {
                return false;
            }

            true
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn get_num_tags_present_correctly() {
            let mut values = CATValues::new();
            assert_eq!(0, values.get_num_tags_present());
            values.values[0] = K_UNDEFINED_CAT + 1;
            assert_eq!(1, values.get_num_tags_present());
        }

        #[test]
        fn check_contain_correctly() {
            let mut values = CATValues::new();
            assert!(!values.contains(K_UNDEFINED_CAT + 1));
            values.values[0] = K_UNDEFINED_CAT + 1;
            assert!(values.contains(K_UNDEFINED_CAT + 1));
        }

        #[test]
        fn are_valid_values() {
            let mut values = CATValues::new();
            values.values[0] = K_UNDEFINED_CAT + 1;
            assert!(values.are_valid());
        }

        #[test]
        fn empty_are_valid() {
            let values = CATValues::new();
            assert!(values.are_valid());
        }

        #[test]
        fn not_valid() {
            let mut values = CATValues::new();
            values.values[0] = K_UNDEFINED_CAT + 1;
            values.values[1] = K_UNDEFINED_CAT + 1;
            assert!(!values.are_valid());
        }

        #[test]
        fn check_against_subject_successfully() {
            let mut values = CATValues::new();
            let cat_in_noc: CaseAuthTag = 0x0001_0001;
            let subject: NodeId = 0xFFFF_FFFD_0001_0001;
            values.values[0] = cat_in_noc;
            assert!(values.check_subject_against_cats(subject));
        }

        #[test]
        fn check_against_subject_not_case_tag() {
            let mut values = CATValues::new();
            let cat_in_noc: CaseAuthTag = 0x0001_0001;
            // <= min case tag
            let subject: NodeId = 0xFFFF_FFFC_0001_0001;
            values.values[0] = cat_in_noc;
            assert!(!values.check_subject_against_cats(subject));
        }

        #[test]
        fn check_against_subject_different_id() {
            let mut values = CATValues::new();
            let cat_in_noc: CaseAuthTag = 0x0002_0001;
            let subject: NodeId = 0xFFFF_FFFD_0001_0001;
            values.values[0] = cat_in_noc;
            assert!(!values.check_subject_against_cats(subject));
        }

        #[test]
        fn check_against_subject_version_0() {
            let mut values = CATValues::new();
            let cat_in_noc: CaseAuthTag = 0x0001_0001;
            // make the subject version 0
            let subject: NodeId = 0xFFFF_FFFD_0001_0000;
            values.values[0] = cat_in_noc;
            assert!(!values.check_subject_against_cats(subject));
        }

        #[test]
        fn check_against_subject_version_is_less() {
            let mut values = CATValues::new();
            let cat_in_noc: CaseAuthTag = 0x0001_0001;
            // make the subject has bigger version
            let subject: NodeId = 0xFFFF_FFFD_0001_0002;
            values.values[0] = cat_in_noc;
            assert!(!values.check_subject_against_cats(subject));
        }

        #[test]
        fn eq() {
            let mut values = CATValues::new();
            let cat_in_noc: CaseAuthTag = 0x0001_0001;
            values.values[0] = cat_in_noc;

            let mut values2 = CATValues::new();
            values2.values[0] = cat_in_noc;
            assert!(values == values2);
        }

        #[test]
        fn not_eq_num_tag() {
            let mut values = CATValues::new();
            let cat_in_noc: CaseAuthTag = 0x0001_0001;
            values.values[0] = cat_in_noc;
            values.values[1] = cat_in_noc + 1;

            let mut values2 = CATValues::new();
            values2.values[0] = cat_in_noc;
            assert!(values != values2);
        }

        #[test]
        fn not_eq_left_not_valid() {
            let mut values = CATValues::new();
            let cat_in_noc: CaseAuthTag = 0x0001_0001;
            values.values[0] = cat_in_noc;
            values.values[1] = cat_in_noc;

            let mut values2 = CATValues::new();
            values2.values[0] = cat_in_noc;
            assert!(values != values2);
        }

        #[test]
        fn not_eq_right_not_valid() {
            let mut values = CATValues::new();
            let cat_in_noc: CaseAuthTag = 0x0001_0001;
            values.values[0] = cat_in_noc;

            let mut values2 = CATValues::new();
            values2.values[0] = cat_in_noc;
            values2.values[1] = cat_in_noc;
            assert!(values != values2);
        }

        #[test]
        fn not_eq_not_contains() {
            let mut values = CATValues::new();
            let cat_in_noc: CaseAuthTag = 0x0001_0001;
            values.values[0] = cat_in_noc;

            let mut values2 = CATValues::new();
            values2.values[0] = cat_in_noc + 1;
            assert!(values != values2);
        }

        #[test]
        fn serialized_and_deserized() {
            let mut to_serialized = CATValues::new();
            let cat_in_noc: CaseAuthTag = 0x0001_0001;
            to_serialized.values[0] = cat_in_noc;
            to_serialized.values[1] = cat_in_noc + 0x1_0001;
            to_serialized.values[2] = cat_in_noc + 0x2_0002;

            let mut buffer = [0; K_SERIALIZED_LENGTH];
            assert!(to_serialized.serialize(&mut buffer).is_ok());

            let mut from_serialized = CATValues::new();
            assert!(from_serialized.deserialize(&buffer).is_ok());

            assert!(to_serialized == from_serialized);
        }

        #[test]
        fn serialized_buffer_too_small() {
            let mut to_serialized = CATValues::new();
            let cat_in_noc: CaseAuthTag = 0x0001_0001;
            to_serialized.values[0] = cat_in_noc;
            to_serialized.values[1] = cat_in_noc + 0x1_0001;
            to_serialized.values[2] = cat_in_noc + 0x2_0002;

            let mut buffer = [0; 1];
            assert!(to_serialized.serialize(&mut buffer).is_err());
        }
    } // end of tests
}

pub use case_auth_tag::*;
