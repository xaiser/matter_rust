use crate::chip::NodeId;

pub struct CatValues(u8);

pub type CaseAuthTag = u32;

const KtagVersionMask: NodeId = 0x0000_0000_0000_FFFF;
const K_MAX_SUBJECT_CAT_ATTRIBUTE_COUNT: usize = crate::chip::chip_lib::core::chip_config::CHIP_CONFIG_CERT_MAX_RDN_ATTRIBUTES - 2;
const K_UNDEFINED_CAT: CaseAuthTag = 0;
const K_TAG_IDENTIFIER_MASK: CaseAuthTag = 0x0000_0000_FFFF_0000;
const K_TAG_IDENTIFIER_SHIFT: u32 = 16;
const K_TAG_VERSION_MASK: CaseAuthTag = 0x0000_0000_0000_FFFF;

pub fn is_valid_case_auth_tag(a_cat: CaseAuthTag) -> bool {
    (a_cat & (KtagVersionMask as u32)) > 0
}

pub const fn get_case_auth_tag_identifier(a_cat: CaseAuthTag) -> u16 {
    ((a_cat & K_TAG_IDENTIFIER_MASK) >> K_TAG_IDENTIFIER_SHIFT) as u16
}

pub fn case_auth_tag_from_node_id(node_id: NodeId) -> CaseAuthTag {
    use crate::chip::chip_lib::core::node_id::K_MASK_CASE_AUTH_TAG;

    return (node_id & K_MASK_CASE_AUTH_TAG) as CaseAuthTag;
}

pub fn get_case_auth_tag_version(a_cat: CaseAuthTag) -> u16 {
    (a_cat & K_TAG_VERSION_MASK) as u16
}

mod case_auth_tag {
    use super::*;
    use crate::{
        chip_core_error,
        chip_error_internal,
        chip_no_error,
        chip_ok,
        chip_sdk_error,
        verify_or_die,
        verify_or_return_error,
        verify_or_return_value,
        chip::chip_lib::core::node_id::{is_case_auth_tag, NodeId},
    };

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
                        (get_case_auth_tag_version(cat_from_noc) >= get_case_auth_tag_version(cat_from_subject)) {
                } {
                    return true;
                }
                false
            })
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
            let mut values = CATValues::new();
            assert!(values.are_valid());
        }

        #[test]
        fn not_valid() {
            let mut values = CATValues::new();
            values.values[0] = K_UNDEFINED_CAT + 1;
            values.values[1] = K_UNDEFINED_CAT + 1;
            assert!(!values.are_valid());
        }
    } // end of tests
}
