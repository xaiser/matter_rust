pub use chip_certificate_set::*;

mod chip_certificate_set {
    /*
    use crate::chip::{
        CompressedFabricId, FabricId, NodeId, ScopedNodeId, VendorId,
        system::system_clock::Seconds32,
        chip_lib::{
            core::{
                tlv_reader::{TlvContiguousBufferReader, TlvReader},
                tlv_writer::{TlvContiguousBufferWriter, TlvWriter},
                case_auth_tag::CatValues,
                tlv_types::TlvType,
                tlv_tags::{self, anonymous_tag},
                data_model_types::{
                    KUNDEFINED_COMPRESSED_FABRIC_ID, KUNDEFINED_FABRIC_ID, KUNDEFINED_FABRIC_INDEX, is_valid_fabric_index,
                    KMIN_VALID_FABRIC_INDEX, KMAX_VALID_FABRIC_INDEX, FabricIndex,
                },
                chip_persistent_storage_delegate::PersistentStorageDelegate,
                node_id::{is_operational_node_id, KUNDEFINED_NODE_ID},
                chip_encoding,
            },
            support::{
                default_string::DefaultString,
                default_storage_key_allocator::DefaultStorageKeyAllocator,
            }
        },
        credentials::{
            self, last_known_good_time::LastKnownGoodTime, chip_certificate_set::ValidationContext,
            certificate_validity_policy::CertificateValidityPolicy, operational_certificate_store::{CertChainElement, OperationalCertificateStore},
            chip_cert::{CertBuffer, K_MAX_CHIP_CERT_LENGTH, extract_public_key_from_chip_cert_byte, extract_node_id_fabric_id_from_op_cert_byte},
        },
        crypto::{
            self,
            generate_compressed_fabric_id,
            crypto_pal::{P256EcdsaSignature, P256Keypair, P256PublicKey, ECPKey, ECPKeypair, P256KeypairBase, P256SerializedKeypair},
        },
    };
    use crate::chip_core_error;
    use crate::chip_error_invalid_argument;
    use crate::chip_error_buffer_too_small;
    use crate::chip_error_internal;
    use crate::chip_error_key_not_found;
    use crate::chip_ok;
    use crate::chip_sdk_error;
    use crate::tlv_estimate_struct_overhead;
    use crate::verify_or_return_error;
    use crate::verify_or_return_value;
    use crate::ChipErrorResult;
    use crate::ChipError;

    use crate::chip_internal_log;
    use crate::chip_internal_log_impl;
    use crate::chip_log_error;
    use crate::chip_log_progress;

    use super::{FabricLabelString, KFABRIC_LABEL_MAX_LENGTH_IN_BYTES};
    use core::{ptr, str::{self, FromStr}};
    */
    use crate::chip::{
        system::system_clock::Seconds32,
        credentials::chip_cert::{KeyUsageFlags, KeyPurposeFlags, ChipCertificateData},
    };

    enum EffectiveTime {
        CurrentChipEpochTime(Seconds32),
        LastKnownGoodChipEpochTime(Seconds32),
    }

    struct TheValidationContext<'a> {
        pub m_effective_time: EffectiveTime,
        pub m_trust_anchor: &'a ChipCertificateData,
    }

    pub struct ValidationContext(u8);
}
