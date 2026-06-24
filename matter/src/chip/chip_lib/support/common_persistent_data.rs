use crate::{
    chip::{
        chip_lib::{
            core::{
                chip_persistent_storage_delegate::PersistentStorageDelegate,
                tlv_writer::{TlvContiguousBufferWriter, TlvWriter},
                tlv_reader::{TlvContiguousBufferReader, TlvReader},
            },
            support::persistent_data::DataAccessor,
        },
    },
    ChipError,
    ChipErrorResult,
    chip_ok,
    chip_sdk_error,
    chip_core_error,
    chip_error_internal,
    verify_or_return_value,
    verify_or_return_error,
};

use core::ptr::NonNull;

pub mod stored_data_list {
    use super::*;
    use crate::{
        chip::{
            chip_lib::{
                core::{
                    tlv_tags::{Tag, context_tag, anonymous_tag},
                    tlv_types::TlvType,
                },
            },
        },
    };

    fn tag_first_entry() -> Tag {
        context_tag(1)
    }

    fn tag_entry_count() -> Tag {
        context_tag(2)
    }

    /// @brief Generic class to implement storage of a list persistently
    /// @tparam EntryType : Type of entry depends on the stored data
    pub trait StoredDataList {
        fn first_entry(&self) -> u16;
        fn entry_count(&self) -> u16;
        fn set_first_entry(&mut self, first_entry: u16);
        fn set_entry_count(&mut self, entry_count: u16);

        fn serialize<Writer: TlvWriter>(&self, writer: &mut Writer) -> ChipErrorResult {
            let mut container = TlvType::KtlvTypeNotSpecified;
            writer.start_container(anonymous_tag(), TlvType::KtlvTypeStructure, &mut container)?;

            writer.put_u16(tag_first_entry(), self.first_entry())?;
            writer.put_u16(tag_entry_count(), self.entry_count())?;

            writer.end_container(container)
        }

        fn deserialize<'a, Reader: TlvReader<'a>>(&mut self, reader: &mut Reader) -> ChipErrorResult {
            reader.next_tag(anonymous_tag())?;
            verify_or_return_error!(TlvType::KtlvTypeStructure == reader.get_type(), Err(chip_error_internal!()));

            let container = reader.enter_container()?;

            // first_entry
            reader.next_tag(tag_first_entry())?;
            self.set_first_entry(reader.get_u16()?);
            // entry_count
            reader.next_tag(tag_entry_count())?;
            self.set_entry_count(reader.get_u16()?);

            reader.exit_container(container)
        }
    }
}

pub mod fabric_list {
    use super::stored_data_list::StoredDataList;
    pub const K_PERSISTENT_FABRIC_BUFFER_MAX: usize = 32;

    pub trait FabricList: StoredDataList {
        const K_UNDEFINED_FABRIC_INDEX: u16 = 0;

        fn clear(&mut self) {
            self.set_first_entry(Self::K_UNDEFINED_FABRIC_INDEX);
            self.set_entry_count(0);
        }
    }
}
