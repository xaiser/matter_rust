use crate::{
    chip::{
        chip_lib::{
            core::{
                chip_persistent_storage_delegate::PersistentStorageDelegate,
                data_model_types::{KeysetId, EndpointId, KUNDEFINED_FABRIC_INDEX},
                //chip_config::{CHIP_CONFIG_MAX_GROUP_NAME_LENGTH, CHIP_CONFIG_MAX_GROUPS_PER_FABRIC, CHIP_CONFIG_MAX_GROUP_KEYS_PER_FABRIC},
                group_id::KUNDEFINED_GROUP_ID,
            },
            support::default_string::DefaultString,
        },
        credentials::group_data_provider::{GroupDataProvider, GroupListener, GroupInfo},
        crypto::{
            self, session_keystore::SessionKeystore,
        },
        GroupId, FabricIndex,
    },
    ChipError,
    ChipErrorResult,
    verify_or_return_error,
    verify_or_return_value,
};

use core::ptr::NonNull;

struct GroupInfoIteratorImpl<Provider: GroupDataProvider>
{
    m_provider: Option<NonNull<Provider>>,
    m_fabric: FabricIndex,
    m_next_id: u16,
    m_count: usize,
    m_total: usize,
}

impl<Provider: GroupDataProvider> GroupInfoIteratorImpl<Provider> {
    pub const fn new() -> Self {
        Self {
            m_provider: None,
            m_fabric: KUNDEFINED_FABRIC_INDEX,
            m_next_id: 0,
            m_count: 0,
            m_total: 0,
        }
    }

    /*
    pub fn new_with(provider: Option<NonNull<Provider>>, fabric_index) -> Self {
    }
    */
}

impl<Provider: GroupDataProvider> Iterator for GroupInfoIteratorImpl<Provider> {
    type Item = GroupInfo;

    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}


pub struct GroupDataProviderImpl<PSD, SKS, LIS>
where
    PSD: PersistentStorageDelegate,
    SKS: SessionKeystore,
    LIS: GroupListener,
{
    m_storage: Option<NonNull<PSD>>,
    m_sesion_keystore: Option<NonNull<SKS>>,
    m_max_groups_per_fabric: u16,
    m_max_group_keys_per_fabric: u16,
    m_listener: Option<NonNull<LIS>>,
}
