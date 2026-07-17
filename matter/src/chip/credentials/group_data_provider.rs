use crate::{
    chip::{
        chip_lib::{
            core::{
                data_model_types::{KeysetId, EndpointId, KUNDEFINED_FABRIC_INDEX},
                chip_config::{CHIP_CONFIG_MAX_GROUP_NAME_LENGTH, CHIP_CONFIG_MAX_GROUPS_PER_FABRIC, CHIP_CONFIG_MAX_GROUP_KEYS_PER_FABRIC},
                group_id::KUNDEFINED_GROUP_ID,
            },
            support::default_string::DefaultString,
        },
        crypto::SymmetricKeyContext,
        GroupId, FabricIndex,
    },
    ChipError,
    ChipErrorResult,
    verify_or_return_error,
    verify_or_return_value,
};

use core::ptr::NonNull;
use zzz_generated::cluster_enums;

pub type SecurityPolicy = cluster_enums::GroupKeyManagement::GroupKeySecurityPolicyEnum;
pub const KIDENTITY_PROTECTION_KEY_SET_ID: KeysetId = 0;

/// Group Info
pub const KGROUP_NAME_MAX: usize = CHIP_CONFIG_MAX_GROUP_NAME_LENGTH;
pub type GroupInfoName = DefaultString< { KGROUP_NAME_MAX + 1 } >;

#[derive(Clone)]
pub struct GroupInfo {
    // Identifies group within the scope of the given Fabric
    pub group_id: GroupId,
    // Lastest group name written for a given GroupId on any Endpoint via the Groups cluster
    pub name: GroupInfoName,
}

impl GroupInfo {
    pub const fn new() -> Self {
        Self {
            group_id: KUNDEFINED_GROUP_ID,
            name: GroupInfoName::new(),
        }
    }

    pub fn new_with_str(group_name: &str) -> Self {
        Self {
            group_id: KUNDEFINED_GROUP_ID,
            name: GroupInfoName::from(group_name),
        }
    }

    pub fn new_with(id: GroupId, group_name: &str) -> Self {
        Self {
            group_id: id,
            name: GroupInfoName::from(group_name),
        }
    }

    pub fn set_name(&mut self, group_name: Option<&str>) {
        if let Some(name) = group_name {
            self.name = GroupInfoName::from(name);
        } else {
            self.name.clear();
        }
    }
}

impl PartialEq for GroupInfo {
    fn eq(&self, other: &Self) -> bool {
        self.group_id == other.group_id && self.name == self.name
    }
}

/// Group Key
pub struct GroupKey {
    // Identifies group within the scope of the given Fabric
    pub group_id: GroupId,
    // Set of group keys that generate operational group keys for use with this group
    pub keyset_id: KeysetId,
}

impl GroupKey {
    pub const fn new() -> Self {
        Self {
            group_id: KUNDEFINED_GROUP_ID,
            keyset_id: 0,
        }
    }

    pub const fn new_with(group_id: GroupId, keyset_id: KeysetId) -> Self {
        Self {
            group_id,
            keyset_id,
        }
    }
}

impl PartialEq for GroupKey {
    fn eq(&self, other: &Self) -> bool {
        self.group_id == other.group_id && self.keyset_id == self.keyset_id
    }
}

/// Group Endpoint
pub struct GroupEndpoint {
    // Identifies group within the scope of the given Fabric
    pub group_id: GroupId,
    // Endpoint on the Node to which messages to this group may be forwarded
    pub endpoint_id: EndpointId,
}

impl GroupEndpoint {
    pub const fn new() -> Self {
        Self {
            group_id: KUNDEFINED_GROUP_ID,
            endpoint_id: 0,
        }
    }

    pub const fn new_with(group_id: GroupId, endpoint_id: EndpointId) -> Self {
        Self {
            group_id,
            endpoint_id,
        }
    }
}

impl PartialEq for GroupEndpoint {
    fn eq(&self, other: &Self) -> bool {
        self.group_id == other.group_id && self.endpoint_id == self.endpoint_id
    }
}

/// Group Session
pub struct GroupSession<KeyContext: SymmetricKeyContext> {
    pub group_id: GroupId,
    pub fabric_index: FabricIndex,
    pub security_policy: SecurityPolicy,
    pub key_context: Option<NonNull<KeyContext>>,
}

impl<KeyContext: SymmetricKeyContext> GroupSession<KeyContext> {
    pub const fn new() -> Self {
        Self {
            group_id: KUNDEFINED_GROUP_ID,
            fabric_index: KUNDEFINED_FABRIC_INDEX,
            security_policy: SecurityPolicy::KcacheAndSync,
            key_context: None,
        }
    }
}

mod epoch_key {
    pub const KLENGTH_BYTES: usize = crate::chip::crypto::CHIP_CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES;
}

/// EpochKey
// An EpochKey is a single key usable to determine an operational group key
pub struct EpochKey {
    // Validity start time in microseconds since 2000-01-01T00:00:00 UTC ("the Epoch")
    pub start_time: u64,
    // Actual key bits. Depending on context, it may be a raw epoch key (as seen within `SetKeySet` calls)
    // or it may be the derived operational group key (as seen in any other usage).
    pub key: [u8; epoch_key::KLENGTH_BYTES],
}

impl EpochKey {
    pub const fn new() -> Self {
        Self {
            start_time: 0,
            key: [0u8; epoch_key::KLENGTH_BYTES],
        }
    }

    pub fn clear(&mut self) {
        self.start_time = 0;
        crate::chip::crypto::clear_secret_data(&mut self.key);
    }
}

impl PartialEq for EpochKey {
    fn eq(&self, other: &Self) -> bool {
        self.start_time == other.start_time && self.key == other.key
    }
}

pub mod key_set {
    pub const KEPOCH_KEYS_MAX: usize = 3;
}

pub struct KeySet {
    // The actual keys for the group key set
    pub epoch_keys: [EpochKey; key_set::KEPOCH_KEYS_MAX],
    // Logical id provided by the Administrator that configured the entry
    pub keyset_id: u16,
    // Security policy to use for groups that use this keyset
    pub policy: SecurityPolicy,
    // Number of keys present
    pub num_keys_used: u8,
}

impl KeySet {
    pub const fn new() -> Self {
        Self {
            epoch_keys: [ const { EpochKey::new() }; key_set::KEPOCH_KEYS_MAX],
            keyset_id: 0,
            policy: SecurityPolicy::KcacheAndSync,
            num_keys_used: 0,
        }
    }

    pub const fn new_with(keyset_id: u16, policy: SecurityPolicy, num_keys_used: u8) -> Self {
        Self {
            epoch_keys: [ const { EpochKey::new() }; key_set::KEPOCH_KEYS_MAX],
            keyset_id,
            policy,
            num_keys_used,
        }
    }

    pub fn clear_keys(&mut self) {
        for k in &mut self.epoch_keys {
            k.clear();
        }
    }
}

impl PartialEq for KeySet {
    fn eq(&self, other: &Self) -> bool {
        verify_or_return_error!(self.policy == other.policy && self.num_keys_used == other.num_keys_used, false);
        for (this, other) in self.epoch_keys.iter().zip(other.epoch_keys.iter()) {
            if *this != *other {
                return false;
            }
        }

        true
    }
}

pub trait GroupListener {
    /*
     *  Callback invoked when a new group is added.
     *
     *  @param[in] new_group  GroupInfo structure of the new group.
     */
    fn on_group_added(&mut self, fabric_index: FabricIndex, new_group: &GroupInfo);
    /*
     *  Callback invoked when an existing group is removed.
     *
     *  @param[in] old_group  GroupInfo structure of the removed group.
     */
    fn on_group_removed(&mut self, fabric_index: FabricIndex, old_group: &GroupInfo);
}

pub trait GroupDataProvider {
    type GroupInfoIterator;
    type GroupKeyIterator;
    type EndpointIterator;
    type KeySetIterator;
    type GroupSessionIterator;
    type Listener: GroupListener;

    fn new() -> Self where Self: Sized{
        <Self as GroupDataProvider>::new_with(CHIP_CONFIG_MAX_GROUPS_PER_FABRIC as u16, CHIP_CONFIG_MAX_GROUP_KEYS_PER_FABRIC as u16)
    }

    fn new_with(max_group_per_fabric: u16, max_group_keys_per_fabric: u16) -> Self;

    fn get_max_groups_per_fabric(&self) -> u16;

    fn get_max_group_keys_per_fabric(&self) -> u16;

    fn init(&mut self) -> ChipErrorResult;

    fn finish(&mut self);

    // By id
    fn set_group_info(&mut self, fabric_index: FabricIndex, info: &GroupInfo) -> ChipErrorResult;
    fn get_group_info(&self, fabric_index: FabricIndex, group_id: GroupId) -> Result<GroupInfo, ChipError>;
    fn remove_group_info(&mut self, fabric_index: FabricIndex, group_id: GroupId) -> ChipErrorResult;
    // By index
    fn set_group_info_at(&mut self, fabric_index: FabricIndex, index: usize, info: &GroupInfo) -> ChipErrorResult;
    fn get_group_info_at(&self, fabric_index: FabricIndex, index: usize) -> Result<GroupInfo, ChipError>;
    fn remove_group_info_at(&mut self, fabric_index: FabricIndex, index: usize) -> ChipErrorResult;

    // Endpoints
    fn has_endpoint(&self, fabric_index: FabricIndex, group_id: GroupId, endpoint_id: EndpointId) -> bool;
    fn add_endpoint(&mut self, fabric_index: FabricIndex, group_id: GroupId, endpoint_id: EndpointId) -> ChipErrorResult;
    fn remove_endpoint(&mut self, fabric_index: FabricIndex, group_id: Option<GroupId>, endpoint_id: EndpointId) -> ChipErrorResult;

    // Iterators
    fn iter_group_info(&self, fabric_index: FabricIndex) -> Option<Self::GroupInfoIterator>;
    fn iter_endpoints(&self, fabric_index: FabricIndex, group_id: Option<GroupId>) -> Option<Self::EndpointIterator>;

    //
    // Group-Key map
    //
    fn set_group_key_at(&mut self, fabric_index: FabricIndex, index: usize, info: &GroupKey) -> ChipErrorResult;
    fn get_group_key_at(&self, fabric_index: FabricIndex, index: usize) -> Result<GroupKey, ChipError>;
    fn remove_group_key_at(&mut self, fabric_index: FabricIndex, index: usize) -> ChipErrorResult;
    fn remove_group_keys(&mut self, fabric_index: FabricIndex) -> ChipErrorResult;

    fn iter_group_keys(&self, fabric_index: FabricIndex) -> Option<Self::GroupKeyIterator>;

    //
    // Key Sets
    //
    fn set_key_set(&mut self, fabric_index: FabricIndex, compressed_fabric_id: &[u8], keys: &KeySet) -> ChipErrorResult;
    fn get_key_set(&self, fabric_index: FabricIndex, keyset_id: KeysetId) -> Result<KeySet, ChipError>;
    fn remove_key_set(&mut self, fabric_index: FabricIndex, keyset_id: KeysetId) -> ChipErrorResult;

    /*
     * @brief Obtain the actual operational Identity Protection Key (IPK) keyset for a given
     *        fabric. These keys are used by the CASE protocol, and do not participate in
     *        any direct traffic encryption. Since the identity protection operational keyset
     *        is used in multiple key derivations and procedures, it cannot be hidden behind a
     *        SymmetricKeyContext, and must be obtainable by value.
     *
     * @param fabric_index - Fabric index for which to get the IPK operational keyset
     * @param out_keyset - Reference to a KeySet where the IPK keys will be stored on success
     * @return CHIP_NO_ERROR on success, CHIP_ERROR_NOT_FOUND if the IPK keyset is somehow unavailable
     *         or another CHIP_ERROR value if an internal storage error occurs.
     */
    fn get_ipk_key_set(&self, fabric_index: FabricIndex) -> Result<&KeySet, ChipError>;

    fn iter_key_sets(&self, fabric_index: FabricIndex) -> Option<Self::KeySetIterator>;

    fn remove_fabric(&mut self, fabric_index: FabricIndex) -> ChipErrorResult;

    fn iter_group_session(&self, session_id: u16) -> Option<Self::GroupSessionIterator>;
    fn get_key_context<C: crate::chip::crypto::SymmetricKeyContext>(&mut self, fabric_index: FabricIndex, group_id: GroupId) -> Result<&C, ChipError>;

    fn set_listener(&mut self, listener: Option<NonNull<Self::Listener>>);
    fn remove_listener(&mut self);
}
