use crate::{
    chip::{
        chip_lib::{
            core::{
                data_model_types::KeysetId,
                chip_config::CHIP_CONFIG_MAX_GROUP_NAME_LENGTH,
                group_id::KUNDEFINED_GROUP_ID,
            },
            support::default_string::DefaultString,
        },
        GroupId,
    },
};

use zzz_generated::cluster_enums;

pub type SecurityPolicy = cluster_enums::GroupKeyManagement::GroupKeySecurityPolicyEnum;
pub const KIDENTITY_PROTECTION_KEY_SET_ID: KeysetId = 0;

/// Group Info
pub const KGROUP_NAME_MAX: usize = CHIP_CONFIG_MAX_GROUP_NAME_LENGTH;
pub type GroupInfoName = DefaultString< { KGROUP_NAME_MAX + 1 } >;
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
    // Set of group keys that generate operational group keys for use with this group
    pub keyset_id: EndpointsetId,
}

impl GroupEndpoint {
    pub const fn new() -> Self {
        Self {
            group_id: KUNDEFINED_GROUP_ID,
            keyset_id: 0,
        }
    }

    pub const fn new_with(group_id: GroupId, keyset_id: EndpointsetId) -> Self {
        Self {
            group_id,
            keyset_id,
        }
    }
}

impl PartialEq for GroupEndpoint {
    fn eq(&self, other: &Self) -> bool {
        self.group_id == other.group_id && self.keyset_id == self.keyset_id
    }
}
