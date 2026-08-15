use crate::{
    chip::{
        chip_lib::{
            address_resolve::address_resolve::{
                NodeLookupRequest,
                ResolveResult,
            },
        },
        PeerId
    },
    ChipError,
};

#[derive(Clone)]
pub struct NodeLookupInfo<'a> {
    pub request: &'a NodeLookupRequest,
}

impl<'a> NodeLookupInfo<'a> {
    pub const fn new(request: &'a NodeLookupRequest) -> Self {
        Self {
            request,
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum DiscoveryInfoType {
    KintermediateResult = 0, // Received intermediate address data
    KresolutionDone     = 1, // resolution completed
    KretryDifferent     = 2, // Try a different/new IP address
}

#[derive(Clone)]
pub struct NodeDiscoveredInfo<'a> {
    pub info_type: DiscoveryInfoType,
    pub peer_id: &'a PeerId,
    pub result: &'a ResolveResult,
}

#[derive(Clone)]
pub struct NodeDiscoveryFailedInfo<'a> {
    pub peer_id: &'a PeerId,
    pub error: ChipError,
}
