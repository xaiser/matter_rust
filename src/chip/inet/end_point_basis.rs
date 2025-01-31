use crate::chip::system::LayerImpl;
use super::inet_layer::EndPointManager;

pub trait EndPointDeletor<EndPointType> {
    fn release(obj: &mut EndPointType);
}

pub trait DefaultWithMgr{
    type EndPointManagerType;
    fn default(mgr: * mut Self::EndPointManagerType) -> Self;
}

pub trait EndPointBasis {
    type EndPointManagerType: EndPointManager;

    fn get_end_point_manager(&self) -> * mut Self::EndPointManagerType;

    fn get_system_layer(&self) -> * mut LayerImpl;
}
