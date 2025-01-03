use chip::system::system_layer::Layer;
use super::inet_layer::EndPointManager;

pub trait EndPointDeletor<EndPointType> {
    fn release(obj: &mut EndPointType) {
        obj.get_end_point_manager().delete_end_point(obj);
    }
}

pub trait EndPointBasis<EndPointType> {
    type EndPoint = EndPointType;

    fn get_end_point_manager<EndPointManagerType>(&self) -> &EndPointManagerType
        where
            EndPointManagerType: EndPointManager
    {
        self.m_end_point_manager
    }

    fn get_system_layer<SystemLayerType>(&self) -> &SystemLayerType
        where 
            SystemLayerType: chip::system::system_layer::Layer
    {
            return self.m_end_point_manager.get_system_layer();
    }
}
