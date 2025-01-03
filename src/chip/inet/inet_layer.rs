use crate::ChipError;
use chip::system::system_layer::Layer;

use crate::verify_or_return_error;
use crate::verify_or_return_value;
use crate::chip_no_error;
use crate::chip_core_error;
use crate::chip_sdk_error;
use crate::chip_error_incorrect_state;

pub trait EndPointManager {
    fn default(&self) { }

    fn init<SystemLayerType>(&mut self, system_layer: &SystemLayerType) -> ChipError 
        where SystemLayerType: chip::system::system_layer::Layer 
    {
        verify_or_return_error!(self.m_layer_state.set_initializing(), chip_error_incorrect_state!());
        verify_or_return_error!(system_layer.is_initialized(), chip_error_incorrect_state!());
        self.m_system_layer = Some(system_layer);
        self.m_layer_state.set_initialized();

        return chip_no_error!();
    }

    fn shut_down(&mut self) {
        self.m_layer_state.reset_from_initialized();
        self.m_system_layer = None;
    }

    fn system_layer(&self) -> &SystemLayerType
        where
            SystemLayerType: chip::system::system_layer::Layer
    {
                return self.m_system_layer.unwrap();
    }
}

pub struct EndPointManagerImplPool<EndPointImpl> {
    m_layer_state: ObjectLefCycle,
    m_system_layer: Layer,
    m_end_point_pool: [EndPointImpl, 8],
}

impl<EndPointImpl> EndPointManager for EndPointManagerImplPool<EndPointImpl> { }

impl EndPointManagerImplPool<EndPointImpl> {
    pub fn default(&self) {}
}
