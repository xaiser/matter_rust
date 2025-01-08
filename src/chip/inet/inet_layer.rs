use crate::ChipError;
use crate::chip::system::system_layer::Layer;
use crate::chip::system::LayerImpl;
use crate::chip::chip_lib::support::object_life_cycle::ObjectLifeCycle;
use super::end_point_basis::EndPointBasis;

use core::ptr;

use crate::verify_or_return_error;
use crate::verify_or_return_value;
use crate::chip_no_error;
use crate::chip_core_error;
use crate::chip_sdk_error;
use crate::chip_error_incorrect_state;

pub trait EndPointManager {
    type EndPointType;

    fn init(&mut self, system_layer: * mut LayerImpl) -> ChipError;

    fn shut_down(&mut self);

    fn system_layer(&self) -> * mut LayerImpl;

    fn delete_end_point(&mut self, point: &Self::EndPointType);
}

pub trait EndPointProperties {
    const NAME: &'static str;
    const NUM_END_POINTS: usize;
    const SYSTEM_STATE_KEY: i32;
}

pub struct EndPointManagerImplPool<EndPointImpl, const N: usize> {
    m_layer_state: ObjectLifeCycle,
    m_system_layer: * mut LayerImpl,
    m_end_point_pool: [EndPointImpl; N],
}

impl<EndPointImpl: Copy, const N: usize> EndPointManagerImplPool<EndPointImpl, N> {
    pub const fn default(init_value: EndPointImpl) -> Self {
        EndPointManagerImplPool {
            m_layer_state: ObjectLifeCycle::default(),
            m_system_layer: ptr::null_mut(),
            m_end_point_pool: [init_value; N],
        }
    }
}

impl<EndPointImpl: EndPointProperties + EndPointBasis + Copy, const N: usize> EndPointManager for EndPointManagerImplPool<EndPointImpl, N> {
    type EndPointType = EndPointImpl;

    fn init(&mut self, system_layer: * mut LayerImpl) -> ChipError 
    {
        verify_or_return_error!(self.m_layer_state.set_initializing(), chip_error_incorrect_state!());
        unsafe {
            verify_or_return_error!((*system_layer).is_initialized(), chip_error_incorrect_state!());
        }
        self.m_system_layer = system_layer;
        self.m_layer_state.set_initialized();

        return chip_no_error!();
    }

    fn shut_down(&mut self) {
        self.m_layer_state.reset_from_initialized();
        self.m_system_layer = ptr::null_mut();
    }

    fn system_layer(&self) -> * mut LayerImpl
    {
        return self.m_system_layer;
    }

    fn delete_end_point(&mut self, point: &Self::EndPointType) {
    }
}

/*
impl EndPointManagerImplPool<EndPointImpl> {
    pub fn default(&self) {}
}
*/
