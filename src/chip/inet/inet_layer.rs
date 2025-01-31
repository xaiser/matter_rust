use crate::ChipError;
use crate::chip::system::system_layer::Layer;
use crate::chip::system::LayerImpl;
use crate::chip::chip_lib::support::object_life_cycle::ObjectLifeCycle;
use crate::chip::chip_lib::support::pool::*;
//use crate::chip::chip_lib::support::internal::pool::*;
use super::end_point_basis::EndPointBasis;
use super::end_point_basis::DefaultWithMgr;
use crate::chip::chip_lib::support::internal::pool::K_BIT_CHUNK_SIZE;
use crate::chip::chip_lib::support::iterators::Loop;

use core::ptr;

use crate::verify_or_return_error;
use crate::verify_or_return_value;
use crate::chip_no_error;
use crate::chip_core_error;
use crate::chip_sdk_error;
use crate::chip_error_incorrect_state;
use crate::chip_error_end_point_pool_full;
//use crate::create_object_pool;

pub trait EndPointManager {
    type EndPointType;

    fn init(&mut self, system_layer: * mut LayerImpl) -> ChipError;

    fn shut_down(&mut self);

    fn system_layer(&self) -> * mut LayerImpl;

    fn delete_end_point(&mut self, point: &Self::EndPointType);

    fn new_end_point(&mut self) -> Result<* mut Self::EndPointType, ChipError>;
    
    fn create_end_point(&mut self) -> * mut Self::EndPointType;

    fn release_end_point(&mut self, end_point: * mut Self::EndPointType) -> ();

    fn for_each_end_point<F>(&mut self, f: F) -> Loop
        where
            F: Fn(* mut Self::EndPointType) -> Loop + FnMut(* mut Self::EndPointType) -> Loop;
}

pub trait EndPointProperties {
    const NAME: &'static str;
    const NUM_END_POINTS: usize;
    const SYSTEM_STATE_KEY: i32;
}

pub struct EndPointManagerImplPool<EndPointImpl, const N: usize> 
where
    [(); (N + K_BIT_CHUNK_SIZE - 1) / K_BIT_CHUNK_SIZE]: {
    m_layer_state: ObjectLifeCycle,
    m_system_layer: * mut LayerImpl,
    m_end_point_pool: BitMapObjectPool<EndPointImpl, N>,
}

impl<EndPointImpl, const N: usize> EndPointManagerImplPool<EndPointImpl, N>
where
    [(); (N + K_BIT_CHUNK_SIZE - 1) / K_BIT_CHUNK_SIZE]: {
    pub const fn default() -> Self 
    {
        EndPointManagerImplPool {
            m_layer_state: ObjectLifeCycle::default(),
            m_system_layer: ptr::null_mut(),
            m_end_point_pool: BitMapObjectPool::<EndPointImpl, N>::new(),
        }
    }
}

impl<EndPointImpl: EndPointProperties + EndPointBasis + DefaultWithMgr, const N: usize> EndPointManager for EndPointManagerImplPool<EndPointImpl, N> 
where
    [(); (N + K_BIT_CHUNK_SIZE - 1) / K_BIT_CHUNK_SIZE]: {
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
    
    fn new_end_point(&mut self) -> Result<* mut Self::EndPointType, ChipError>
    {
        verify_or_return_error!(self.m_layer_state.is_initialized(), Err(chip_error_incorrect_state!()));

        let ret_end_point = self.create_end_point();
        if ret_end_point.is_null() == true {
            return Err(chip_error_end_point_pool_full!());
        }
        return Ok(ret_end_point);
    }
    
    fn create_end_point(&mut self) -> * mut Self::EndPointType
    {
        let mgr = self as * mut Self as * mut <Self::EndPointType as DefaultWithMgr>::EndPointManagerType;
        return self.m_end_point_pool.create_object(Self::EndPointType::default(mgr));
    }

    fn release_end_point(&mut self, end_point: * mut Self::EndPointType) -> ()
    {
        self.m_end_point_pool.release_object(end_point);
    }

    fn for_each_end_point<F>(&mut self, f: F) -> Loop
        where
            F: Fn(* mut Self::EndPointType) -> Loop + FnMut(* mut Self::EndPointType) -> Loop
    {
        return self.m_end_point_pool.for_each_active_object(f);
    }
}

/*
impl EndPointManagerImplPool<EndPointImpl> {
    pub fn default(&self) {}
}
*/
