//use crate::chip::system::LayerImpl;
//use crate::chip::system::system_layer::Layer;
use core::ptr;

/*
static mut S_MOCKED_SYSTEM_LAYER: * mut crate::chip::system::LayerImpl = ptr::null_mut();

pub fn set_system_layer_for_test(layer: * mut crate::chip::system::LayerImpl) {
    S_MOCKED_SYSTEM_LAYER = layer;
}
*/

pub fn system_layer_impl() -> * mut crate::chip::system::LayerImpl {
    /*
    if S_MOCKED_SYSTEM_LAYER.is_null() == false {
        return ptr::addr_of_mut!(S_MOCKED_SYSTEM_LAYER);
    }
    */
    static mut G_SYSTEM_LAYER_IMPL: crate::chip::system::LayerImpl = crate::chip::system::LayerImpl::default();
    return ptr::addr_of_mut!(G_SYSTEM_LAYER_IMPL);
}

pub fn system_layer() -> * mut crate::chip::system::LayerImpl
{
    return system_layer_impl();
}
