use crate::ChipError;
use super::system_layer::Layer;
use crate::chip::chip_lib::support::object_life_cycle::ObjectLifeCycle;
use crate::verify_or_return_error;
use crate::verify_or_return_value;
use crate::chip_no_error;
use crate::chip_core_error;
use crate::chip_sdk_error;
use crate::chip_error_incorrect_state;

pub type LayerImpl = LayerImplThreadX;

pub struct LayerImplThreadX {
    m_layer_state: ObjectLifeCycle,
}

impl LayerImplThreadX {
    pub fn default() -> Self {
        LayerImplThreadX {
            m_layer_state: ObjectLifeCycle::default(),
        }
    }
}

impl Layer for LayerImplThreadX {
    fn init(&mut self) -> ChipError {
        verify_or_return_error!(self.m_layer_state.set_initializing(), chip_error_incorrect_state!());
        verify_or_return_error!(self.m_layer_state.set_initialized(), chip_error_incorrect_state!());

        return chip_no_error!();
    }

    fn shutdown(&mut self) {
        self.m_layer_state.reset_from_initialized();
    }

    fn is_initialized(&self) -> bool {
        self.m_layer_state.is_initialized()
    }
}

impl Drop for LayerImplThreadX {
    fn drop(&mut self) {
        self.m_layer_state.destory();
    }
}

#[cfg(test)]
mod test {
  use super::*;
  use std::*;

  mod new {
      use super::super::*;
      use std::*;

      fn set_up() {
      }

      #[test]
      fn new_layer() {
          set_up();
          let l = LayerImpl::default();

          assert_eq!(false, l.is_initialized());
      }

      #[test]
      fn init() {
          set_up();
          let mut l = LayerImpl::default();

          l.init();

          assert_eq!(true, l.is_initialized());
      }
  }
}
