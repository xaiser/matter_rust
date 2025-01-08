use super::inet_layer::EndPointManagerImplPool;
use super::inet_layer::EndPointManager;
use super::inet_layer::EndPointProperties;
use super::end_point_basis::EndPointBasis;
use super::end_point_basis::EndPointDeletor;
use super::inet_config::*;
use crate::chip::system::LayerImpl as SystemLayer;
use crate::chip::system::system_layer::Layer;
use crate::chip::chip_lib::support::object_life_cycle::ObjectLifeCycle;
use crate::chip::platform::global::system_layer;
use core::ptr;

type TestEndPointManager = EndPointManagerImplPool<TestEndPoint, {TestEndPoint::NUM_END_POINTS}>;

#[derive(Clone, Copy)]
pub struct TestEndPoint {
    m_end_point_manager: * mut TestEndPointManager,
}

impl TestEndPoint {
    pub const fn default() -> Self {
        TestEndPoint {
            m_end_point_manager: ptr::null_mut(),
        }
    }
}

impl EndPointBasis for TestEndPoint { 
    type EndPointManagerType = TestEndPointManager;

    fn get_end_point_manager(&self) -> * mut Self::EndPointManagerType
    {
        self.m_end_point_manager
    }

    fn get_system_layer(&self) -> * mut SystemLayer
    {
        unsafe {
            return (*self.m_end_point_manager).system_layer();
        }
    }
}

impl EndPointDeletor<TestEndPoint> for TestEndPoint {
    fn release(obj: &mut TestEndPoint) {
        unsafe {
            (*obj.get_end_point_manager()).delete_end_point(obj);
        }
    }
}

impl EndPointProperties for TestEndPoint {
    const NAME: &'static str = "TEST";
    const NUM_END_POINTS: usize = INET_CONFIG_NUM_TEST_ENDPOINTS;
    const SYSTEM_STATE_KEY: i32 = 0;
}

#[cfg(test)]
mod test {
  use super::*;
  use std::*;
  static mut test: bool = false;
  static mut END_POINT_MANAGER: TestEndPointManager = TestEndPointManager::default(TestEndPoint::default());
  mod new {
      use super::super::*;
      use super::*;
      use std::*;

      fn set_up() {
          unsafe {
              /* reinit system layer */
              let sl = system_layer();
              (*sl).init();

              /* reinit end point manager */
              END_POINT_MANAGER = TestEndPointManager::default(TestEndPoint::default());
              END_POINT_MANAGER.init(system_layer());
          }
      }

      #[test]
      fn new_packet_buffer() {
          set_up();
          assert_eq!(1,1);
      }

      #[test]
      fn new_packet_buffer_1() {
          set_up();
          assert_eq!(1,1);
      }
  }
}
