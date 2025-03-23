use crate::chip::transport::PeerAddress;
use crate::chip::system::system_packet_buffer::PacketBufferHandle;
use super::raw::base::{Base,Init,MessageTransportContext,RawTransportDelegate};
use super::raw::tuple::Tuple;

use crate::ChipErrorResult;
use crate::chip_ok;

use core::ptr;

pub trait TransportMgrDelegate {
    fn on_message_received(&mut self, source: &PeerAddress, msg_buf: PacketBufferHandle, ctext: &MessageTransportContext);
}

pub struct TransportMgr<T>
{
    m_transports: Tuple<T>,
}

impl<T> RawTransportDelegate for TransportMgr<T> {
    fn handle_message_received(&self, peer_address: PeerAddress, msg: PacketBufferHandle,
        ctxt: * const MessageTransportContext)
    {}
}

impl<Type0> TransportMgr<(Type0,)> 
where
    Type0: Init + Base,
{
    pub fn init(&mut self, p0: <Type0 as Init>::InitParamType) -> ChipErrorResult {
        unsafe {
            let err = self.m_transports.init((ptr::addr_of!(self) as * mut <Type0 as Base>::DelegateType,), (p0,));
            if err.is_success() == false {
                return Err(err);
            }
        }

        chip_ok!()
    }
}

#[cfg(test)]
mod test {
  use super::*;
  use std::*;

  use crate::chip::inet::test_end_point::TestEndPointManager;
  static mut END_POINT_MANAGER: TestEndPointManager = TestEndPointManager::default();

  #[test]
  fn init() {
  }
}
