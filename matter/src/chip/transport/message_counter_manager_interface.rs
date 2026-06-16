use crate::{
    chip::{
        transport::{
            raw::{
                peer_address::PeerAddress,
                message_header::PacketHeader,
            },
            session::SessionHandle,
        },
        system::system_packet_buffer::PacketBufferHandle,
    },
    ChipError,
    ChipErrorResult,
};

pub trait MessageCounterManagerInterface {
    /*
     * Start sync if the sync procedure is not started yet.
     */
    fn start_sync(&mut self, session: &SessionHandle, state: &mut SessionHandle) -> ChipErrorResult;


    /*
     * Called when have received a message but session message counter is not synced.  It will queue the message and start sync if
     * the sync procedure is not started yet.
     */
    fn queue_received_message_and_start_sync(&mut self, packet_header: &PacketHeader, session: &SessionHandle, state: &mut SessionHandle,
        peer_address: &PeerAddress) -> Result<PacketBufferHandle, ChipError>;
}
