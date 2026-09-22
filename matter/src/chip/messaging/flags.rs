use bitflags::bitflags;

bitflags! {
    #[derive(Copy,Clone)]
    pub struct MessageFlagValues: u32 {
        /* Indicates that the message is a duplicate of a previously received message. */
        const KduplicateMessage = 0x00000001;
    }
}

bitflags! {
    #[derive(Copy,Clone)]
    pub struct SendMessageFlags: u16 {
        const Knone = 0x0000;
        /* Used to indicate that a response is expected within a specified timeout. */
        const KexpectResponse = 0x0001;
        /* Suppress the auto-request acknowledgment feature when sending a message. */
        const KnoAutoRequestAck = 0x0002;
    }
}
