mod peer_message_counter {
    #[derive(PartialEq, Eq, Clone, Copy)]
    enum Status {
        NotSynced,     // No state associated
        SyncInProcess, // mSyncInProcess will be active
        Synced,        // mSynced will be active
    }

    struct SyncInProcess {
        pub m_challenge: [u8; super::PeerMessageCounter::K_CHALLENGE_SIZE],
    }

    struct Synced {
        pub m_max_counter: u32,
    }

    /*
    enum Sync {
        SyncInProcess(
    }
    */
}

pub struct PeerMessageCounter;

impl PeerMessageCounter {
    pub const K_CHALLENGE_SIZE: usize = 8;
}
