mod peer_message_counter {
    #[derive(PartialEq, Eq, Clone, Copy)]
    enum Status {
        NotSynced,     // No state associated
        SyncInProcess, // mSyncInProcess will be active
        Synced,        // mSynced will be active
    }

    enum Sync {
        SyncInProcess(
    }
}
