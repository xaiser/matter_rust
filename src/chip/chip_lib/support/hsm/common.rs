pub type IdType = u8;

pub const ROOT_IDX: usize = 0;

pub trait State {
    type Event;

    fn handle(&self, event: Self::Event) -> (Option<Self::Event>, Option<IdType>);

    fn entry(&self) {}

    fn exit(&self) {}

    fn parent(&self) -> Option<IdType>;

    fn id(&self) -> IdType;
}
