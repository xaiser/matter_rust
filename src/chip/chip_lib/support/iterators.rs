#[repr(u8)]
#[derive(PartialEq, Debug)]
pub enum Loop {
    Continue,
    Break,
    Finish,
}
