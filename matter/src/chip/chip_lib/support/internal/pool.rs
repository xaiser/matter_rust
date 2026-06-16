type BitChunkType = u32;

pub const K_BIT1: BitChunkType = 1;
// it's using digit in the C++ std lib, but we cannot do that in rust. Just hard code it for now.
pub const K_BIT_CHUNK_SIZE: usize = 32;

pub trait Statistics {
    fn allocated(&self) -> usize;
    fn high_water_mark(&self) -> usize;
    fn increase_usage(&mut self);
    fn decrease_usage(&mut self);
}

pub trait StaticAllocatorBitMap {
    fn capacity(&self) -> usize;
    fn exhausted(&self) -> bool;
}
