pub trait U8Put {
    fn put_u8(&mut self, c: u8) -> &mut Self;
}

pub trait BufferWriter: U8Put {
    fn default_with_buf(buf: &mut [u8]) -> Self;

    fn skip(&mut self, len: usize) -> &mut Self;

    fn put(&mut self, &[u8]) -> &mut Self;

    fn needed(&self) -> usize;

    fn write_pos(&self) -> usize {
        self.needed()
    }

    fn available(&self) -> usize;

    fn is_fit(&self) -> bool {
        return self.fit().is_ok();
    }

    fn fit(&self) -> Result<usize, usize>;

    fn size(&self) -> usize;

    fn buffer(&mut self) -> &mut [u8];

    fn const_buffer(&self) -> &[u8];

    fn reset(&mut self);
}

pub trait EndianPut: U8Put {
    fn endian_sign_put(&mut self, x: mut i64, len: usize) -> &mut Self;
    fn endian_unsign_put(&mut self, x: u64, len: usize) -> &mut Self;
}

struct EndianBufferWriter<EndianPuter>
where
    EndianPuter: EndianPut
{
}
