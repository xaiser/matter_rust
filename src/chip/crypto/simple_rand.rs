use rand_core::{RngCore, CryptoRng, SeedableRng, Error};

pub struct SimpleRng {
    state: u32,
}

impl SimpleRng {
    pub fn default_with_seed(seed: u32) -> Self {
        assert!(seed != 0, "Seed must be nonzero!");
        Self { state: seed }
    }
}

impl Default for SimpleRng {
    fn default() -> Self {
        SimpleRng::default_with_seed(1234321)
    }
}

impl RngCore for SimpleRng {
    fn next_u32(&mut self) -> u32 {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 17;
        self.state ^= self.state << 5;
        self.state
    }

    fn next_u64(&mut self) -> u64 {
        ((self.next_u32() as u64) << 32) | (self.next_u32() as u64)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut i = 0;
        while i + 4 <= dest.len() {
            let rnd = self.next_u32().to_le_bytes();
            dest[i..i+4].copy_from_slice(&rnd);
            i += 4;
        }
        if i < dest.len() {
            let rnd = self.next_u32().to_le_bytes();
            let len = dest.len() - i;
            //dest[i..].copy_from_slice(&rnd[..(dest.len() - i)]);
            dest[i..].copy_from_slice(&rnd[..(len)]);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for SimpleRng {}

impl SeedableRng for SimpleRng {
    type Seed = [u8; 4];

    fn from_seed(seed: Self::Seed) -> Self {
        let seed_value = u32::from_le_bytes(seed);
        Self::default_with_seed(seed_value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::RngCore;

    #[test]
    fn test_rng() {
        let mut rng = SimpleRng::default_with_seed(12345);
        let value = rng.next_u32();
        assert!(value != 0);
    }
}

