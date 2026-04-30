//TODO: optimize N = 32 bits
use core::ops::ShlAssign;

const fn bits_per_word() -> usize {
    core::mem::size_of::<WordT>() * 8
}

pub const fn words(n: usize) -> usize {
    (n + bits_per_word() - 1) / bits_per_word()
}

const fn which_bit(pos: usize) -> usize {
    pos % bits_per_word()
}

const fn which_word(pos: usize) -> usize {
    pos / bits_per_word()
}

const fn bitmask(pos: usize) -> WordT {
    ((1 as WordT) << which_bit(pos)) as WordT
}

type WordT = u32;

pub struct Bitset<const N: usize> 
where
    [(); words(N)]:
{
    m_data: [WordT; words(N)],
}

impl<const NB: usize> Default for Bitset<NB>
where
    [(); words(NB)]:
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const NB: usize> Bitset<NB>
where
    [(); words(NB)]:
{

    pub const fn new() -> Self {
        Self {
            m_data: [0; words(NB)],
        }
    }

    fn getword(&self, pos: usize) -> Option<&WordT> {
        self.m_data.get(which_word(pos))
    }

    fn getword_mut(&mut self, pos: usize) -> Option<&mut WordT> {
        self.m_data.get_mut(which_word(pos))
    }

    fn set_val(&mut self, pos: usize, val: bool) -> Option<&mut Self> {
        if let Some(w) = self.getword_mut(pos) {
            if val {
                *w |= bitmask(pos);
            } else {
                *w &= !bitmask(pos);
            }

            Some(self)
        } else {
            None
        }
    }

    pub fn set(&mut self, pos: usize)  {
        let _ = self.set_val(pos, true);
    }

    pub fn clean(&mut self, pos: usize) {
        let _ = self.set_val(pos, false);
    }

    pub fn reset(&mut self) {
        self.m_data.fill(0)
    }

    pub fn test(&self, pos: usize) -> bool {
        if let Some(w) = self.getword(pos) {
            (w & bitmask(pos)) != (0 as WordT)
        } else {
            false
        }
    }

    pub fn all(&self) -> bool {
        if let Some((last, rest)) = self.m_data.split_last() {
            for w in rest {
                if *w != !(0 as WordT) {
                    return false;
                }
            }

            return *last == (!(0 as WordT) >> (words(NB) * bits_per_word() - NB));
        }

        false
    }

    pub fn any(&self) -> bool {
        for w in self.m_data {
            if w != (0 as WordT) {
                return true;
            }
        }

        return false;
    }

    pub fn none(&self) -> bool {
        !self.any()
    }
}

impl<const NB: usize> ShlAssign<usize> for Bitset<NB>
where
    [(); words(NB)]:
{
    fn shl_assign(&mut self, rhs: usize) {
        if rhs < NB {
            if rhs != 0 {
                let wshift = rhs / bits_per_word();
                let offset = rhs % bits_per_word();
                if offset == 0 {
                    for n in (wshift..=(words(NB)-1)).rev() {
                        self.m_data[n] = self.m_data[n - wshift];
                    }
                } else {
                    let sub_offset = bits_per_word() - offset;
                    for n in (wshift+1..=(words(NB)-1)).rev() {
                        self.m_data[n] = (self.m_data[n - wshift] << offset) | (self.m_data[n - wshift - 1] >> sub_offset);
                    }
                    self.m_data[wshift] = self.m_data[0] << offset;
                }
                self.m_data[..wshift].fill(0);
            }
        } else {
            self.m_data.fill(0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init() {
        let mut w = Bitset::<1>::new();
        w.set(0);
        assert!(w.test(0));
    }

    #[test]
    fn init_0() {
        let mut w = Bitset::<0>::new();
        w.set(0);
        assert!(!w.test(0));
    }

    #[test]
    fn test() {
        let mut w = Bitset::<1>::new();
        w.set(0);
        assert!(w.test(0));
    }

    #[test]
    fn test_33() {
        let mut w = Bitset::<33>::new();
        w.set(32);
        assert!(w.test(32));
    }

    #[test]
    fn all() {
        let mut w = Bitset::<10>::new();
        assert!(!w.all());
        for i in 0..10 {
            w.set(i);
        }

        assert!(w.all());
    }

    #[test]
    fn all_0() {
        let mut w = Bitset::<0>::new();
        assert!(!w.all());
    }

    #[test]
    fn not_all() {
        let mut w = Bitset::<10>::new();
        assert!(!w.all());
        for i in 0..9 {
            w.set(i);
        }

        assert!(!w.all());
    }

    #[test]
    fn any() {
        let mut w = Bitset::<1>::new();
        assert!(!w.any());
        w.set(0);
        assert!(w.any());
    }

    #[test]
    fn left_shift_assign() {
        let mut w = Bitset::<1>::new();
        w.set(0);
        assert!(w.any());
        w <<= 1;
        assert!(w.none());
    }

    #[test]
    fn left_shift_assign_2() {
        let mut w = Bitset::<2>::new();
        w.set(0);
        assert!(w.test(0));
        w <<= 1;
        assert!(!w.test(0));
        assert!(w.test(1));
    }

    #[test]
    fn left_shift_assign_33() {
        let mut w = Bitset::<33>::new();
        w.set(31);
        assert!(w.test(31));
        w <<= 1;
        assert!(!w.test(31));
        assert!(w.test(32));
    }

    #[test]
    fn left_shift_0() {
        let mut w = Bitset::<0>::new();
        w <<= 1;
        w.set(0);
        assert!(!w.test(0));
    }
} // end of tests
