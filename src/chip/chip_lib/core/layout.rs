/// Some help function to calculate the layout

fn size_rounded_up_to_custom_alignment(size: usize, alignment: usize) -> usize {
    /********
    unsafe {
        let align_m1 = unchecked_sub(alignment, 1);
        unchecked_add(size, align_m1) & !align_m1
    }
    */
    let align_m1 = alignment - 1;
    (size + align_m1) & !align_m1
}

pub fn padding_needed_for(size: usize, alignment: usize) -> usize {
    /*
    let len_rounded_up = size_rounded_up_to_custom_alignment(size, alignment);
    unsafe { unchecked_sub(len_rounded_up, size) }
    */
    let len_rounded_up = size_rounded_up_to_custom_alignment(size, alignment);
    len_rounded_up - size
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_for_2() {
        let output = padding_needed_for(3, 2);
        assert_eq!(1, output);
    }

    #[test]
    fn padding_for_8() {
        let output = padding_needed_for(3, 8);
        assert_eq!(5, output);
    }

    #[test]
    fn padding_for_8_from_1() {
        let output = padding_needed_for(1, 8);
        assert_eq!(7, output);
    }

    #[test]
    fn padding_for_1() {
        let output = padding_needed_for(3, 1);
        assert_eq!(0, output);
    }

    #[test]
    fn padding_for_1_from_2() {
        let output = padding_needed_for(2, 1);
        assert_eq!(0, output);
    }

    #[test]
    fn padding_for_32_from_16() {
        let output = padding_needed_for(16, 32);
        assert_eq!(16, output);
    }
}
