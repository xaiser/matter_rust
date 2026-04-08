use aes::Aes128;
use ccm::{
    consts::{U8, U13},
    Ccm,
};

type Aes128CCM = Ccm<Aes128, U8, U13>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chip::crypto::{
        simple_rand::SimpleRng,
    };
    use ccm::{
        consts::{U8, U10, U13},
        Ccm,
        Nonce,
        Tag,
        AeadInPlace,
        KeyInit,
    };

    #[test]
    fn encrypt() {
        let mut rng = SimpleRng::default_with_seed(12345);
        let key = [1u8; 16];
        let ccm = Aes128CCM::new_from_slice(&key);
        assert!(ccm.is_ok());
        let ccm = ccm.unwrap();
        let nonce = Nonce::<U13>::from_slice(&[1u8; 13]);
        let aad = [1u8; 1];

        let input = [1u8; 16];
        let mut output = [1u8; 16];

        assert!(ccm.encrypt_in_place_detached(&nonce, &aad[..], &mut output).is_ok());
        let mut output = [1u8; 16];
        let r1 = ccm.encrypt_in_place_detached(&nonce, &aad[..], &mut output);
        let mut output = [1u8; 16];
        let r2 = ccm.encrypt_in_place_detached(&nonce, &aad[..], &mut output);

        assert_eq!(r1, r2);
    }
} // end of tests
