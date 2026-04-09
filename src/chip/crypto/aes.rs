//type Aes128Ccm = Ccm<Aes128, U8, U13>;

mod aes128_ccm {
    use crate::{
        ChipError,
        chip::{
            crypto::{
                Symmetric128BitsKeyByteArray, Aes128KeyHandle, 
            },
        },
    };
    use aes::Aes128;
    use ccm::{
        KeyInit,
        Ccm,
    };

    pub fn create_aes128_ccm<Ccm: KeyInit>(key: &Aes128KeyHandle) -> Result<Ccm, ()> {
            Ccm::new_from_slice(key.as_ref::<Symmetric128BitsKeyByteArray>()).map_err(|_| ())
    }
}

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
        let ccm = Aes128Ccm::new_from_slice(&key);
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

    #[test]
    fn decrypt() {
        let mut rng = SimpleRng::default_with_seed(12345);
        let key = [1u8; 16];
        let ccm = Aes128Ccm::new_from_slice(&key);
        assert!(ccm.is_ok());
        let ccm = ccm.unwrap();
        let nonce = Nonce::<U13>::from_slice(&[1u8; 13]);
        let aad = [1u8; 1];

        let input = [1u8; 16];
        let mut output = [1u8; 16];

        let tag = ccm.encrypt_in_place_detached(&nonce, &aad[..], &mut output);
        assert!(tag.is_ok());
        let tag = tag.unwrap();

        assert!(ccm.decrypt_in_place_detached(&nonce, &aad[..], &mut output, &tag).is_ok());

        assert_eq!(output, [1u8; 16]);
    }
} // end of tests
