use crate::traits::NAEAD;
use crate::Error;
use orion::hazardous::mac::poly1305;
use orion::hazardous::stream::chacha20;
use orion::util::secure_cmp;

pub struct ChaCha20Poly1305;

impl NAEAD<32, 12, 16> for ChaCha20Poly1305 {
    /// This returns `ciphertext, tag`
    fn encrypt(
        key: &[u8; 32],
        nonce: &[u8; 12],
        message: &[u8],
        ad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let k = chacha20::SecretKey::from_slice(key).map_err(|_| Error)?;
        let n = chacha20::Nonce::from_slice(nonce).map_err(|_| Error)?;
        let m = message;

        let mut c = vec![0u8; message.len()];
        chacha20::encrypt(&k, &n, 1, m, &mut c).map_err(|_| Error)?;
        let t: Vec<u8> = Self::mac(key, nonce, &c, ad)?.to_vec();

        Ok((c, t))
    }

    fn mac(
        key: &[u8; 32],
        nonce: &[u8; 12],
        ciphertext_no_tag: &[u8],
        ad: &[u8],
    ) -> Result<[u8; 16], crate::Error> {
        const PAD_BLOCK: [u8; 16] = [0u8; 16];
        fn padding(input: usize) -> usize {
            if input == 0 {
                return 0;
            }

            let rem = input % 16;

            if rem != 0 {
                16 - rem
            } else {
                0
            }
        }

        let c = ciphertext_no_tag;

        let mut buf: Vec<u8> = Vec::with_capacity(1024);
        buf.extend_from_slice(ad);
        buf.extend_from_slice(&PAD_BLOCK[..padding(ad.len())]);
        buf.extend_from_slice(c);
        buf.extend_from_slice(&PAD_BLOCK[..padding(c.len())]);
        buf.extend_from_slice(&(ad.len() as u64).to_le_bytes());
        buf.extend_from_slice(&(c.len() as u64).to_le_bytes());
        debug_assert_eq!(buf.len() % 16, 0);

        let k = chacha20::SecretKey::from_slice(key).map_err(|_| Error)?;
        let n = chacha20::Nonce::from_slice(nonce).map_err(|_| Error)?;
        let mut poly1305_key = [0u8; 32];
        chacha20::encrypt(&k, &n, 0, &[0u8; 32], &mut poly1305_key).map_err(|_| Error)?;
        let auth_k = poly1305::OneTimeKey::from(poly1305_key);
        let mut mac = poly1305::Poly1305::new(&auth_k);
        mac.update(&buf).unwrap();

        let mut t = [0u8; 16];
        t.copy_from_slice(mac.finalize().unwrap().unprotected_as_bytes());

        Ok(t)
    }

    fn decrypt(
        key: &[u8; 32],
        nonce: &[u8; 12],
        ad: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
        should_use_native_auth: bool,
    ) -> Result<Vec<u8>, crate::Error> {
        let k = chacha20::SecretKey::from_slice(key).map_err(|_| Error)?;
        let n = chacha20::Nonce::from_slice(nonce).map_err(|_| Error)?;
        let c = ciphertext;

        if should_use_native_auth {
            let t = Self::mac(key, nonce, c, ad)?;
            if secure_cmp(&t, tag).is_err() {
                return Err(Error);
            }
        }

        let mut buf = vec![0u8; c.len()];
        chacha20::decrypt(&k, &n, 1, c, &mut buf).map_err(|_| Error)?;

        Ok(buf)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_chacha20_poly1305_roundtrip() {
        let k = [0u8; 32];
        let n = [0u8; 12];
        let m = b"Hello, world!";
        let a = b"v1";

        let (c, t) = ChaCha20Poly1305::encrypt(&k, &n, m, a).expect("enc fails");
        assert!(ChaCha20Poly1305::decrypt(&k, &n, a, &c, &t, true).is_ok());
    }
}
