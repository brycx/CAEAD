use crate::traits::{Hash, NAEAD};
use crate::Error;
use core::marker::PhantomData;
use orion::util::secure_cmp;

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::{Aes256, Block};

/// Committing authenticated encryption (cAE) using the CTX construction.
///
/// "On Committing Authenticated Encryption", John Chan and Phillip Rogaway (https://eprint.iacr.org/2022/1260)
pub struct CTX<
    A: NAEAD<K, N, T>,
    H: Hash<D>,
    const K: usize,
    const N: usize,
    const T: usize,
    const D: usize,
> {
    hash: H,
    key: [u8; K],
    nae: PhantomData<A>,
}

impl<
        A: NAEAD<K, N, T>,
        H: Hash<D>,
        const K: usize,
        const N: usize,
        const T: usize,
        const D: usize,
    > CTX<A, H, K, N, T, D>
{
    /// Create a new [`CTX`] instance given some key.
    pub fn new(key: [u8; K]) -> Result<Self, Error> {
        let mut h: H = H::init()?;
        h.update(&key)?;

        Ok(Self {
            hash: h,
            key,
            nae: PhantomData,
        })
    }

    /// Returns (ciphertext, T*)
    pub fn encrypt(
        &self,
        nonce: &[u8; N],
        message: &[u8],
        ad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let (ciphertext, tag) = A::encrypt(&self.key, nonce, message, ad)?;

        let mut h_ctx = self.hash.clone();
        h_ctx.update(nonce)?;
        h_ctx.update(ad)?;
        h_ctx.update(&tag)?;
        // T* = H(K, N, A, T )
        let digest = h_ctx.finialize()?.to_vec();

        Ok((ciphertext, digest))
    }

    /// Return message. `tag` == T*
    pub fn decrypt(
        &self,
        nonce: &[u8; N],
        ciphertext: &[u8],
        ad: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let nae_tag = A::mac(&self.key, nonce, ciphertext, ad)?;

        let mut h_ctx = self.hash.clone();
        h_ctx.update(nonce)?;
        h_ctx.update(ad)?;
        h_ctx.update(&nae_tag)?;
        let digest = h_ctx.finialize()?;
        secure_cmp(&digest, tag).map_err(|_| Error)?;

        A::decrypt(&self.key, nonce, ad, ciphertext, &nae_tag, false)
    }
}

/// Committing authenticated encryption (cAE) using the UtC construction.
///
/// "Efficient Schemes for Committing Authenticated Encryption", Mihir Bellare and Viet Tung Hoang (https://eprint.iacr.org/2022/268)
///
/// Credits to https://github.com/rozbb/kc-aeads dfor inspiration on this implementation.
pub struct UtC<A: NAEAD<K, N, T>, const K: usize, const N: usize, const T: usize> {
    // NOTE: We save the key-initilized state to avoid doing the AES key-schedule for each block.
    aes256: Aes256,
    nae: PhantomData<A>,
}

impl<A: NAEAD<K, N, T>, const K: usize, const N: usize, const T: usize> UtC<A, K, N, T> {
    /// As the CX[E] is built upon AES the blocksize will always be 16.
    const CX_BLOCKSIZE: usize = 16;

    /// The CX[E] committing PRF built on top of a blockcipher. See Figure 14 https://eprint.iacr.org/2022/268.
    ///
    /// Returns the (P, L) tuple, of PL and LL length, respectively.
    /// 
    /// ref: https://github.com/rozbb/kc-aeads
    fn comitting_prf<const PL: usize, const LL: usize>(
        &self,
        message: &[u8],
    ) -> Result<([u8; PL], [u8; LL]), Error> {
        debug_assert!(
            message.len() < Self::CX_BLOCKSIZE,
            "We need a block plus one position for length encoding in CX[E]"
        );

        // As Figure 16 defines, we always assume lengths to be multiples of the blocksize.
        debug_assert_eq!(PL % Self::CX_BLOCKSIZE, 0);
        debug_assert_eq!(LL % Self::CX_BLOCKSIZE, 0);

        // a ← ⌈l/n⌉; b ← ⌈λ/n⌉
        let a = PL / Self::CX_BLOCKSIZE;
        let b = LL / Self::CX_BLOCKSIZE;

        // For i ← 1 to a+b do Xi ← pad(M,i);
        let mut blocks = vec![Block::default(); a + b];
        for (i, block) in (0_u8..).zip(blocks.iter_mut()) {
            debug_assert_eq!(block.len(), Self::CX_BLOCKSIZE);

            block[..message.len()].copy_from_slice(message);
            block[Self::CX_BLOCKSIZE - 1] = i + 1;
        }

        let mut block1 = [0u8; 16];
        block1.copy_from_slice(&blocks[0]);

        // Vi ← EK(Xi)
        self.aes256.encrypt_blocks(&mut blocks);

        // V1 ← V1 ⊕ X1
        for (v1, x1) in blocks[0].iter_mut().zip(block1.iter()) {
            *v1 ^= x1;
        }

        // P ← (V1 ···Va)[1 : l]; L ← (Va+1 ···Va+b)[1 : λ]
        let mut p = [0u8; PL];
        let mut l = [0u8; LL];

        for (p_chunk, block) in p
            .chunks_exact_mut(Self::CX_BLOCKSIZE)
            .zip(blocks.iter().take(a))
        {
            p_chunk.copy_from_slice(block);
        }

        for (l_chunk, block) in l
            .chunks_exact_mut(Self::CX_BLOCKSIZE)
            .zip(blocks.iter().skip(a))
        {
            l_chunk.copy_from_slice(block);
        }

        Ok((p, l))
    }

    /// Create new [`UtC`] instance.
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        if key.len() != K {
            return Err(Error);
        }

        let key = GenericArray::from_slice(key);

        Ok(Self {
            aes256: Aes256::new(key),
            nae: PhantomData,
        })
    }

    /// The UtC[F, SE].Enc(K, N, A, M). See Figure 15 https://eprint.iacr.org/2022/268.
    ///
    /// Return P, C
    pub fn encrypt(
        &self,
        nonce: &[u8; N],
        message: &[u8],
        ad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        // (P,L) ← F(K,N)
        let (p, l) = self.comitting_prf::<K, K>(nonce)?;
        // C ← SE.Enc(L,N,A,M)
        let (mut c, mut t) = A::encrypt(&l, nonce, message, ad)?;
        c.append(&mut t);

        Ok((p.to_vec(), c))
    }

    /// The UtC[F, SE].Dec(K, N, A, P*||C). See Figure 15 https://eprint.iacr.org/2022/268.
    ///
    /// Return SE.Dec(L, N, A, C) or ⊥
    pub fn decrypt(
        &self,
        nonce: &[u8; N],
        ciphertext: &[u8],
        ad: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, Error> {
        // (P,L) ← F(K,N)
        let (p, l) = self.comitting_prf::<K, K>(nonce)?;
        // If P*  != P then return ⊥
        if secure_cmp(&p, tag).is_err() {
            return Err(Error);
        }

        A::decrypt(
            &l,
            nonce,
            ad,
            &ciphertext[..ciphertext.len() - T],
            &ciphertext[ciphertext.len() - T..],
            true,
        )
    }
}

/// Hash-then-Encrypt (HtE) transform turning a CMT-1 cipher into a CMT-4 cipher.
///
/// "Efficient Schemes for Committing Authenticated Encryption", Mihir Bellare and Viet Tung Hoang (https://eprint.iacr.org/2022/268)
pub struct HtE<
    A: NAEAD<K, N, T>,
    H: Hash<D>,
    const K: usize,
    const N: usize,
    const T: usize,
    const D: usize,
> {
    hash: H,
    nae: PhantomData<A>,
}

impl<
        A: NAEAD<K, N, T>,
        H: Hash<D>,
        const K: usize,
        const N: usize,
        const T: usize,
        const D: usize,
    > HtE<A, H, K, N, T, D>
{
    pub fn new(key: [u8; K]) -> Result<Self, Error> {
        if key.len() != K {
            return Err(Error);
        }

        let mut h: H = H::init()?;
        h.update(&key)?;

        Ok(Self {
            hash: h,
            nae: PhantomData,
        })
    }

    /// The SE.Enc(K, N, A, M ). See Figure 6 https://eprint.iacr.org/2022/268.
    ///
    /// Return P, C
    pub fn encrypt(
        &self,
        nonce: &[u8; N],
        message: &[u8],
        ad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        // L ← H(K,(N,A))
        let mut h_ctx = self.hash.clone();
        h_ctx.update(nonce)?;
        h_ctx.update(ad)?;
        let l = h_ctx.finialize()?;

        // C ← SE.Enc(L,N,ε,M)
        let utc = UtC::<A, K, N, T>::new(&l)?;
        let (p, c) = utc.encrypt(nonce, message, &[]).unwrap();

        Ok((p, c))
    }

    /// The UtC[F, SE].Dec(K, N, A, P*||C). See Figure 15 https://eprint.iacr.org/2022/268.
    ///
    /// Return SE.Dec(L, N, A, C) or ⊥
    pub fn decrypt(
        &self,
        nonce: &[u8; N],
        ciphertext: &[u8],
        ad: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, Error> {
        // L ← H(K,(N,A))
        let mut h_ctx = self.hash.clone();
        h_ctx.update(nonce)?;
        h_ctx.update(ad)?;
        let l = h_ctx.finialize()?;

        // M ← SE.Dec(L, N, ε, C)
        let utc = UtC::<A, K, N, T>::new(&l)?;

        utc.decrypt(nonce, ciphertext, &[], tag)
    }
}

#[cfg(test)]
mod test {
    use orion::hazardous::hash::blake2::blake2b::Blake2b;

    use crate::nae::ChaCha20Poly1305;

    use super::*;

    #[test]
    fn test_roundtrip_ctx() {
        let ctx = CTX::<ChaCha20Poly1305, Blake2b, 32, 12, 16, 32>::new([0u8; 32]).unwrap();

        let n = [0u8; 12];
        let m = b"Hello, world!";
        let a = b"v1";

        let (c, t) = ctx.encrypt(&n, m, a).expect("enc fails");
        let plaintext = ctx.decrypt(&n, &c, a, &t).expect("dec fails");

        assert_eq!(plaintext, m);
    }

    #[test]
    fn test_working_cx_e() {
        let utc = UtC::<ChaCha20Poly1305, 32, 12, 16>::new(&[0u8; 32]).unwrap();
        // We intend on using AES-GCM for the tests so testing with 12-byte nonce sahould be fine.
        let (p, l) = utc.comitting_prf::<32, 32>(&[0u8; 12]).unwrap();
        assert_ne!(p, [0u8; 32]);
        assert_ne!(l, [0u8; 32]);
    }

    #[test]
    fn test_roundtrip_utc() {
        let utc = UtC::<ChaCha20Poly1305, 32, 12, 16>::new(&[0u8; 32]).unwrap();

        let n = [0u8; 12];
        let m = b"Hello, world!";
        let a = b"v1";

        let (p, c) = utc.encrypt(&n, m, a).expect("enc fails");
        let plaintext = utc.decrypt(&n, &c, a, &p).expect("dec fails");

        assert_eq!(plaintext, m);
    }

    #[test]
    fn test_roundtrip_hte() {
        let hte = HtE::<ChaCha20Poly1305, Blake2b, 32, 12, 16, 32>::new([0u8; 32]).unwrap();

        let n = [0u8; 12];
        let m = b"Hello, world!";
        let a = b"v1";

        let (p, c) = hte.encrypt(&n, m, a).expect("enc fails");
        let plaintext = hte.decrypt(&n, &c, a, &p).expect("dec fails");

        assert_eq!(plaintext, m);
    }
}
