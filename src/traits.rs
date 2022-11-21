use crate::Error;

/// Trait for a cryptographic hash function.
pub trait Hash<const D: usize>: Clone {
    /// Initialize the hash state.
    fn init() -> Result<Self, Error>
    where
        Self: Sized;

    /// Update the hash state.
    fn update(&mut self, message: &[u8]) -> Result<(), Error>;

    /// Finalize and return the digest based on the hash state.
    fn finialize(&mut self) -> Result<[u8; D], Error>;
}

/// Trait for nonce-based authenticated encryption (nAE)/(UNAE).
pub trait NAEAD<const K: usize, const N: usize, const T: usize> {
    const TAG_SIZE: usize = T;

    /// Encrypt with nAE returning ciphertext.
    fn encrypt(
        key: &[u8; K],
        nonce: &[u8; N],
        message: &[u8],
        ad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Error>;

    /// Produce the authentication tag of length T for this given nAE scheme.
    fn mac(key: &[u8; K], nonce: &[u8; N], ciphertext: &[u8], ad: &[u8]) -> Result<[u8; T], Error>;

    /// Decryption, returning plaintext.
    /// NOTE: It's important that the tag is not always being verified as part of this routine.
    /// This is implemented in [`CAE`], as the construction changes the authentication tag used.
    /// It should however still produce the original authentication tag of the nAE's spec,
    /// since this is fed to H.
    ///
    /// `should_use_native_auth`: Indicates whether the native AEAD authentication mechanism should be preserved.
    /// This is the case of HtE+UtC but not for CTX.
    ///
    /// There is a difference in how some key-committing transformations handle the
    /// native AEAD tag validation. For example, with UtC, this validation should still
    /// be performed but in CTX this is replaced entirely. We use this flag to choose during runtime,
    /// to make the struct implementing NAEAD re-usable between UtC and CTX for a given AEAD.
    fn decrypt(
        key: &[u8; K],
        nonce: &[u8; N],
        ad: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
        should_use_native_auth: bool,
    ) -> Result<Vec<u8>, Error>;
}
