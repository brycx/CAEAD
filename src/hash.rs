use crate::traits::Hash;
use crate::Error;
use orion::hazardous::hash::blake2::blake2b::*;

// TODO: This only works for BALEK2b-256 because of the const arguments digest size.
impl Hash<32> for Blake2b {
    fn init() -> Result<Self, Error> {
        Blake2b::new(32).map_err(|_| Error)
    }

    fn update(&mut self, message: &[u8]) -> Result<(), Error> {
        self.update(message).map_err(|_| Error)
    }

    fn finialize(&mut self) -> Result<[u8; 32], crate::Error> {
        let mut digest = [0u8; 32];
        let d = self.finalize().unwrap();
        digest.copy_from_slice(d.as_ref());

        Ok(digest)
    }
}
