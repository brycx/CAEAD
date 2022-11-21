use core::fmt::Debug;

#[derive(Debug, PartialEq, Eq)]
/// Generic error.
pub struct Error;

pub mod traits;

pub mod nae;

pub mod kc;

pub mod hash;
