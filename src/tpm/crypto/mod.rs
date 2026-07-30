//! Cryptographic primitives.
//!
//! The TPM selects algorithms by TPM_ALG_ID at run time, so every primitive
//! here takes an identifier rather than a type parameter. The implementations
//! come from aws-lc-rs, with its aws-lc-sys bindings used where the TPM needs
//! control that the higher level interface does not offer, such as unpadded
//! block cipher modes and deterministic key generation from a seed.

pub mod hash;
pub mod hmac;
pub mod rand;
pub mod sym;
