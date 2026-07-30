//! Sized buffers, digests and PCR selections from Part 2 clauses 10 and 11.

use crate::tpm::config;
use crate::tpm::constants::{alg, rc};
use crate::tpm::error::{TpmRc, TpmResult};
use crate::tpm::marshal::{Marshal, Reader, Unmarshal, Writer};

/// Largest digest produced by any implemented hash, in octets.
pub const MAX_DIGEST_SIZE: usize = 64;
/// Size of a TPMU_HA, which is the largest digest.
pub const SIZEOF_TPMU_HA: usize = MAX_DIGEST_SIZE;
/// Size of a TPMT_HA: a TPM_ALG_ID followed by a digest.
pub const SIZEOF_TPMT_HA: usize = 2 + SIZEOF_TPMU_HA;
/// Largest RSA modulus, in octets.
pub const MAX_RSA_KEY_BYTES: usize = config::MAX_RSA_KEY_BITS as usize / 8;
/// Largest symmetric key, in octets.
pub const MAX_SYM_KEY_BYTES: usize = config::MAX_SYM_KEY_BITS as usize / 8;
/// Largest value carried in a TPMU_SENSITIVE_CREATE.
pub const MAX_SYM_DATA: usize = 128;

/// The digest size for `hash_alg`, or `None` when the algorithm is not a hash.
pub fn digest_size(hash_alg: u16) -> Option<usize> {
    Some(match hash_alg {
        alg::SHA1 => 20,
        alg::SHA256 | alg::SHA3_256 => 32,
        alg::SHA384 | alg::SHA3_384 => 48,
        alg::SHA512 | alg::SHA3_512 => 64,
        alg::SM3_256 => 32,
        _ => return None,
    })
}

/// True when `hash_alg` names a hash this TPM implements.
pub fn is_implemented_hash(hash_alg: u16) -> bool {
    config::IMPLEMENTED_HASHES.contains(&hash_alg)
}

macro_rules! tpm2b {
    ($(#[$meta:meta])* $name:ident, $max:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
        pub struct $name {
            pub buffer: Vec<u8>,
        }

        impl $name {
            /// Largest `size` the specification allows for this type.
            pub const MAX: usize = $max;

            /// A buffer of size zero.
            pub fn empty() -> Self {
                $name { buffer: Vec::new() }
            }

            /// Build from octets, rejecting anything longer than `MAX`.
            pub fn new(buffer: Vec<u8>) -> TpmResult<Self> {
                if buffer.len() > Self::MAX {
                    return Err(TpmRc(rc::SIZE));
                }
                Ok($name { buffer })
            }

            /// Build from a slice, rejecting anything longer than `MAX`.
            pub fn from_slice(b: &[u8]) -> TpmResult<Self> {
                Self::new(b.to_vec())
            }

            /// Number of octets in the buffer.
            pub fn len(&self) -> usize {
                self.buffer.len()
            }

            /// True when `size` is zero.
            pub fn is_empty(&self) -> bool {
                self.buffer.is_empty()
            }

            /// The octets in the buffer.
            pub fn as_slice(&self) -> &[u8] {
                &self.buffer
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.buffer
            }
        }

        impl Marshal for $name {
            fn marshal(&self, w: &mut Writer) {
                w.sized16(&self.buffer);
            }
        }

        impl Unmarshal for $name {
            fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
                let size = r.u16()? as usize;
                if size > Self::MAX {
                    return Err(TpmRc(rc::SIZE));
                }
                Ok($name {
                    buffer: r.take(size)?.to_vec(),
                })
            }
        }
    };
}

tpm2b! {
    /// TPM2B_DIGEST, Part 2 Table 90.
    Tpm2bDigest, SIZEOF_TPMU_HA
}
tpm2b! {
    /// TPM2B_DATA, Part 2 Table 91.
    Tpm2bData, SIZEOF_TPMT_HA
}
tpm2b! {
    /// TPM2B_EVENT, Part 2 Table 95.
    Tpm2bEvent, 1024
}
tpm2b! {
    /// TPM2B_MAX_BUFFER, Part 2 Table 96.
    Tpm2bMaxBuffer, config::MAX_DIGEST_BUFFER
}
tpm2b! {
    /// TPM2B_MAX_NV_BUFFER, Part 2 Table 97.
    Tpm2bMaxNvBuffer, config::MAX_NV_BUFFER_SIZE
}
tpm2b! {
    /// TPM2B_TIMEOUT, Part 2 Table 98.
    Tpm2bTimeout, 8
}
tpm2b! {
    /// TPM2B_IV, Part 2 Table 99.
    Tpm2bIv, config::MAX_SYM_BLOCK_SIZE
}
tpm2b! {
    /// TPM2B_NAME, Part 2 Table 105.
    ///
    /// A Name is either a four octet handle or a TPMT_HA.
    Tpm2bName, SIZEOF_TPMT_HA
}
tpm2b! {
    /// TPM2B_ATTEST, Part 2 Table 155.
    Tpm2bAttest, 2048
}
tpm2b! {
    /// TPM2B_SYM_KEY, Part 2 Table 164.
    Tpm2bSymKey, MAX_SYM_KEY_BYTES
}
tpm2b! {
    /// TPM2B_LABEL, Part 2 Table 166.
    Tpm2bLabel, config::LABEL_MAX_BUFFER
}
tpm2b! {
    /// TPM2B_SENSITIVE_DATA, Part 2 Table 170.
    Tpm2bSensitiveData, MAX_SYM_DATA
}
tpm2b! {
    /// TPM2B_PUBLIC_KEY_RSA, Part 2 Table 194.
    Tpm2bPublicKeyRsa, MAX_RSA_KEY_BYTES
}
tpm2b! {
    /// TPM2B_PRIVATE_KEY_RSA, Part 2 Table 196.
    ///
    /// Large enough for the five values of a CRT private key.
    Tpm2bPrivateKeyRsa, (MAX_RSA_KEY_BYTES / 2) * 5
}
tpm2b! {
    /// TPM2B_ECC_PARAMETER, Part 2 Table 197.
    Tpm2bEccParameter, config::MAX_ECC_KEY_BYTES
}
tpm2b! {
    /// TPM2B_ENCRYPTED_SECRET, Part 2 Table 224.
    Tpm2bEncryptedSecret, MAX_RSA_KEY_BYTES
}
tpm2b! {
    /// TPM2B_PRIVATE, Part 2 Table 243.
    Tpm2bPrivate, 1024
}
tpm2b! {
    /// TPM2B_ID_OBJECT, Part 2 Table 245.
    Tpm2bIdObject, 1024
}
tpm2b! {
    /// TPM2B_CONTEXT_SENSITIVE, Part 2 Table 257.
    Tpm2bContextSensitive, config::MAX_CONTEXT_SIZE
}
tpm2b! {
    /// TPM2B_CONTEXT_DATA, Part 2 Table 259.
    Tpm2bContextData, config::MAX_CONTEXT_SIZE
}
tpm2b! {
    /// TPM2B_PRIVATE_VENDOR_SPECIFIC, Part 2 Table 238.
    Tpm2bPrivateVendorSpecific, MAX_RSA_KEY_BYTES
}
tpm2b! {
    /// TPM2B_TEMPLATE, Part 2 Table 237.
    Tpm2bTemplate, 1024
}
tpm2b! {
    /// TPM2B_VENDOR_PROPERTY, Part 2 Table 103.
    Tpm2bVendorProperty, config::MAX_VENDOR_BUFFER_SIZE
}
tpm2b! {
    /// TPM2B_SHARED_SECRET, Part 2 Table 100.
    Tpm2bSharedSecret, SIZEOF_TPMU_HA
}

/// TPM2B_NONCE, an alias of TPM2B_DIGEST, Part 2 Table 92.
pub type Tpm2bNonce = Tpm2bDigest;
/// TPM2B_AUTH, an alias of TPM2B_DIGEST, Part 2 Table 93.
pub type Tpm2bAuth = Tpm2bDigest;
/// TPM2B_OPERAND, an alias of TPM2B_DIGEST, Part 2 Table 94.
pub type Tpm2bOperand = Tpm2bDigest;

/// TPMT_HA, Part 2 Table 89.
///
/// A hash algorithm identifier followed by a digest of exactly the size that
/// algorithm produces. TPM_ALG_NULL selects an empty digest.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TpmtHa {
    pub hash_alg: u16,
    pub digest: Vec<u8>,
}

impl TpmtHa {
    /// A TPMT_HA with TPM_ALG_NULL and no digest.
    pub fn null() -> TpmtHa {
        TpmtHa {
            hash_alg: alg::NULL,
            digest: Vec::new(),
        }
    }

    /// Build a TPMT_HA, checking the digest length against the algorithm.
    pub fn new(hash_alg: u16, digest: Vec<u8>) -> TpmResult<TpmtHa> {
        if hash_alg == alg::NULL {
            if !digest.is_empty() {
                return Err(TpmRc(rc::SIZE));
            }
            return Ok(TpmtHa { hash_alg, digest });
        }
        match digest_size(hash_alg) {
            Some(n) if n == digest.len() => Ok(TpmtHa { hash_alg, digest }),
            Some(_) => Err(TpmRc(rc::SIZE)),
            None => Err(TpmRc(rc::HASH)),
        }
    }
}

impl Marshal for TpmtHa {
    fn marshal(&self, w: &mut Writer) {
        w.u16(self.hash_alg);
        w.bytes(&self.digest);
    }
}

impl Unmarshal for TpmtHa {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        let hash_alg = r.u16()?;
        if hash_alg == alg::NULL {
            return Ok(TpmtHa {
                hash_alg,
                digest: Vec::new(),
            });
        }
        let size = digest_size(hash_alg).ok_or(TpmRc(rc::HASH))?;
        Ok(TpmtHa {
            hash_alg,
            digest: r.take(size)?.to_vec(),
        })
    }
}

/// TPMS_PCR_SELECT, Part 2 Table 106.
///
/// A bit map over PCR indices. Bit `n` of octet `m` selects PCR `m * 8 + n`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PcrSelect {
    pub bits: Vec<u8>,
}

impl PcrSelect {
    /// An empty selection covering the implemented PCR.
    pub fn none() -> PcrSelect {
        PcrSelect {
            bits: vec![0u8; config::PCR_SELECT_MIN as usize],
        }
    }

    /// True when PCR `index` is selected.
    pub fn is_selected(&self, index: usize) -> bool {
        let byte = index / 8;
        let bit = index % 8;
        self.bits.get(byte).is_some_and(|b| b & (1 << bit) != 0)
    }

    /// Select PCR `index`, growing the bit map if needed.
    pub fn select(&mut self, index: usize) {
        let byte = index / 8;
        if self.bits.len() <= byte {
            self.bits.resize(byte + 1, 0);
        }
        self.bits[byte] |= 1 << (index % 8);
    }

    /// Clear PCR `index`.
    pub fn deselect(&mut self, index: usize) {
        let byte = index / 8;
        if let Some(b) = self.bits.get_mut(byte) {
            *b &= !(1 << (index % 8));
        }
    }

    /// Every selected PCR index, in increasing order.
    pub fn selected(&self) -> Vec<usize> {
        let mut out = Vec::new();
        for (i, byte) in self.bits.iter().enumerate() {
            for bit in 0..8 {
                if byte & (1 << bit) != 0 {
                    out.push(i * 8 + bit);
                }
            }
        }
        out
    }

    /// True when no PCR is selected.
    pub fn is_empty_selection(&self) -> bool {
        self.bits.iter().all(|b| *b == 0)
    }
}

impl Marshal for PcrSelect {
    fn marshal(&self, w: &mut Writer) {
        w.u8(self.bits.len() as u8);
        w.bytes(&self.bits);
    }
}

impl Unmarshal for PcrSelect {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        let size = r.u8()? as usize;
        if !(config::PCR_SELECT_MIN as usize..=config::PCR_SELECT_MAX as usize).contains(&size) {
            return Err(TpmRc(rc::VALUE));
        }
        Ok(PcrSelect {
            bits: r.take(size)?.to_vec(),
        })
    }
}

/// TPMS_PCR_SELECTION, Part 2 Table 107.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PcrSelection {
    pub hash_alg: u16,
    pub select: PcrSelect,
}

impl PcrSelection {
    pub fn new(hash_alg: u16, select: PcrSelect) -> PcrSelection {
        PcrSelection { hash_alg, select }
    }
}

impl Marshal for PcrSelection {
    fn marshal(&self, w: &mut Writer) {
        w.u16(self.hash_alg);
        self.select.marshal(w);
    }
}

impl Unmarshal for PcrSelection {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
        let hash_alg = r.u16()?;
        if digest_size(hash_alg).is_none() {
            return Err(TpmRc(rc::HASH));
        }
        let select = PcrSelect::unmarshal(r)?;
        Ok(PcrSelection { hash_alg, select })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_sizes_match_the_algorithms() {
        assert_eq!(digest_size(alg::SHA1), Some(20));
        assert_eq!(digest_size(alg::SHA256), Some(32));
        assert_eq!(digest_size(alg::SHA384), Some(48));
        assert_eq!(digest_size(alg::SHA512), Some(64));
        assert_eq!(digest_size(alg::SHA3_256), Some(32));
        assert_eq!(digest_size(alg::SHA3_384), Some(48));
        assert_eq!(digest_size(alg::SHA3_512), Some(64));
        assert_eq!(digest_size(alg::NULL), None);
        assert_eq!(digest_size(alg::RSA), None);
    }

    #[test]
    fn tpm2b_marshals_size_then_body() {
        let d = Tpm2bDigest::from_slice(&[0xaa, 0xbb, 0xcc]).unwrap();
        assert_eq!(d.to_bytes(), vec![0x00, 0x03, 0xaa, 0xbb, 0xcc]);
        assert_eq!(Tpm2bDigest::from_bytes(&d.to_bytes()).unwrap(), d);

        let e = Tpm2bDigest::empty();
        assert_eq!(e.to_bytes(), vec![0x00, 0x00]);
        assert!(e.is_empty());
    }

    #[test]
    fn tpm2b_rejects_oversized_values() {
        assert!(Tpm2bDigest::from_slice(&[0u8; 64]).is_ok());
        assert_eq!(
            Tpm2bDigest::from_slice(&[0u8; 65]).unwrap_err(),
            TpmRc(rc::SIZE)
        );
        // Unmarshalling refuses a size field larger than the maximum before it
        // touches the body.
        let mut raw = vec![0x00, 0x41];
        raw.extend_from_slice(&[0u8; 65]);
        assert_eq!(
            Tpm2bDigest::from_bytes(&raw).unwrap_err(),
            TpmRc(rc::SIZE)
        );
    }

    #[test]
    fn tpm2b_truncated_body_is_insufficient() {
        let raw = [0x00u8, 0x04, 0x01, 0x02];
        assert_eq!(
            Tpm2bDigest::from_bytes(&raw).unwrap_err(),
            TpmRc(rc::INSUFFICIENT)
        );
    }

    #[test]
    fn tpmt_ha_digest_length_follows_the_algorithm() {
        let h = TpmtHa::new(alg::SHA256, vec![0x11; 32]).unwrap();
        let bytes = h.to_bytes();
        assert_eq!(bytes.len(), 34);
        assert_eq!(&bytes[0..2], &alg::SHA256.to_be_bytes());
        assert_eq!(TpmtHa::from_bytes(&bytes).unwrap(), h);

        assert_eq!(
            TpmtHa::new(alg::SHA256, vec![0x11; 31]).unwrap_err(),
            TpmRc(rc::SIZE)
        );
        assert_eq!(
            TpmtHa::new(alg::RSA, vec![0x11; 32]).unwrap_err(),
            TpmRc(rc::HASH)
        );
    }

    #[test]
    fn tpmt_ha_null_has_no_digest() {
        let h = TpmtHa::null();
        assert_eq!(h.to_bytes(), vec![0x00, 0x10]);
        assert_eq!(TpmtHa::from_bytes(&[0x00, 0x10]).unwrap(), h);
        assert!(TpmtHa::new(alg::NULL, vec![0x00]).is_err());
    }

    #[test]
    fn tpmt_ha_rejects_unknown_algorithm() {
        assert_eq!(
            TpmtHa::from_bytes(&[0x00, 0x01, 0x00]).unwrap_err(),
            TpmRc(rc::HASH)
        );
    }

    #[test]
    fn pcr_select_bit_mapping() {
        let mut s = PcrSelect::none();
        assert_eq!(s.bits.len(), 3);
        s.select(0);
        s.select(7);
        s.select(8);
        s.select(23);
        assert_eq!(s.bits, vec![0b1000_0001, 0b0000_0001, 0b1000_0000]);
        assert_eq!(s.selected(), vec![0, 7, 8, 23]);
        assert!(s.is_selected(0));
        assert!(!s.is_selected(1));
        s.deselect(0);
        assert!(!s.is_selected(0));
        assert!(!s.is_empty_selection());
    }

    #[test]
    fn pcr_select_marshals_with_a_size_octet() {
        let mut s = PcrSelect::none();
        s.select(1);
        assert_eq!(s.to_bytes(), vec![0x03, 0x02, 0x00, 0x00]);
        assert_eq!(PcrSelect::from_bytes(&s.to_bytes()).unwrap(), s);
    }

    #[test]
    fn pcr_select_size_is_checked() {
        // A size below PCR_SELECT_MIN is rejected.
        assert_eq!(
            PcrSelect::from_bytes(&[0x02, 0x00, 0x00]).unwrap_err(),
            TpmRc(rc::VALUE)
        );
        // A size above PCR_SELECT_MAX is rejected.
        assert_eq!(
            PcrSelect::from_bytes(&[0x04, 0x00, 0x00, 0x00, 0x00]).unwrap_err(),
            TpmRc(rc::VALUE)
        );
    }

    #[test]
    fn pcr_selection_round_trip() {
        let mut s = PcrSelect::none();
        s.select(16);
        let sel = PcrSelection::new(alg::SHA256, s);
        let bytes = sel.to_bytes();
        assert_eq!(&bytes[0..2], &alg::SHA256.to_be_bytes());
        assert_eq!(PcrSelection::from_bytes(&bytes).unwrap(), sel);
        // A non-hash algorithm is rejected.
        let mut bad = bytes.clone();
        bad[0..2].copy_from_slice(&alg::RSA.to_be_bytes());
        assert_eq!(
            PcrSelection::from_bytes(&bad).unwrap_err(),
            TpmRc(rc::HASH)
        );
    }
}
