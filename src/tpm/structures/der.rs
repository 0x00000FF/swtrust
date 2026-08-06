//! The part of DER that TPM2_CertifyX509 needs.
//!
//! Part 3 clause 18.8 has the caller hand in a DER encoded partial certificate
//! and has the TPM return the DER encoded fields it added, so the TPM has to
//! both read and write the encoding. Only what an RFC 5280 TBSCertificate uses
//! is here: definite length tag-length-value elements, unsigned integers, bit
//! strings, object identifiers and sequences.

use crate::tpm::constants::rc;
use crate::tpm::error::{TpmRc, TpmResult};

/// The universal class tags this module names.
pub mod tag {
    /// INTEGER.
    pub const INTEGER: u8 = 0x02;
    /// BIT STRING.
    pub const BIT_STRING: u8 = 0x03;
    /// OCTET STRING.
    pub const OCTET_STRING: u8 = 0x04;
    /// NULL.
    pub const NULL: u8 = 0x05;
    /// OBJECT IDENTIFIER.
    pub const OID: u8 = 0x06;
    /// SEQUENCE, always constructed.
    pub const SEQUENCE: u8 = 0x30;

    /// A context specific constructed tag, as `[0]` and `[3]` are written in
    /// the RFC 5280 grammar.
    pub const fn context(number: u8) -> u8 {
        0xA0 | number
    }
}

/// One tag-length-value element, borrowed from the buffer it was read out of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Element<'a> {
    /// The identifier octet.
    pub tag: u8,
    /// The content octets, with the tag and length taken off.
    pub value: &'a [u8],
    /// The element as it appeared, tag and length included.
    pub raw: &'a [u8],
}

/// A reader over a sequence of DER elements.
pub struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    /// Read the elements of `data` one after another.
    pub fn new(data: &'a [u8]) -> Reader<'a> {
        Reader { data, at: 0 }
    }

    /// True once every element has been read.
    pub fn is_empty(&self) -> bool {
        self.at >= self.data.len()
    }

    /// How many octets are left unread.
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.at)
    }

    /// Read the next element.
    ///
    /// Only the definite length forms are accepted. The indefinite form is not
    /// DER, and a length that does not fit the buffer is refused rather than
    /// read past.
    pub fn element(&mut self) -> TpmResult<Element<'a>> {
        let start = self.at;
        let tag = *self.data.get(self.at).ok_or(TpmRc(rc::INSUFFICIENT))?;
        self.at += 1;
        let first = *self.data.get(self.at).ok_or(TpmRc(rc::INSUFFICIENT))?;
        self.at += 1;
        let length = if first < 0x80 {
            first as usize
        } else {
            let count = (first & 0x7F) as usize;
            // 0x80 is the indefinite form, which DER does not allow, and a
            // length field longer than a pointer cannot address this buffer.
            if count == 0 || count > 4 {
                return Err(TpmRc(rc::VALUE));
            }
            let mut length = 0usize;
            for _ in 0..count {
                let octet = *self.data.get(self.at).ok_or(TpmRc(rc::INSUFFICIENT))?;
                self.at += 1;
                length = (length << 8) | octet as usize;
            }
            // DER writes the shortest length, so a long form that a short form
            // could have held is not DER.
            if length < 0x80 {
                return Err(TpmRc(rc::VALUE));
            }
            length
        };
        let end = self.at.checked_add(length).ok_or(TpmRc(rc::VALUE))?;
        if end > self.data.len() {
            return Err(TpmRc(rc::INSUFFICIENT));
        }
        let value = &self.data[self.at..end];
        let raw = &self.data[start..end];
        self.at = end;
        Ok(Element { tag, value, raw })
    }

    /// Read the next element and require its tag.
    pub fn tagged(&mut self, want: u8) -> TpmResult<Element<'a>> {
        let element = self.element()?;
        if element.tag != want {
            return Err(TpmRc(rc::VALUE));
        }
        Ok(element)
    }
}

/// Write one element, with the shortest length DER allows.
pub fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 6);
    out.push(tag);
    let length = value.len();
    if length < 0x80 {
        out.push(length as u8);
    } else {
        let octets = length.to_be_bytes();
        let first = octets.iter().position(|o| *o != 0).unwrap_or(octets.len() - 1);
        let significant = &octets[first..];
        out.push(0x80 | significant.len() as u8);
        out.extend_from_slice(significant);
    }
    out.extend_from_slice(value);
    out
}

/// Write a SEQUENCE holding the parts in order.
pub fn sequence(parts: &[&[u8]]) -> Vec<u8> {
    let mut body = Vec::new();
    for part in parts {
        body.extend_from_slice(part);
    }
    tlv(tag::SEQUENCE, &body)
}

/// Write a context specific constructed element holding the parts in order.
pub fn context(number: u8, parts: &[&[u8]]) -> Vec<u8> {
    let mut body = Vec::new();
    for part in parts {
        body.extend_from_slice(part);
    }
    tlv(tag::context(number), &body)
}

/// Write a non-negative INTEGER from its big endian octets.
///
/// DER writes the shortest two's complement form, so leading zero octets come
/// off and one goes back on when the top bit would otherwise make the value
/// negative.
pub fn unsigned_integer(value: &[u8]) -> Vec<u8> {
    let first = value.iter().position(|o| *o != 0).unwrap_or(value.len());
    let trimmed = &value[first..];
    if trimmed.is_empty() {
        return tlv(tag::INTEGER, &[0]);
    }
    if trimmed[0] & 0x80 != 0 {
        let mut body = Vec::with_capacity(trimmed.len() + 1);
        body.push(0);
        body.extend_from_slice(trimmed);
        return tlv(tag::INTEGER, &body);
    }
    tlv(tag::INTEGER, trimmed)
}

/// Write a BIT STRING whose length is a whole number of octets.
pub fn bit_string(value: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(value.len() + 1);
    body.push(0); // unused bits in the final octet
    body.extend_from_slice(value);
    tlv(tag::BIT_STRING, &body)
}

/// The value of a BIT STRING as a big endian bit field, most significant bit
/// first, which is how X.509 numbers the bits of a KeyUsage.
///
/// RFC 5280 clause 4.2.1.3 writes KeyUsage as a named bit list, so the encoder
/// drops trailing zero bits and says how many of the last octet are unused.
/// Reading it back has to put those bits back.
pub fn bit_field(value: &[u8]) -> TpmResult<u32> {
    let unused = *value.first().ok_or(TpmRc(rc::INSUFFICIENT))? as usize;
    let bits = &value[1..];
    if unused > 7 || (bits.is_empty() && unused != 0) {
        return Err(TpmRc(rc::VALUE));
    }
    if bits.len() > 4 {
        return Err(TpmRc(rc::SIZE));
    }
    let mut out = 0u32;
    for (index, octet) in bits.iter().enumerate() {
        out |= (*octet as u32) << (24 - 8 * index);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_length_round_trips() {
        let encoded = tlv(tag::OCTET_STRING, &[1, 2, 3]);
        assert_eq!(encoded, vec![0x04, 0x03, 1, 2, 3]);
        let mut r = Reader::new(&encoded);
        let e = r.element().unwrap();
        assert_eq!(e.tag, tag::OCTET_STRING);
        assert_eq!(e.value, &[1, 2, 3]);
        assert!(r.is_empty());
    }

    #[test]
    fn a_long_length_round_trips() {
        let body = vec![0x5au8; 300];
        let encoded = tlv(tag::OCTET_STRING, &body);
        assert_eq!(&encoded[..4], &[0x04, 0x82, 0x01, 0x2C]);
        let mut r = Reader::new(&encoded);
        assert_eq!(r.element().unwrap().value, body.as_slice());
    }

    #[test]
    fn the_indefinite_form_is_refused() {
        let mut r = Reader::new(&[0x30, 0x80, 0x00, 0x00]);
        assert_eq!(r.element().unwrap_err(), TpmRc(rc::VALUE));
    }

    #[test]
    fn a_length_that_is_not_the_shortest_is_refused() {
        // 0x81 0x05 says five octets in the long form, which the short form
        // could have said.
        let mut r = Reader::new(&[0x04, 0x81, 0x05, 1, 2, 3, 4, 5]);
        assert_eq!(r.element().unwrap_err(), TpmRc(rc::VALUE));
    }

    #[test]
    fn a_length_past_the_buffer_is_refused() {
        let mut r = Reader::new(&[0x04, 0x08, 1, 2, 3]);
        assert_eq!(r.element().unwrap_err(), TpmRc(rc::INSUFFICIENT));
    }

    #[test]
    fn an_integer_takes_the_shortest_form() {
        assert_eq!(unsigned_integer(&[0x00, 0x00, 0x2A]), vec![0x02, 0x01, 0x2A]);
        assert_eq!(unsigned_integer(&[0x80, 0x01]), vec![0x02, 0x03, 0x00, 0x80, 0x01]);
        assert_eq!(unsigned_integer(&[0x00]), vec![0x02, 0x01, 0x00]);
    }

    #[test]
    fn a_bit_field_puts_the_dropped_bits_back() {
        // KeyUsage with digitalSignature alone: bit 0 of the X.509 numbering,
        // which is bit 31 of the TPMA_X509_KEY_USAGE word.
        assert_eq!(bit_field(&[7, 0x80]).unwrap(), 0x8000_0000);
        // digitalSignature and keyCertSign, X.509 bits 0 and 5.
        assert_eq!(bit_field(&[2, 0x84]).unwrap(), 0x8400_0000);
    }

    #[test]
    fn a_bit_field_refuses_more_unused_bits_than_an_octet_has() {
        assert_eq!(bit_field(&[8, 0x80]).unwrap_err(), TpmRc(rc::VALUE));
    }

    #[test]
    fn a_sequence_holds_its_parts_in_order() {
        let a = unsigned_integer(&[1]);
        let b = unsigned_integer(&[2]);
        let s = sequence(&[&a, &b]);
        let mut r = Reader::new(&s);
        let outer = r.tagged(tag::SEQUENCE).unwrap();
        let mut inner = Reader::new(outer.value);
        assert_eq!(inner.tagged(tag::INTEGER).unwrap().value, &[1]);
        assert_eq!(inner.tagged(tag::INTEGER).unwrap().value, &[2]);
        assert!(inner.is_empty());
    }
}
