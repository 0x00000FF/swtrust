//! Canonical marshalling and unmarshalling.
//!
//! Part 2 clause 4 defines the octet order for every type: integers are big
//! endian, arrays are written element by element with no padding, and a TPM2B
//! is a UINT16 size followed by that many octets. Part 2 Table 2 lists the
//! response codes that unmarshalling errors produce.

use crate::tpm::constants::rc;
use crate::tpm::error::{TpmRc, TpmResult};

/// Reads values out of a command buffer.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf, pos: 0 }
    }

    /// Octets not yet consumed.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Refuse a buffer that holds more than has been read.
    ///
    /// Part 3 clause 5.8.2 answers TPM_RC_SIZE when a command carries surplus
    /// parameter octets. A command calls this once it has read what its
    /// schematic defines and before it changes anything, so clause 5.6 leaves
    /// the TPM alone.
    pub fn expect_end(&self) -> TpmResult<()> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(TpmRc(rc::SIZE))
        }
    }

    /// True when every octet has been consumed.
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Current offset from the start of the buffer.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// The octets that have not been consumed.
    pub fn rest(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    /// Consume `n` octets.
    pub fn take(&mut self, n: usize) -> TpmResult<&'a [u8]> {
        if self.remaining() < n {
            return Err(TpmRc(rc::INSUFFICIENT));
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    /// Consume every remaining octet.
    pub fn take_rest(&mut self) -> &'a [u8] {
        let out = &self.buf[self.pos..];
        self.pos = self.buf.len();
        out
    }

    /// A reader over a sub range, used to unmarshal sized buffers.
    pub fn sub(&mut self, n: usize) -> TpmResult<Reader<'a>> {
        Ok(Reader::new(self.take(n)?))
    }

    pub fn u8(&mut self) -> TpmResult<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> TpmResult<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self) -> TpmResult<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64(&mut self) -> TpmResult<u64> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    pub fn i8(&mut self) -> TpmResult<i8> {
        Ok(self.u8()? as i8)
    }

    /// Unmarshal any type that implements `Unmarshal`.
    pub fn get<T: Unmarshal>(&mut self) -> TpmResult<T> {
        T::unmarshal(self)
    }
}

/// Writes values into a response buffer.
///
/// A TPM2B length field is a UINT16, so a body longer than 65535 octets cannot
/// be described. Nothing the TPM produces is that large, but rather than
/// silently write a truncated length the writer records the overflow and
/// [`Writer::finish`] turns it into TPM_RC_SIZE.
#[derive(Debug, Default, Clone)]
pub struct Writer {
    buf: Vec<u8>,
    overflow: bool,
}

impl Writer {
    pub fn new() -> Writer {
        Writer {
            buf: Vec::new(),
            overflow: false,
        }
    }

    pub fn with_capacity(n: usize) -> Writer {
        Writer {
            buf: Vec::with_capacity(n),
            overflow: false,
        }
    }

    /// True when a sized field could not hold its own length.
    pub fn overflowed(&self) -> bool {
        self.overflow
    }

    /// The octets written, or TPM_RC_SIZE when a length field overflowed.
    pub fn finish(self) -> TpmResult<Vec<u8>> {
        if self.overflow {
            return Err(TpmRc(rc::SIZE));
        }
        Ok(self.buf)
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }

    pub fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn i8(&mut self, v: i8) {
        self.buf.push(v as u8);
    }

    /// Marshal any type that implements `Marshal`.
    pub fn put<T: Marshal + ?Sized>(&mut self, v: &T) {
        v.marshal(self);
    }

    /// Write a UINT16 length prefix followed by `body`, as a TPM2B does.
    pub fn sized16(&mut self, body: &[u8]) {
        match u16::try_from(body.len()) {
            Ok(n) => self.u16(n),
            Err(_) => {
                self.overflow = true;
                self.u16(0);
            }
        }
        self.bytes(body);
    }

    /// Reserve a UINT16 length field, run `f`, then fill in the length with the
    /// number of octets `f` produced. Used for TPM2B structures whose body is
    /// itself a marshalled structure.
    pub fn sized16_with<F: FnOnce(&mut Writer)>(&mut self, f: F) {
        let at = self.buf.len();
        self.u16(0);
        let start = self.buf.len();
        f(self);
        match u16::try_from(self.buf.len() - start) {
            Ok(n) => self.buf[at..at + 2].copy_from_slice(&n.to_be_bytes()),
            Err(_) => self.overflow = true,
        }
    }
}

/// A type that can be written to a response.
pub trait Marshal {
    fn marshal(&self, w: &mut Writer);

    /// Convenience helper returning the marshalled octets.
    fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.marshal(&mut w);
        w.into_vec()
    }
}

/// A type that can be read from a command.
pub trait Unmarshal: Sized {
    fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self>;

    /// Convenience helper that requires the whole slice to be consumed.
    fn from_bytes(b: &[u8]) -> TpmResult<Self> {
        let mut r = Reader::new(b);
        let v = Self::unmarshal(&mut r)?;
        if !r.is_empty() {
            return Err(TpmRc(rc::SIZE));
        }
        Ok(v)
    }
}

macro_rules! primitive {
    ($t:ty, $get:ident, $put:ident) => {
        impl Marshal for $t {
            fn marshal(&self, w: &mut Writer) {
                w.$put(*self);
            }
        }
        impl Unmarshal for $t {
            fn unmarshal(r: &mut Reader<'_>) -> TpmResult<Self> {
                r.$get()
            }
        }
    };
}

primitive!(u8, u8, u8);
primitive!(u16, u16, u16);
primitive!(u32, u32, u32);
primitive!(u64, u64, u64);
primitive!(i8, i8, i8);

impl Marshal for [u8] {
    fn marshal(&self, w: &mut Writer) {
        w.bytes(self);
    }
}

impl Marshal for Vec<u8> {
    fn marshal(&self, w: &mut Writer) {
        w.bytes(self);
    }
}

/// Unmarshal a counted list of `T`, rejecting counts above `max`.
pub fn unmarshal_list<T: Unmarshal>(r: &mut Reader<'_>, max: usize) -> TpmResult<Vec<T>> {
    let count = r.u32()? as usize;
    if count > max {
        return Err(TpmRc(rc::SIZE));
    }
    let mut out = Vec::with_capacity(count.min(max));
    for _ in 0..count {
        out.push(T::unmarshal(r)?);
    }
    Ok(out)
}

/// Marshal a counted list of `T`.
pub fn marshal_list<T: Marshal>(w: &mut Writer, items: &[T]) {
    w.u32(items.len() as u32);
    for item in items {
        item.marshal(w);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_are_big_endian() {
        let mut w = Writer::new();
        w.u8(0x01);
        w.u16(0x0203);
        w.u32(0x0405_0607);
        w.u64(0x0809_0a0b_0c0d_0e0f);
        assert_eq!(
            w.as_slice(),
            &[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f
            ]
        );

        let bytes = w.into_vec();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.u8().unwrap(), 0x01);
        assert_eq!(r.u16().unwrap(), 0x0203);
        assert_eq!(r.u32().unwrap(), 0x0405_0607);
        assert_eq!(r.u64().unwrap(), 0x0809_0a0b_0c0d_0e0f);
        assert!(r.is_empty());
    }

    #[test]
    fn reading_past_the_end_is_insufficient() {
        let mut r = Reader::new(&[0x00]);
        assert_eq!(r.u16().unwrap_err(), TpmRc(rc::INSUFFICIENT));
        // The failed read does not consume anything.
        assert_eq!(r.remaining(), 1);
        assert_eq!(r.u8().unwrap(), 0);
        assert_eq!(r.u8().unwrap_err(), TpmRc(rc::INSUFFICIENT));
    }

    #[test]
    fn sized_writer_backfills_the_length() {
        let mut w = Writer::new();
        w.sized16_with(|w| {
            w.u32(0xdead_beef);
            w.u16(0x1234);
        });
        assert_eq!(
            w.as_slice(),
            &[0x00, 0x06, 0xde, 0xad, 0xbe, 0xef, 0x12, 0x34]
        );
    }

    #[test]
    fn sized16_matches_manual_prefix() {
        let mut w = Writer::new();
        w.sized16(&[1, 2, 3]);
        assert_eq!(w.as_slice(), &[0x00, 0x03, 1, 2, 3]);
        assert!(!w.overflowed());
        assert_eq!(w.finish().unwrap(), vec![0x00, 0x03, 1, 2, 3]);
    }

    #[test]
    fn a_body_too_long_for_a_uint16_is_reported() {
        let big = vec![0u8; 65_536];
        let mut w = Writer::new();
        w.sized16(&big);
        assert!(w.overflowed());
        assert_eq!(w.finish().unwrap_err(), TpmRc(rc::SIZE));

        let mut w = Writer::new();
        w.sized16_with(|w| w.bytes(&big));
        assert!(w.overflowed());
        assert_eq!(w.finish().unwrap_err(), TpmRc(rc::SIZE));

        // The largest body a UINT16 can describe is still accepted.
        let mut w = Writer::new();
        w.sized16(&vec![0u8; 65_535]);
        assert!(!w.overflowed());
        assert_eq!(&w.as_slice()[0..2], &0xFFFFu16.to_be_bytes());
    }

    #[test]
    fn sub_reader_is_bounded() {
        let data = [1u8, 2, 3, 4, 5, 6];
        let mut r = Reader::new(&data);
        let mut s = r.sub(3).unwrap();
        assert_eq!(s.take_rest(), &[1, 2, 3]);
        assert_eq!(r.take_rest(), &[4, 5, 6]);
    }

    #[test]
    fn list_round_trip() {
        let items: Vec<u32> = vec![1, 2, 3];
        let mut w = Writer::new();
        marshal_list(&mut w, &items);
        assert_eq!(w.as_slice()[..4], [0, 0, 0, 3]);
        let bytes = w.into_vec();
        let mut r = Reader::new(&bytes);
        let back: Vec<u32> = unmarshal_list(&mut r, 8).unwrap();
        assert_eq!(back, items);
    }

    #[test]
    fn list_rejects_oversized_count() {
        let bytes = [0u8, 0, 0, 9];
        let mut r = Reader::new(&bytes);
        let e = unmarshal_list::<u32>(&mut r, 8).unwrap_err();
        assert_eq!(e, TpmRc(rc::SIZE));
    }

    #[test]
    fn from_bytes_requires_full_consumption() {
        assert_eq!(u16::from_bytes(&[0x12, 0x34]).unwrap(), 0x1234);
        assert_eq!(
            u16::from_bytes(&[0x12, 0x34, 0x56]).unwrap_err(),
            TpmRc(rc::SIZE)
        );
    }
}
