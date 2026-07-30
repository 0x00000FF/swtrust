//! The TPM simulator TCP protocol.
//!
//! Requests are a UINT32 opcode followed by opcode specific fields. All
//! integers are big endian. Most requests end with a UINT32 acknowledgement of
//! zero. This is the protocol used by the reference simulator, so tools such as
//! the TSS libraries connect without changes.

use std::io::{self, Read, Write};

/// Opcodes carried on both ports.
pub mod op {
    pub const SIGNAL_POWER_ON: u32 = 1;
    pub const SIGNAL_POWER_OFF: u32 = 2;
    pub const SIGNAL_PHYS_PRES_ON: u32 = 3;
    pub const SIGNAL_PHYS_PRES_OFF: u32 = 4;
    pub const SIGNAL_HASH_START: u32 = 5;
    pub const SIGNAL_HASH_DATA: u32 = 6;
    pub const SIGNAL_HASH_END: u32 = 7;
    pub const SEND_COMMAND: u32 = 8;
    pub const SIGNAL_CANCEL_ON: u32 = 9;
    pub const SIGNAL_CANCEL_OFF: u32 = 10;
    pub const SIGNAL_NV_ON: u32 = 11;
    pub const SIGNAL_NV_OFF: u32 = 12;
    pub const SIGNAL_KEY_CACHE_ON: u32 = 13;
    pub const SIGNAL_KEY_CACHE_OFF: u32 = 14;
    pub const REMOTE_HANDSHAKE: u32 = 15;
    pub const SET_ALTERNATIVE_RESULT: u32 = 16;
    pub const SIGNAL_RESET: u32 = 17;
    pub const SIGNAL_RESTART: u32 = 18;
    pub const SESSION_END: u32 = 20;
    pub const STOP: u32 = 21;
    pub const GET_COMMAND_RESPONSE_SIZES: u32 = 25;
    pub const ACT_GET_SIGNALED: u32 = 26;
    pub const TEST_FAILURE_MODE: u32 = 30;
}

/// Protocol version reported in the handshake.
pub const SERVER_VERSION: u32 = 1;

/// Flags describing what the endpoint supports, returned by the handshake.
pub mod endpoint {
    pub const PLATFORM_AVAILABLE: u32 = 0x01;
    pub const USES_TBS: u32 = 0x02;
    pub const IN_RAW_MODE: u32 = 0x04;
    pub const SUPPORTS_PP: u32 = 0x08;
    pub const NO_POWER_CTL: u32 = 0x10;
    pub const NO_LOCALITY_CTL: u32 = 0x20;
}

/// What this implementation supports: a separate platform port and physical
/// presence signalling.
pub const ENDPOINT_INFO: u32 = endpoint::PLATFORM_AVAILABLE | endpoint::SUPPORTS_PP;

/// Acknowledgement value appended to most replies.
pub const ACK_OK: u32 = 0;

/// Largest buffer accepted from a client, which bounds memory use if a peer
/// sends a bogus length.
///
/// Commands are limited to `config::MAX_COMMAND_SIZE` by the TPM itself. This
/// bound applies to the transport, and covers the H-CRTM data blobs as well as
/// commands, so it is set well above the command limit but far below anything
/// that would strain memory.
pub const MAX_TRANSFER: u32 = 64 * 1024;

/// Read a big endian UINT32, returning `None` at a clean end of stream.
pub fn read_u32_opt<R: Read>(r: &mut R) -> io::Result<Option<u32>> {
    let mut b = [0u8; 4];
    let mut filled = 0;
    while filled < 4 {
        match r.read(&mut b[filled..])? {
            0 if filled == 0 => return Ok(None),
            0 => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated length",
                ))
            }
            n => filled += n,
        }
    }
    Ok(Some(u32::from_be_bytes(b)))
}

/// Read a big endian UINT32.
pub fn read_u32<R: Read>(r: &mut R) -> io::Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_be_bytes(b))
}

/// Read one octet.
pub fn read_u8<R: Read>(r: &mut R) -> io::Result<u8> {
    let mut b = [0u8; 1];
    r.read_exact(&mut b)?;
    Ok(b[0])
}

/// Read a UINT32 length followed by that many octets.
pub fn read_blob<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
    let len = read_u32(r)?;
    if len > MAX_TRANSFER {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("transfer of {len} octets is too large"),
        ));
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// Write a big endian UINT32.
pub fn write_u32<W: Write>(w: &mut W, v: u32) -> io::Result<()> {
    w.write_all(&v.to_be_bytes())
}

/// Write a UINT32 length followed by the octets.
pub fn write_blob<W: Write>(w: &mut W, b: &[u8]) -> io::Result<()> {
    write_u32(w, b.len() as u32)?;
    w.write_all(b)
}

/// Write the standard acknowledgement.
pub fn write_ack<W: Write>(w: &mut W) -> io::Result<()> {
    write_u32(w, ACK_OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_round_trip() {
        let mut buf = Vec::new();
        write_u32(&mut buf, 0x1234_5678).unwrap();
        assert_eq!(buf, vec![0x12, 0x34, 0x56, 0x78]);
        let mut cur = std::io::Cursor::new(buf);
        assert_eq!(read_u32(&mut cur).unwrap(), 0x1234_5678);
    }

    #[test]
    fn blob_round_trip() {
        let mut buf = Vec::new();
        write_blob(&mut buf, &[1, 2, 3]).unwrap();
        assert_eq!(buf, vec![0, 0, 0, 3, 1, 2, 3]);
        let mut cur = std::io::Cursor::new(buf);
        assert_eq!(read_blob(&mut cur).unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn clean_end_of_stream_is_none() {
        let mut cur = std::io::Cursor::new(Vec::new());
        assert_eq!(read_u32_opt(&mut cur).unwrap(), None);
    }

    #[test]
    fn partial_length_is_an_error() {
        let mut cur = std::io::Cursor::new(vec![0x00, 0x01]);
        let e = read_u32_opt(&mut cur).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn oversized_blob_is_rejected() {
        let mut data = Vec::new();
        write_u32(&mut data, MAX_TRANSFER + 1).unwrap();
        let mut cur = std::io::Cursor::new(data);
        let e = read_blob(&mut cur).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn endpoint_info_advertises_platform_and_pp() {
        assert_eq!(ENDPOINT_INFO, 0x09);
    }
}
