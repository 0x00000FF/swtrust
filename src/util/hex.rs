//! Hex encoding and decoding for the state file and log records.

/// Encode bytes as lowercase hex.
pub fn encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

/// Encode bytes as hex wrapped at `width` characters per line.
pub fn encode_wrapped(bytes: &[u8], width: usize) -> String {
    let flat = encode(bytes);
    if width == 0 {
        return flat;
    }
    let mut out = String::with_capacity(flat.len() + flat.len() / width + 1);
    for (i, ch) in flat.chars().enumerate() {
        if i > 0 && i % width == 0 {
            out.push('\n');
        }
        out.push(ch);
    }
    out
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Decode hex, ignoring ASCII whitespace so wrapped text decodes cleanly.
pub fn decode(text: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(text.len() / 2);
    let mut high: Option<u8> = None;
    for (i, c) in text.bytes().enumerate() {
        if c.is_ascii_whitespace() {
            continue;
        }
        let n = nibble(c).ok_or_else(|| format!("invalid hex character at offset {i}"))?;
        match high.take() {
            None => high = Some(n),
            Some(h) => out.push((h << 4) | n),
        }
    }
    if high.is_some() {
        return Err("hex input has an odd number of digits".to_string());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let data: Vec<u8> = (0u8..=255).collect();
        let text = encode(&data);
        assert_eq!(text.len(), 512);
        assert_eq!(decode(&text).unwrap(), data);
    }

    #[test]
    fn known_vectors() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(&[0x00, 0x0f, 0xf0, 0xff]), "000ff0ff");
        assert_eq!(decode("DEADBEEF").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn whitespace_is_ignored() {
        assert_eq!(decode(" de ad\nbe\r\nef\t").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn wrapping_and_decode() {
        let data: Vec<u8> = (0u8..64).collect();
        let text = encode_wrapped(&data, 32);
        for line in text.lines() {
            assert!(line.len() <= 32);
        }
        assert_eq!(decode(&text).unwrap(), data);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(decode("abc").is_err());
        assert!(decode("zz").is_err());
    }
}
