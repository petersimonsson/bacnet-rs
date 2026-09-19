//! BACnet CharacterString encoding and decoding.
//!
//! This module implements ASHRAE 135-2024, Clause 20.2.9 ("Encoding of a
//! Character String Value") in full: all six character sets the standard
//! defines, not just UTF-8.
//!
//! # Content layout
//!
//! A CharacterString's content is one character-set octet followed by zero
//! or more data octets:
//!
//! | Charset octet | Character set |
//! |---|---|
//! | `0x00` | ISO 10646 (UTF-8) |
//! | `0x01` | IBM/Microsoft DBCS (followed by a 2-octet, big-endian code page number) |
//! | `0x02` | JIS X 0208 |
//! | `0x03` | ISO 10646 (UCS-4) — 4 octets per character, big-endian |
//! | `0x04` | ISO 10646 (UCS-2) — 2 octets per character, big-endian |
//! | `0x05` | ISO 8859-1 |
//!
//! Other charset octet values are reserved by ASHRAE and are rejected.
//!
//! # Decoding legacy charsets
//!
//! DBCS (`0x01`) and JIS X 0208 (`0x02`) are genuine variable-width,
//! code-page-dependent encodings that cannot be hand-rolled from the spec
//! text alone. When this crate's `legacy-charsets` feature is enabled
//! (opt-in — off by default), they are decoded via the `encoding_rs` crate (for
//! Windows/WHATWG code pages such as Shift_JIS, GBK, EUC-KR, Big5, and the
//! `windows-125x` family) and the `oem_cp` crate (for classic single-byte
//! DOS/OEM code pages such as 437 and 850 — the latter is the code page used
//! in the standard's own DBCS worked example). Without that feature, or for
//! a code page neither crate recognizes, only the ASCII-safe byte range
//! (`< 0x80`) is decoded; genuine multi-byte content is reported as an
//! error rather than guessed at.
//!
//! # Encoding
//!
//! This module only ever *encodes* as UTF-8 (`0x00`). Every compliant
//! BACnet implementation must be able to decode UTF-8 CharacterStrings, so
//! there is no interoperability reason to emit any of the legacy charsets
//! this module can decode.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use super::{
    tag::{ApplicationTagNumber, Tag, TagClass, TagValue},
    EncodingError, Result,
};

const CHARSET_UTF8: u8 = 0x00;
const CHARSET_DBCS: u8 = 0x01;
const CHARSET_JIS_X0208: u8 = 0x02;
const CHARSET_UCS4: u8 = 0x03;
const CHARSET_UCS2: u8 = 0x04;
const CHARSET_ISO_8859_1: u8 = 0x05;

/// The character set a decoded BACnet CharacterString was encoded in
/// (ASHRAE 135-2024, Clause 20.2.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CharacterSet {
    /// ISO 10646 (UTF-8).
    Utf8,
    /// IBM/Microsoft DBCS, carrying its 16-bit code page number.
    Dbcs(u16),
    /// JIS X 0208.
    JisX0208,
    /// ISO 10646 (UCS-4).
    Ucs4,
    /// ISO 10646 (UCS-2).
    Ucs2,
    /// ISO 8859-1.
    Iso8859_1,
}

/// Encodes `value` as a BACnet application-tagged CharacterString.
///
/// Always uses charset `0x00` (ISO 10646 UTF-8) — see the module docs for why.
pub fn encode_character_string(buffer: &mut Vec<u8>, value: &str) -> Result<()> {
    Tag {
        number: ApplicationTagNumber::CharacterString as u32,
        class: TagClass::Application,
        value: TagValue::Primitive(value.len() as u32 + 1),
    }
    .encode(buffer)?;
    encode_utf8_content(buffer, value);
    Ok(())
}

/// Encodes just the character-set-octet-plus-data content of a
/// CharacterString, with no tag of its own.
///
/// For callers that build their own tag framing around the content, such as
/// a context-tagged CharacterString.
pub fn encode_utf8_content(buffer: &mut Vec<u8>, value: &str) {
    buffer.push(CHARSET_UTF8);
    buffer.extend_from_slice(value.as_bytes());
}

/// Decodes a BACnet application-tagged CharacterString.
///
/// Returns the decoded text, the charset it was encoded in, and the number
/// of octets consumed (tag plus content).
pub fn decode_character_string_full(data: &[u8]) -> Result<(String, CharacterSet, usize)> {
    let (t, mut consumed) = Tag::decode(data)?;

    if t.class != TagClass::Application || t.number != ApplicationTagNumber::CharacterString as u32
    {
        return Err(EncodingError::InvalidTag);
    }
    let length = t.content_length().unwrap_or(0) as usize;

    if length == 0 || data.len() < consumed + length {
        return Err(EncodingError::BufferUnderflow);
    }

    let content = &data[consumed..consumed + length];
    let charset_byte = content[0];
    let body = &content[1..];

    let (text, charset) = match charset_byte {
        CHARSET_UTF8 => (
            String::from_utf8(body.to_vec()).map_err(|_| {
                EncodingError::InvalidFormat("invalid UTF-8 character string".to_string())
            })?,
            CharacterSet::Utf8,
        ),
        CHARSET_UCS4 => (decode_ucs4(body)?, CharacterSet::Ucs4),
        CHARSET_UCS2 => (decode_ucs2(body)?, CharacterSet::Ucs2),
        CHARSET_ISO_8859_1 => (decode_iso_8859_1(body), CharacterSet::Iso8859_1),
        CHARSET_DBCS => {
            if body.len() < 2 {
                return Err(EncodingError::BufferUnderflow);
            }
            let code_page = u16::from_be_bytes([body[0], body[1]]);
            (
                decode_legacy_codepage(&body[2..], code_page)?,
                CharacterSet::Dbcs(code_page),
            )
        }
        CHARSET_JIS_X0208 => (decode_jis_x0208(body)?, CharacterSet::JisX0208),
        _ => {
            return Err(EncodingError::InvalidFormat(format!(
                "reserved character set 0x{:02X}",
                charset_byte
            )))
        }
    };

    consumed += length;
    Ok((text, charset, consumed))
}

/// Decodes a BACnet application-tagged CharacterString into a Rust `String`,
/// discarding which charset it was originally encoded in.
pub fn decode_character_string(data: &[u8]) -> Result<(String, usize)> {
    let (text, _charset, consumed) = decode_character_string_full(data)?;
    Ok((text, consumed))
}

fn decode_ucs4(body: &[u8]) -> Result<String> {
    if !body.len().is_multiple_of(4) {
        return Err(EncodingError::InvalidFormat(
            "UCS-4 character string length is not a multiple of 4".to_string(),
        ));
    }

    body.as_chunks::<4>()
        .0
        .iter()
        .map(|chunk| {
            let scalar = u32::from_be_bytes(*chunk);
            char::from_u32(scalar)
                .ok_or_else(|| EncodingError::InvalidFormat("invalid UCS-4 code point".to_string()))
        })
        .collect()
}

fn decode_ucs2(body: &[u8]) -> Result<String> {
    if !body.len().is_multiple_of(2) {
        return Err(EncodingError::InvalidFormat(
            "UCS-2 character string length is not a multiple of 2".to_string(),
        ));
    }

    let units: Vec<u16> = body
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| u16::from_be_bytes(*chunk))
        .collect();

    String::from_utf16(&units)
        .map_err(|_| EncodingError::InvalidFormat("invalid UCS-2 sequence".to_string()))
}

fn decode_iso_8859_1(body: &[u8]) -> String {
    // ISO 8859-1 maps every byte directly to the identical Unicode scalar value.
    body.iter().map(|&b| b as char).collect()
}

/// Decodes `body` assuming it is plain ASCII, for use when a legacy
/// code-page-dependent charset can't be decoded via a real table. `reason`
/// explains why (feature disabled vs. code page/charset not recognized) and
/// is folded into the error on non-ASCII content, rather than guessing at
/// its meaning.
fn decode_ascii_fallback(body: &[u8], charset_description: &str, reason: &str) -> Result<String> {
    if body.iter().all(|&b| b < 0x80) {
        Ok(body.iter().map(|&b| b as char).collect())
    } else {
        Err(EncodingError::InvalidFormat(format!(
            "{} is not supported ({}; non-ASCII bytes present)",
            charset_description, reason
        )))
    }
}

#[cfg(feature = "legacy-charsets")]
fn decode_legacy_codepage(body: &[u8], code_page: u16) -> Result<String> {
    if let Some(encoding) = windows_codepage_encoding(code_page) {
        let (text, _, had_errors) = encoding.decode(body);
        return if had_errors {
            Err(EncodingError::InvalidFormat(format!(
                "invalid bytes for DBCS code page {}",
                code_page
            )))
        } else {
            Ok(text.into_owned())
        };
    }

    if let Some(table) = oem_cp::code_table::DECODING_TABLE_CP_MAP.get(&code_page) {
        return table.decode_string_checked(body).ok_or_else(|| {
            EncodingError::InvalidFormat(format!("invalid bytes for DBCS code page {}", code_page))
        });
    }

    decode_ascii_fallback(
        body,
        &format!("DBCS code page {}", code_page),
        "code page not recognized by the `legacy-charsets` backends",
    )
}

#[cfg(not(feature = "legacy-charsets"))]
fn decode_legacy_codepage(body: &[u8], code_page: u16) -> Result<String> {
    decode_ascii_fallback(
        body,
        &format!("DBCS code page {}", code_page),
        "the `legacy-charsets` feature is not enabled",
    )
}

#[cfg(feature = "legacy-charsets")]
fn decode_jis_x0208(body: &[u8]) -> Result<String> {
    // JIS X 0208 characters are conveyed over the wire via the Shift_JIS
    // transport encoding, the conventional choice for this charset in
    // legacy Windows/BACnet contexts.
    let (text, _, had_errors) = encoding_rs::SHIFT_JIS.decode(body);
    if had_errors {
        Err(EncodingError::InvalidFormat(
            "invalid JIS X 0208 (Shift_JIS) bytes".to_string(),
        ))
    } else {
        Ok(text.into_owned())
    }
}

#[cfg(not(feature = "legacy-charsets"))]
fn decode_jis_x0208(body: &[u8]) -> Result<String> {
    decode_ascii_fallback(
        body,
        "JIS X 0208",
        "the `legacy-charsets` feature is not enabled",
    )
}

/// Maps a Windows/DBCS code page number to the `encoding_rs` static encoding
/// that decodes it, for the code pages `encoding_rs` covers. Numbers it
/// doesn't recognize fall through to `oem_cp`'s classic DOS/OEM tables.
#[cfg(feature = "legacy-charsets")]
fn windows_codepage_encoding(code_page: u16) -> Option<&'static encoding_rs::Encoding> {
    Some(match code_page {
        866 => encoding_rs::IBM866,
        874 => encoding_rs::WINDOWS_874,
        932 => encoding_rs::SHIFT_JIS,
        936 => encoding_rs::GBK,
        949 => encoding_rs::EUC_KR,
        950 => encoding_rs::BIG5,
        1250 => encoding_rs::WINDOWS_1250,
        1251 => encoding_rs::WINDOWS_1251,
        1252 => encoding_rs::WINDOWS_1252,
        1253 => encoding_rs::WINDOWS_1253,
        1254 => encoding_rs::WINDOWS_1254,
        1255 => encoding_rs::WINDOWS_1255,
        1256 => encoding_rs::WINDOWS_1256,
        1257 => encoding_rs::WINDOWS_1257,
        1258 => encoding_rs::WINDOWS_1258,
        20866 => encoding_rs::KOI8_R,
        21866 => encoding_rs::KOI8_U,
        51932 => encoding_rs::EUC_JP,
        54936 => encoding_rs::GB18030,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_decodes_to(data: &[u8], expected_text: &str, expected_charset: CharacterSet) {
        let (text, charset, consumed) = decode_character_string_full(data).unwrap();
        assert_eq!(text, expected_text);
        assert_eq!(charset, expected_charset);
        assert_eq!(consumed, data.len());
    }

    // --- Worked examples from ASHRAE 135-2024, Clause 20.2.9 ---

    #[test]
    fn spec_utf8_ascii() {
        // "Application-tagged character string": "This is a BACnet string!"
        // Encoded Tag = X'75', Length Extension = X'19', Character Set = X'00'
        let mut data = vec![0x75, 0x19, 0x00];
        data.extend_from_slice(b"This is a BACnet string!");
        assert_decodes_to(&data, "This is a BACnet string!", CharacterSet::Utf8);
    }

    #[test]
    fn spec_utf8_non_ascii() {
        // "Application-tagged character string with non-ANSI character": "Français"
        // Encoded Tag = X'75', Length Extension = X'0A', Character Set = X'00'
        // Encoded Data = X'4672616EC3A7616973'
        let mut data = vec![0x75, 0x0A, 0x00];
        data.extend_from_slice(&[0x46, 0x72, 0x61, 0x6E, 0xC3, 0xA7, 0x61, 0x69, 0x73]);
        assert_decodes_to(&data, "Français", CharacterSet::Utf8);
    }

    #[test]
    fn spec_dbcs_code_page_850() {
        // "Application-tagged character string (DBCS)": "This is a BACnet String!"
        // (code page 850), Encoded Tag = X'75', Length Extension = X'1B'
        // Encoded Data = X'010352546869732069732061204241436E657420737472696E6721'
        let mut data = vec![0x75, 0x1B, 0x01, 0x03, 0x52];
        data.extend_from_slice(b"This is a BACnet string!");
        assert_decodes_to(&data, "This is a BACnet string!", CharacterSet::Dbcs(850));
    }

    #[test]
    #[cfg(feature = "legacy-charsets")]
    fn dbcs_code_page_850_non_ascii_byte() {
        // 0x80 in CP850 is 'Ç' (U+00C7) — distinct from ASCII, so this only
        // passes if the real CP850 table is actually consulted rather than
        // the ASCII-safe fallback.
        let content = [CHARSET_DBCS, 0x03, 0x52, 0x80];
        assert_decodes_to(&wrap_content(&content), "Ç", CharacterSet::Dbcs(850));
    }

    #[test]
    #[cfg(not(feature = "legacy-charsets"))]
    fn dbcs_code_page_850_non_ascii_byte_rejected_without_feature() {
        // Without `legacy-charsets`, only the ASCII-safe fallback is
        // available, so a genuine high-byte CP850 character is an error
        // rather than a guess.
        let content = [CHARSET_DBCS, 0x03, 0x52, 0x80];
        assert!(decode_character_string_full(&wrap_content(&content)).is_err());
    }

    #[test]
    fn spec_ucs2() {
        // "Application-tagged character string (UCS-2)": "This is a BACnet String!"
        // Encoded Tag = X'75', Length Extension = X'31'
        // Encoded Data = X'0400540068...0067 0021'
        let text = "This is a BACnet string!";
        let mut data = vec![0x75, 0x31, 0x04];
        for unit in text.encode_utf16() {
            data.extend_from_slice(&unit.to_be_bytes());
        }
        assert_decodes_to(&data, text, CharacterSet::Ucs2);
    }

    /// Wraps raw CharacterString content (charset octet + data) in a
    /// correctly-encoded application tag, so tests don't hand-compute tag
    /// bytes for anything other than the literal spec examples.
    fn wrap_content(content: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        Tag::primitive(
            TagClass::Application,
            ApplicationTagNumber::CharacterString as u32,
            content.len() as u32,
        )
        .unwrap()
        .encode(&mut data)
        .unwrap();
        data.extend_from_slice(content);
        data
    }

    // --- Round trips for charsets without a literal spec byte example ---

    #[test]
    fn ucs4_round_trip_non_bmp_character() {
        // U+1F600 (an emoji) requires UCS-4; if this were accidentally
        // truncated to 16 bits, this test would fail.
        let text = "hi \u{1F600} bye";
        let mut content = vec![CHARSET_UCS4];
        for c in text.chars() {
            content.extend_from_slice(&(c as u32).to_be_bytes());
        }

        assert_decodes_to(&wrap_content(&content), text, CharacterSet::Ucs4);
    }

    #[test]
    fn iso_8859_1_round_trip_high_byte() {
        // 0xE9 in ISO 8859-1 is 'é' (U+00E9), identical scalar value.
        let content = [CHARSET_ISO_8859_1, b'e', 0xE9];
        assert_decodes_to(&wrap_content(&content), "eé", CharacterSet::Iso8859_1);
    }

    #[test]
    fn empty_string() {
        // Charset octet present, zero data octets following.
        let content = [CHARSET_UTF8];
        assert_decodes_to(&wrap_content(&content), "", CharacterSet::Utf8);
    }

    // --- Rejections ---

    #[test]
    fn rejects_invalid_utf8() {
        let content = [CHARSET_UTF8, 0xFF, 0xFE];
        assert!(decode_character_string_full(&wrap_content(&content)).is_err());
    }

    #[test]
    fn rejects_lone_surrogate_in_ucs2() {
        // 0xD800 is a lone high surrogate with no following low surrogate.
        let content = [CHARSET_UCS2, 0xD8, 0x00];
        assert!(decode_character_string_full(&wrap_content(&content)).is_err());
    }

    #[test]
    fn rejects_surrogate_scalar_in_ucs4() {
        // 0x0000D800 is in the surrogate range, not a valid scalar value.
        let content = [CHARSET_UCS4, 0x00, 0x00, 0xD8, 0x00];
        assert!(decode_character_string_full(&wrap_content(&content)).is_err());
    }

    #[test]
    fn rejects_reserved_charset() {
        let content = [0x06, b'h', b'i'];
        assert!(decode_character_string_full(&wrap_content(&content)).is_err());
    }

    #[test]
    fn rejects_non_ascii_dbcs_with_unrecognized_code_page() {
        // Code page 0xFFFF is not a recognized code page under any backend.
        let content = [CHARSET_DBCS, 0xFF, 0xFF, 0x80];
        assert!(decode_character_string_full(&wrap_content(&content)).is_err());
    }

    #[test]
    fn decodes_ascii_dbcs_with_unrecognized_code_page() {
        // Plain ASCII content is decodable even under an unrecognized code page.
        let content = [CHARSET_DBCS, 0xFF, 0xFF, b'h', b'i'];
        assert_decodes_to(&wrap_content(&content), "hi", CharacterSet::Dbcs(0xFFFF));
    }

    // --- encode always uses UTF-8 ---

    #[test]
    fn encode_decode_round_trip() {
        let mut buffer = Vec::new();
        encode_character_string(&mut buffer, "round trip: café 🎉").unwrap();
        let (text, charset, consumed) = decode_character_string_full(&buffer).unwrap();
        assert_eq!(text, "round trip: café 🎉");
        assert_eq!(charset, CharacterSet::Utf8);
        assert_eq!(consumed, buffer.len());
    }

    #[test]
    fn decode_character_string_discards_charset() {
        let mut data = vec![0x75, 0x1B, 0x01, 0x03, 0x52];
        data.extend_from_slice(b"This is a BACnet string!");
        let (text, consumed) = decode_character_string(&data).unwrap();
        assert_eq!(text, "This is a BACnet string!");
        assert_eq!(consumed, data.len());
    }
}
