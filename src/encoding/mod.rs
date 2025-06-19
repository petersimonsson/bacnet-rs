//! BACnet Encoding/Decoding Module
//!
//! This module provides functionality for encoding and decoding BACnet protocol data.
//! It handles the serialization and deserialization of BACnet data types according
//! to the ASHRAE 135 standard.
//!
//! # Overview
//!
//! The encoding module is responsible for:
//! - Converting BACnet data types to/from wire format
//! - Handling primitive data types (Boolean, Integer, Real, etc.)
//! - Encoding/decoding constructed data types
//! - Managing BACnet application tags
//! - Context-specific encoding/decoding
//!
//! # Example
//!
//! ```no_run
//! use bacnet_rs::encoding::*;
//!
//! // Example of encoding a value
//! let mut buffer: Vec<u8> = Vec::new();
//! // encode_application_unsigned(&mut buffer, 42)?;
//! ```

#[cfg(feature = "std")]
use std::error::Error;

#[cfg(not(feature = "std"))]
use core::fmt;

#[cfg(feature = "std")]
use std::fmt;

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

/// Result type for encoding operations
#[cfg(feature = "std")]
pub type Result<T> = std::result::Result<T, EncodingError>;

#[cfg(not(feature = "std"))]
pub type Result<T> = core::result::Result<T, EncodingError>;

/// Errors that can occur during encoding/decoding operations
#[derive(Debug, Clone)]
pub enum EncodingError {
    /// Buffer overflow during encoding
    BufferOverflow,
    /// Buffer underflow during decoding
    BufferUnderflow,
    /// Invalid tag number encountered
    InvalidTag,
    /// Invalid length value
    InvalidLength,
    /// Unexpected end of data during decoding
    UnexpectedEndOfData,
    /// Invalid encoding format
    InvalidFormat(String),
    /// Value out of valid range
    ValueOutOfRange,
}

impl fmt::Display for EncodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodingError::BufferOverflow => write!(f, "Buffer overflow during encoding"),
            EncodingError::BufferUnderflow => write!(f, "Buffer underflow during decoding"),
            EncodingError::InvalidTag => write!(f, "Invalid tag number encountered"),
            EncodingError::InvalidLength => write!(f, "Invalid length value"),
            EncodingError::UnexpectedEndOfData => write!(f, "Unexpected end of data"),
            EncodingError::InvalidFormat(msg) => write!(f, "Invalid format: {}", msg),
            EncodingError::ValueOutOfRange => write!(f, "Value out of valid range"),
        }
    }
}

#[cfg(feature = "std")]
impl Error for EncodingError {}

/// BACnet application tag numbers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ApplicationTag {
    Null = 0,
    Boolean = 1,
    UnsignedInt = 2,
    SignedInt = 3,
    Real = 4,
    Double = 5,
    OctetString = 6,
    CharacterString = 7,
    BitString = 8,
    Enumerated = 9,
    Date = 10,
    Time = 11,
    ObjectIdentifier = 12,
    Reserved13 = 13,
    Reserved14 = 14,
    Reserved15 = 15,
}

/// Encode a BACnet application tag
pub fn encode_application_tag(buffer: &mut Vec<u8>, tag: ApplicationTag, length: usize) -> Result<()> {
    let tag_byte = if length < 5 {
        (tag as u8) << 4 | (length as u8)
    } else {
        (tag as u8) << 4 | 5
    };
    
    buffer.push(tag_byte);
    
    if length >= 5 {
        if length < 254 {
            buffer.push(length as u8);
        } else if length < 65536 {
            buffer.push(254);
            buffer.extend_from_slice(&(length as u16).to_be_bytes());
        } else {
            buffer.push(255);
            buffer.extend_from_slice(&(length as u32).to_be_bytes());
        }
    }
    
    Ok(())
}

/// Decode a BACnet application tag
pub fn decode_application_tag(data: &[u8]) -> Result<(ApplicationTag, usize, usize)> {
    if data.is_empty() {
        return Err(EncodingError::InvalidTag);
    }
    
    let tag_byte = data[0];
    let tag = ApplicationTag::try_from(tag_byte >> 4)?;
    let mut length = (tag_byte & 0x0F) as usize;
    let mut consumed = 1;
    
    if length == 5 {
        if data.len() < 2 {
            return Err(EncodingError::BufferUnderflow);
        }
        
        let len_byte = data[1];
        consumed += 1;
        
        if len_byte < 254 {
            length = len_byte as usize;
        } else if len_byte == 254 {
            if data.len() < 4 {
                return Err(EncodingError::BufferUnderflow);
            }
            length = u16::from_be_bytes([data[2], data[3]]) as usize;
            consumed += 2;
        } else {
            if data.len() < 6 {
                return Err(EncodingError::BufferUnderflow);
            }
            length = u32::from_be_bytes([data[2], data[3], data[4], data[5]]) as usize;
            consumed += 4;
        }
    }
    
    Ok((tag, length, consumed))
}

/// Encode a BACnet boolean value
pub fn encode_boolean(buffer: &mut Vec<u8>, value: bool) -> Result<()> {
    encode_application_tag(buffer, ApplicationTag::Boolean, if value { 1 } else { 0 })?;
    Ok(())
}

/// Decode a BACnet boolean value
pub fn decode_boolean(data: &[u8]) -> Result<(bool, usize)> {
    let (tag, length, consumed) = decode_application_tag(data)?;
    
    if tag != ApplicationTag::Boolean {
        return Err(EncodingError::InvalidTag);
    }
    
    let value = match length {
        0 => false,
        1 => true,
        _ => return Err(EncodingError::InvalidLength),
    };
    
    Ok((value, consumed))
}

/// Encode a BACnet unsigned integer
pub fn encode_unsigned(buffer: &mut Vec<u8>, value: u32) -> Result<()> {
    let bytes = if value == 0 {
        vec![0]
    } else if value <= 0xFF {
        vec![value as u8]
    } else if value <= 0xFFFF {
        (value as u16).to_be_bytes().to_vec()
    } else if value <= 0xFFFFFF {
        let bytes = (value as u32).to_be_bytes();
        bytes[1..].to_vec()
    } else {
        (value as u32).to_be_bytes().to_vec()
    };
    
    encode_application_tag(buffer, ApplicationTag::UnsignedInt, bytes.len())?;
    buffer.extend_from_slice(&bytes);
    Ok(())
}

/// Decode a BACnet unsigned integer
pub fn decode_unsigned(data: &[u8]) -> Result<(u32, usize)> {
    let (tag, length, mut consumed) = decode_application_tag(data)?;
    
    if tag != ApplicationTag::UnsignedInt {
        return Err(EncodingError::InvalidTag);
    }
    
    if data.len() < consumed + length {
        return Err(EncodingError::BufferUnderflow);
    }
    
    let value = match length {
        1 => data[consumed] as u32,
        2 => u16::from_be_bytes([data[consumed], data[consumed + 1]]) as u32,
        3 => {
            let bytes = [0, data[consumed], data[consumed + 1], data[consumed + 2]];
            u32::from_be_bytes(bytes)
        },
        4 => u32::from_be_bytes([
            data[consumed],
            data[consumed + 1],
            data[consumed + 2],
            data[consumed + 3],
        ]),
        _ => return Err(EncodingError::InvalidLength),
    };
    
    consumed += length;
    Ok((value, consumed))
}

/// Encode a BACnet signed integer
pub fn encode_signed(buffer: &mut Vec<u8>, value: i32) -> Result<()> {
    let bytes = if value >= -128 && value <= 127 {
        vec![value as u8]
    } else if value >= -32768 && value <= 32767 {
        (value as i16).to_be_bytes().to_vec()
    } else if value >= -8388608 && value <= 8388607 {
        let bytes = (value as i32).to_be_bytes();
        bytes[1..].to_vec()
    } else {
        (value as i32).to_be_bytes().to_vec()
    };
    
    encode_application_tag(buffer, ApplicationTag::SignedInt, bytes.len())?;
    buffer.extend_from_slice(&bytes);
    Ok(())
}

/// Decode a BACnet signed integer
pub fn decode_signed(data: &[u8]) -> Result<(i32, usize)> {
    let (tag, length, mut consumed) = decode_application_tag(data)?;
    
    if tag != ApplicationTag::SignedInt {
        return Err(EncodingError::InvalidTag);
    }
    
    if data.len() < consumed + length {
        return Err(EncodingError::BufferUnderflow);
    }
    
    let value = match length {
        1 => data[consumed] as i8 as i32,
        2 => i16::from_be_bytes([data[consumed], data[consumed + 1]]) as i32,
        3 => {
            let sign_extend = if data[consumed] & 0x80 != 0 { 0xFF } else { 0x00 };
            let bytes = [sign_extend, data[consumed], data[consumed + 1], data[consumed + 2]];
            i32::from_be_bytes(bytes)
        },
        4 => i32::from_be_bytes([
            data[consumed],
            data[consumed + 1],
            data[consumed + 2],
            data[consumed + 3],
        ]),
        _ => return Err(EncodingError::InvalidLength),
    };
    
    consumed += length;
    Ok((value, consumed))
}

/// Encode a BACnet real (float) value
pub fn encode_real(buffer: &mut Vec<u8>, value: f32) -> Result<()> {
    encode_application_tag(buffer, ApplicationTag::Real, 4)?;
    buffer.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

/// Decode a BACnet real (float) value
pub fn decode_real(data: &[u8]) -> Result<(f32, usize)> {
    let (tag, length, mut consumed) = decode_application_tag(data)?;
    
    if tag != ApplicationTag::Real {
        return Err(EncodingError::InvalidTag);
    }
    
    if length != 4 {
        return Err(EncodingError::InvalidLength);
    }
    
    if data.len() < consumed + 4 {
        return Err(EncodingError::BufferUnderflow);
    }
    
    let value = f32::from_be_bytes([
        data[consumed],
        data[consumed + 1],
        data[consumed + 2],
        data[consumed + 3],
    ]);
    
    consumed += 4;
    Ok((value, consumed))
}

/// Encode a BACnet octet string
pub fn encode_octet_string(buffer: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    encode_application_tag(buffer, ApplicationTag::OctetString, value.len())?;
    buffer.extend_from_slice(value);
    Ok(())
}

/// Decode a BACnet octet string
pub fn decode_octet_string(data: &[u8]) -> Result<(Vec<u8>, usize)> {
    let (tag, length, mut consumed) = decode_application_tag(data)?;
    
    if tag != ApplicationTag::OctetString {
        return Err(EncodingError::InvalidTag);
    }
    
    if data.len() < consumed + length {
        return Err(EncodingError::BufferUnderflow);
    }
    
    let value = data[consumed..consumed + length].to_vec();
    consumed += length;
    
    Ok((value, consumed))
}

/// Encode a BACnet character string
pub fn encode_character_string(buffer: &mut Vec<u8>, value: &str) -> Result<()> {
    let string_bytes = value.as_bytes();
    encode_application_tag(buffer, ApplicationTag::CharacterString, string_bytes.len() + 1)?;
    buffer.push(0); // Character set encoding (0 = ANSI X3.4)
    buffer.extend_from_slice(string_bytes);
    Ok(())
}

/// Decode a BACnet character string
pub fn decode_character_string(data: &[u8]) -> Result<(String, usize)> {
    let (tag, length, mut consumed) = decode_application_tag(data)?;
    
    if tag != ApplicationTag::CharacterString {
        return Err(EncodingError::InvalidTag);
    }
    
    if data.len() < consumed + length || length == 0 {
        return Err(EncodingError::BufferUnderflow);
    }
    
    // Skip character set encoding byte
    let _encoding = data[consumed];
    consumed += 1;
    
    let string_data = &data[consumed..consumed + length - 1];
    let value = String::from_utf8(string_data.to_vec())
        .map_err(|_| EncodingError::InvalidFormat("Invalid UTF-8 string".to_string()))?;
    
    consumed += length - 1;
    
    Ok((value, consumed))
}

/// Encode a BACnet enumerated value
pub fn encode_enumerated(buffer: &mut Vec<u8>, value: u32) -> Result<()> {
    let bytes = if value <= 0xFF {
        vec![value as u8]
    } else if value <= 0xFFFF {
        (value as u16).to_be_bytes().to_vec()
    } else if value <= 0xFFFFFF {
        let bytes = (value as u32).to_be_bytes();
        bytes[1..].to_vec()
    } else {
        (value as u32).to_be_bytes().to_vec()
    };
    
    encode_application_tag(buffer, ApplicationTag::Enumerated, bytes.len())?;
    buffer.extend_from_slice(&bytes);
    Ok(())
}

/// Decode a BACnet enumerated value
pub fn decode_enumerated(data: &[u8]) -> Result<(u32, usize)> {
    let (tag, length, mut consumed) = decode_application_tag(data)?;
    
    if tag != ApplicationTag::Enumerated {
        return Err(EncodingError::InvalidTag);
    }
    
    if data.len() < consumed + length {
        return Err(EncodingError::BufferUnderflow);
    }
    
    let value = match length {
        1 => data[consumed] as u32,
        2 => u16::from_be_bytes([data[consumed], data[consumed + 1]]) as u32,
        3 => {
            let bytes = [0, data[consumed], data[consumed + 1], data[consumed + 2]];
            u32::from_be_bytes(bytes)
        },
        4 => u32::from_be_bytes([
            data[consumed],
            data[consumed + 1],
            data[consumed + 2],
            data[consumed + 3],
        ]),
        _ => return Err(EncodingError::InvalidLength),
    };
    
    consumed += length;
    Ok((value, consumed))
}

/// Encode a BACnet date
pub fn encode_date(buffer: &mut Vec<u8>, year: u16, month: u8, day: u8, weekday: u8) -> Result<()> {
    encode_application_tag(buffer, ApplicationTag::Date, 4)?;
    buffer.push(((year - 1900) % 256) as u8);
    buffer.push(month);
    buffer.push(day);
    buffer.push(weekday);
    Ok(())
}

/// Decode a BACnet date
pub fn decode_date(data: &[u8]) -> Result<((u16, u8, u8, u8), usize)> {
    let (tag, length, mut consumed) = decode_application_tag(data)?;
    
    if tag != ApplicationTag::Date {
        return Err(EncodingError::InvalidTag);
    }
    
    if length != 4 || data.len() < consumed + 4 {
        return Err(EncodingError::InvalidLength);
    }
    
    let year = if data[consumed] == 255 { 255 } else { 1900 + data[consumed] as u16 };
    let month = data[consumed + 1];
    let day = data[consumed + 2];
    let weekday = data[consumed + 3];
    
    consumed += 4;
    Ok(((year, month, day, weekday), consumed))
}

/// Encode a BACnet time
pub fn encode_time(buffer: &mut Vec<u8>, hour: u8, minute: u8, second: u8, hundredths: u8) -> Result<()> {
    encode_application_tag(buffer, ApplicationTag::Time, 4)?;
    buffer.push(hour);
    buffer.push(minute);
    buffer.push(second);
    buffer.push(hundredths);
    Ok(())
}

/// Decode a BACnet time
pub fn decode_time(data: &[u8]) -> Result<((u8, u8, u8, u8), usize)> {
    let (tag, length, mut consumed) = decode_application_tag(data)?;
    
    if tag != ApplicationTag::Time {
        return Err(EncodingError::InvalidTag);
    }
    
    if length != 4 || data.len() < consumed + 4 {
        return Err(EncodingError::InvalidLength);
    }
    
    let hour = data[consumed];
    let minute = data[consumed + 1];
    let second = data[consumed + 2];
    let hundredths = data[consumed + 3];
    
    consumed += 4;
    Ok(((hour, minute, second, hundredths), consumed))
}

/// Encode a BACnet object identifier
pub fn encode_object_identifier(buffer: &mut Vec<u8>, object_type: u16, instance: u32) -> Result<()> {
    if object_type > 0x3FF || instance > 0x3FFFFF {
        return Err(EncodingError::ValueOutOfRange);
    }
    
    let object_id = ((object_type as u32) << 22) | instance;
    encode_application_tag(buffer, ApplicationTag::ObjectIdentifier, 4)?;
    buffer.extend_from_slice(&object_id.to_be_bytes());
    Ok(())
}

/// Decode a BACnet object identifier
pub fn decode_object_identifier(data: &[u8]) -> Result<((u16, u32), usize)> {
    let (tag, length, mut consumed) = decode_application_tag(data)?;
    
    if tag != ApplicationTag::ObjectIdentifier {
        return Err(EncodingError::InvalidTag);
    }
    
    if length != 4 || data.len() < consumed + 4 {
        return Err(EncodingError::InvalidLength);
    }
    
    let object_id = u32::from_be_bytes([
        data[consumed],
        data[consumed + 1],
        data[consumed + 2],
        data[consumed + 3],
    ]);
    
    let object_type = (object_id >> 22) as u16;
    let instance = object_id & 0x3FFFFF;
    
    consumed += 4;
    Ok(((object_type, instance), consumed))
}

/// Encode a BACnet double (64-bit float)
pub fn encode_double(buffer: &mut Vec<u8>, value: f64) -> Result<()> {
    encode_application_tag(buffer, ApplicationTag::Double, 8)?;
    buffer.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

/// Decode a BACnet double (64-bit float)
pub fn decode_double(data: &[u8]) -> Result<(f64, usize)> {
    let (tag, length, mut consumed) = decode_application_tag(data)?;
    
    if tag != ApplicationTag::Double {
        return Err(EncodingError::InvalidTag);
    }
    
    if length != 8 || data.len() < consumed + 8 {
        return Err(EncodingError::InvalidLength);
    }
    
    let value = f64::from_be_bytes([
        data[consumed],
        data[consumed + 1],
        data[consumed + 2],
        data[consumed + 3],
        data[consumed + 4],
        data[consumed + 5],
        data[consumed + 6],
        data[consumed + 7],
    ]);
    
    consumed += 8;
    Ok((value, consumed))
}

impl TryFrom<u8> for ApplicationTag {
    type Error = EncodingError;
    
    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(ApplicationTag::Null),
            1 => Ok(ApplicationTag::Boolean),
            2 => Ok(ApplicationTag::UnsignedInt),
            3 => Ok(ApplicationTag::SignedInt),
            4 => Ok(ApplicationTag::Real),
            5 => Ok(ApplicationTag::Double),
            6 => Ok(ApplicationTag::OctetString),
            7 => Ok(ApplicationTag::CharacterString),
            8 => Ok(ApplicationTag::BitString),
            9 => Ok(ApplicationTag::Enumerated),
            10 => Ok(ApplicationTag::Date),
            11 => Ok(ApplicationTag::Time),
            12 => Ok(ApplicationTag::ObjectIdentifier),
            _ => Err(EncodingError::InvalidTag),
        }
    }
}

/// Advanced encoding features and optimizations
pub mod advanced {
    use super::*;
    #[cfg(not(feature = "std"))]
    use alloc::{vec::Vec, collections::BTreeMap};

    /// Buffer manager for efficient encoding/decoding operations
    #[derive(Debug)]
    pub struct BufferManager {
        /// Reusable buffers for encoding operations
        #[cfg(feature = "std")]
        encode_buffers: Vec<Vec<u8>>,
        #[cfg(not(feature = "std"))]
        encode_buffers: alloc::vec::Vec<alloc::vec::Vec<u8>>,
        /// Maximum buffer size to cache
        max_buffer_size: usize,
        /// Statistics for buffer usage
        pub stats: BufferStats,
    }

    /// Buffer usage statistics
    #[derive(Debug, Default)]
    pub struct BufferStats {
        pub total_allocations: u64,
        pub buffer_reuses: u64,
        pub max_buffer_size_used: usize,
        pub total_bytes_encoded: u64,
        pub total_bytes_decoded: u64,
    }

    impl BufferManager {
        /// Create a new buffer manager
        pub fn new(max_buffer_size: usize) -> Self {
            Self {
                encode_buffers: Vec::with_capacity(8),
                max_buffer_size,
                stats: BufferStats::default(),
            }
        }

        /// Get a buffer for encoding, reusing if possible
        pub fn get_encode_buffer(&mut self) -> Vec<u8> {
            if let Some(mut buffer) = self.encode_buffers.pop() {
                buffer.clear();
                self.stats.buffer_reuses += 1;
                buffer
            } else {
                self.stats.total_allocations += 1;
                Vec::with_capacity(256)
            }
        }

        /// Return a buffer for reuse
        pub fn return_buffer(&mut self, buffer: Vec<u8>) {
            self.stats.total_bytes_encoded += buffer.len() as u64;
            if buffer.capacity() <= self.max_buffer_size && self.encode_buffers.len() < 16 {
                self.encode_buffers.push(buffer);
            }
        }

        /// Update decoding statistics
        pub fn update_decode_stats(&mut self, bytes_decoded: usize) {
            self.stats.total_bytes_decoded += bytes_decoded as u64;
        }
    }

    /// Context-specific tag encoding/decoding
    pub mod context {
        use super::*;

        /// Encode a context-specific tag
        pub fn encode_context_tag(buffer: &mut Vec<u8>, tag_number: u8, length: usize) -> Result<()> {
            if tag_number > 14 {
                return Err(EncodingError::ValueOutOfRange);
            }

            let tag_byte = if length < 5 {
                0x08 | (tag_number << 4) | (length as u8)
            } else {
                0x08 | (tag_number << 4) | 5
            };

            buffer.push(tag_byte);

            if length >= 5 {
                if length < 254 {
                    buffer.push(length as u8);
                } else if length < 65536 {
                    buffer.push(254);
                    buffer.extend_from_slice(&(length as u16).to_be_bytes());
                } else {
                    buffer.push(255);
                    buffer.extend_from_slice(&(length as u32).to_be_bytes());
                }
            }

            Ok(())
        }

        /// Decode a context-specific tag
        pub fn decode_context_tag(data: &[u8]) -> Result<(u8, usize, usize)> {
            if data.is_empty() {
                return Err(EncodingError::InvalidTag);
            }

            let tag_byte = data[0];
            if (tag_byte & 0x08) == 0 {
                return Err(EncodingError::InvalidTag);
            }

            let tag_number = (tag_byte >> 4) & 0x0F;
            let mut length = (tag_byte & 0x07) as usize;
            let mut consumed = 1;

            if length == 5 {
                if data.len() < 2 {
                    return Err(EncodingError::BufferUnderflow);
                }

                let len_byte = data[1];
                consumed += 1;

                if len_byte < 254 {
                    length = len_byte as usize;
                } else if len_byte == 254 {
                    if data.len() < 4 {
                        return Err(EncodingError::BufferUnderflow);
                    }
                    length = u16::from_be_bytes([data[2], data[3]]) as usize;
                    consumed += 2;
                } else {
                    if data.len() < 6 {
                        return Err(EncodingError::BufferUnderflow);
                    }
                    length = u32::from_be_bytes([data[2], data[3], data[4], data[5]]) as usize;
                    consumed += 4;
                }
            }

            Ok((tag_number, length, consumed))
        }

        /// Encode opening tag for constructed data
        pub fn encode_opening_tag(buffer: &mut Vec<u8>, tag_number: u8) -> Result<()> {
            if tag_number > 14 {
                return Err(EncodingError::ValueOutOfRange);
            }
            buffer.push(0x0E | (tag_number << 4));
            Ok(())
        }

        /// Encode closing tag for constructed data
        pub fn encode_closing_tag(buffer: &mut Vec<u8>, tag_number: u8) -> Result<()> {
            if tag_number > 14 {
                return Err(EncodingError::ValueOutOfRange);
            }
            buffer.push(0x0F | (tag_number << 4));
            Ok(())
        }
    }

    /// Bit string encoding/decoding utilities
    pub mod bitstring {
        use super::*;

        /// Encode a bit string
        pub fn encode_bit_string(buffer: &mut Vec<u8>, bits: &[bool]) -> Result<()> {
            let byte_count = (bits.len() + 7) / 8;
            let unused_bits = if bits.len() % 8 == 0 { 0 } else { 8 - (bits.len() % 8) };

            encode_application_tag(buffer, ApplicationTag::BitString, byte_count + 1)?;
            buffer.push(unused_bits as u8);

            let mut current_byte = 0u8;
            let mut bit_pos = 0;

            for &bit in bits {
                if bit {
                    current_byte |= 1 << (7 - bit_pos);
                }
                bit_pos += 1;

                if bit_pos == 8 {
                    buffer.push(current_byte);
                    current_byte = 0;
                    bit_pos = 0;
                }
            }

            if bit_pos > 0 {
                buffer.push(current_byte);
            }

            Ok(())
        }

        /// Decode a bit string
        pub fn decode_bit_string(data: &[u8]) -> Result<(Vec<bool>, usize)> {
            let (tag, length, mut consumed) = decode_application_tag(data)?;

            if tag != ApplicationTag::BitString {
                return Err(EncodingError::InvalidTag);
            }

            if length == 0 || data.len() < consumed + length {
                return Err(EncodingError::BufferUnderflow);
            }

            let unused_bits = data[consumed] as usize;
            consumed += 1;

            if unused_bits > 7 {
                return Err(EncodingError::InvalidFormat("Invalid unused bits count".to_string()));
            }

            let mut bits = Vec::new();
            let byte_count = length - 1;

            for i in 0..byte_count {
                let byte_val = data[consumed + i];
                let bits_in_byte = if i == byte_count - 1 { 8 - unused_bits } else { 8 };

                for bit_pos in 0..bits_in_byte {
                    bits.push((byte_val & (1 << (7 - bit_pos))) != 0);
                }
            }

            consumed += byte_count;
            Ok((bits, consumed))
        }
    }

    /// Performance optimization utilities
    pub mod perf {
        use super::*;

        /// Fast path encoder for common data types
        pub struct FastEncoder {
            buffer: Vec<u8>,
        }

        impl FastEncoder {
            /// Create a new fast encoder
            pub fn new(capacity: usize) -> Self {
                Self {
                    buffer: Vec::with_capacity(capacity),
                }
            }

            /// Get the encoded data
            pub fn data(&self) -> &[u8] {
                &self.buffer
            }

            /// Clear the buffer for reuse
            pub fn clear(&mut self) {
                self.buffer.clear();
            }

            /// Fast encode unsigned integer (optimized for common sizes)
            pub fn encode_unsigned_fast(&mut self, value: u32) -> Result<()> {
                match value {
                    0 => {
                        self.buffer.extend_from_slice(&[0x21, 0x00]);
                    }
                    1..=255 => {
                        self.buffer.extend_from_slice(&[0x21, value as u8]);
                    }
                    256..=65535 => {
                        let bytes = (value as u16).to_be_bytes();
                        self.buffer.extend_from_slice(&[0x22]);
                        self.buffer.extend_from_slice(&bytes);
                    }
                    65536..=16777215 => {
                        let bytes = (value as u32).to_be_bytes();
                        self.buffer.extend_from_slice(&[0x23]);
                        self.buffer.extend_from_slice(&bytes[1..]);
                    }
                    _ => {
                        let bytes = (value as u32).to_be_bytes();
                        self.buffer.extend_from_slice(&[0x24]);
                        self.buffer.extend_from_slice(&bytes);
                    }
                }
                Ok(())
            }

            /// Fast encode boolean
            pub fn encode_boolean_fast(&mut self, value: bool) -> Result<()> {
                self.buffer.push(if value { 0x11 } else { 0x10 });
                Ok(())
            }

            /// Fast encode real (32-bit float)
            pub fn encode_real_fast(&mut self, value: f32) -> Result<()> {
                self.buffer.push(0x44);
                self.buffer.extend_from_slice(&value.to_be_bytes());
                Ok(())
            }
        }
    }

    /// Validation utilities for encoded data
    pub mod validation {
        use super::*;

        /// Validate encoded BACnet data
        pub struct DataValidator {
            /// Maximum allowed tag depth for constructed data
            max_tag_depth: usize,
            /// Maximum allowed string length
            max_string_length: usize,
        }

        impl DataValidator {
            /// Create a new data validator
            pub fn new(max_tag_depth: usize, max_string_length: usize) -> Self {
                Self {
                    max_tag_depth,
                    max_string_length,
                }
            }

            /// Validate a complete BACnet data structure
            pub fn validate(&self, data: &[u8]) -> Result<()> {
                self.validate_recursive(data, 0)
            }

            fn validate_recursive(&self, data: &[u8], depth: usize) -> Result<()> {
                if depth > self.max_tag_depth {
                    return Err(EncodingError::InvalidFormat("Maximum tag depth exceeded".to_string()));
                }

                let mut pos = 0;
                while pos < data.len() {
                    let (tag, length, consumed) = decode_application_tag(&data[pos..])?;
                    pos += consumed;

                    match tag {
                        ApplicationTag::CharacterString => {
                            if length > self.max_string_length {
                                return Err(EncodingError::InvalidFormat("String too long".to_string()));
                            }
                        }
                        ApplicationTag::OctetString => {
                            if length > self.max_string_length * 2 {
                                return Err(EncodingError::InvalidFormat("Octet string too long".to_string()));
                            }
                        }
                        _ => {}
                    }

                    pos += length;
                }

                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encode_decode_boolean() {
        let mut buffer = Vec::new();
        
        // Test true
        encode_boolean(&mut buffer, true).unwrap();
        let (value, consumed) = decode_boolean(&buffer).unwrap();
        assert_eq!(value, true);
        assert_eq!(consumed, 1);
        
        // Test false
        buffer.clear();
        encode_boolean(&mut buffer, false).unwrap();
        let (value, consumed) = decode_boolean(&buffer).unwrap();
        assert_eq!(value, false);
        assert_eq!(consumed, 1);
    }
    
    #[test]
    fn test_encode_decode_unsigned() {
        let mut buffer = Vec::new();
        let test_values = [0, 255, 65535, 16777215, 4294967295];
        
        for &test_value in &test_values {
            buffer.clear();
            encode_unsigned(&mut buffer, test_value).unwrap();
            let (value, _) = decode_unsigned(&buffer).unwrap();
            assert_eq!(value, test_value);
        }
    }
    
    #[test]
    fn test_encode_decode_signed() {
        let mut buffer = Vec::new();
        let test_values = [-128, -1, 0, 1, 127, -32768, 32767, -8388608, 8388607];
        
        for &test_value in &test_values {
            buffer.clear();
            encode_signed(&mut buffer, test_value).unwrap();
            let (value, _) = decode_signed(&buffer).unwrap();
            assert_eq!(value, test_value);
        }
    }
    
    #[test]
    fn test_encode_decode_real() {
        let mut buffer = Vec::new();
        let test_values = [0.0, 1.0, -1.0, 3.14159, -273.15, f32::MAX, f32::MIN];
        
        for &test_value in &test_values {
            buffer.clear();
            encode_real(&mut buffer, test_value).unwrap();
            let (value, _) = decode_real(&buffer).unwrap();
            assert_eq!(value, test_value);
        }
    }

    #[test]
    fn test_encode_decode_character_string() {
        let mut buffer = Vec::new();
        let test_strings = ["Hello", "BACnet", "Temperature Sensor", ""];
        
        for &test_string in &test_strings {
            buffer.clear();
            encode_character_string(&mut buffer, test_string).unwrap();
            let (value, _) = decode_character_string(&buffer).unwrap();
            assert_eq!(value, test_string);
        }
    }

    #[test]
    fn test_encode_decode_octet_string() {
        let mut buffer = Vec::new();
        let test_data = vec![0x01, 0x02, 0x03, 0xFF, 0x00];
        
        encode_octet_string(&mut buffer, &test_data).unwrap();
        let (decoded, _) = decode_octet_string(&buffer).unwrap();
        assert_eq!(decoded, test_data);
    }

    #[test]
    fn test_encode_decode_enumerated() {
        let mut buffer = Vec::new();
        let test_values = [0, 1, 255, 256, 65535, 65536, 16777215];
        
        for &test_value in &test_values {
            buffer.clear();
            encode_enumerated(&mut buffer, test_value).unwrap();
            let (value, _) = decode_enumerated(&buffer).unwrap();
            assert_eq!(value, test_value);
        }
    }

    #[test]
    fn test_encode_decode_date() {
        let mut buffer = Vec::new();
        
        encode_date(&mut buffer, 2024, 3, 15, 5).unwrap(); // Friday, March 15, 2024
        let ((year, month, day, weekday), _) = decode_date(&buffer).unwrap();
        assert_eq!(year, 2024);
        assert_eq!(month, 3);
        assert_eq!(day, 15);
        assert_eq!(weekday, 5);
    }

    #[test]
    fn test_encode_decode_time() {
        let mut buffer = Vec::new();
        
        encode_time(&mut buffer, 14, 30, 45, 50).unwrap(); // 14:30:45.50
        let ((hour, minute, second, hundredths), _) = decode_time(&buffer).unwrap();
        assert_eq!(hour, 14);
        assert_eq!(minute, 30);
        assert_eq!(second, 45);
        assert_eq!(hundredths, 50);
    }

    #[test]
    fn test_encode_decode_object_identifier() {
        let mut buffer = Vec::new();
        
        encode_object_identifier(&mut buffer, 2, 12345).unwrap(); // Analog Value 12345
        let ((object_type, instance), _) = decode_object_identifier(&buffer).unwrap();
        assert_eq!(object_type, 2);
        assert_eq!(instance, 12345);
    }

    #[test]
    fn test_encode_decode_double() {
        let mut buffer = Vec::new();
        let test_values = [0.0, 1.0, -1.0, 3.141592653589793, -273.15, f64::MAX, f64::MIN];
        
        for &test_value in &test_values {
            buffer.clear();
            encode_double(&mut buffer, test_value).unwrap();
            let (value, _) = decode_double(&buffer).unwrap();
            assert_eq!(value, test_value);
        }
    }

    #[test]
    fn test_buffer_manager() {
        use advanced::BufferManager;
        
        let mut manager = BufferManager::new(1024);
        
        // Test getting and returning buffers
        let buffer1 = manager.get_encode_buffer();
        let buffer2 = manager.get_encode_buffer();
        
        assert_eq!(manager.stats.total_allocations, 2);
        assert_eq!(manager.stats.buffer_reuses, 0);
        
        manager.return_buffer(buffer1);
        let buffer3 = manager.get_encode_buffer();
        
        assert_eq!(manager.stats.total_allocations, 2);
        assert_eq!(manager.stats.buffer_reuses, 1);
        
        manager.return_buffer(buffer2);
        manager.return_buffer(buffer3);
    }

    #[test]
    fn test_context_specific_encoding() {
        use advanced::context::*;
        
        let mut buffer = Vec::new();
        
        // Test context-specific tag encoding
        encode_context_tag(&mut buffer, 5, 10).unwrap();
        let (tag_number, length, consumed) = decode_context_tag(&buffer).unwrap();
        
        assert_eq!(tag_number, 5);
        assert_eq!(length, 10);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn test_opening_closing_tags() {
        use advanced::context::*;
        
        let mut buffer = Vec::new();
        
        // Test opening and closing tags
        encode_opening_tag(&mut buffer, 3).unwrap();
        encode_closing_tag(&mut buffer, 3).unwrap();
        
        assert_eq!(buffer, vec![0x3E, 0x3F]);
    }

    #[test]
    fn test_bit_string_encoding() {
        use advanced::bitstring::*;
        
        let mut buffer = Vec::new();
        let bits = vec![true, false, true, true, false, false, true, false, true];
        
        encode_bit_string(&mut buffer, &bits).unwrap();
        let (decoded_bits, _) = decode_bit_string(&buffer).unwrap();
        
        assert_eq!(decoded_bits, bits);
    }

    #[test]
    fn test_fast_encoder() {
        use advanced::perf::FastEncoder;
        
        let mut encoder = FastEncoder::new(256);
        
        // Test fast encoding
        encoder.encode_unsigned_fast(42).unwrap();
        encoder.encode_boolean_fast(true).unwrap();
        encoder.encode_real_fast(3.14159).unwrap();
        
        let data = encoder.data();
        assert!(!data.is_empty());
        
        encoder.clear();
        assert_eq!(encoder.data().len(), 0);
    }

    #[test]
    fn test_data_validator() {
        use advanced::validation::DataValidator;
        
        let validator = DataValidator::new(10, 1000);
        
        // Test with valid data
        let mut buffer = Vec::new();
        encode_unsigned(&mut buffer, 42).unwrap();
        encode_character_string(&mut buffer, "Hello").unwrap();
        
        assert!(validator.validate(&buffer).is_ok());
    }

    #[test]
    fn test_encode_decode_performance() {
        let mut buffer = Vec::new();
        let iterations = 1000;
        
        // Performance test for encoding/decoding
        for i in 0..iterations {
            buffer.clear();
            encode_unsigned(&mut buffer, i).unwrap();
            let (value, _) = decode_unsigned(&buffer).unwrap();
            assert_eq!(value, i);
        }
    }
}
