//! Utility Functions Module
//!
//! This module provides common utility functions and helpers used throughout the
//! BACnet stack implementation. These utilities include data conversion, validation,
//! debugging tools, and other helper functions.
//!
//! # Overview
//!
//! Utilities provided include:
//! - CRC calculation for MS/TP
//! - Data conversion helpers
//! - Time and date utilities
//! - Debugging and logging helpers
//! - Buffer management utilities
//! - BACnet-specific validations
//!
//! # Example
//!
//! ```no_run
//! use bacnet_rs::util::*;
//!
//! // Example of using CRC calculation
//! let data = b"Hello BACnet";
//! let crc = crc16_mstp(data);
//! ```

// TODO: Will be needed for debug formatting
// #[cfg(feature = "std")]
// use std::fmt;
// #[cfg(not(feature = "std"))]
// use core::fmt;

#[cfg(not(feature = "std"))]
use alloc::{format, string::String};

/// Calculate CRC-16 for MS/TP frames
///
/// Uses the polynomial x^16 + x^15 + x^2 + 1 (0xA001)
pub fn crc16_mstp(data: &[u8]) -> u16 {
    let mut crc = 0xFFFF;

    for byte in data {
        crc ^= *byte as u16;
        for _ in 0..8 {
            if crc & 0x0001 != 0 {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }

    !crc
}

/// Calculate CRC-32C (Castagnoli) for BACnet/SC
pub fn crc32c(data: &[u8]) -> u32 {
    let mut crc = 0xFFFFFFFF;

    for byte in data {
        crc ^= *byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0x82F63B78;
            } else {
                crc >>= 1;
            }
        }
    }

    !crc
}

/// Convert BACnet date to string representation
pub fn bacnet_date_to_string(year: u16, month: u8, day: u8, weekday: u8) -> String {
    let year_str = if year == 255 {
        String::from("*")
    } else {
        format!("{}", year)
    };
    let month_str = match month {
        13 => String::from("odd"),
        14 => String::from("even"),
        255 => String::from("*"),
        _ => format!("{}", month),
    };
    let day_str = if day == 32 {
        String::from("last")
    } else if day == 255 {
        String::from("*")
    } else {
        format!("{}", day)
    };
    let weekday_str = if weekday == 255 {
        String::from("*")
    } else {
        String::from(match weekday {
            1 => "Mon",
            2 => "Tue",
            3 => "Wed",
            4 => "Thu",
            5 => "Fri",
            6 => "Sat",
            7 => "Sun",
            _ => "?",
        })
    };

    format!("{}/{}/{} ({})", year_str, month_str, day_str, weekday_str)
}

/// Convert BACnet time to string representation
pub fn bacnet_time_to_string(hour: u8, minute: u8, second: u8, hundredths: u8) -> String {
    let hour_str = if hour == 255 {
        String::from("*")
    } else {
        format!("{:02}", hour)
    };
    let minute_str = if minute == 255 {
        String::from("*")
    } else {
        format!("{:02}", minute)
    };
    let second_str = if second == 255 {
        String::from("*")
    } else {
        format!("{:02}", second)
    };
    let hundredths_str = if hundredths == 255 {
        String::from("*")
    } else {
        format!("{:02}", hundredths)
    };

    format!(
        "{}:{}:{}.{}",
        hour_str, minute_str, second_str, hundredths_str
    )
}

/// Validate object instance number (must be 0-4194302)
pub fn is_valid_instance_number(instance: u32) -> bool {
    instance <= 0x3FFFFF
}

/// Convert object type and instance to object identifier (32-bit)
pub fn encode_object_id(object_type: u16, instance: u32) -> Option<u32> {
    if object_type > 0x3FF || instance > 0x3FFFFF {
        return None;
    }
    Some(((object_type as u32) << 22) | instance)
}

/// Decode object identifier to object type and instance
pub fn decode_object_id(object_id: u32) -> (u16, u32) {
    let object_type = (object_id >> 22) as u16;
    let instance = object_id & 0x3FFFFF;
    (object_type, instance)
}

/// Buffer utilities for reading/writing data
pub struct Buffer<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Buffer<'a> {
    /// Create a new buffer reader
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    /// Get remaining bytes
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.position)
    }

    /// Check if buffer has at least n bytes remaining
    pub fn has_remaining(&self, n: usize) -> bool {
        self.remaining() >= n
    }

    /// Read a single byte
    pub fn read_u8(&mut self) -> Option<u8> {
        if self.has_remaining(1) {
            let value = self.data[self.position];
            self.position += 1;
            Some(value)
        } else {
            None
        }
    }

    /// Read a 16-bit value (big-endian)
    pub fn read_u16(&mut self) -> Option<u16> {
        if self.has_remaining(2) {
            let value =
                u16::from_be_bytes([self.data[self.position], self.data[self.position + 1]]);
            self.position += 2;
            Some(value)
        } else {
            None
        }
    }

    /// Read a 32-bit value (big-endian)
    pub fn read_u32(&mut self) -> Option<u32> {
        if self.has_remaining(4) {
            let value = u32::from_be_bytes([
                self.data[self.position],
                self.data[self.position + 1],
                self.data[self.position + 2],
                self.data[self.position + 3],
            ]);
            self.position += 4;
            Some(value)
        } else {
            None
        }
    }

    /// Read n bytes
    pub fn read_bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.has_remaining(n) {
            let bytes = &self.data[self.position..self.position + n];
            self.position += n;
            Some(bytes)
        } else {
            None
        }
    }

    /// Get current position
    pub fn position(&self) -> usize {
        self.position
    }

    /// Skip n bytes
    pub fn skip(&mut self, n: usize) -> bool {
        if self.has_remaining(n) {
            self.position += n;
            true
        } else {
            false
        }
    }
}

/// Hex dump utility for debugging
pub fn hex_dump(data: &[u8], prefix: &str) -> String {
    let mut result = String::new();

    for (i, chunk) in data.chunks(16).enumerate() {
        result.push_str(prefix);
        result.push_str(&format!("{:04X}: ", i * 16));

        // Hex bytes
        for (j, byte) in chunk.iter().enumerate() {
            if j == 8 {
                result.push(' ');
            }
            result.push_str(&format!("{:02X} ", byte));
        }

        // Padding
        for j in chunk.len()..16 {
            if j == 8 {
                result.push(' ');
            }
            result.push_str("   ");
        }

        result.push_str(" |");

        // ASCII representation
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                result.push(*byte as char);
            } else {
                result.push('.');
            }
        }

        result.push_str("|\n");
    }

    result
}

/// Priority array utilities
pub mod priority {
    /// BACnet priority levels (1-16, where 1 is highest)
    pub const MANUAL_LIFE_SAFETY: u8 = 1;
    pub const AUTOMATIC_LIFE_SAFETY: u8 = 2;
    pub const AVAILABLE_3: u8 = 3;
    pub const AVAILABLE_4: u8 = 4;
    pub const CRITICAL_EQUIPMENT_CONTROL: u8 = 5;
    pub const MINIMUM_ON_OFF: u8 = 6;
    pub const AVAILABLE_7: u8 = 7;
    pub const MANUAL_OPERATOR: u8 = 8;
    pub const AVAILABLE_9: u8 = 9;
    pub const AVAILABLE_10: u8 = 10;
    pub const AVAILABLE_11: u8 = 11;
    pub const AVAILABLE_12: u8 = 12;
    pub const AVAILABLE_13: u8 = 13;
    pub const AVAILABLE_14: u8 = 14;
    pub const AVAILABLE_15: u8 = 15;
    pub const LOWEST: u8 = 16;

    /// Check if priority is valid (1-16)
    pub fn is_valid(priority: u8) -> bool {
        priority >= 1 && priority <= 16
    }
}

// TODO: Add more utility functions as needed
// TODO: Add performance monitoring utilities
// TODO: Add statistics collection helpers
