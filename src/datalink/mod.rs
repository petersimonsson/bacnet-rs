//! BACnet Data Link Layer Module
//!
//! This module implements the data link layer functionality for BACnet communication.
//! It provides support for various data link protocols used in BACnet networks.
//!
//! # Overview
//!
//! The data link layer is responsible for:
//! - Frame assembly and disassembly
//! - Address handling at the data link level
//! - Error detection (CRC)
//! - Support for multiple data link types (Ethernet, MS/TP, PTP, etc.)
//!
//! # Supported Data Link Types
//!
//! - BACnet/IP (Annex J)
//! - BACnet/Ethernet (ISO 8802-3)
//! - MS/TP (Master-Slave/Token-Passing)
//! - PTP (Point-to-Point)
//! - ARCnet
//!
//! # Example
//!
//! ```no_run
//! use bacnet_rs::datalink::*;
//!
//! // Example of creating a data link handler
//! // let mut handler = BacnetIpHandler::new("0.0.0.0:47808")?;
//! ```

#[cfg(feature = "std")]
use std::error::Error;

#[cfg(feature = "std")]
use std::fmt;

#[cfg(not(feature = "std"))]
use core::fmt;

#[cfg(feature = "std")]
use std::net::SocketAddr;

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

/// Result type for data link operations
#[cfg(feature = "std")]
pub type Result<T> = std::result::Result<T, DataLinkError>;

#[cfg(not(feature = "std"))]
pub type Result<T> = core::result::Result<T, DataLinkError>;

/// Errors that can occur in data link operations
#[derive(Debug)]
pub enum DataLinkError {
    /// Network I/O error
    #[cfg(feature = "std")]
    IoError(std::io::Error),
    /// Invalid frame format
    InvalidFrame,
    /// CRC check failed
    CrcError,
    /// Address resolution failed
    AddressError(String),
    /// Unsupported data link type
    UnsupportedType,
}

impl fmt::Display for DataLinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "std")]
            DataLinkError::IoError(e) => write!(f, "I/O error: {}", e),
            DataLinkError::InvalidFrame => write!(f, "Invalid frame format"),
            DataLinkError::CrcError => write!(f, "CRC check failed"),
            DataLinkError::AddressError(msg) => write!(f, "Address error: {}", msg),
            DataLinkError::UnsupportedType => write!(f, "Unsupported data link type"),
        }
    }
}

#[cfg(feature = "std")]
impl Error for DataLinkError {}

/// BACnet data link layer types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataLinkType {
    /// BACnet/IP
    BacnetIp,
    /// BACnet/Ethernet
    Ethernet,
    /// MS/TP
    MsTP,
    /// PTP
    PointToPoint,
    /// ARCnet
    Arcnet,
}

/// Common trait for all data link implementations
pub trait DataLink: Send + Sync {
    /// Send a frame
    fn send_frame(&mut self, frame: &[u8], dest: &DataLinkAddress) -> Result<()>;

    /// Receive a frame
    fn receive_frame(&mut self) -> Result<(Vec<u8>, DataLinkAddress)>;

    /// Get the data link type
    fn link_type(&self) -> DataLinkType;

    /// Get local address
    fn local_address(&self) -> DataLinkAddress;
}

/// Data link address representation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataLinkAddress {
    /// IP address and port
    #[cfg(feature = "std")]
    Ip(SocketAddr),
    /// Ethernet MAC address
    Ethernet([u8; 6]),
    /// MS/TP address
    MsTP(u8),
    /// Broadcast address
    Broadcast,
}

/// BACnet/IP implementation
pub mod bip;

/// Ethernet implementation
pub mod ethernet;

/// MS/TP implementation
pub mod mstp;

/// Frame validation utilities
pub mod validation;

#[cfg(feature = "std")]
pub use bip::BacnetIpDataLink;

#[cfg(feature = "std")]
pub use ethernet::EthernetDataLink;

#[cfg(feature = "std")]
pub use mstp::MstpDataLink;
