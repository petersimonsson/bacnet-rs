//! BACnet Transport Layer Module
//!
//! This module provides transport layer functionality for BACnet communication.
//! While BACnet doesn't have a traditional transport layer like TCP/UDP, this module
//! handles transport-related concerns such as connection management, flow control,
//! and reliable delivery mechanisms.
//!
//! # Overview
//!
//! The transport layer handles:
//! - BACnet/IP specific transport (UDP port 47808)
//! - BACnet Virtual Link Layer (BVLL) for BACnet/IP
//! - Foreign Device Registration
//! - Broadcast Distribution Table (BDT) management
//! - Connection-oriented transports (BACnet/SC)
//!
//! # BACnet/IP
//!
//! BACnet/IP uses UDP as its transport with BVLL providing:
//! - Original-Unicast-NPDU
//! - Original-Broadcast-NPDU
//! - Forwarded-NPDU
//! - Register-Foreign-Device
//! - Distribute-Broadcast-To-Network
//!
//! # Example
//!
//! ```no_run
//! use bacnet_rs::transport::*;
//!
//! // Example of creating a BACnet/IP transport
//! // let transport = BacnetIpTransport::new("0.0.0.0:47808")?;
//! ```

#[cfg(feature = "std")]
use std::error::Error;

#[cfg(feature = "std")]
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    time::Instant,
};

#[cfg(not(feature = "std"))]
use core::fmt;

#[cfg(not(feature = "std"))]
use alloc::string::String;

// TODO: Will be needed for timeouts
// #[cfg(feature = "std")]
// use std::time::Duration;
// #[cfg(not(feature = "std"))]
// use core::time::Duration;

/// Result type for transport operations
#[cfg(feature = "std")]
pub type Result<T> = std::result::Result<T, TransportError>;

#[cfg(not(feature = "std"))]
pub type Result<T> = core::result::Result<T, TransportError>;

/// Errors that can occur in transport operations
#[derive(Debug)]
pub enum TransportError {
    /// I/O error
    #[cfg(feature = "std")]
    IoError(std::io::Error),
    /// Invalid BVLL format
    InvalidBvll(String),
    /// Foreign device registration failed
    RegistrationFailed,
    /// Transport not connected
    NotConnected,
    /// Invalid transport configuration
    InvalidConfiguration(String),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "std")]
            TransportError::IoError(e) => write!(f, "I/O error: {}", e),
            TransportError::InvalidBvll(msg) => write!(f, "Invalid BVLL: {}", msg),
            TransportError::RegistrationFailed => write!(f, "Foreign device registration failed"),
            TransportError::NotConnected => write!(f, "Transport not connected"),
            TransportError::InvalidConfiguration(msg) => {
                write!(f, "Invalid configuration: {}", msg)
            }
        }
    }
}

#[cfg(feature = "std")]
impl Error for TransportError {}

#[cfg(feature = "std")]
impl From<std::io::Error> for TransportError {
    fn from(error: std::io::Error) -> Self {
        TransportError::IoError(error)
    }
}

/// BACnet Virtual Link Layer (BVLL) message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BvllType {
    /// BACnet/IP specific
    BacnetIp = 0x81,
}

/// BVLL function codes for BACnet/IP
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BvllFunction {
    /// Pass NPDU to remote device
    OriginalUnicastNpdu = 0x0A,
    /// Broadcast NPDU to local network
    OriginalBroadcastNpdu = 0x0B,
    /// Secured NPDU
    SecureBvll = 0x0C,
    /// Distribute broadcast to remote network
    DistributeBroadcastToNetwork = 0x09,
    /// Register as foreign device
    RegisterForeignDevice = 0x05,
    /// Read broadcast distribution table
    ReadBroadcastDistributionTable = 0x02,
    /// Acknowledge read BDT
    ReadBroadcastDistributionTableAck = 0x03,
    /// Forwarded NPDU
    ForwardedNpdu = 0x04,
    /// Write broadcast distribution table
    WriteBroadcastDistributionTable = 0x01,
    /// Read foreign device table
    ReadForeignDeviceTable = 0x06,
    /// Acknowledge read FDT
    ReadForeignDeviceTableAck = 0x07,
    /// Delete foreign device table entry
    DeleteForeignDeviceTableEntry = 0x08,
    /// Result of operation
    Result = 0x00,
}

/// BVLL header
#[derive(Debug, Clone)]
pub struct BvllHeader {
    /// BVLL type (0x81 for BACnet/IP)
    pub bvll_type: BvllType,
    /// Function code
    pub function: BvllFunction,
    /// Total length including header
    pub length: u16,
}

/// Foreign device registration info
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct ForeignDeviceRegistration {
    /// BBMD (BACnet Broadcast Management Device) address
    pub bbmd_address: SocketAddr,
    /// Time-to-live in seconds
    pub ttl: u16,
    /// Last registration time
    pub last_registration: Instant,
}

/// Broadcast distribution table entry
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct BdtEntry {
    /// IP address
    pub address: IpAddr,
    /// Port number
    pub port: u16,
    /// Broadcast mask
    pub mask: IpAddr,
}

/// Common trait for BACnet transports
#[cfg(feature = "std")]
pub trait Transport: Send + Sync {
    /// Send data to a specific address
    fn send(&mut self, data: &[u8], dest: &SocketAddr) -> Result<()>;

    /// Receive data with source address
    fn receive(&mut self) -> Result<(Vec<u8>, SocketAddr)>;

    /// Get local address
    fn local_address(&self) -> Result<SocketAddr>;

    /// Check if transport is connected/ready
    fn is_connected(&self) -> bool;
}

/// BACnet/IP transport configuration
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct BacnetIpConfig {
    /// Local bind address
    pub bind_address: SocketAddr,
    /// Enable broadcast reception
    pub broadcast_enabled: bool,
    /// Foreign device registration
    pub foreign_device: Option<ForeignDeviceRegistration>,
    /// Broadcast distribution table
    pub bdt: Vec<BdtEntry>,
    /// Receive buffer size
    pub buffer_size: usize,
}

#[cfg(feature = "std")]
impl Default for BacnetIpConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0:47808".parse().unwrap(),
            broadcast_enabled: true,
            foreign_device: None,
            bdt: Vec::new(),
            buffer_size: 1500,
        }
    }
}

/// BACnet/IP specific constants
pub mod constants {
    /// Default BACnet/IP UDP port
    pub const BACNET_IP_PORT: u16 = 0xBAC0; // 47808

    /// Maximum BVLL length
    pub const MAX_BVLL_LENGTH: usize = 1497;

    /// BVLL header size
    pub const BVLL_HEADER_SIZE: usize = 4;

    /// Default foreign device TTL (seconds)
    pub const DEFAULT_FD_TTL: u16 = 900; // 15 minutes
}

// TODO: Implement BACnet/IP transport
// TODO: Add BVLL encoding/decoding
// TODO: Implement foreign device registration
// TODO: Add broadcast management
// TODO: Support for BACnet/SC (Secure Connect)
