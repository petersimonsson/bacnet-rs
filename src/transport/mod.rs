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

impl BvllHeader {
    /// Create a new BVLL header
    pub fn new(function: BvllFunction, length: u16) -> Self {
        Self {
            bvll_type: BvllType::BacnetIp,
            function,
            length,
        }
    }

    /// Encode BVLL header to bytes
    pub fn encode(&self) -> [u8; 4] {
        [
            self.bvll_type as u8,
            self.function as u8,
            (self.length >> 8) as u8,
            (self.length & 0xFF) as u8,
        ]
    }

    /// Decode BVLL header from bytes
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(TransportError::InvalidBvll("Header too short".into()));
        }

        let bvll_type = match data[0] {
            0x81 => BvllType::BacnetIp,
            _ => return Err(TransportError::InvalidBvll("Invalid BVLL type".into())),
        };

        let function = match data[1] {
            0x00 => BvllFunction::Result,
            0x01 => BvllFunction::WriteBroadcastDistributionTable,
            0x02 => BvllFunction::ReadBroadcastDistributionTable,
            0x03 => BvllFunction::ReadBroadcastDistributionTableAck,
            0x04 => BvllFunction::ForwardedNpdu,
            0x05 => BvllFunction::RegisterForeignDevice,
            0x06 => BvllFunction::ReadForeignDeviceTable,
            0x07 => BvllFunction::ReadForeignDeviceTableAck,
            0x08 => BvllFunction::DeleteForeignDeviceTableEntry,
            0x09 => BvllFunction::DistributeBroadcastToNetwork,
            0x0A => BvllFunction::OriginalUnicastNpdu,
            0x0B => BvllFunction::OriginalBroadcastNpdu,
            0x0C => BvllFunction::SecureBvll,
            _ => return Err(TransportError::InvalidBvll("Invalid BVLL function".into())),
        };

        let length = ((data[2] as u16) << 8) | (data[3] as u16);

        Ok(Self {
            bvll_type,
            function,
            length,
        })
    }
}

/// BVLL message containing header and data
#[derive(Debug, Clone)]
pub struct BvllMessage {
    /// BVLL header
    pub header: BvllHeader,
    /// Message data (NPDU)
    pub data: Vec<u8>,
}

impl BvllMessage {
    /// Create a new BVLL message
    pub fn new(function: BvllFunction, data: Vec<u8>) -> Self {
        let length = (constants::BVLL_HEADER_SIZE + data.len()) as u16;
        Self {
            header: BvllHeader::new(function, length),
            data,
        }
    }

    /// Encode BVLL message to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.header.encode());
        result.extend_from_slice(&self.data);
        result
    }

    /// Decode BVLL message from bytes
    pub fn decode(data: &[u8]) -> Result<Self> {
        let header = BvllHeader::decode(data)?;
        
        if data.len() < header.length as usize {
            return Err(TransportError::InvalidBvll("Message too short".into()));
        }

        let message_data = data[constants::BVLL_HEADER_SIZE..header.length as usize].to_vec();

        Ok(Self {
            header,
            data: message_data,
        })
    }
}

#[cfg(feature = "std")]
use std::net::UdpSocket;

/// BACnet/IP transport implementation
#[cfg(feature = "std")]
pub struct BacnetIpTransport {
    /// UDP socket
    socket: UdpSocket,
    /// Configuration
    config: BacnetIpConfig,
    /// Receive buffer
    buffer: Vec<u8>,
}

#[cfg(feature = "std")]
impl BacnetIpTransport {
    /// Create a new BACnet/IP transport
    pub fn new(config: BacnetIpConfig) -> Result<Self> {
        let socket = UdpSocket::bind(config.bind_address)?;
        
        // Enable broadcast if configured
        if config.broadcast_enabled {
            socket.set_broadcast(true)?;
        }

        let buffer = vec![0u8; config.buffer_size];

        Ok(Self {
            socket,
            config,
            buffer,
        })
    }

    /// Create with default configuration
    pub fn new_default(bind_addr: &str) -> Result<Self> {
        let mut config = BacnetIpConfig::default();
        config.bind_address = bind_addr.parse()
            .map_err(|_| TransportError::InvalidConfiguration("Invalid bind address".into()))?;
        Self::new(config)
    }

    /// Send a BVLL message
    pub fn send_bvll(&mut self, message: BvllMessage, dest: SocketAddr) -> Result<()> {
        let encoded = message.encode();
        self.socket.send_to(&encoded, dest)?;
        Ok(())
    }

    /// Send NPDU as original unicast
    pub fn send_npdu_unicast(&mut self, npdu: &[u8], dest: SocketAddr) -> Result<()> {
        let message = BvllMessage::new(BvllFunction::OriginalUnicastNpdu, npdu.to_vec());
        self.send_bvll(message, dest)
    }

    /// Send NPDU as original broadcast
    pub fn send_npdu_broadcast(&mut self, npdu: &[u8], dest: SocketAddr) -> Result<()> {
        let message = BvllMessage::new(BvllFunction::OriginalBroadcastNpdu, npdu.to_vec());
        self.send_bvll(message, dest)
    }

    /// Receive a BVLL message
    pub fn receive_bvll(&mut self) -> Result<(BvllMessage, SocketAddr)> {
        let (len, src) = self.socket.recv_from(&mut self.buffer)?;
        let message = BvllMessage::decode(&self.buffer[..len])?;
        Ok((message, src))
    }

    /// Register as foreign device with BBMD
    pub fn register_foreign_device(&mut self, bbmd_addr: SocketAddr, ttl: u16) -> Result<()> {
        let mut data = Vec::new();
        data.extend_from_slice(&ttl.to_be_bytes());
        
        let message = BvllMessage::new(BvllFunction::RegisterForeignDevice, data);
        self.send_bvll(message, bbmd_addr)?;

        // Update foreign device registration
        self.config.foreign_device = Some(ForeignDeviceRegistration {
            bbmd_address: bbmd_addr,
            ttl,
            last_registration: Instant::now(),
        });

        Ok(())
    }

    /// Send heartbeat to maintain foreign device registration
    pub fn send_foreign_device_heartbeat(&mut self) -> Result<()> {
        if let Some(ref fd_reg) = self.config.foreign_device {
            let elapsed = fd_reg.last_registration.elapsed().as_secs() as u16;
            if elapsed >= fd_reg.ttl / 2 {
                // Re-register when half TTL has elapsed
                self.register_foreign_device(fd_reg.bbmd_address, fd_reg.ttl)?;
            }
        }
        Ok(())
    }

    /// Get configuration
    pub fn config(&self) -> &BacnetIpConfig {
        &self.config
    }

    /// Update configuration
    pub fn update_config(&mut self, config: BacnetIpConfig) -> Result<()> {
        // Validate new configuration
        if config.bind_address != self.config.bind_address {
            return Err(TransportError::InvalidConfiguration(
                "Cannot change bind address on existing transport".into()
            ));
        }
        
        self.config = config;
        Ok(())
    }
}

#[cfg(feature = "std")]
impl Transport for BacnetIpTransport {
    fn send(&mut self, data: &[u8], dest: &SocketAddr) -> Result<()> {
        self.send_npdu_unicast(data, *dest)
    }

    fn receive(&mut self) -> Result<(Vec<u8>, SocketAddr)> {
        let (message, src) = self.receive_bvll()?;
        Ok((message.data, src))
    }

    fn local_address(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }

    fn is_connected(&self) -> bool {
        true // UDP is connectionless
    }
}

/// BDT (Broadcast Distribution Table) management
#[cfg(feature = "std")]
pub struct BroadcastManager {
    /// BDT entries
    bdt: Vec<BdtEntry>,
}

#[cfg(feature = "std")]
impl BroadcastManager {
    /// Create new broadcast manager
    pub fn new() -> Self {
        Self {
            bdt: Vec::new(),
        }
    }

    /// Add BDT entry
    pub fn add_bdt_entry(&mut self, entry: BdtEntry) {
        self.bdt.push(entry);
    }

    /// Remove BDT entry
    pub fn remove_bdt_entry(&mut self, address: IpAddr) {
        self.bdt.retain(|entry| entry.address != address);
    }

    /// Get all BDT entries
    pub fn get_bdt_entries(&self) -> &[BdtEntry] {
        &self.bdt
    }

    /// Encode BDT for transmission
    pub fn encode_bdt(&self) -> Vec<u8> {
        let mut data = Vec::new();
        
        for entry in &self.bdt {
            match entry.address {
                IpAddr::V4(addr) => {
                    data.extend_from_slice(&addr.octets());
                    data.extend_from_slice(&entry.port.to_be_bytes());
                    
                    if let IpAddr::V4(mask) = entry.mask {
                        data.extend_from_slice(&mask.octets());
                    } else {
                        data.extend_from_slice(&[255, 255, 255, 255]); // Default mask
                    }
                }
                IpAddr::V6(_) => {
                    // IPv6 support would go here
                    // For now, skip IPv6 entries
                }
            }
        }
        
        data
    }

    /// Decode BDT from received data
    pub fn decode_bdt(&mut self, data: &[u8]) -> Result<()> {
        self.bdt.clear();
        
        let entry_size = 10; // 4 bytes IP + 2 bytes port + 4 bytes mask
        if data.len() % entry_size != 0 {
            return Err(TransportError::InvalidBvll("Invalid BDT data length".into()));
        }

        for chunk in data.chunks_exact(entry_size) {
            let ip_bytes = [chunk[0], chunk[1], chunk[2], chunk[3]];
            let address = IpAddr::V4(ip_bytes.into());
            
            let port = u16::from_be_bytes([chunk[4], chunk[5]]);
            
            let mask_bytes = [chunk[6], chunk[7], chunk[8], chunk[9]];
            let mask = IpAddr::V4(mask_bytes.into());

            self.bdt.push(BdtEntry {
                address,
                port,
                mask,
            });
        }

        Ok(())
    }
}

/// BACnet/SC (Secure Connect) Support Planning
/// 
/// BACnet/SC is defined in ASHRAE 135-2020 and provides secure WebSocket-based
/// communication for BACnet. This would be a future enhancement to the transport layer.
/// 
/// Key BACnet/SC Features to Implement:
/// 
/// 1. **WebSocket Transport**: TLS-secured WebSocket connections (wss://)
/// 2. **Node Authentication**: X.509 certificates and certificate authorities
/// 3. **Hub and Direct Connect**: Support for hub-based and direct node connections
/// 4. **Message Encryption**: All messages encrypted using TLS
/// 5. **Connection Management**: Automatic reconnection and connection state tracking
/// 6. **Discovery**: Integration with DNS-SD for automatic node discovery
/// 
/// Implementation Plan:
/// 
/// ```rust
/// // Future BACnet/SC structures (not implemented yet)
/// 
/// #[cfg(feature = "bacnet-sc")]
/// pub struct BacnetScConfig {
///     pub certificate_path: PathBuf,
///     pub private_key_path: PathBuf,
///     pub ca_certificates: Vec<PathBuf>,
///     pub hub_uri: Option<String>,
///     pub node_uuid: String,
///     pub max_connections: usize,
/// }
/// 
/// #[cfg(feature = "bacnet-sc")]
/// pub struct BacnetScTransport {
///     config: BacnetScConfig,
///     connections: HashMap<String, WebSocketConnection>,
///     hub_connection: Option<WebSocketConnection>,
/// }
/// 
/// #[cfg(feature = "bacnet-sc")]
/// pub enum BacnetScMessage {
///     Advertisement(NodeAdvertisement),
///     Connect(ConnectRequest),
///     Disconnect(DisconnectRequest),
///     Data(EncryptedData),
///     Heartbeat,
/// }
/// ```
/// 
/// Dependencies needed for BACnet/SC:
/// - tokio-tungstenite (WebSocket client/server)
/// - rustls (TLS implementation)
/// - webpki (Certificate validation)
/// - serde_json (JSON message serialization)
/// - uuid (Node identification)
/// 
/// Security Considerations:
/// - Certificate validation and revocation checking
/// - Secure random number generation
/// - Protection against replay attacks
/// - Rate limiting and DoS protection
/// 
/// This would require a separate feature flag and significant additional dependencies,
/// so it's planned for a future major version.

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_bvll_header_encode_decode() {
        let header = BvllHeader::new(BvllFunction::OriginalUnicastNpdu, 100);
        let encoded = header.encode();
        
        assert_eq!(encoded[0], 0x81); // BACnet/IP
        assert_eq!(encoded[1], 0x0A); // Original-Unicast-NPDU
        assert_eq!(encoded[2], 0x00); // Length high byte
        assert_eq!(encoded[3], 0x64); // Length low byte (100)
        
        let decoded = BvllHeader::decode(&encoded).unwrap();
        assert_eq!(decoded.bvll_type as u8, header.bvll_type as u8);
        assert_eq!(decoded.function as u8, header.function as u8);
        assert_eq!(decoded.length, header.length);
    }
    
    #[test]
    fn test_bvll_message_encode_decode() {
        let test_data = vec![0x01, 0x02, 0x03, 0x04];
        let message = BvllMessage::new(BvllFunction::OriginalBroadcastNpdu, test_data.clone());
        
        let encoded = message.encode();
        assert_eq!(encoded.len(), 4 + test_data.len()); // Header + data
        
        let decoded = BvllMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.header.function as u8, BvllFunction::OriginalBroadcastNpdu as u8);
        assert_eq!(decoded.data, test_data);
    }
    
    #[test]
    fn test_bvll_function_decode() {
        // Test all BVLL function codes
        let test_cases = [
            (0x00, BvllFunction::Result),
            (0x0A, BvllFunction::OriginalUnicastNpdu),
            (0x0B, BvllFunction::OriginalBroadcastNpdu),
            (0x05, BvllFunction::RegisterForeignDevice),
        ];
        
        for (code, expected) in test_cases.iter() {
            let data = [0x81, *code, 0x00, 0x04];
            let header = BvllHeader::decode(&data).unwrap();
            assert_eq!(header.function as u8, *expected as u8);
        }
    }
    
    #[test]
    fn test_broadcast_manager() {
        let mut manager = BroadcastManager::new();
        
        let entry = BdtEntry {
            address: "192.168.1.1".parse().unwrap(),
            port: 47808,
            mask: "255.255.255.0".parse().unwrap(),
        };
        
        manager.add_bdt_entry(entry.clone());
        assert_eq!(manager.get_bdt_entries().len(), 1);
        
        let encoded = manager.encode_bdt();
        assert_eq!(encoded.len(), 10); // 4 + 2 + 4 bytes per entry
        
        let mut new_manager = BroadcastManager::new();
        new_manager.decode_bdt(&encoded).unwrap();
        
        let decoded_entries = new_manager.get_bdt_entries();
        assert_eq!(decoded_entries.len(), 1);
        assert_eq!(decoded_entries[0].address, entry.address);
        assert_eq!(decoded_entries[0].port, entry.port);
    }
    
    #[cfg(feature = "std")]
    #[test]
    fn test_bacnet_ip_config_default() {
        let config = BacnetIpConfig::default();
        assert_eq!(config.bind_address.port(), constants::BACNET_IP_PORT);
        assert!(config.broadcast_enabled);
        assert!(config.foreign_device.is_none());
        assert_eq!(config.buffer_size, 1500);
    }
    
    #[test]
    fn test_invalid_bvll_decode() {
        // Test too short header
        let short_data = [0x81, 0x0A];
        assert!(BvllHeader::decode(&short_data).is_err());
        
        // Test invalid BVLL type
        let invalid_type = [0x82, 0x0A, 0x00, 0x04];
        assert!(BvllHeader::decode(&invalid_type).is_err());
        
        // Test invalid function code
        let invalid_function = [0x81, 0xFF, 0x00, 0x04];
        assert!(BvllHeader::decode(&invalid_function).is_err());
    }
}
