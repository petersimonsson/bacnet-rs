//! BACnet/IP Data Link Implementation
//!
//! This module implements the BACnet/IP data link layer as defined in ASHRAE 135 Annex J.
//! BACnet/IP uses UDP as the transport protocol on port 47808 (0xBAC0).
//!
//! # Overview
//!
//! BACnet/IP provides:
//! - UDP-based communication over IP networks
//! - BVLC (BACnet Virtual Link Control) for broadcast management
//! - Support for broadcast distribution tables (BDT)
//! - Foreign device registration
//!
//! # BVLC Functions
//!
//! - Original-Unicast-NPDU
//! - Original-Broadcast-NPDU
//! - Forwarded-NPDU
//! - Register-Foreign-Device
//! - Read-Broadcast-Distribution-Table
//! - Read-Foreign-Device-Table
//! - And more...

#[cfg(feature = "std")]
use std::{
    io::ErrorKind,
    net::{SocketAddr, UdpSocket, ToSocketAddrs},
    time::{Duration, Instant},
};

#[cfg(not(feature = "std"))]
use alloc::{vec::Vec, string::String};

use crate::datalink::{DataLink, DataLinkAddress, DataLinkError, DataLinkType, Result};

/// BACnet/IP well-known port number (0xBAC0)
pub const BACNET_IP_PORT: u16 = 47808;

/// BVLC (BACnet Virtual Link Control) message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BvlcFunction {
    /// Original-Unicast-NPDU
    OriginalUnicastNpdu = 0x0A,
    /// Original-Broadcast-NPDU
    OriginalBroadcastNpdu = 0x0B,
    /// Forwarded-NPDU
    ForwardedNpdu = 0x04,
    /// Register-Foreign-Device
    RegisterForeignDevice = 0x05,
    /// Read-Broadcast-Distribution-Table
    ReadBroadcastDistributionTable = 0x02,
    /// Read-Broadcast-Distribution-Table-Ack
    ReadBroadcastDistributionTableAck = 0x03,
    /// Read-Foreign-Device-Table
    ReadForeignDeviceTable = 0x06,
    /// Read-Foreign-Device-Table-Ack
    ReadForeignDeviceTableAck = 0x07,
    /// Delete-Foreign-Device-Table-Entry
    DeleteForeignDeviceTableEntry = 0x08,
    /// Distribute-Broadcast-To-Network
    DistributeBroadcastToNetwork = 0x09,
    /// Forwarded-NPDU-From-Device
    ForwardedNpduFromDevice = 0x0C,
    /// Secure-BVLL
    SecureBvll = 0x0D,
}

/// BVLC header structure
#[derive(Debug, Clone)]
pub struct BvlcHeader {
    /// BVLC type (always 0x81 for BACnet/IP)
    pub bvlc_type: u8,
    /// BVLC function
    pub function: BvlcFunction,
    /// Total message length including BVLC header
    pub length: u16,
}

impl BvlcHeader {
    /// Create a new BVLC header
    pub fn new(function: BvlcFunction, length: u16) -> Self {
        Self {
            bvlc_type: 0x81, // BACnet/IP
            function,
            length,
        }
    }

    /// Encode BVLC header to bytes
    pub fn encode(&self) -> Vec<u8> {
        vec![
            self.bvlc_type,
            self.function as u8,
            (self.length >> 8) as u8,
            (self.length & 0xFF) as u8,
        ]
    }

    /// Decode BVLC header from bytes
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(DataLinkError::InvalidFrame);
        }

        let bvlc_type = data[0];
        if bvlc_type != 0x81 {
            return Err(DataLinkError::InvalidFrame);
        }

        let function = match data[1] {
            0x0A => BvlcFunction::OriginalUnicastNpdu,
            0x0B => BvlcFunction::OriginalBroadcastNpdu,
            0x04 => BvlcFunction::ForwardedNpdu,
            0x05 => BvlcFunction::RegisterForeignDevice,
            0x02 => BvlcFunction::ReadBroadcastDistributionTable,
            0x03 => BvlcFunction::ReadBroadcastDistributionTableAck,
            0x06 => BvlcFunction::ReadForeignDeviceTable,
            0x07 => BvlcFunction::ReadForeignDeviceTableAck,
            0x08 => BvlcFunction::DeleteForeignDeviceTableEntry,
            0x09 => BvlcFunction::DistributeBroadcastToNetwork,
            0x0C => BvlcFunction::ForwardedNpduFromDevice,
            0x0D => BvlcFunction::SecureBvll,
            _ => return Err(DataLinkError::InvalidFrame),
        };

        let length = ((data[2] as u16) << 8) | (data[3] as u16);

        Ok(BvlcHeader {
            bvlc_type,
            function,
            length,
        })
    }
}

/// Broadcast Distribution Table entry
#[derive(Debug, Clone)]
#[cfg(feature = "std")]
pub struct BdtEntry {
    /// IP address and port
    pub address: SocketAddr,
    /// Broadcast distribution mask
    pub mask: [u8; 4],
}

/// Foreign Device Table entry
#[derive(Debug, Clone)]
#[cfg(feature = "std")]
pub struct FdtEntry {
    /// IP address and port
    pub address: SocketAddr,
    /// Time-to-live in seconds
    pub ttl: u16,
    /// Registration time
    pub registration_time: Instant,
}

/// BACnet/IP data link implementation
#[cfg(feature = "std")]
pub struct BacnetIpDataLink {
    /// UDP socket for communication
    socket: UdpSocket,
    /// Local address
    local_addr: SocketAddr,
    /// Broadcast Distribution Table
    bdt: Vec<BdtEntry>,
    /// Foreign Device Table
    fdt: Vec<FdtEntry>,
    /// Broadcast address
    broadcast_addr: SocketAddr,
}

#[cfg(feature = "std")]
impl BacnetIpDataLink {
    /// Create a new BACnet/IP data link
    pub fn new<A: ToSocketAddrs>(bind_addr: A) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr)
            .map_err(DataLinkError::IoError)?;
        
        let local_addr = socket.local_addr()
            .map_err(DataLinkError::IoError)?;

        // Enable broadcast
        socket.set_broadcast(true)
            .map_err(DataLinkError::IoError)?;

        // Set receive timeout
        socket.set_read_timeout(Some(Duration::from_millis(100)))
            .map_err(DataLinkError::IoError)?;

        // Calculate broadcast address based on local address
        let broadcast_addr = match local_addr {
            SocketAddr::V4(addr) => {
                let ip = addr.ip().octets();
                // Simple broadcast calculation - in production, use proper subnet mask
                let broadcast_ip = std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], 255);
                SocketAddr::new(broadcast_ip.into(), BACNET_IP_PORT)
            }
            SocketAddr::V6(_) => {
                // IPv6 uses multicast instead of broadcast
                return Err(DataLinkError::UnsupportedType);
            }
        };

        Ok(Self {
            socket,
            local_addr,
            bdt: Vec::new(),
            fdt: Vec::new(),
            broadcast_addr,
        })
    }

    /// Send a unicast NPDU
    pub fn send_unicast_npdu(&mut self, npdu: &[u8], dest: SocketAddr) -> Result<()> {
        let header = BvlcHeader::new(
            BvlcFunction::OriginalUnicastNpdu,
            4 + npdu.len() as u16,
        );

        let mut frame = header.encode();
        frame.extend_from_slice(npdu);

        self.socket.send_to(&frame, dest)
            .map_err(DataLinkError::IoError)?;

        Ok(())
    }

    /// Send a broadcast NPDU
    pub fn send_broadcast_npdu(&mut self, npdu: &[u8]) -> Result<()> {
        let header = BvlcHeader::new(
            BvlcFunction::OriginalBroadcastNpdu,
            4 + npdu.len() as u16,
        );

        let mut frame = header.encode();
        frame.extend_from_slice(npdu);

        // Send to local broadcast address
        self.socket.send_to(&frame, self.broadcast_addr)
            .map_err(DataLinkError::IoError)?;

        // Send to all BDT entries
        for entry in &self.bdt {
            let _ = self.socket.send_to(&frame, entry.address);
        }

        Ok(())
    }

    /// Register as a foreign device
    pub fn register_foreign_device(&mut self, bbmd_addr: SocketAddr, ttl: u16) -> Result<()> {
        let header = BvlcHeader::new(BvlcFunction::RegisterForeignDevice, 6);
        let mut frame = header.encode();
        frame.extend_from_slice(&ttl.to_be_bytes());

        self.socket.send_to(&frame, bbmd_addr)
            .map_err(DataLinkError::IoError)?;

        Ok(())
    }

    /// Add entry to Broadcast Distribution Table
    pub fn add_bdt_entry(&mut self, address: SocketAddr, mask: [u8; 4]) {
        self.bdt.push(BdtEntry { address, mask });
    }

    /// Clean up expired foreign device entries
    pub fn cleanup_fdt(&mut self) {
        let now = Instant::now();
        self.fdt.retain(|entry| {
            now.duration_since(entry.registration_time).as_secs() < entry.ttl as u64
        });
    }

    /// Process received BVLC message
    fn process_bvlc_message(&mut self, data: &[u8], source: SocketAddr) -> Result<Option<Vec<u8>>> {
        let header = BvlcHeader::decode(data)?;

        if data.len() != header.length as usize {
            return Err(DataLinkError::InvalidFrame);
        }

        match header.function {
            BvlcFunction::OriginalUnicastNpdu | BvlcFunction::OriginalBroadcastNpdu => {
                // Return the NPDU portion (skip 4-byte BVLC header)
                if data.len() > 4 {
                    Ok(Some(data[4..].to_vec()))
                } else {
                    Err(DataLinkError::InvalidFrame)
                }
            }
            BvlcFunction::ForwardedNpdu => {
                // Forwarded NPDU has original source address after header
                if data.len() > 10 {
                    Ok(Some(data[10..].to_vec()))
                } else {
                    Err(DataLinkError::InvalidFrame)
                }
            }
            BvlcFunction::RegisterForeignDevice => {
                // Handle foreign device registration
                if data.len() == 6 {
                    let ttl = u16::from_be_bytes([data[4], data[5]]);
                    self.fdt.push(FdtEntry {
                        address: source,
                        ttl,
                        registration_time: Instant::now(),
                    });
                }
                Ok(None)
            }
            _ => {
                // Other BVLC functions not yet implemented
                Ok(None)
            }
        }
    }
}

#[cfg(feature = "std")]
impl DataLink for BacnetIpDataLink {
    fn send_frame(&mut self, frame: &[u8], dest: &DataLinkAddress) -> Result<()> {
        match dest {
            DataLinkAddress::Ip(addr) => {
                self.send_unicast_npdu(frame, *addr)
            }
            DataLinkAddress::Broadcast => {
                self.send_broadcast_npdu(frame)
            }
            _ => Err(DataLinkError::UnsupportedType),
        }
    }

    fn receive_frame(&mut self) -> Result<(Vec<u8>, DataLinkAddress)> {
        let mut buffer = [0u8; 1500]; // MTU size
        
        match self.socket.recv_from(&mut buffer) {
            Ok((len, source)) => {
                let data = &buffer[..len];
                
                if let Some(npdu) = self.process_bvlc_message(data, source)? {
                    Ok((npdu, DataLinkAddress::Ip(source)))
                } else {
                    // No NPDU to return, try again
                    Err(DataLinkError::InvalidFrame)
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                Err(DataLinkError::IoError(e))
            }
            Err(e) => Err(DataLinkError::IoError(e)),
        }
    }

    fn link_type(&self) -> DataLinkType {
        DataLinkType::BacnetIp
    }

    fn local_address(&self) -> DataLinkAddress {
        DataLinkAddress::Ip(self.local_addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bvlc_header_encode_decode() {
        let header = BvlcHeader::new(BvlcFunction::OriginalUnicastNpdu, 1024);
        let encoded = header.encode();
        
        assert_eq!(encoded.len(), 4);
        assert_eq!(encoded[0], 0x81);
        assert_eq!(encoded[1], 0x0A);
        assert_eq!(encoded[2], 0x04);
        assert_eq!(encoded[3], 0x00);

        let decoded = BvlcHeader::decode(&encoded).unwrap();
        assert_eq!(decoded.bvlc_type, 0x81);
        assert_eq!(decoded.function, BvlcFunction::OriginalUnicastNpdu);
        assert_eq!(decoded.length, 1024);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_bacnet_ip_creation() {
        let result = BacnetIpDataLink::new("127.0.0.1:0");
        assert!(result.is_ok());
        
        let datalink = result.unwrap();
        assert_eq!(datalink.link_type(), DataLinkType::BacnetIp);
    }
}