//! BACnet/Ethernet Data Link Implementation
//!
//! This module implements the BACnet/Ethernet data link layer as defined in ASHRAE 135 Clause 7.
//! BACnet/Ethernet uses IEEE 802.3 Ethernet frames with the BACnet LLC header.
//!
//! # Overview
//!
//! BACnet/Ethernet provides:
//! - Direct Ethernet frame communication
//! - LLC (Logical Link Control) header for BACnet identification
//! - MAC address-based communication
//! - Broadcast support via Ethernet broadcast address
//!
//! # Frame Format
//!
//! Ethernet Frame:
//! - Destination MAC (6 bytes)
//! - Source MAC (6 bytes)
//! - Length/Type (2 bytes) - 0x82 for BACnet
//! - LLC Header (3 bytes) - 0x82, 0x82, 0x03
//! - NPDU (Network Protocol Data Unit)
//! - FCS (Frame Check Sequence) - handled by hardware

#[cfg(feature = "std")]
use std::{
    sync::{Arc, Mutex},
};

#[cfg(not(feature = "std"))]
use alloc::{vec::Vec, string::String};

use crate::datalink::{DataLink, DataLinkAddress, DataLinkError, DataLinkType, Result};

/// Ethernet broadcast MAC address
pub const ETHERNET_BROADCAST_MAC: [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

/// BACnet Ethernet type field
pub const BACNET_ETHERNET_TYPE: u16 = 0x82DC;

/// BACnet LLC header
pub const BACNET_LLC_HEADER: [u8; 3] = [0x82, 0x82, 0x03];

/// Minimum Ethernet frame size (without FCS)
pub const MIN_ETHERNET_FRAME_SIZE: usize = 60;

/// Maximum Ethernet frame size (without FCS)
pub const MAX_ETHERNET_FRAME_SIZE: usize = 1514;

/// Ethernet header size (dest MAC + src MAC + type)
pub const ETHERNET_HEADER_SIZE: usize = 14;

/// LLC header size
pub const LLC_HEADER_SIZE: usize = 3;

/// Total BACnet/Ethernet header size
pub const BACNET_ETHERNET_HEADER_SIZE: usize = ETHERNET_HEADER_SIZE + LLC_HEADER_SIZE;

/// Ethernet frame structure
#[derive(Debug, Clone)]
pub struct EthernetFrame {
    /// Destination MAC address
    pub dest_mac: [u8; 6],
    /// Source MAC address
    pub src_mac: [u8; 6],
    /// Ethernet type field
    pub ether_type: u16,
    /// LLC header
    pub llc_header: [u8; 3],
    /// Payload (NPDU)
    pub payload: Vec<u8>,
}

impl EthernetFrame {
    /// Create a new Ethernet frame for BACnet
    pub fn new(dest_mac: [u8; 6], src_mac: [u8; 6], npdu: Vec<u8>) -> Self {
        Self {
            dest_mac,
            src_mac,
            ether_type: BACNET_ETHERNET_TYPE,
            llc_header: BACNET_LLC_HEADER,
            payload: npdu,
        }
    }

    /// Create a broadcast frame
    pub fn broadcast(src_mac: [u8; 6], npdu: Vec<u8>) -> Self {
        Self::new(ETHERNET_BROADCAST_MAC, src_mac, npdu)
    }

    /// Encode frame to bytes (without FCS - hardware adds it)
    pub fn encode(&self) -> Vec<u8> {
        let mut frame = Vec::with_capacity(BACNET_ETHERNET_HEADER_SIZE + self.payload.len());
        
        // Destination MAC
        frame.extend_from_slice(&self.dest_mac);
        
        // Source MAC
        frame.extend_from_slice(&self.src_mac);
        
        // Ethernet type
        frame.extend_from_slice(&self.ether_type.to_be_bytes());
        
        // LLC header
        frame.extend_from_slice(&self.llc_header);
        
        // Payload
        frame.extend_from_slice(&self.payload);
        
        // Pad to minimum frame size if necessary
        while frame.len() < MIN_ETHERNET_FRAME_SIZE {
            frame.push(0);
        }
        
        frame
    }

    /// Decode frame from bytes
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < BACNET_ETHERNET_HEADER_SIZE {
            return Err(DataLinkError::InvalidFrame);
        }

        // Extract fields
        let mut dest_mac = [0u8; 6];
        dest_mac.copy_from_slice(&data[0..6]);
        
        let mut src_mac = [0u8; 6];
        src_mac.copy_from_slice(&data[6..12]);
        
        let ether_type = u16::from_be_bytes([data[12], data[13]]);
        
        // Verify this is a BACnet frame
        if ether_type != BACNET_ETHERNET_TYPE {
            return Err(DataLinkError::InvalidFrame);
        }
        
        let mut llc_header = [0u8; 3];
        llc_header.copy_from_slice(&data[14..17]);
        
        // Verify LLC header
        if llc_header != BACNET_LLC_HEADER {
            return Err(DataLinkError::InvalidFrame);
        }
        
        // Extract payload (strip any padding)
        let payload = data[17..].to_vec();
        
        Ok(Self {
            dest_mac,
            src_mac,
            ether_type,
            llc_header,
            payload,
        })
    }

    /// Check if frame is broadcast
    pub fn is_broadcast(&self) -> bool {
        self.dest_mac == ETHERNET_BROADCAST_MAC
    }

    /// Check if frame is multicast
    pub fn is_multicast(&self) -> bool {
        self.dest_mac[0] & 0x01 == 0x01
    }
}

/// BACnet/Ethernet data link implementation
#[cfg(feature = "std")]
pub struct EthernetDataLink {
    /// Local MAC address
    local_mac: [u8; 6],
    /// Interface name (e.g., "eth0")
    _interface: String,
    /// Receive buffer
    rx_buffer: Arc<Mutex<Vec<(EthernetFrame, DataLinkAddress)>>>,
    /// Running flag
    _running: Arc<Mutex<bool>>,
}

#[cfg(feature = "std")]
impl EthernetDataLink {
    /// Create a new Ethernet data link
    /// 
    /// Note: In a real implementation, this would use raw sockets or a packet capture library
    /// like pcap to send/receive Ethernet frames. This is a simplified simulation.
    pub fn new(interface: &str, local_mac: [u8; 6]) -> Result<Self> {
        let rx_buffer = Arc::new(Mutex::new(Vec::new()));
        let running = Arc::new(Mutex::new(true));
        
        // In a real implementation, we would:
        // 1. Open a raw socket or pcap handle for the interface
        // 2. Set up BPF filters for BACnet frames
        // 3. Start a receive thread
        
        Ok(Self {
            local_mac,
            _interface: interface.to_string(),
            rx_buffer,
            _running: running,
        })
    }

    /// Send an Ethernet frame
    fn send_ethernet_frame(&self, frame: &EthernetFrame) -> Result<()> {
        // In a real implementation, this would:
        // 1. Encode the frame
        // 2. Send it via raw socket or pcap
        
        let encoded = frame.encode();
        
        // Validate frame size
        if encoded.len() > MAX_ETHERNET_FRAME_SIZE {
            return Err(DataLinkError::InvalidFrame);
        }
        
        // Simulate sending (in real implementation, use raw socket)
        println!("Sending Ethernet frame: {} bytes to {:02X?}", 
            encoded.len(), frame.dest_mac);
        
        Ok(())
    }

    /// Simulate receiving a frame (for testing)
    #[cfg(test)]
    pub fn simulate_receive(&self, frame: EthernetFrame, source: DataLinkAddress) {
        let mut buffer = self.rx_buffer.lock().unwrap();
        buffer.push((frame, source));
    }
}

#[cfg(feature = "std")]
impl DataLink for EthernetDataLink {
    fn send_frame(&mut self, frame: &[u8], dest: &DataLinkAddress) -> Result<()> {
        let dest_mac = match dest {
            DataLinkAddress::Ethernet(mac) => *mac,
            DataLinkAddress::Broadcast => ETHERNET_BROADCAST_MAC,
            _ => return Err(DataLinkError::AddressError("Invalid address type for Ethernet".into())),
        };
        
        let eth_frame = EthernetFrame::new(dest_mac, self.local_mac, frame.to_vec());
        self.send_ethernet_frame(&eth_frame)
    }

    fn receive_frame(&mut self) -> Result<(Vec<u8>, DataLinkAddress)> {
        // Check receive buffer
        let mut buffer = self.rx_buffer.lock().unwrap();
        
        if let Some((frame, source)) = buffer.pop() {
            Ok((frame.payload, source))
        } else {
            // In real implementation, this would block on socket recv
            Err(DataLinkError::InvalidFrame)
        }
    }

    fn link_type(&self) -> DataLinkType {
        DataLinkType::Ethernet
    }

    fn local_address(&self) -> DataLinkAddress {
        DataLinkAddress::Ethernet(self.local_mac)
    }
}

/// Parse MAC address from string
pub fn parse_mac_address(mac_str: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = mac_str.split(':').collect();
    if parts.len() != 6 {
        return Err(DataLinkError::AddressError("Invalid MAC address format".into()));
    }
    
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16)
            .map_err(|_| DataLinkError::AddressError("Invalid MAC address hex".into()))?;
    }
    
    Ok(mac)
}

/// Format MAC address as string
pub fn format_mac_address(mac: &[u8; 6]) -> String {
    format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

/// Validate Ethernet frame
pub fn validate_ethernet_frame(data: &[u8]) -> Result<()> {
    // Check minimum size
    if data.len() < BACNET_ETHERNET_HEADER_SIZE {
        return Err(DataLinkError::InvalidFrame);
    }
    
    // Check maximum size
    if data.len() > MAX_ETHERNET_FRAME_SIZE {
        return Err(DataLinkError::InvalidFrame);
    }
    
    // Check Ethernet type
    let ether_type = u16::from_be_bytes([data[12], data[13]]);
    if ether_type != BACNET_ETHERNET_TYPE {
        return Err(DataLinkError::InvalidFrame);
    }
    
    // Check LLC header
    if data.len() >= 17 && &data[14..17] != BACNET_LLC_HEADER {
        return Err(DataLinkError::InvalidFrame);
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethernet_frame_encode_decode() {
        let dest_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let src_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let npdu = vec![0x01, 0x02, 0x03, 0x04];
        
        let frame = EthernetFrame::new(dest_mac, src_mac, npdu.clone());
        let encoded = frame.encode();
        
        // Check minimum size with padding
        assert!(encoded.len() >= MIN_ETHERNET_FRAME_SIZE);
        
        // Decode and verify
        let decoded = EthernetFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.dest_mac, dest_mac);
        assert_eq!(decoded.src_mac, src_mac);
        assert_eq!(decoded.ether_type, BACNET_ETHERNET_TYPE);
        assert_eq!(decoded.llc_header, BACNET_LLC_HEADER);
        
        // Payload might have padding, so check prefix
        assert!(decoded.payload.starts_with(&npdu));
    }

    #[test]
    fn test_broadcast_frame() {
        let src_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let npdu = vec![0x01, 0x02, 0x03, 0x04];
        
        let frame = EthernetFrame::broadcast(src_mac, npdu);
        assert_eq!(frame.dest_mac, ETHERNET_BROADCAST_MAC);
        assert!(frame.is_broadcast());
        assert!(frame.is_multicast());
    }

    #[test]
    fn test_mac_address_parsing() {
        let mac_str = "00:11:22:33:44:55";
        let mac = parse_mac_address(mac_str).unwrap();
        assert_eq!(mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        
        let formatted = format_mac_address(&mac);
        assert_eq!(formatted, "00:11:22:33:44:55");
        
        // Test invalid format
        assert!(parse_mac_address("invalid").is_err());
        assert!(parse_mac_address("00:11:22:33:44").is_err());
        assert!(parse_mac_address("00:11:22:33:44:GG").is_err());
    }

    #[test]
    fn test_frame_validation() {
        let dest_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let src_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let npdu = vec![0x01, 0x02, 0x03, 0x04];
        
        let frame = EthernetFrame::new(dest_mac, src_mac, npdu);
        let encoded = frame.encode();
        
        assert!(validate_ethernet_frame(&encoded).is_ok());
        
        // Test invalid frames
        assert!(validate_ethernet_frame(&[]).is_err()); // Too short
        assert!(validate_ethernet_frame(&encoded[..16]).is_err()); // Missing LLC
        
        // Test wrong Ethernet type
        let mut bad_frame = encoded.clone();
        bad_frame[12] = 0x08;
        bad_frame[13] = 0x00;
        assert!(validate_ethernet_frame(&bad_frame).is_err());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_ethernet_datalink() {
        let local_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let mut datalink = EthernetDataLink::new("eth0", local_mac).unwrap();
        
        assert_eq!(datalink.link_type(), DataLinkType::Ethernet);
        assert_eq!(datalink.local_address(), DataLinkAddress::Ethernet(local_mac));
        
        // Test sending
        let dest_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let npdu = vec![0x01, 0x02, 0x03, 0x04];
        let result = datalink.send_frame(&npdu, &DataLinkAddress::Ethernet(dest_mac));
        assert!(result.is_ok());
        
        // Test broadcast
        let result = datalink.send_frame(&npdu, &DataLinkAddress::Broadcast);
        assert!(result.is_ok());
    }
}