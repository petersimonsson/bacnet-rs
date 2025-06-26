//! Simple BACnet Who-Is Example
//!
//! This example shows how to send a Who-Is request exactly like bacnet-stack

use bacnet_rs::{
    service::{WhoIsRequest, IAmRequest},
    network::Npdu,
    vendor::get_vendor_name,
};
use std::{
    net::{SocketAddr, UdpSocket},
    time::{Duration, Instant},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Simple BACnet Who-Is Example");
    println!("===========================\n");

    // Create UDP socket
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_broadcast(true)?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    
    println!("Socket bound to: {}", socket.local_addr()?);

    // Create Who-Is request
    let whois = WhoIsRequest::new();  // Broadcast to all devices
    
    // To search for specific device or range:
    // let whois = WhoIsRequest::for_device(12345);  // Specific device
    // let whois = WhoIsRequest::for_range(1000, 2000);  // Range of devices

    // Encode Who-Is service data
    let mut service_data = Vec::new();
    whois.encode(&mut service_data)?;
    
    // Create NPDU (matching bacnet-stack behavior)
    // For global broadcast Who-Is, we need to set destination network
    let npdu = Npdu::global_broadcast();
    
    // Encode NPDU
    let npdu_bytes = npdu.encode();
    
    // Create APDU
    let mut apdu = Vec::new();
    apdu.push(0x10);  // PDU_TYPE_UNCONFIRMED_SERVICE_REQUEST
    apdu.push(0x08);  // SERVICE_UNCONFIRMED_WHO_IS
    apdu.extend_from_slice(&service_data);
    
    // Create complete BACnet/IP message with BVLC header
    let mut message = Vec::new();
    message.push(0x81);  // BVLC Type
    message.push(0x0B);  // Original-Broadcast-NPDU
    
    // Calculate and add BVLC length
    let total_len = 4 + npdu_bytes.len() + apdu.len();
    message.push((total_len >> 8) as u8);
    message.push((total_len & 0xFF) as u8);
    
    // Add NPDU and APDU
    message.extend_from_slice(&npdu_bytes);
    message.extend_from_slice(&apdu);
    
    // Send broadcast
    let broadcast_addr: SocketAddr = "255.255.255.255:47808".parse()?;
    println!("Sending Who-Is broadcast to {}", broadcast_addr);
    println!("Message ({} bytes): {:02X?}\n", message.len(), message);
    
    socket.send_to(&message, broadcast_addr)?;
    
    // Also try local subnet broadcast
    if let Ok(local_broadcast) = "10.161.1.255:47808".parse::<SocketAddr>() {
        socket.send_to(&message, local_broadcast)?;
        println!("Also sent to local broadcast: {}", local_broadcast);
    }
    
    // Listen for I-Am responses
    println!("\nListening for I-Am responses for 5 seconds...\n");
    
    let mut buffer = [0u8; 1500];
    let start = Instant::now();
    let mut device_count = 0;
    
    while start.elapsed() < Duration::from_secs(5) {
        match socket.recv_from(&mut buffer) {
            Ok((len, source)) => {
                println!("Received {} bytes from {}", len, source);
                
                // Try to decode as I-Am
                if let Some((device_id, vendor_name)) = decode_iam(&buffer[..len]) {
                    device_count += 1;
                    println!("  -> Device {} - {}", device_id, vendor_name);
                }
                println!();
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Timeout - normal
            }
            Err(e) => {
                eprintln!("Error receiving: {}", e);
            }
        }
    }
    
    println!("Scan complete. Found {} devices.", device_count);
    
    Ok(())
}

/// Simple I-Am decoder
fn decode_iam(data: &[u8]) -> Option<(u32, String)> {
    // Skip BVLC header (4 bytes)
    if data.len() < 4 || data[0] != 0x81 {
        return None;
    }
    
    // Find APDU start (skip NPDU)
    let mut pos = 4;
    
    // Skip NPDU (simplified - just look for APDU pattern)
    while pos < data.len() - 2 {
        if data[pos] == 0x10 && data[pos + 1] == 0x00 {  // Unconfirmed + I-Am
            pos += 2;
            break;
        }
        pos += 1;
    }
    
    if pos >= data.len() {
        return None;
    }
    
    // Try to decode I-Am
    match IAmRequest::decode(&data[pos..]) {
        Ok(iam) => {
            let vendor_name = get_vendor_name(iam.vendor_identifier as u16)
                .unwrap_or("Unknown")
                .to_string();
            Some((iam.device_identifier.instance, vendor_name))
        }
        Err(_) => None,
    }
}