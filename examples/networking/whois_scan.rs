//! BACnet Who-Is Scan Example
//!
//! This example demonstrates how to perform a Who-Is scan to discover
//! BACnet devices on the network.

use bacnet_rs::{
    service::{WhoIsRequest, IAmRequest, UnconfirmedServiceChoice},
    network::Npdu,
    vendor::get_vendor_name,
};
use std::{
    net::{SocketAddr, UdpSocket},
    time::{Duration, Instant},
    collections::HashMap,
    thread,
};

/// Structure to hold discovered device information
#[derive(Debug)]
struct DiscoveredDevice {
    device_id: u32,
    address: SocketAddr,
    vendor_id: u32,
    vendor_name: String,
    max_apdu: u32,
    segmentation: u32,
    discovered_at: Instant,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("BACnet Who-Is Scan Example");
    println!("========================\n");

    // Create a BACnet/IP data link on the default port
    let local_addr = "0.0.0.0:47808";
    println!("Creating BACnet/IP data link on {}...", local_addr);
    
    let socket = UdpSocket::bind(local_addr)?;
    socket.set_broadcast(true)?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    
    println!("Data link created successfully!");
    println!("Starting Who-Is scan...\n");

    // Send Who-Is broadcast
    let whois = WhoIsRequest::new();
    let mut buffer = Vec::new();
    whois.encode(&mut buffer)?;
    
    // Create NPDU for broadcast
    let mut npdu = Npdu::new();
    npdu.control.expecting_reply = true;
    npdu.control.priority = 0; // Normal priority
    
    let npdu_buffer = npdu.encode();
    
    // Create unconfirmed service request APDU
    let mut apdu = vec![0x10]; // Unconfirmed-Request PDU type
    apdu.push(UnconfirmedServiceChoice::WhoIs as u8);
    apdu.extend_from_slice(&buffer);
    
    // Combine NPDU and APDU
    let mut message = npdu_buffer.clone();
    message.extend_from_slice(&apdu);
    
    // Wrap in BVLC header for BACnet/IP
    let mut bvlc_message = vec![
        0x81, // BVLC Type
        0x0B, // Original-Broadcast-NPDU
        0x00, 0x00, // Length placeholder
    ];
    bvlc_message.extend_from_slice(&message);
    
    // Update BVLC length
    let total_len = bvlc_message.len() as u16;
    bvlc_message[2] = (total_len >> 8) as u8;
    bvlc_message[3] = (total_len & 0xFF) as u8;
    
    // Send broadcast to 255.255.255.255:47808
    let broadcast_addr: SocketAddr = "255.255.255.255:47808".parse()?;
    socket.send_to(&bvlc_message, broadcast_addr)?;
    println!("Who-Is broadcast sent!");
    
    // Also try local broadcast based on common network configurations
    let local_broadcasts = vec![
        "192.168.1.255:47808",
        "192.168.0.255:47808",
        "10.0.0.255:47808",
        "172.16.0.255:47808",
    ];
    
    for addr in local_broadcasts {
        if let Ok(broadcast) = addr.parse::<SocketAddr>() {
            let _ = socket.send_to(&bvlc_message, broadcast);
        }
    }
    
    println!("Waiting for I-Am responses...\n");
    
    // Listen for I-Am responses
    let mut discovered_devices: HashMap<u32, DiscoveredDevice> = HashMap::new();
    let scan_start = Instant::now();
    let scan_duration = Duration::from_secs(5);
    
    let mut recv_buffer = [0u8; 1500];
    
    while scan_start.elapsed() < scan_duration {
        match socket.recv_from(&mut recv_buffer) {
            Ok((len, source)) => {
                // Process received message
                if let Some(device) = process_response(&recv_buffer[..len], source) {
                    if !discovered_devices.contains_key(&device.device_id) {
                        println!("Discovered device:");
                        println!("  Device ID: {}", device.device_id);
                        println!("  Address: {}", device.address);
                        println!("  Vendor: {} (ID: {})", device.vendor_name, device.vendor_id);
                        println!("  Max APDU: {}", device.max_apdu);
                        println!("  Segmentation: {}", 
                            match device.segmentation {
                                0 => "Both",
                                1 => "Transmit",
                                2 => "Receive",
                                3 => "None",
                                _ => "Unknown",
                            }
                        );
                        println!();
                        
                        discovered_devices.insert(device.device_id, device);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Timeout - continue scanning
            }
            Err(e) => {
                eprintln!("Error receiving: {}", e);
            }
        }
        
        // Show progress
        let elapsed = scan_start.elapsed().as_secs();
        if elapsed > 0 && elapsed % 1 == 0 {
            print!("\rScanning... {} seconds elapsed", elapsed);
            use std::io::{self, Write};
            io::stdout().flush()?;
        }
    }
    
    println!("\n\nScan complete!");
    println!("================");
    println!("Total devices discovered: {}", discovered_devices.len());
    
    if !discovered_devices.is_empty() {
        println!("\nDevice Summary:");
        println!("---------------");
        
        // Sort by device ID for consistent output
        let mut devices: Vec<_> = discovered_devices.values().collect();
        devices.sort_by_key(|d| d.device_id);
        
        for device in devices {
            println!("Device {} @ {} - {}", 
                device.device_id, 
                device.address, 
                device.vendor_name
            );
        }
    }
    
    // Optionally, send targeted Who-Is to specific devices
    if discovered_devices.len() > 0 {
        println!("\nSending targeted Who-Is to first discovered device...");
        
        if let Some(device) = discovered_devices.values().next() {
            let targeted_whois = WhoIsRequest::for_device(device.device_id);
            let mut buffer = Vec::new();
            targeted_whois.encode(&mut buffer)?;
            
            // Prepare targeted message (similar to above but unicast)
            let mut targeted_apdu = vec![0x10]; // Unconfirmed-Request PDU type
            targeted_apdu.push(UnconfirmedServiceChoice::WhoIs as u8);
            targeted_apdu.extend_from_slice(&buffer);
            
            let mut targeted_message = npdu_buffer.clone();
            targeted_message.extend_from_slice(&targeted_apdu);
            
            // BVLC for unicast
            let mut targeted_bvlc = vec![
                0x81, // BVLC Type
                0x0A, // Original-Unicast-NPDU
                0x00, 0x00, // Length placeholder
            ];
            targeted_bvlc.extend_from_slice(&targeted_message);
            
            let total_len = targeted_bvlc.len() as u16;
            targeted_bvlc[2] = (total_len >> 8) as u8;
            targeted_bvlc[3] = (total_len & 0xFF) as u8;
            
            socket.send_to(&targeted_bvlc, device.address)?;
            println!("Targeted Who-Is sent to device {}", device.device_id);
            
            // Wait briefly for response
            thread::sleep(Duration::from_millis(500));
            
            match socket.recv_from(&mut recv_buffer) {
                Ok((len, source)) => {
                    if process_response(&recv_buffer[..len], source).is_some() {
                        println!("Received response from targeted Who-Is!");
                    }
                }
                _ => println!("No response to targeted Who-Is"),
            }
        }
    }
    
    Ok(())
}

/// Process a received message and extract I-Am information
fn process_response(data: &[u8], source: SocketAddr) -> Option<DiscoveredDevice> {
    // Check BVLC header
    if data.len() < 4 || data[0] != 0x81 {
        return None;
    }
    
    let bvlc_function = data[1];
    let bvlc_length = ((data[2] as u16) << 8) | (data[3] as u16);
    
    if data.len() != bvlc_length as usize {
        return None;
    }
    
    // Skip BVLC header to get to NPDU
    let npdu_start = match bvlc_function {
        0x0A | 0x0B => 4, // Original-Unicast/Broadcast-NPDU
        0x04 => 10, // Forwarded-NPDU (has original source address)
        _ => return None,
    };
    
    if data.len() <= npdu_start {
        return None;
    }
    
    // Decode NPDU
    let (_npdu, npdu_len) = match Npdu::decode(&data[npdu_start..]) {
        Ok(result) => result,
        Err(_) => return None,
    };
    
    // Skip to APDU
    let apdu_start = npdu_start + npdu_len;
    if data.len() <= apdu_start {
        return None;
    }
    
    let apdu = &data[apdu_start..];
    
    // Check if this is an unconfirmed I-Am service
    if apdu.len() < 2 || apdu[0] != 0x10 {
        return None;
    }
    
    let service_choice = apdu[1];
    if service_choice != UnconfirmedServiceChoice::IAm as u8 {
        return None;
    }
    
    // Decode I-Am request
    if apdu.len() <= 2 {
        return None;
    }
    
    match IAmRequest::decode(&apdu[2..]) {
        Ok(iam) => {
            let vendor_name = get_vendor_name(iam.vendor_identifier as u16)
                .unwrap_or("Unknown Vendor")
                .to_string();
            
            Some(DiscoveredDevice {
                device_id: iam.device_identifier.instance,
                address: source,
                vendor_id: iam.vendor_identifier,
                vendor_name,
                max_apdu: iam.max_apdu_length_accepted,
                segmentation: iam.segmentation_supported,
                discovered_at: Instant::now(),
            })
        }
        Err(_) => None,
    }
}