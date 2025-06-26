//! BACnet Who-Is Scan Example (Proper Implementation)
//!
//! This example demonstrates the correct way to perform a Who-Is scan
//! using the service layer, matching the bacnet-stack implementation.

use bacnet_rs::{
    service::{WhoIsRequest, IAmRequest, UnconfirmedServiceChoice},
    network::{Npdu, NpduControl, NetworkAddress},
    app::{ApduType, UnconfirmedRequestPdu},
    datalink::bip::BacnetIpDataLink,
    vendor::get_vendor_name,
};
use std::{
    net::{SocketAddr, IpAddr, Ipv4Addr},
    time::{Duration, Instant},
    collections::HashMap,
};
use tokio::time::timeout;

/// Structure to hold discovered device information
#[derive(Debug, Clone)]
struct DiscoveredDevice {
    device_id: u32,
    address: SocketAddr,
    vendor_id: u32,
    vendor_name: String,
    max_apdu: u32,
    segmentation: u32,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("BACnet Who-Is Scan Example (Proper Implementation)");
    println!("=================================================\n");

    // Create BACnet/IP data link
    let local_addr: SocketAddr = "0.0.0.0:0".parse()?;
    let broadcast_addr: SocketAddr = "255.255.255.255:47808".parse()?;
    
    println!("Creating BACnet/IP data link...");
    let mut datalink = BacnetIpDataLink::new(local_addr, broadcast_addr).await?;
    
    println!("Data link created on {}", datalink.local_addr()?);
    println!("Starting Who-Is scan...\n");

    // Create Who-Is request (broadcast to all devices)
    let whois = WhoIsRequest::new();
    
    // Encode the Who-Is service
    let mut service_data = Vec::new();
    whois.encode(&mut service_data)?;
    
    // Create APDU (Application Protocol Data Unit)
    let apdu = UnconfirmedRequestPdu {
        service_choice: UnconfirmedServiceChoice::WhoIs,
        service_data,
    };
    
    // Encode APDU
    let mut apdu_buffer = Vec::new();
    apdu_buffer.push(ApduType::UnconfirmedRequest as u8);
    apdu_buffer.push(UnconfirmedServiceChoice::WhoIs as u8);
    apdu_buffer.extend_from_slice(&apdu.service_data);
    
    // Create NPDU (Network Protocol Data Unit)
    let mut npdu = Npdu::new();
    npdu.control.expecting_reply = true;  // Match bacnet-stack behavior
    npdu.control.priority = 0;  // Normal priority
    npdu.hop_count = 255;  // Maximum hop count
    
    // For global broadcast, set destination network
    npdu.destination = Some(NetworkAddress {
        network: 0xFFFF,  // Global broadcast
        address: vec![],  // Empty MAC for broadcast
    });
    
    // Encode NPDU
    let npdu_buffer = npdu.encode();
    
    // Combine NPDU and APDU
    let mut message = npdu_buffer;
    message.extend_from_slice(&apdu_buffer);
    
    // Send the Who-Is broadcast
    println!("Sending Who-Is broadcast (matching bacnet-stack)...");
    datalink.send_broadcast(&message).await?;
    
    // Also send to specific local subnets if known
    let local_broadcasts = vec![
        "10.161.1.255:47808",
        "192.168.1.255:47808",
        "192.168.0.255:47808",
    ];
    
    for addr_str in local_broadcasts {
        if let Ok(addr) = addr_str.parse::<SocketAddr>() {
            println!("Sending Who-Is to local broadcast: {}", addr);
            datalink.send_to(&message, addr).await?;
        }
    }
    
    println!("\nListening for I-Am responses...\n");
    
    // Listen for responses
    let mut discovered_devices: HashMap<u32, DiscoveredDevice> = HashMap::new();
    let scan_duration = Duration::from_secs(5);
    let start_time = Instant::now();
    
    // Send periodic Who-Is broadcasts
    let mut last_broadcast = Instant::now();
    
    while start_time.elapsed() < scan_duration {
        // Re-broadcast every 2 seconds
        if last_broadcast.elapsed() > Duration::from_secs(2) {
            println!("Sending periodic Who-Is broadcast...");
            datalink.send_broadcast(&message).await?;
            last_broadcast = Instant::now();
        }
        
        // Try to receive a response with timeout
        match timeout(Duration::from_millis(100), datalink.receive()).await {
            Ok(Ok((data, source))) => {
                // Process the received message
                if let Some(device) = process_response(&data, source) {
                    if !discovered_devices.contains_key(&device.device_id) {
                        println!("Discovered new device:");
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
            Ok(Err(_)) => {
                // Error receiving - ignore
            }
            Err(_) => {
                // Timeout - normal, continue
            }
        }
        
        // Show progress
        print!("\rScanning... {} seconds elapsed, {} devices found", 
            start_time.elapsed().as_secs(),
            discovered_devices.len()
        );
        use std::io::{self, Write};
        io::stdout().flush()?;
    }
    
    println!("\n\nScan Complete!");
    println!("==============");
    println!("Total devices discovered: {}", discovered_devices.len());
    
    if !discovered_devices.is_empty() {
        println!("\nDevice Summary:");
        println!("---------------");
        
        // Sort by device ID
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
    
    Ok(())
}

/// Process a received message and extract I-Am information
fn process_response(data: &[u8], source: SocketAddr) -> Option<DiscoveredDevice> {
    // Skip BVLC header (4 bytes for BACnet/IP)
    if data.len() < 4 {
        return None;
    }
    
    let bvlc_type = data[0];
    let bvlc_function = data[1];
    let bvlc_length = ((data[2] as u16) << 8) | (data[3] as u16);
    
    // Check BVLC header
    if bvlc_type != 0x81 || data.len() != bvlc_length as usize {
        return None;
    }
    
    // Skip BVLC header
    let npdu_start = 4;
    if data.len() <= npdu_start {
        return None;
    }
    
    // Decode NPDU
    let (npdu, npdu_len) = match Npdu::decode(&data[npdu_start..]) {
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
    if apdu.len() < 2 || apdu[0] != 0x10 {  // Unconfirmed Request PDU
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
            })
        }
        Err(_) => None,
    }
}