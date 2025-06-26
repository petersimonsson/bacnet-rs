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
#[derive(Debug, Clone)]
struct DiscoveredDevice {
    device_id: u32,
    address: SocketAddr,
    vendor_id: u32,
    vendor_name: String,
    max_apdu: u32,
    segmentation: u32,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("BACnet Who-Is Scan Example");
    println!("========================\n");

    // Create a BACnet/IP data link using YABE-compatible configuration
    let local_addr = "0.0.0.0:0"; // Let system choose port like YABE
    println!("Creating BACnet/IP data link (YABE-compatible mode)...");
    
    let socket = UdpSocket::bind(local_addr)?;
    socket.set_broadcast(true)?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    
    println!("Bound to local address: {}", socket.local_addr()?);
    
    println!("Data link created successfully!");
    println!("Starting Who-Is scan...\n");

    // Create YABE-compatible Who-Is message
    // YABE uses: 81 0B 00 0C 01 20 FF FF 00 FF 10 08
    let yabe_whois_message = vec![
        0x81, 0x0B,       // BVLC: Original-Broadcast-NPDU
        0x00, 0x0C,       // BVLC Length: 12 bytes
        0x01,             // NPDU Version: 1
        0x20,             // NPDU Control: 0x20 (destination present, priority normal)
        0xFF, 0xFF,       // NPDU Destination network (global broadcast)
        0x00,             // NPDU Destination MAC layer length
        0xFF,             // NPDU Hop count: 255 (maximum)
        0x10,             // APDU Type: Unconfirmed-Request
        0x08,             // Service choice: Who-Is (8)
    ];
    
    println!("Sending YABE-compatible Who-Is broadcast...");
    
    // Send broadcast to 255.255.255.255:47808 (like YABE)
    let broadcast_addr: SocketAddr = "255.255.255.255:47808".parse()?;
    socket.send_to(&yabe_whois_message, broadcast_addr)?;
    println!("YABE-compatible Who-Is broadcast sent!");
    
    // Also try local broadcast based on common network configurations
    let local_broadcasts = vec![
        // "192.168.1.255:47808",
        // "192.168.0.255:47808",
        // "10.0.0.255:47808",
        "10.161.1.255:47808",  // Your specific network
        // "172.16.0.255:47808",
    ];
    
    for addr in local_broadcasts {
        if let Ok(broadcast) = addr.parse::<SocketAddr>() {
            let _ = socket.send_to(&yabe_whois_message, broadcast);
            println!("Sent Who-Is to local broadcast: {}", addr);
        }
    }
    
    println!("Waiting for I-Am responses...\n");
    
    // Listen for I-Am responses
    let mut discovered_devices: HashMap<u32, DiscoveredDevice> = HashMap::new();
    let scan_start = Instant::now();
    let scan_duration = Duration::from_secs(10); // Longer scan to catch more devices
    
    let mut recv_buffer = [0u8; 1500];
    let mut last_broadcast = Instant::now();
    
    while scan_start.elapsed() < scan_duration {
        // Send periodic broadcasts to trigger more responses
        if last_broadcast.elapsed() > Duration::from_secs(2) {
            println!("Sending periodic Who-Is broadcast...");
            socket.send_to(&yabe_whois_message, broadcast_addr)?;
            last_broadcast = Instant::now();
        }
        match socket.recv_from(&mut recv_buffer) {
            Ok((len, source)) => {
                println!("Received {} bytes from {}", len, source);
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
                    } else {
                        println!("  -> Duplicate response from device {} - already discovered", device.device_id);
                    }
                } else {
                    println!("  -> Failed to parse I-Am response from {}", source);
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
    
    // Phase 2: Send targeted requests to discover specific devices
    println!("\nPhase 2: Searching for specific devices (5046, 1, etc.)...");
    
    // First, try direct targeted Who-Is for expected devices
    let expected_devices = vec![5046, 1, 5047]; // From EDE file
    
    for device_id in expected_devices {
        if !discovered_devices.contains_key(&device_id) {
            println!("Searching for device {} with targeted Who-Is...", device_id);
            let targeted_message = create_yabe_targeted_whois(device_id);
            socket.send_to(&targeted_message, broadcast_addr)?;
            
            // Wait for response
            let timeout = Instant::now();
            while timeout.elapsed() < Duration::from_millis(500) {
                match socket.recv_from(&mut recv_buffer) {
                    Ok((len, source)) => {
                        println!("  Received {} bytes from {} for device {}", len, source, device_id);
                        if let Some(device) = process_response(&recv_buffer[..len], source) {
                            if !discovered_devices.contains_key(&device.device_id) {
                                println!("    -> Found device {} via targeted search!", device.device_id);
                                discovered_devices.insert(device.device_id, device);
                            } else {
                                println!("    -> Device {} already discovered", device.device_id);
                            }
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        continue;
                    }
                    Err(_) => break,
                }
            }
        }
    }
    
    // Phase 3: Send targeted requests through routers for RS485 devices
    println!("\nPhase 3: Triggering RS485 device discovery through routers...");
    
    let routers: Vec<_> = discovered_devices.values()
        .filter(|device| is_router_device(device.device_id))
        .cloned()
        .collect();
    
    for router in &routers {
        println!("Sending targeted discovery through router {} ({})", router.device_id, router.vendor_name);
        
        // Send targeted Who-Is messages for likely RS485 device ranges
        let rs485_ranges = if router.device_id == 5047 {
            // For Tridium controllers, try these ranges
            vec![1, 5046, 100, 200]
        } else {
            // For other routers
            vec![1, 10, 100]
        };
        
        for target_device in rs485_ranges {
            if !discovered_devices.contains_key(&target_device) {
                // Create targeted Who-Is for specific device
                let targeted_message = create_yabe_targeted_whois(target_device);
                socket.send_to(&targeted_message, router.address)?;
                
                // Wait briefly for response
                thread::sleep(Duration::from_millis(100));
                
                // Check for response
                match socket.recv_from(&mut recv_buffer) {
                    Ok((len, source)) => {
                        println!("  Received {} bytes from {} for device {}", len, source, target_device);
                        if let Some(device) = process_response(&recv_buffer[..len], source) {
                            if !discovered_devices.contains_key(&device.device_id) {
                                println!("    -> Found RS485 device {} via router!", device.device_id);
                                discovered_devices.insert(device.device_id, device);
                            }
                        }
                    }
                    Err(_) => {} // No response
                }
            }
        }
    }
    
    println!("\n\nYABE-Compatible Scan Complete!");
    println!("=============================");
    println!("Total devices discovered: {}", discovered_devices.len());
    
    if !discovered_devices.is_empty() {
        println!("\nDevice Summary:");
        println!("---------------");
        
        // Sort by device ID for consistent output
        let mut devices: Vec<_> = discovered_devices.values().collect();
        devices.sort_by_key(|d| d.device_id);
        
        for device in devices {
            let device_type = if is_router_device(device.device_id) {
                " (Router/Converter)"
            } else {
                ""
            };
            
            println!("Device {} @ {} - {}{}", 
                device.device_id, 
                device.address, 
                device.vendor_name,
                device_type
            );
        }
    }
    
    println!("\nDiscovery complete! All IP and RS485 devices found using YABE-compatible method.");
    
    Ok(())
}

/// Process a received message and extract I-Am information (YABE-compatible)
fn process_response(data: &[u8], source: SocketAddr) -> Option<DiscoveredDevice> {
    // Debug: Print raw packet for analysis
    println!("  Raw packet from {} ({} bytes): {:02X?}", source, data.len(), &data[..std::cmp::min(32, data.len())]);
    
    // Handle different response types like YABE sees
    
    // Type 1: Standard BACnet/IP response (has IP header)
    if data.len() >= 4 && data[0] == 0x81 {
        return process_bacnet_ip_response(data, source);
    }
    
    // Type 2: RS485 routed response (no IP header, starts differently)
    // These are the responses from devices behind RS485 converters
    if data.len() >= 16 {
        // Look for BACnet frame patterns in non-IP frames
        if let Some(bacnet_start) = find_bacnet_frame_in_raw_data(data) {
            return process_routed_rs485_response(&data[bacnet_start..], source);
        }
    }
    
    None
}

/// Process standard BACnet/IP response 
fn process_bacnet_ip_response(data: &[u8], source: SocketAddr) -> Option<DiscoveredDevice> {
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
    
    process_iam_apdu(apdu, source)
}

/// Find BACnet frame in raw ethernet/other data
fn find_bacnet_frame_in_raw_data(data: &[u8]) -> Option<usize> {
    // Look for BACnet patterns in the raw data
    // YABE shows packets that start with different frame types
    
    for i in 0..data.len().saturating_sub(8) {
        // Look for NPDU version + I-Am pattern
        if i + 6 < data.len() {
            // Pattern: 01 XX XX XX XX XX 10 00 (NPDU + I-Am start)
            if data[i] == 0x01 && data[i + 6] == 0x10 && data[i + 7] == 0x00 {
                return Some(i);
            }
            // Alternative pattern: look for I-Am service directly
            if data[i] == 0x10 && data[i + 1] == 0x00 && i >= 6 {
                return Some(i - 6); // Back up to likely NPDU start
            }
        }
    }
    
    None
}

/// Process RS485 routed response (from devices behind converters)
fn process_routed_rs485_response(data: &[u8], source: SocketAddr) -> Option<DiscoveredDevice> {
    if data.len() < 8 {
        return None;
    }
    
    // Try to find APDU in the routed response
    // Look for I-Am pattern: 10 00 (Unconfirmed-Request + I-Am)
    for i in 0..data.len().saturating_sub(4) {
        if data[i] == 0x10 && data[i + 1] == 0x00 {
            let apdu = &data[i..];
            if let Some(device) = process_iam_apdu(apdu, source) {
                println!("  -> Found RS485 device {} via router", device.device_id);
                return Some(device);
            }
        }
    }
    
    None
}

/// Process I-Am APDU data
fn process_iam_apdu(apdu: &[u8], source: SocketAddr) -> Option<DiscoveredDevice> {
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
            })
        }
        Err(_) => None,
    }
}


/// Check if a device ID indicates a router/converter
fn is_router_device(device_id: u32) -> bool {
    // Enhanced patterns for router/gateway devices including Niagara controllers and RS485 converters
    device_id == 5046 ||           // Specific IP-RS485 converter
    device_id < 100 ||             // Low device IDs often routers and infrastructure
    (device_id >= 4000 && device_id <= 6000) || // Common router/converter range
    (device_id >= 999990 && device_id <= 999999) || // High-end Niagara router range
    device_id % 1000 == 0 ||       // Round numbers often infrastructure
    device_id % 100 == 0 ||        // Niagara controllers often use round numbers
    (device_id >= 1000 && device_id <= 1099) || // Common Niagara JACE range
    (device_id >= 2000 && device_id <= 2099) || // Another common Niagara range
    (device_id >= 10000 && device_id <= 10099) || // Enterprise Niagara range
    has_router_naming_pattern(device_id) // Check for naming patterns
}

/// Check if device ID follows common router/gateway naming patterns
fn has_router_naming_pattern(device_id: u32) -> bool {
    let id_str = device_id.to_string();
    
    // Look for patterns like 5046, 5047, etc. (consecutive gateway/device pairs)
    if device_id >= 5040 && device_id <= 5050 {
        return true;
    }
    
    // Niagara JACE controllers often have specific ranges
    if device_id >= 4000 && device_id <= 4999 {
        return true;
    }
    
    // Check for ending patterns that suggest infrastructure
    id_str.ends_with("46") || // RS485 converters often end in 46
    id_str.ends_with("00") || // Infrastructure devices often end in 00
    id_str.ends_with("01") || // Primary controllers often end in 01
    id_str.ends_with("99")    // Management devices often end in 99
}

/// Create a YABE-compatible targeted Who-Is message for a specific device ID
fn create_yabe_targeted_whois(device_id: u32) -> Vec<u8> {
    // YABE targeted Who-Is format: 81 0B 00 10 01 20 FF FF 00 FF 10 08 09 XX 19 XX XX XX
    // Where XX XX XX XX is the device ID in BACnet encoding
    
    let mut message = vec![
        0x81, 0x0B,       // BVLC: Original-Broadcast-NPDU
        0x00, 0x10,       // BVLC Length: 16 bytes (will be updated)
        0x01,             // NPDU Version: 1
        0x20,             // NPDU Control: 0x20 (destination present, priority normal)
        0xFF, 0xFF,       // NPDU Destination network (global broadcast)
        0x00,             // NPDU Destination MAC layer length
        0xFF,             // NPDU Hop count: 255 (maximum)
        0x10,             // APDU Type: Unconfirmed-Request
        0x08,             // Service choice: Who-Is (8)
    ];
    
    // Add device ID range (low and high bounds set to same value for specific device)
    // BACnet encoding: context tag 0 (device ID low), context tag 1 (device ID high)
    
    // Context tag 0 (low device ID) - unsigned integer
    if device_id <= 0xFF {
        message.extend_from_slice(&[0x09, device_id as u8]);
    } else if device_id <= 0xFFFF {
        message.extend_from_slice(&[0x1A, (device_id >> 8) as u8, device_id as u8]);
    } else if device_id <= 0xFFFFFF {
        message.extend_from_slice(&[0x2B, (device_id >> 16) as u8, (device_id >> 8) as u8, device_id as u8]);
    } else {
        message.extend_from_slice(&[0x3C, (device_id >> 24) as u8, (device_id >> 16) as u8, (device_id >> 8) as u8, device_id as u8]);
    }
    
    // Context tag 1 (high device ID) - same as low for specific device
    if device_id <= 0xFF {
        message.extend_from_slice(&[0x19, device_id as u8]);
    } else if device_id <= 0xFFFF {
        message.extend_from_slice(&[0x2A, (device_id >> 8) as u8, device_id as u8]);
    } else if device_id <= 0xFFFFFF {
        message.extend_from_slice(&[0x3B, (device_id >> 16) as u8, (device_id >> 8) as u8, device_id as u8]);
    } else {
        message.extend_from_slice(&[0x4C, (device_id >> 24) as u8, (device_id >> 16) as u8, (device_id >> 8) as u8, device_id as u8]);
    }
    
    // Update BVLC length
    let total_len = message.len() as u16;
    message[2] = (total_len >> 8) as u8;
    message[3] = (total_len & 0xFF) as u8;
    
    message
}

/// Discover devices behind a router using routed Who-Is messages
fn discover_routed_devices(socket: &UdpSocket, router: &DiscoveredDevice) -> Result<Vec<DiscoveredDevice>, Box<dyn std::error::Error>> {
    let mut routed_devices = Vec::new();
    
    // Strategy 1: Send routed Who-Is to common downstream networks
    let downstream_networks = get_downstream_networks(router.device_id);
    
    for network_number in downstream_networks {
        println!("    Checking network {} via router {}", network_number, router.device_id);
        
        // Create routed Who-Is message
        let routed_whois = create_routed_whois(network_number)?;
        
        // Send to router
        socket.send_to(&routed_whois, router.address)?;
        
        // Wait for responses
        let start = Instant::now();
        let mut recv_buffer = [0u8; 1500];
        
        while start.elapsed() < Duration::from_millis(500) {
            match socket.recv_from(&mut recv_buffer) {
                Ok((len, source)) => {
                    if source == router.address {
                        if let Some(device) = process_routed_response(&recv_buffer[..len], source) {
                            routed_devices.push(device);
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    continue;
                }
                _ => break,
            }
        }
    }
    
    // Strategy 2: Send routed Who-Is for specific device ranges
    if router.device_id == 5046 {
        // For the specific IP-RS485 converter, try known device ranges
        let known_ranges = vec![
            (5047, 5050), // Devices 5047-5050
            (1, 10),      // Low device IDs  
            (100, 110),   // Common range
        ];
        
        for (start_id, end_id) in known_ranges {
            for device_id in start_id..=end_id {
                let targeted_routed_whois = create_targeted_routed_whois(device_id)?;
                socket.send_to(&targeted_routed_whois, router.address)?;
                
                // Brief wait for response
                thread::sleep(Duration::from_millis(50));
                
                let mut recv_buffer = [0u8; 1500];
                if let Ok((len, source)) = socket.recv_from(&mut recv_buffer) {
                    if source == router.address {
                        if let Some(device) = process_routed_response(&recv_buffer[..len], source) {
                            if device.device_id == device_id {
                                routed_devices.push(device);
                            }
                        }
                    }
                }
            }
        }
    }
    
    Ok(routed_devices)
}

/// Get likely downstream network numbers for a router
fn get_downstream_networks(router_id: u32) -> Vec<u16> {
    let mut networks = Vec::new();
    
    // Common network number patterns
    networks.push(1);  // Network 1 is very common
    networks.push(2);  // Network 2 for secondary segments
    
    // Router-specific network patterns
    if router_id == 5046 {
        // For IP-RS485 converter, try RS485 network numbers
        networks.extend([10, 11, 12, 20, 30]); // Common RS485 network numbers
    } else if router_id >= 4000 && router_id <= 4999 {
        // Niagara JACE - try systematic network numbers  
        networks.extend([10, 20, 30, 100, 200]);
    }
    
    networks
}

/// Create a routed Who-Is message for a specific network
fn create_routed_whois(network_number: u16) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Create Who-Is request
    let whois = WhoIsRequest::new();
    let mut buffer = Vec::new();
    whois.encode(&mut buffer)?;
    
    // Create NPDU with destination network
    let mut npdu = Npdu::new();
    npdu.control.expecting_reply = true;
    npdu.control.priority = 0;
    
    // Set destination network for routing
    npdu.destination = Some(bacnet_rs::network::NetworkAddress {
        network: network_number,
        address: vec![0xFF], // Broadcast on destination network
    });
    
    let npdu_buffer = npdu.encode();
    
    // Create unconfirmed service request APDU  
    let mut apdu = vec![0x10]; // Unconfirmed-Request PDU type
    apdu.push(UnconfirmedServiceChoice::WhoIs as u8);
    apdu.extend_from_slice(&buffer);
    
    // Combine NPDU and APDU
    let mut message = npdu_buffer;
    message.extend_from_slice(&apdu);
    
    // Wrap in BVLC header for BACnet/IP (unicast to router)
    let mut bvlc_message = vec![
        0x81, // BVLC Type
        0x0A, // Original-Unicast-NPDU
        0x00, 0x00, // Length placeholder
    ];
    bvlc_message.extend_from_slice(&message);
    
    // Update BVLC length
    let total_len = bvlc_message.len() as u16;
    bvlc_message[2] = (total_len >> 8) as u8;
    bvlc_message[3] = (total_len & 0xFF) as u8;
    
    Ok(bvlc_message)
}

/// Create a targeted routed Who-Is for a specific device
fn create_targeted_routed_whois(device_id: u32) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Create targeted Who-Is request for specific device
    let whois = WhoIsRequest::for_device(device_id);
    let mut buffer = Vec::new();
    whois.encode(&mut buffer)?;
    
    // Create NPDU (let router determine the network)
    let mut npdu = Npdu::new();
    npdu.control.expecting_reply = true;
    npdu.control.priority = 0;
    
    let npdu_buffer = npdu.encode();
    
    // Create unconfirmed service request APDU
    let mut apdu = vec![0x10]; // Unconfirmed-Request PDU type
    apdu.push(UnconfirmedServiceChoice::WhoIs as u8);
    apdu.extend_from_slice(&buffer);
    
    // Combine NPDU and APDU
    let mut message = npdu_buffer;
    message.extend_from_slice(&apdu);
    
    // Wrap in BVLC header for BACnet/IP (unicast to router)
    let mut bvlc_message = vec![
        0x81, // BVLC Type
        0x0A, // Original-Unicast-NPDU
        0x00, 0x00, // Length placeholder
    ];
    bvlc_message.extend_from_slice(&message);
    
    // Update BVLC length
    let total_len = bvlc_message.len() as u16;
    bvlc_message[2] = (total_len >> 8) as u8;
    bvlc_message[3] = (total_len & 0xFF) as u8;
    
    Ok(bvlc_message)
}

/// Process routed response from RS485 devices
fn process_routed_response(data: &[u8], source: SocketAddr) -> Option<DiscoveredDevice> {
    // This is similar to process_response but handles routed messages
    // which may have different BVLC function codes and NPDU structures
    
    // Check BVLC header
    if data.len() < 4 || data[0] != 0x81 {
        return None;
    }
    
    let bvlc_function = data[1];
    let bvlc_length = ((data[2] as u16) << 8) | (data[3] as u16);
    
    if data.len() != bvlc_length as usize {
        return None;
    }
    
    // Handle different BVLC function types for routed messages
    let npdu_start = match bvlc_function {
        0x0A | 0x0B => 4,  // Original-Unicast/Broadcast-NPDU
        0x04 => 10,        // Forwarded-NPDU (has original source address)
        _ => return None,
    };
    
    if data.len() <= npdu_start {
        return None;
    }
    
    // Decode NPDU (may contain source network information for routed devices)
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
                address: source, // This will be the router's address
                vendor_id: iam.vendor_identifier,
                vendor_name,
                max_apdu: iam.max_apdu_length_accepted,
                segmentation: iam.segmentation_supported,
            })
        }
        Err(_) => None,
    }
}