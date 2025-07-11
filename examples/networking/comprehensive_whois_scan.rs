//! Comprehensive BACnet Who-Is Scan
//!
//! This example performs a complete BACnet network scan to discover all devices
//! and their objects, including devices behind routers on different networks.

use bacnet_rs::{
    service::{WhoIsRequest, IAmRequest, ReadPropertyResponse},
    network::{Npdu, NetworkAddress},
    datalink::bip::{BvlcHeader, BvlcFunction},
    vendor::get_vendor_name,
    object::{ObjectType, PropertyIdentifier},
};
use std::{
    net::{SocketAddr, UdpSocket},
    time::{Duration, Instant},
    collections::HashMap,
    io::ErrorKind,
    sync::atomic::{AtomicU8, Ordering},
};

const BACNET_PORT: u16 = 0xBAC0; // 47808

#[derive(Debug, Clone)]
struct BACnetDevice {
    device_id: u32,
    network_number: u16,
    mac_address: Vec<u8>,
    socket_addr: SocketAddr,
    vendor_id: u32,
    vendor_name: String,
    max_apdu: u32,
    segmentation: u32,
    // Device properties
    object_name: Option<String>,
    model_name: Option<String>,
    firmware_revision: Option<String>,
    // Objects in this device
    objects: Vec<BACnetObject>,
}

#[derive(Debug, Clone)]
struct BACnetObject {
    object_type: ObjectType,
    instance: u32,
    name: Option<String>,
    present_value: Option<String>,
    description: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("===========================================");
    println!("  BACnet Comprehensive Network Scan");
    println!("===========================================\n");

    // Create UDP socket
    let socket = match UdpSocket::bind(format!("0.0.0.0:{}", BACNET_PORT)) {
        Ok(s) => s,
        Err(_) => {
            println!("Standard port busy, using alternative port...");
            UdpSocket::bind("0.0.0.0:0")?
        }
    };
    
    socket.set_broadcast(true)?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    
    println!("📡 Listening on {}", socket.local_addr()?);
    println!("🔍 Starting network discovery...\n");

    // Step 1: Discover routers
    println!("Step 1: Router Discovery");
    println!("========================");
    let routers = discover_routers(&socket)?;
    
    if routers.is_empty() {
        println!("ℹ️  No routers found on the network");
    } else {
        println!("🔗 Found {} router(s):", routers.len());
        for (network, addr) in &routers {
            println!("   Network {:>4}: Router at {}", network, addr);
        }
    }

    // Step 2: Discover all devices
    println!("\nStep 2: Device Discovery");
    println!("========================");
    let mut devices = HashMap::new();
    
    // Global broadcast first
    println!("🌐 Performing global broadcast...");
    discover_devices_global(&socket, &mut devices)?;
    
    // Then directed discovery for each known network
    for (network, _) in &routers {
        println!("🎯 Scanning network {}...", network);
        discover_devices_on_network(&socket, *network, &mut devices)?;
    }

    if devices.is_empty() {
        println!("❌ No BACnet devices found on the network");
        return Ok(());
    }

    println!("\n📱 Discovered {} device(s):", devices.len());
    for device in devices.values() {
        let network_info = if device.network_number == 0 {
            "Local".to_string()
        } else {
            format!("Network {}", device.network_number)
        };
        println!("   Device {:>3}: {} ({})", device.device_id, device.vendor_name, network_info);
    }

    // Step 3: Read device properties and objects
    println!("\nStep 3: Detailed Device Analysis");
    println!("=================================");
    
    for device in devices.values_mut() {
        analyze_device(&socket, device)?;
    }

    // Step 4: Display comprehensive summary
    println!("\n");
    println!("===========================================");
    println!("           NETWORK SCAN SUMMARY");
    println!("===========================================");
    
    display_comprehensive_summary(&devices);

    Ok(())
}

fn discover_routers(socket: &UdpSocket) -> Result<HashMap<u16, SocketAddr>, Box<dyn std::error::Error>> {
    let mut routers = HashMap::new();
    
    // Create Who-Is-Router-To-Network NPDU
    let mut npdu = Npdu::new();
    npdu.control.network_message = true;
    
    let network_msg = vec![0x01]; // Who-Is-Router-To-Network
    let npdu_bytes = encode_npdu_with_data(&npdu, &network_msg);
    
    let header = BvlcHeader::new(BvlcFunction::OriginalBroadcastNpdu, 4 + npdu_bytes.len() as u16);
    let mut frame = header.encode();
    frame.extend_from_slice(&npdu_bytes);
    
    // Send broadcast
    let _ = socket.send_to(&frame, "255.255.255.255:47808");
    
    // Listen for responses
    let start = Instant::now();
    let mut buffer = [0u8; 1500];
    
    while start.elapsed() < Duration::from_secs(3) {
        match socket.recv_from(&mut buffer) {
            Ok((len, src_addr)) => {
                if len > 4 {
                    let npdu_data = &buffer[4..len];
                    if let Ok((npdu, offset)) = Npdu::decode(npdu_data) {
                        if npdu.is_network_message() && npdu_data.len() > offset && npdu_data[offset] == 0x02 {
                            let mut idx = offset + 1;
                            while idx + 1 < npdu_data.len() {
                                let network = u16::from_be_bytes([npdu_data[idx], npdu_data[idx + 1]]);
                                routers.insert(network, src_addr);
                                idx += 2;
                            }
                        }
                    }
                }
            }
            Err(_) => {}
        }
    }
    
    Ok(routers)
}

fn discover_devices_global(socket: &UdpSocket, devices: &mut HashMap<u32, BACnetDevice>) -> Result<(), Box<dyn std::error::Error>> {
    let who_is = WhoIsRequest::new();
    let mut who_is_data = Vec::new();
    who_is.encode(&mut who_is_data)?;
    
    let mut apdu = vec![0x10, 0x08]; // Unconfirmed-Request, Who-Is
    apdu.extend_from_slice(&who_is_data);
    
    let npdu = Npdu::global_broadcast();
    let npdu_bytes = encode_npdu_with_data(&npdu, &apdu);
    
    let header = BvlcHeader::new(BvlcFunction::OriginalBroadcastNpdu, 4 + npdu_bytes.len() as u16);
    let mut frame = header.encode();
    frame.extend_from_slice(&npdu_bytes);
    
    let _ = socket.send_to(&frame, "255.255.255.255:47808");
    
    collect_i_am_responses(socket, devices, Duration::from_secs(5))?;
    Ok(())
}

fn discover_devices_on_network(socket: &UdpSocket, network: u16, devices: &mut HashMap<u32, BACnetDevice>) -> Result<(), Box<dyn std::error::Error>> {
    let who_is = WhoIsRequest::new();
    let mut who_is_data = Vec::new();
    who_is.encode(&mut who_is_data)?;
    
    let mut apdu = vec![0x10, 0x08]; // Unconfirmed-Request, Who-Is
    apdu.extend_from_slice(&who_is_data);
    
    let mut npdu = Npdu::new();
    npdu.control.destination_present = true;
    npdu.destination = Some(NetworkAddress {
        network,
        address: vec![], // Broadcast
    });
    npdu.hop_count = Some(255);
    
    let npdu_bytes = encode_npdu_with_data(&npdu, &apdu);
    
    let header = BvlcHeader::new(BvlcFunction::OriginalBroadcastNpdu, 4 + npdu_bytes.len() as u16);
    let mut frame = header.encode();
    frame.extend_from_slice(&npdu_bytes);
    
    let _ = socket.send_to(&frame, "255.255.255.255:47808");
    
    collect_i_am_responses(socket, devices, Duration::from_secs(3))?;
    Ok(())
}

fn collect_i_am_responses(socket: &UdpSocket, devices: &mut HashMap<u32, BACnetDevice>, timeout: Duration) -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();
    let mut buffer = [0u8; 1500];
    
    while start.elapsed() < timeout {
        match socket.recv_from(&mut buffer) {
            Ok((len, src_addr)) => {
                if len > 4 {
                    let npdu_data = &buffer[4..len];
                    if let Ok((npdu, offset)) = Npdu::decode(npdu_data) {
                        if !npdu.is_network_message() && npdu_data.len() > offset {
                            let apdu_data = &npdu_data[offset..];
                            if apdu_data.len() > 1 && apdu_data[0] == 0x10 && apdu_data[1] == 0x00 {
                                if let Ok(i_am) = IAmRequest::decode(&apdu_data[2..]) {
                                    let device_id = i_am.device_identifier.instance;
                                    
                                    let (network_number, mac_address) = if let Some(src_net) = npdu.source {
                                        (src_net.network, src_net.address)
                                    } else {
                                        (0, vec![])
                                    };
                                    
                                    let vendor_name = get_vendor_name(i_am.vendor_identifier as u16)
                                        .unwrap_or("Unknown Vendor");
                                    
                                    let device = BACnetDevice {
                                        device_id,
                                        network_number,
                                        mac_address,
                                        socket_addr: src_addr,
                                        vendor_id: i_am.vendor_identifier,
                                        vendor_name: vendor_name.to_string(),
                                        max_apdu: i_am.max_apdu_length_accepted,
                                        segmentation: i_am.segmentation_supported,
                                        object_name: None,
                                        model_name: None,
                                        firmware_revision: None,
                                        objects: Vec::new(),
                                    };
                                    
                                    devices.insert(device_id, device);
                                    print!(".");
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                if e.kind() != ErrorKind::WouldBlock && e.kind() != ErrorKind::TimedOut {
                    break;
                }
            }
        }
    }
    
    Ok(())
}

fn analyze_device(socket: &UdpSocket, device: &mut BACnetDevice) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n📱 Analyzing Device {} ({})", device.device_id, device.vendor_name);
    println!("   Network: {}, Address: {}", 
             if device.network_number == 0 { "Local".to_string() } else { device.network_number.to_string() },
             device.socket_addr);
    
    // Read basic device properties (commented out due to timeout issues)
    println!("   📋 Reading device properties...");
    
    // if let Ok(name) = read_device_property(socket, device, PropertyIdentifier::ObjectName as u32) {
    //     device.object_name = Some(name);
    //     println!("      Name: {}", device.object_name.as_ref().unwrap());
    // }
    
    // if let Ok(model) = read_device_property(socket, device, PropertyIdentifier::ModelName as u32) {
    //     device.model_name = Some(model);
    //     println!("      Model: {}", device.model_name.as_ref().unwrap());
    // }
    
    // if let Ok(firmware) = read_device_property(socket, device, PropertyIdentifier::FirmwareRevision as u32) {
    //     device.firmware_revision = Some(firmware);
    //     println!("      Firmware: {}", device.firmware_revision.as_ref().unwrap());
    // }
    
    // Read object list with alternative approaches
    println!("   🔍 Discovering objects...");
    
    // Try different approaches to read object list
    if let Ok(count) = try_read_object_list_multiple_approaches(socket, device) {
        println!("      Found {} objects using alternative method", count);
        
        // Read details for each object (limit to avoid overwhelming output)
        if count > 1 { // More than just the device object
            println!("      Reading object details...");
            let objects_to_read = std::cmp::min(device.objects.len(), 10); // Reasonable limit
            for i in 0..objects_to_read {
                // Read object name
                if let Ok(name) = read_object_property_simple(socket, device, &device.objects[i], PropertyIdentifier::ObjectName as u32) {
                    if let Ok(parsed_name) = parse_string_from_response(&name) {
                        device.objects[i].name = Some(parsed_name);
                    }
                }
                
                // Read present value for I/O objects
                if is_io_object(device.objects[i].object_type) {
                    if let Ok(value) = read_object_property_simple(socket, device, &device.objects[i], PropertyIdentifier::PresentValue as u32) {
                        if let Ok(parsed_value) = parse_value_from_response(&value) {
                            device.objects[i].present_value = Some(parsed_value);
                        }
                    }
                    
                    // Try to read units for analog objects
                    if matches!(device.objects[i].object_type, ObjectType::AnalogInput | ObjectType::AnalogOutput | ObjectType::AnalogValue) {
                        if let Ok(units) = read_object_property_simple(socket, device, &device.objects[i], PropertyIdentifier::OutputUnits as u32) {
                            if let Ok(parsed_units) = parse_units_from_response(&units) {
                                device.objects[i].description = Some(format!("Units: {}", parsed_units));
                            }
                        }
                    }
                }
                
                std::thread::sleep(Duration::from_millis(100)); // Small delay between reads
            }
        }
    }
    
    // match read_object_list(socket, device) {
    //     Ok(object_count) => {
    //         println!("      Found {} objects", object_count);
    //         
    //         // Read details for each object (limit to avoid overwhelming output)
    //         let objects_to_read = std::cmp::min(device.objects.len(), 10);
    //         for i in 0..objects_to_read {
    //             // Read object name
    //             if let Ok(name) = read_object_property(socket, device, &device.objects[i], PropertyIdentifier::ObjectName as u32) {
    //                 device.objects[i].name = Some(name);
    //             }
    //             
    //             // Read present value for I/O objects
    //             if is_io_object(device.objects[i].object_type) {
    //                 if let Ok(value) = read_object_property(socket, device, &device.objects[i], PropertyIdentifier::PresentValue as u32) {
    //                     device.objects[i].present_value = Some(value);
    //                 }
    //             }
    //             
    //             std::thread::sleep(Duration::from_millis(50));
    //         }
    //     }
    //     Err(e) => {
    //         println!("      Failed to read object list: {}", e);
    //     }
    // }
    
    Ok(())
}

fn read_device_property(socket: &UdpSocket, device: &BACnetDevice, property_id: u32) -> Result<String, Box<dyn std::error::Error>> {
    static INVOKE_ID: AtomicU8 = AtomicU8::new(1);
    let invoke_id = INVOKE_ID.fetch_add(1, Ordering::SeqCst);
    let invoke_id = if invoke_id == 0 { 1 } else { invoke_id }; // Never use 0
    
    // Create ReadProperty request following the official BACnet C stack implementation
    let mut apdu = Vec::new();
    
    // APDU Header (4 bytes) - following rp_encode_apdu()
    apdu.push(0x00); // PDU_TYPE_CONFIRMED_SERVICE_REQUEST
    apdu.push(0x05); // encode_max_segs_max_apdu(0, MAX_APDU) - no segmentation, 1476 bytes
    apdu.push(invoke_id); // invoke_id
    apdu.push(0x0C); // SERVICE_CONFIRMED_READ_PROPERTY (12)
    
    // ReadProperty Service Data - following read_property_request_encode()
    
    // Context tag 0: Object Identifier (BACnetObjectIdentifier)
    // Encode as 4-byte object identifier: (object_type << 22) | instance
    let object_type = ObjectType::Device as u32; // 8
    let object_id = (object_type << 22) | (device.device_id & 0x3FFFFF);
    apdu.push(0x0C); // Context tag [0], length 4
    apdu.extend_from_slice(&object_id.to_be_bytes());
    
    // Context tag 1: Property Identifier (BACnetPropertyIdentifier)
    // Encode as enumerated value
    if property_id <= 255 {
        apdu.push(0x19); // Context tag [1], length 1
        apdu.push(property_id as u8);
    } else if property_id <= 65535 {
        apdu.push(0x1A); // Context tag [1], length 2
        apdu.extend_from_slice(&(property_id as u16).to_be_bytes());
    } else {
        apdu.push(0x1C); // Context tag [1], length 4
        apdu.extend_from_slice(&property_id.to_be_bytes());
    }
    
    send_request_and_get_response(socket, device, &apdu, invoke_id)
}

fn try_read_object_list_multiple_approaches(socket: &UdpSocket, device: &mut BACnetDevice) -> Result<usize, Box<dyn std::error::Error>> {
    match read_device_property_simple(socket, device, PropertyIdentifier::ObjectList as u32) {
        Ok(response) => {
            if let Ok(objects) = parse_object_identifiers_from_response(&response) {
                for obj_id in objects {
                    let obj = BACnetObject {
                        object_type: obj_id.object_type,
                        instance: obj_id.instance,
                        name: None,
                        present_value: None,
                        description: None,
                    };
                    device.objects.push(obj);
                }
                return Ok(device.objects.len());
            }
        }
        Err(_) => {},
    }
    
    match read_device_property_alternative(socket, device, PropertyIdentifier::ObjectList as u32) {
        Ok(_) => return Ok(0),
        Err(_) => {},
    }
    
    read_object_list(socket, device)
}

fn read_device_property_simple(socket: &UdpSocket, device: &BACnetDevice, property_id: u32) -> Result<String, Box<dyn std::error::Error>> {
    static INVOKE_ID: AtomicU8 = AtomicU8::new(50);
    let invoke_id = INVOKE_ID.fetch_add(1, Ordering::SeqCst);
    let invoke_id = if invoke_id == 0 { 1 } else { invoke_id };
    
    // Simpler APDU construction
    let mut apdu = Vec::new();
    apdu.push(0x00); // Confirmed-Request
    apdu.push(0x05); // Max segments/APDU
    apdu.push(invoke_id);
    apdu.push(0x0C); // ReadProperty
    
    // Object ID for device
    let obj_id = ((ObjectType::Device as u32) << 22) | (device.device_id & 0x3FFFFF);
    apdu.push(0x0C); // Context tag 0, length 4
    apdu.extend_from_slice(&obj_id.to_be_bytes());
    
    // Property ID 
    apdu.push(0x19); // Context tag 1, length 1
    apdu.push(property_id as u8);
    
    send_request_and_get_response(socket, device, &apdu, invoke_id)
}

fn read_device_property_alternative(socket: &UdpSocket, device: &BACnetDevice, property_id: u32) -> Result<String, Box<dyn std::error::Error>> {
    static INVOKE_ID: AtomicU8 = AtomicU8::new(150);
    let invoke_id = INVOKE_ID.fetch_add(1, Ordering::SeqCst);
    let invoke_id = if invoke_id == 0 { 1 } else { invoke_id };
    
    // Alternative encoding - try different max APDU
    let mut apdu = Vec::new();
    apdu.push(0x00); // Confirmed-Request
    apdu.push(0x00); // No segmentation, 50 byte APDU
    apdu.push(invoke_id);
    apdu.push(0x0C); // ReadProperty
    
    // Object ID for device
    let obj_id = ((ObjectType::Device as u32) << 22) | (device.device_id & 0x3FFFFF);
    apdu.push(0x0C); // Context tag 0, length 4
    apdu.extend_from_slice(&obj_id.to_be_bytes());
    
    // Property ID 
    apdu.push(0x19); // Context tag 1, length 1
    apdu.push(property_id as u8);
    
    send_request_and_get_response(socket, device, &apdu, invoke_id)
}

fn read_object_list(socket: &UdpSocket, device: &mut BACnetDevice) -> Result<usize, Box<dyn std::error::Error>> {
    // First try to read the entire object list at once
    match read_device_property(socket, device, PropertyIdentifier::ObjectList as u32) {
        Ok(obj_list_data) => {
            if let Ok(objects) = parse_object_list_response(&obj_list_data) {
                for obj_id in objects {
                    let obj = BACnetObject {
                        object_type: obj_id.object_type,
                        instance: obj_id.instance,
                        name: None,
                        present_value: None,
                        description: None,
                    };
                    device.objects.push(obj);
                }
                return Ok(device.objects.len());
            }
        }
        Err(_) => {}
    }
    
    // Fallback to reading array length first
    match read_property_with_array_index(socket, device, PropertyIdentifier::ObjectList as u32, 0) {
        Ok(length_str) => {
            if let Ok(length) = length_str.parse::<u32>() {
                // Read each object identifier
                for i in 1..=std::cmp::min(length, 50) {
                    match read_property_with_array_index(socket, device, PropertyIdentifier::ObjectList as u32, i) {
                        Ok(obj_data) => {
                            if let Ok(obj_id) = parse_object_identifier(&obj_data) {
                                let obj = BACnetObject {
                                    object_type: obj_id.object_type,
                                    instance: obj_id.instance,
                                    name: None,
                                    present_value: None,
                                    description: None,
                                };
                                device.objects.push(obj);
                            }
                        }
                        Err(_) => break,
                    }
                    std::thread::sleep(Duration::from_millis(30));
                }
                Ok(device.objects.len())
            } else {
                Err("Could not parse object list length".into())
            }
        }
        Err(_) => {
            // Fallback: try reading indices until we get errors
            for i in 1..=20 {
                match read_property_with_array_index(socket, device, PropertyIdentifier::ObjectList as u32, i) {
                    Ok(obj_data) => {
                        if let Ok(obj_id) = parse_object_identifier(&obj_data) {
                            let obj = BACnetObject {
                                object_type: obj_id.object_type,
                                instance: obj_id.instance,
                                name: None,
                                present_value: None,
                                description: None,
                            };
                            device.objects.push(obj);
                        }
                    }
                    Err(_) => break,
                }
                std::thread::sleep(Duration::from_millis(30));
            }
            Ok(device.objects.len())
        }
    }
}

fn read_property_with_array_index(socket: &UdpSocket, device: &BACnetDevice, property_id: u32, array_index: u32) -> Result<String, Box<dyn std::error::Error>> {
    static INVOKE_ID: AtomicU8 = AtomicU8::new(100);
    let invoke_id = INVOKE_ID.fetch_add(1, Ordering::SeqCst);
    let invoke_id = if invoke_id == 0 { 1 } else { invoke_id }; // Never use 0
    
    // Create ReadProperty request following the official BACnet C stack implementation
    let mut apdu = Vec::new();
    
    // APDU Header (4 bytes) - following rp_encode_apdu()
    apdu.push(0x00); // PDU_TYPE_CONFIRMED_SERVICE_REQUEST
    apdu.push(0x05); // encode_max_segs_max_apdu(0, MAX_APDU) - no segmentation, 1476 bytes
    apdu.push(invoke_id); // invoke_id
    apdu.push(0x0C); // SERVICE_CONFIRMED_READ_PROPERTY (12)
    
    // ReadProperty Service Data - following read_property_request_encode()
    
    // Context tag 0: Object Identifier (BACnetObjectIdentifier)
    // Encode as 4-byte object identifier: (object_type << 22) | instance
    let object_type = ObjectType::Device as u32; // 8
    let object_id = (object_type << 22) | (device.device_id & 0x3FFFFF);
    apdu.push(0x0C); // Context tag [0], length 4
    apdu.extend_from_slice(&object_id.to_be_bytes());
    
    // Context tag 1: Property Identifier (BACnetPropertyIdentifier)
    // Encode as enumerated value
    if property_id <= 255 {
        apdu.push(0x19); // Context tag [1], length 1
        apdu.push(property_id as u8);
    } else if property_id <= 65535 {
        apdu.push(0x1A); // Context tag [1], length 2
        apdu.extend_from_slice(&(property_id as u16).to_be_bytes());
    } else {
        apdu.push(0x1C); // Context tag [1], length 4
        apdu.extend_from_slice(&property_id.to_be_bytes());
    }
    
    // Context tag 2: Property Array Index (optional)
    if array_index <= 255 {
        apdu.push(0x29); // Context tag [2], length 1
        apdu.push(array_index as u8);
    } else if array_index <= 65535 {
        apdu.push(0x2A); // Context tag [2], length 2
        apdu.extend_from_slice(&(array_index as u16).to_be_bytes());
    } else {
        apdu.push(0x2C); // Context tag [2], length 4
        apdu.extend_from_slice(&array_index.to_be_bytes());
    }
    
    send_request_and_get_response(socket, device, &apdu, invoke_id)
}

fn read_object_property_simple(socket: &UdpSocket, device: &BACnetDevice, object: &BACnetObject, property_id: u32) -> Result<String, Box<dyn std::error::Error>> {
    static INVOKE_ID: AtomicU8 = AtomicU8::new(200);
    let invoke_id = INVOKE_ID.fetch_add(1, Ordering::SeqCst);
    let invoke_id = if invoke_id == 0 { 1 } else { invoke_id };
    
    // Simple APDU construction for object properties
    let mut apdu = Vec::new();
    apdu.push(0x00); // Confirmed-Request
    apdu.push(0x05); // Max segments/APDU
    apdu.push(invoke_id);
    apdu.push(0x0C); // ReadProperty
    
    // Object ID
    let obj_id = ((object.object_type as u32) << 22) | (object.instance & 0x3FFFFF);
    apdu.push(0x0C); // Context tag 0, length 4
    apdu.extend_from_slice(&obj_id.to_be_bytes());
    
    // Property ID 
    apdu.push(0x19); // Context tag 1, length 1
    apdu.push(property_id as u8);
    
    send_request_and_get_response(socket, device, &apdu, invoke_id)
}

fn read_object_property(socket: &UdpSocket, device: &BACnetDevice, object: &BACnetObject, property_id: u32) -> Result<String, Box<dyn std::error::Error>> {
    static INVOKE_ID: AtomicU8 = AtomicU8::new(200);
    let invoke_id = INVOKE_ID.fetch_add(1, Ordering::SeqCst);
    let invoke_id = if invoke_id == 0 { 1 } else { invoke_id }; // Never use 0
    
    // Create ReadProperty request following the official BACnet C stack implementation
    let mut apdu = Vec::new();
    
    // APDU Header (4 bytes) - following rp_encode_apdu()
    apdu.push(0x00); // PDU_TYPE_CONFIRMED_SERVICE_REQUEST
    apdu.push(0x05); // encode_max_segs_max_apdu(0, MAX_APDU) - no segmentation, 1476 bytes
    apdu.push(invoke_id); // invoke_id
    apdu.push(0x0C); // SERVICE_CONFIRMED_READ_PROPERTY (12)
    
    // ReadProperty Service Data - following read_property_request_encode()
    
    // Context tag 0: Object Identifier (BACnetObjectIdentifier)
    // Encode as 4-byte object identifier: (object_type << 22) | instance
    let object_id = ((object.object_type as u32) << 22) | (object.instance & 0x3FFFFF);
    apdu.push(0x0C); // Context tag [0], length 4
    apdu.extend_from_slice(&object_id.to_be_bytes());
    
    // Context tag 1: Property Identifier (BACnetPropertyIdentifier)
    // Encode as enumerated value
    if property_id <= 255 {
        apdu.push(0x19); // Context tag [1], length 1
        apdu.push(property_id as u8);
    } else if property_id <= 65535 {
        apdu.push(0x1A); // Context tag [1], length 2
        apdu.extend_from_slice(&(property_id as u16).to_be_bytes());
    } else {
        apdu.push(0x1C); // Context tag [1], length 4
        apdu.extend_from_slice(&property_id.to_be_bytes());
    }
    
    send_request_and_get_response(socket, device, &apdu, invoke_id)
}

fn send_request_and_get_response(socket: &UdpSocket, device: &BACnetDevice, apdu: &[u8], invoke_id: u8) -> Result<String, Box<dyn std::error::Error>> {
    let mut npdu = Npdu::new();
    npdu.control.expecting_reply = true;
    
    if device.network_number != 0 {
        npdu.control.destination_present = true;
        npdu.destination = Some(NetworkAddress {
            network: device.network_number,
            address: device.mac_address.clone(),
        });
        npdu.hop_count = Some(255);
    }
    
    let npdu_bytes = encode_npdu_with_data(&npdu, apdu);
    let header = BvlcHeader::new(BvlcFunction::OriginalUnicastNpdu, 4 + npdu_bytes.len() as u16);
    let mut frame = header.encode();
    frame.extend_from_slice(&npdu_bytes);
    
    socket.send_to(&frame, device.socket_addr)?;
    
    let start = Instant::now();
    let mut buffer = [0u8; 1500];
    
    while start.elapsed() < Duration::from_secs(2) { // Shorter timeout for property reads
        match socket.recv_from(&mut buffer) {
            Ok((len, src_addr)) => {
                if len > 4 {
                    let npdu_data = &buffer[4..len];
                    
                    if let Ok((npdu, offset)) = Npdu::decode(npdu_data) {
                        if !npdu.is_network_message() && npdu_data.len() > offset {
                            let apdu_data = &npdu_data[offset..];
                            let pdu_type = (apdu_data[0] & 0xF0) >> 4;
                            let resp_invoke_id = apdu_data[0] & 0x0F;
                            
                            // Some devices don't echo invoke ID correctly, so accept any response from our target device
                            if resp_invoke_id == (invoke_id & 0x0F) || src_addr == device.socket_addr {
                                if pdu_type == 0x3 { // Complex ACK
                                    if apdu_data.len() >= 2 && apdu_data[1] == 0x0C {
                                        if let Ok(response) = ReadPropertyResponse::decode(&apdu_data[2..]) {
                                            return extract_string_value(&response.property_value);
                                        }
                                    } else {
                                        // Try to parse as raw property data
                                        return parse_raw_response(&apdu_data);
                                    }
                                } else if pdu_type == 0x5 { // Error
                                    return Err("Device returned error".into());
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                if e.kind() != std::io::ErrorKind::WouldBlock && e.kind() != std::io::ErrorKind::TimedOut {
                    continue;
                }
            }
        }
    }
    Err("Timeout".into())
}

fn display_comprehensive_summary(devices: &HashMap<u32, BACnetDevice>) {
    let total_objects: usize = devices.values().map(|d| d.objects.len()).sum();
    
    println!("STATISTICS:");
    println!("   Total Devices: {}", devices.len());
    println!("   Total Objects: {}", total_objects);
    
    let mut networks: Vec<u16> = devices.values().map(|d| d.network_number).collect();
    networks.sort();
    networks.dedup();
    println!("   Networks: {}", if networks.len() == 1 && networks[0] == 0 { 
        "Local".to_string() 
    } else { 
        format!("{:?}", networks) 
    });
    
    println!("\nDEVICE INVENTORY:");
    println!("{}", "=".repeat(80));
    
    for device in devices.values() {
        let network_info = if device.network_number == 0 {
            "Local".to_string()
        } else {
            format!("Network {}", device.network_number)
        };
        
        println!("\nDEVICE {} - {} ({})", device.device_id, device.vendor_name, network_info);
        if let Some(name) = &device.object_name {
            println!("   Name: {}", name);
        }
        if let Some(model) = &device.model_name {
            println!("   Model: {}", model);
        }
        if let Some(firmware) = &device.firmware_revision {
            println!("   Firmware: {}", firmware);
        }
        println!("   Address: {}", device.socket_addr);
        println!("   Max APDU: {}, Segmentation: {}", device.max_apdu, device.segmentation);
        
        if !device.objects.is_empty() {
            println!("   OBJECTS ({}):", device.objects.len());
            
            for (i, obj) in device.objects.iter().enumerate() {
                if i >= 15 { // Limit display to first 15 objects
                    println!("      ... and {} more objects", device.objects.len() - 15);
                    break;
                }
                
                let obj_name = obj.name.as_deref().unwrap_or("<unnamed>");
                let type_name = object_type_name(obj.object_type);
                
                print!("      {:2}. {} {} '{}'", i + 1, type_name, obj.instance, obj_name);
                
                if let Some(value) = &obj.present_value {
                    print!(" = {}", value);
                }
                
                if let Some(description) = &obj.description {
                    if description.starts_with("Units: ") {
                        print!(" {}", description);
                    }
                }
                
                println!();
            }
        } else {
            println!("   OBJECTS: Unable to read object list");
        }
    }
    
    println!("\n{}", "=".repeat(80));
    println!("Network scan complete!");
}

// Helper functions (same as previous example)
fn encode_npdu_with_data(npdu: &Npdu, data: &[u8]) -> Vec<u8> {
    let mut buffer = npdu.encode();
    buffer.extend_from_slice(data);
    buffer
}

#[derive(Debug, Clone, Copy)]
struct BACnetObjectId {
    object_type: ObjectType,
    instance: u32,
}

fn parse_object_identifier(data: &str) -> Result<BACnetObjectId, Box<dyn std::error::Error>> {
    if data.starts_with("0x") && data.len() >= 10 {
        if let Ok(obj_id_value) = u32::from_str_radix(&data[2..], 16) {
            let object_type_num = (obj_id_value >> 22) & 0x3FF;
            let instance = obj_id_value & 0x3FFFFF;
            
            let object_type = ObjectType::try_from(object_type_num as u16)
                .unwrap_or(ObjectType::Device);
            
            return Ok(BACnetObjectId {
                object_type,
                instance,
            });
        }
    }
    Err(format!("Could not parse object identifier: {}", data).into())
}

fn parse_object_list_response(data: &str) -> Result<Vec<BACnetObjectId>, Box<dyn std::error::Error>> {
    let mut objects = Vec::new();
    
    // Try to parse as hex string containing multiple object identifiers
    if data.starts_with("0x") {
        let hex_data = &data[2..];
        
        // Each object identifier is 4 bytes (8 hex characters)
        if hex_data.len() % 8 == 0 {
            for i in (0..hex_data.len()).step_by(8) {
                if i + 8 <= hex_data.len() {
                    let obj_hex = &hex_data[i..i+8];
                    let obj_data = format!("0x{}", obj_hex);
                    
                    if let Ok(obj_id) = parse_object_identifier(&obj_data) {
                        objects.push(obj_id);
                    }
                }
            }
        }
    }
    
    if objects.is_empty() {
        Err("No objects found in response".into())
    } else {
        Ok(objects)
    }
}

fn parse_object_identifiers_from_response(response: &str) -> Result<Vec<BACnetObjectId>, Box<dyn std::error::Error>> {
    if !response.starts_with("Objects: [") {
        return Err("Not an object list response".into());
    }
    
    let objects_str = &response[10..response.len()-1]; // Remove "Objects: [" and "]"
    let mut objects = Vec::new();
    
    for obj_str in objects_str.split(", ") {
        if let Some(colon_pos) = obj_str.find(':') {
            let type_str = &obj_str[..colon_pos];
            let instance_str = &obj_str[colon_pos+1..];
            
            if let Ok(instance) = instance_str.parse::<u32>() {
                let object_type = match type_str {
                    "DEV" => ObjectType::Device,
                    "AI" => ObjectType::AnalogInput,
                    "AO" => ObjectType::AnalogOutput,
                    "AV" => ObjectType::AnalogValue,
                    "BI" => ObjectType::BinaryInput,
                    "BO" => ObjectType::BinaryOutput,
                    "BV" => ObjectType::BinaryValue,
                    "MSI" => ObjectType::MultiStateInput,
                    "MSO" => ObjectType::MultiStateOutput,
                    "MSV" => ObjectType::MultiStateValue,
                    _ => continue, // Skip unknown types
                };
                
                objects.push(BACnetObjectId { object_type, instance });
            }
        }
    }
    
    Ok(objects)
}

fn parse_raw_response(apdu_data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    // Look for object identifiers in the response (pattern: C4 XX XX XX XX for object IDs)
    let mut objects = Vec::new();
    let mut i = 0;
    
    while i + 4 < apdu_data.len() {
        if apdu_data[i] == 0xC4 { // Object identifier tag
            let obj_bytes = [apdu_data[i+1], apdu_data[i+2], apdu_data[i+3], apdu_data[i+4]];
            let obj_id_value = u32::from_be_bytes(obj_bytes);
            let object_type_num = (obj_id_value >> 22) & 0x3FF;
            let instance = obj_id_value & 0x3FFFFF;
            
            if let Ok(object_type) = ObjectType::try_from(object_type_num as u16) {
                objects.push(format!("{}:{}", object_type_name(object_type), instance));
            }
            i += 5;
        } else {
            i += 1;
        }
    }
    
    if !objects.is_empty() {
        Ok(format!("Objects: [{}]", objects.join(", ")))
    } else {
        // Fallback to hex dump
        let hex_str = apdu_data.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join("");
        Ok(format!("Raw: {}", hex_str))
    }
}

fn decode_hex(hex_str: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if hex_str.len() % 2 != 0 {
        return Err("Hex string length must be even".into());
    }
    
    let mut bytes = Vec::new();
    for i in (0..hex_str.len()).step_by(2) {
        let byte_str = &hex_str[i..i+2];
        if let Ok(byte) = u8::from_str_radix(byte_str, 16) {
            bytes.push(byte);
        } else {
            return Err("Invalid hex character".into());
        }
    }
    Ok(bytes)
}

fn parse_string_from_response(response: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Handle our custom response format
    if response.starts_with("Raw: ") {
        let hex_str = &response[5..];
        if let Ok(bytes) = decode_hex(hex_str) {
            return extract_string_value(&bytes);
        }
    }
    Ok(response.to_string())
}

fn parse_value_from_response(response: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Handle our custom response format  
    if response.starts_with("Raw: ") {
        let hex_str = &response[5..];
        if let Ok(bytes) = decode_hex(hex_str) {
            return extract_numeric_value(&bytes);
        }
    }
    Ok(response.to_string())
}

fn parse_units_from_response(response: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Handle our custom response format
    if response.starts_with("Raw: ") {
        let hex_str = &response[5..];
        if let Ok(bytes) = decode_hex(hex_str) {
            return extract_units_value(&bytes);
        }
    }
    Ok(response.to_string())
}

fn extract_numeric_value(data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    if data.is_empty() {
        return Ok("(empty)".to_string());
    }
    
    // Look for IEEE 754 float patterns in the hex data
    for i in 0..data.len().saturating_sub(3) {
        if data[i] == 0x44 && i + 4 < data.len() {
            let bytes = [data[i+1], data[i+2], data[i+3], data[i+4]];
            let value = f32::from_be_bytes(bytes);
            if value.is_finite() && value.abs() < 1000000.0 { // Reasonable range check
                return Ok(format!("{:.2}", value));
            }
        }
    }
    
    // Real value at start
    if data[0] == 0x44 && data.len() >= 5 {
        let bytes = [data[1], data[2], data[3], data[4]];
        let value = f32::from_be_bytes(bytes);
        return Ok(format!("{:.2}", value));
    }
    
    // Unsigned integer
    if (data[0] & 0xF0) == 0x20 {
        let len = (data[0] & 0x07) as usize;
        if len <= 4 && data.len() > len {
            let mut value = 0u32;
            for i in 0..len {
                value = (value << 8) | (data[1 + i] as u32);
            }
            return Ok(value.to_string());
        }
    }
    
    // Boolean
    if data[0] == 0x11 && data.len() >= 2 {
        return Ok(if data[1] == 0 { "false".to_string() } else { "true".to_string() });
    }
    
    // Enumerated
    if (data[0] & 0xF0) == 0x90 {
        let len = (data[0] & 0x07) as usize;
        if len <= 4 && data.len() > len {
            let mut value = 0u32;
            for i in 0..len {
                value = (value << 8) | (data[1 + i] as u32);
            }
            return Ok(format!("enum({})", value));
        }
    }
    
    // Fallback to hex
    let hex_str = data.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join("");
    Ok(format!("0x{}", hex_str))
}

fn extract_units_value(data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    if data.is_empty() {
        return Ok("(none)".to_string());
    }
    
    // Enumerated units
    if (data[0] & 0xF0) == 0x90 {
        let len = (data[0] & 0x07) as usize;
        if len <= 4 && data.len() > len {
            let mut value = 0u32;
            for i in 0..len {
                value = (value << 8) | (data[1 + i] as u32);
            }
            
            // Common BACnet engineering units
            let unit_name = match value {
                95 => "degrees-celsius",
                96 => "degrees-fahrenheit", 
                98 => "percent",
                99 => "percent-relative-humidity",
                118 => "volts",
                119 => "kilovolts",
                120 => "millivolts",
                121 => "amperes",
                122 => "milliamperes",
                123 => "kiloamperes",
                132 => "watts",
                133 => "kilowatts",
                159 => "pascals",
                160 => "kilopascals",
                162 => "bars",
                _ => return Ok(format!("unit-{}", value)),
            };
            
            return Ok(unit_name.to_string());
        }
    }
    
    Ok("unknown".to_string())
}

fn extract_string_value(data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    if data.is_empty() {
        return Ok("(empty)".to_string());
    }
    
    // Character string
    if data[0] == 0x74 || data[0] == 0x75 {
        let len = if data[0] == 0x74 {
            data[1] as usize
        } else {
            ((data[1] as usize) << 8) | (data[2] as usize)
        };
        
        let start = if data[0] == 0x74 { 2 } else { 3 };
        if data.len() >= start + len {
            let string_data = &data[start..start + len];
            
            // Check if this looks like UTF-16 (every other byte is 0x00)
            if string_data.len() > 4 && string_data.len() % 2 == 0 {
                let mut is_utf16 = true;
                for i in (1..string_data.len()).step_by(2) {
                    if string_data[i] != 0x00 {
                        is_utf16 = false;
                        break;
                    }
                }
                
                if is_utf16 {
                    // Extract UTF-16 string by taking every other byte
                    let utf8_bytes: Vec<u8> = string_data.iter().step_by(2).copied().collect();
                    return Ok(String::from_utf8_lossy(&utf8_bytes).to_string());
                }
            }
            
            return Ok(String::from_utf8_lossy(string_data).to_string());
        }
    }
    
    // Unsigned integer
    if (data[0] & 0xF0) == 0x20 {
        let len = (data[0] & 0x07) as usize;
        if len <= 4 && data.len() > len {
            let mut value = 0u32;
            for i in 0..len {
                value = (value << 8) | (data[1 + i] as u32);
            }
            return Ok(value.to_string());
        }
    }
    
    // Real value
    if data[0] == 0x44 && data.len() >= 5 {
        let bytes = [data[1], data[2], data[3], data[4]];
        let value = f32::from_be_bytes(bytes);
        return Ok(format!("{:.2}", value));
    }
    
    // Boolean
    if data[0] == 0x11 && data.len() >= 2 {
        return Ok(if data[1] == 0 { "false".to_string() } else { "true".to_string() });
    }
    
    // Fallback to hex
    let hex_str = data.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join("");
    Ok(format!("0x{}", hex_str))
}

fn object_type_name(obj_type: ObjectType) -> &'static str {
    match obj_type {
        ObjectType::AnalogInput => "AI",
        ObjectType::AnalogOutput => "AO", 
        ObjectType::AnalogValue => "AV",
        ObjectType::BinaryInput => "BI",
        ObjectType::BinaryOutput => "BO",
        ObjectType::BinaryValue => "BV",
        ObjectType::Device => "DEV",
        ObjectType::MultiStateInput => "MSI",
        ObjectType::MultiStateOutput => "MSO",
        ObjectType::MultiStateValue => "MSV",
        ObjectType::TrendLog => "TL",
        ObjectType::Schedule => "SCH",
        ObjectType::Calendar => "CAL",
        _ => "UNK",
    }
}

fn is_io_object(obj_type: ObjectType) -> bool {
    matches!(obj_type, 
        ObjectType::AnalogInput | ObjectType::AnalogOutput | ObjectType::AnalogValue |
        ObjectType::BinaryInput | ObjectType::BinaryOutput | ObjectType::BinaryValue |
        ObjectType::MultiStateInput | ObjectType::MultiStateOutput | ObjectType::MultiStateValue
    )
}