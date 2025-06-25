//! BACnet Device Objects Discovery Example
//!
//! This example demonstrates how to discover and read all objects in a specific
//! BACnet device using ReadPropertyMultiple requests.

use bacnet_rs::{
    service::{ReadPropertyMultipleRequest, ReadAccessSpecification, PropertyReference, ConfirmedServiceChoice, WhoIsRequest, IAmRequest, UnconfirmedServiceChoice},
    object::{ObjectIdentifier, ObjectType},
    network::Npdu,
    app::{Apdu, MaxSegments, MaxApduSize},
    property::decode_units,
};
use std::{
    net::{SocketAddr, UdpSocket},
    time::{Duration, Instant},
    env,
};

/// Structure to hold object information
#[derive(Debug)]
struct ObjectInfo {
    object_identifier: ObjectIdentifier,
    object_name: Option<String>,
    description: Option<String>,
    present_value: Option<String>,
    units: Option<String>,
    object_type_name: String,
}

impl ObjectInfo {
    fn new(object_identifier: ObjectIdentifier) -> Self {
        let object_type_name = match object_identifier.object_type {
            ObjectType::Device => "Device",
            ObjectType::AnalogInput => "Analog Input",
            ObjectType::AnalogOutput => "Analog Output", 
            ObjectType::AnalogValue => "Analog Value",
            ObjectType::BinaryInput => "Binary Input",
            ObjectType::BinaryOutput => "Binary Output",
            ObjectType::BinaryValue => "Binary Value",
            ObjectType::MultiStateInput => "Multi-State Input",
            ObjectType::MultiStateOutput => "Multi-State Output",
            ObjectType::MultiStateValue => "Multi-State Value",
            ObjectType::Calendar => "Calendar",
            ObjectType::Command => "Command",
            ObjectType::EventEnrollment => "Event Enrollment",
            ObjectType::File => "File",
            ObjectType::Group => "Group",
            ObjectType::Loop => "Loop",
            ObjectType::NotificationClass => "Notification Class",
            ObjectType::Program => "Program",
            ObjectType::Schedule => "Schedule",
            ObjectType::Averaging => "Averaging",
            ObjectType::TrendLog => "Trend Log",
            ObjectType::LifeSafetyPoint => "Life Safety Point",
            ObjectType::LifeSafetyZone => "Life Safety Zone",
            ObjectType::Accumulator => "Accumulator",
            ObjectType::PulseConverter => "Pulse Converter",
            ObjectType::EventLog => "Event Log",
            ObjectType::GlobalGroup => "Global Group",
            ObjectType::TrendLogMultiple => "Trend Log Multiple",
            ObjectType::LoadControl => "Load Control",
            ObjectType::StructuredView => "Structured View",
            ObjectType::AccessDoor => "Access Door",
        }.to_string();

        Self {
            object_identifier,
            object_name: None,
            description: None,
            present_value: None,
            units: None,
            object_type_name,
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <target_device_ip>", args[0]);
        eprintln!("Example: {} 10.161.1.211", args[0]);
        std::process::exit(1);
    }

    let target_ip = &args[1];
    let target_addr: SocketAddr = format!("{}:47808", target_ip).parse()?;

    println!("BACnet Device Objects Discovery");
    println!("==============================\n");
    println!("Target device: {}", target_addr);

    // Create UDP socket
    let local_addr = "0.0.0.0:0"; // Use any available port
    let socket = UdpSocket::bind(local_addr)?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;

    println!("Connected from: {}", socket.local_addr()?);
    println!();

    // Step 0: Discover the device ID first
    println!("Step 0: Discovering device ID...");
    let device_id = discover_device_id(&socket, target_addr)?;
    println!("Found device ID: {}", device_id);
    println!();

    // Step 1: Read the device's object-list property to discover all objects
    println!("Step 1: Reading device object list...");
    let device_objects = read_device_object_list(&socket, target_addr, device_id)?;
    
    if device_objects.is_empty() {
        println!("No objects found in device object list!");
        return Ok(());
    }

    println!("Found {} objects in device", device_objects.len());
    println!();

    // Step 2: Read properties for each object using ReadPropertyMultiple
    println!("Step 2: Reading object properties...");
    let objects_info = read_objects_properties(&socket, target_addr, &device_objects)?;

    // Step 3: Display results
    println!();
    println!("Device Objects Summary");
    println!("=====================");
    
    // Group objects by type for better organization
    let mut objects_by_type: std::collections::HashMap<String, Vec<&ObjectInfo>> = std::collections::HashMap::new();
    for obj in &objects_info {
        objects_by_type.entry(obj.object_type_name.clone()).or_default().push(obj);
    }

    for (object_type, objects) in objects_by_type {
        println!("\n{} Objects ({}):", object_type, objects.len());
        println!("{}", "-".repeat(object_type.len() + 15));
        
        for obj in objects {
            println!("  {} Instance {}", obj.object_type_name, obj.object_identifier.instance);
            
            // Always show object name if available
            if let Some(name) = &obj.object_name {
                println!("    Object Name: {}", name);
            } else {
                println!("    Object Name: [Not Available]");
            }
            
            // Show description if available
            if let Some(desc) = &obj.description {
                println!("    Description: {}", desc);
            } else {
                println!("    Description: [Not Available]");
            }
            
            // Show present value for relevant object types
            match obj.object_identifier.object_type {
                ObjectType::AnalogInput | ObjectType::AnalogOutput | ObjectType::AnalogValue |
                ObjectType::BinaryInput | ObjectType::BinaryOutput | ObjectType::BinaryValue |
                ObjectType::MultiStateInput | ObjectType::MultiStateOutput | ObjectType::MultiStateValue => {
                    if let Some(value) = &obj.present_value {
                        println!("    Present Value: {}", value);
                    } else {
                        println!("    Present Value: [Not Available]");
                    }
                }
                _ => {}
            }
            
            // Show units for analog objects
            match obj.object_identifier.object_type {
                ObjectType::AnalogInput | ObjectType::AnalogOutput | ObjectType::AnalogValue => {
                    if let Some(units) = &obj.units {
                        println!("    Units: {}", units);
                    } else {
                        println!("    Units: [Not Available]");
                    }
                }
                _ => {}
            }
            
            // Show object type for clarity
            println!("    Object Type: {}", obj.object_type_name);
            println!();
        }
    }

    println!("Total objects discovered: {}", objects_info.len());
    Ok(())
}

/// Discover the device ID by sending Who-Is and waiting for I-Am response
fn discover_device_id(socket: &UdpSocket, target_addr: SocketAddr) -> Result<u32, Box<dyn std::error::Error>> {
    // Send Who-Is request to the specific device
    let whois = WhoIsRequest::new();
    let mut buffer = Vec::new();
    whois.encode(&mut buffer)?;
    
    // Create NPDU for unicast
    let mut npdu = Npdu::new();
    npdu.control.expecting_reply = false; // Unconfirmed service
    npdu.control.priority = 0;
    let npdu_buffer = npdu.encode();
    
    // Create unconfirmed service request APDU
    let mut apdu = vec![0x10]; // Unconfirmed-Request PDU type
    apdu.push(UnconfirmedServiceChoice::WhoIs as u8);
    apdu.extend_from_slice(&buffer);
    
    // Combine NPDU and APDU
    let mut message = npdu_buffer;
    message.extend_from_slice(&apdu);
    
    // Wrap in BVLC header for BACnet/IP (unicast)
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
    
    // Send Who-Is
    socket.send_to(&bvlc_message, target_addr)?;
    
    // Wait for I-Am response
    let mut recv_buffer = [0u8; 1500];
    let start_time = Instant::now();
    
    while start_time.elapsed() < Duration::from_secs(3) {
        match socket.recv_from(&mut recv_buffer) {
            Ok((len, source)) => {
                if source == target_addr {
                    if let Some(device_id) = process_iam_response(&recv_buffer[..len]) {
                        return Ok(device_id);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(_) => {
                continue;
            }
        }
    }
    
    Err("Failed to discover device ID - no I-Am response received".into())
}

/// Process I-Am response to extract device ID
fn process_iam_response(data: &[u8]) -> Option<u32> {
    // Check BVLC header
    if data.len() < 4 || data[0] != 0x81 {
        return None;
    }

    let bvlc_length = ((data[2] as u16) << 8) | (data[3] as u16);
    if data.len() != bvlc_length as usize {
        return None;
    }

    // Skip BVLC header to get to NPDU
    let npdu_start = 4;
    if data.len() <= npdu_start {
        return None;
    }

    // Decode NPDU
    let (_npdu, npdu_len) = Npdu::decode(&data[npdu_start..]).ok()?;

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
        Ok(iam) => Some(iam.device_identifier.instance),
        Err(_) => None,
    }
}

/// Read the device's object-list property to discover all objects
fn read_device_object_list(socket: &UdpSocket, target_addr: SocketAddr, device_id: u32) -> Result<Vec<ObjectIdentifier>, Box<dyn std::error::Error>> {
    // Create ReadPropertyMultiple request for device object list
    let device_object = ObjectIdentifier::new(ObjectType::Device, device_id);
    
    let property_ref = PropertyReference::new(76); // Object_List property
    let read_spec = ReadAccessSpecification::new(device_object, vec![property_ref]);
    let rpm_request = ReadPropertyMultipleRequest::new(vec![read_spec]);

    // Send the request
    let invoke_id = 1;
    let response_data = send_confirmed_request(socket, target_addr, invoke_id, ConfirmedServiceChoice::ReadPropertyMultiple as u8, &encode_rpm_request(&rpm_request)?)?;

    // Parse the response to extract object identifiers
    let object_list = parse_object_list_response(&response_data)?;
    
    println!("Device object list contains {} objects", object_list.len());
    for (i, obj) in object_list.iter().enumerate() {
        if i < 10 { // Show first 10 for preview
            println!("  {}: {} Instance {}", i + 1, get_object_type_name(obj.object_type), obj.instance);
        } else if i == 10 {
            println!("  ... and {} more objects", object_list.len() - 10);
            break;
        }
    }

    Ok(object_list)
}

/// Read properties for multiple objects using ReadPropertyMultiple
fn read_objects_properties(socket: &UdpSocket, target_addr: SocketAddr, objects: &[ObjectIdentifier]) -> Result<Vec<ObjectInfo>, Box<dyn std::error::Error>> {
    let mut objects_info = Vec::new();
    let batch_size = 5; // Read properties for 5 objects at a time to avoid large responses

    for chunk in objects.chunks(batch_size) {
        println!("Reading properties for {} objects...", chunk.len());
        
        let mut read_specs = Vec::new();
        
        for obj in chunk {
            let mut property_refs = Vec::new();
            
            // Always try to read these basic properties
            property_refs.push(PropertyReference::new(77)); // Object_Name
            property_refs.push(PropertyReference::new(28)); // Description
            
            // Add Present_Value for input/output/value objects
            match obj.object_type {
                ObjectType::AnalogInput | ObjectType::AnalogOutput | ObjectType::AnalogValue |
                ObjectType::BinaryInput | ObjectType::BinaryOutput | ObjectType::BinaryValue |
                ObjectType::MultiStateInput | ObjectType::MultiStateOutput | ObjectType::MultiStateValue => {
                    property_refs.push(PropertyReference::new(85)); // Present_Value
                }
                _ => {}
            }
            
            // Add Units for analog objects
            match obj.object_type {
                ObjectType::AnalogInput | ObjectType::AnalogOutput | ObjectType::AnalogValue => {
                    property_refs.push(PropertyReference::new(117)); // Units
                }
                _ => {}
            }
            
            read_specs.push(ReadAccessSpecification::new(*obj, property_refs));
        }

        let rpm_request = ReadPropertyMultipleRequest::new(read_specs);
        
        // Send request
        let invoke_id = (objects_info.len() / batch_size + 2) as u8; // Unique invoke ID
        match send_confirmed_request(socket, target_addr, invoke_id, ConfirmedServiceChoice::ReadPropertyMultiple as u8, &encode_rpm_request(&rpm_request)?) {
            Ok(response_data) => {
                match parse_rpm_response(&response_data, chunk) {
                    Ok(mut batch_info) => {
                        objects_info.append(&mut batch_info);
                        println!("  Successfully read properties for {} objects", chunk.len());
                    }
                    Err(e) => {
                        println!("  Warning: Failed to parse response for batch: {}", e);
                        // Add objects with minimal info
                        for obj in chunk {
                            objects_info.push(ObjectInfo::new(*obj));
                        }
                    }
                }
            }
            Err(e) => {
                println!("  Warning: Failed to read properties for batch: {}", e);
                // Add objects with minimal info
                for obj in chunk {
                    objects_info.push(ObjectInfo::new(*obj));
                }
            }
        }
        
        // Small delay between requests
        std::thread::sleep(Duration::from_millis(100));
    }

    Ok(objects_info)
}

/// Send a confirmed request and wait for response
fn send_confirmed_request(socket: &UdpSocket, target_addr: SocketAddr, invoke_id: u8, service_choice: u8, service_data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Create confirmed request APDU
    let apdu = Apdu::ConfirmedRequest {
        segmented: false,
        more_follows: false,
        segmented_response_accepted: true,
        max_segments: MaxSegments::Unspecified,
        max_response_size: MaxApduSize::Up1476,
        invoke_id,
        sequence_number: None,
        proposed_window_size: None,
        service_choice,
        service_data: service_data.to_vec(),
    };

    // Encode APDU
    let apdu_data = apdu.encode();

    // Create NPDU
    let mut npdu = Npdu::new();
    npdu.control.expecting_reply = true;
    npdu.control.priority = 0;
    let npdu_data = npdu.encode();

    // Combine NPDU and APDU
    let mut message = npdu_data;
    message.extend_from_slice(&apdu_data);

    // Wrap in BVLC header for BACnet/IP (unicast)
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

    // Send request
    socket.send_to(&bvlc_message, target_addr)?;

    // Wait for response
    let mut recv_buffer = [0u8; 1500];
    let start_time = Instant::now();
    
    while start_time.elapsed() < Duration::from_secs(5) {
        match socket.recv_from(&mut recv_buffer) {
            Ok((len, source)) => {
                if source == target_addr {
                    // Process response
                    if let Some(response_data) = process_confirmed_response(&recv_buffer[..len], invoke_id) {
                        return Ok(response_data);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(e) => {
                return Err(format!("Error receiving response: {}", e).into());
            }
        }
    }

    Err("Timeout waiting for response".into())
}

/// Process confirmed response and extract service data
fn process_confirmed_response(data: &[u8], expected_invoke_id: u8) -> Option<Vec<u8>> {
    // Check BVLC header
    if data.len() < 4 || data[0] != 0x81 {
        return None;
    }

    let bvlc_length = ((data[2] as u16) << 8) | (data[3] as u16);
    if data.len() != bvlc_length as usize {
        return None;
    }

    // Skip BVLC header
    let npdu_start = 4;
    if data.len() <= npdu_start {
        return None;
    }

    // Decode NPDU
    let (_npdu, npdu_len) = Npdu::decode(&data[npdu_start..]).ok()?;
    
    // Skip to APDU
    let apdu_start = npdu_start + npdu_len;
    if data.len() <= apdu_start {
        return None;
    }

    // Decode APDU
    let apdu = Apdu::decode(&data[apdu_start..]).ok()?;
    
    match apdu {
        Apdu::ComplexAck { invoke_id, service_data, .. } => {
            if invoke_id == expected_invoke_id {
                Some(service_data)
            } else {
                None
            }
        }
        Apdu::Error { invoke_id, error_class, error_code, .. } => {
            if invoke_id == expected_invoke_id {
                println!("    Error response: class={}, code={}", error_class, error_code);
            }
            None
        }
        _ => None,
    }
}

/// Encode ReadPropertyMultiple request (simplified)
fn encode_rpm_request(request: &ReadPropertyMultipleRequest) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut buffer = Vec::new();
    
    for spec in &request.read_access_specifications {
        // Object identifier - context tag 0
        let object_id = encode_object_id(spec.object_identifier.object_type as u16, spec.object_identifier.instance);
        buffer.push(0x0C); // Context tag 0, length 4
        buffer.extend_from_slice(&object_id.to_be_bytes());
        
        // Property references - context tag 1 (opening tag)
        buffer.push(0x1E); // Context tag 1, opening tag
        
        for prop_ref in &spec.property_references {
            // Property identifier
            buffer.push(0x09); // Context tag 0 (within property reference), length 1
            buffer.push(prop_ref.property_identifier as u8);
            
            // Array index (optional)
            if let Some(array_index) = prop_ref.property_array_index {
                buffer.push(0x19); // Context tag 1 (within property reference), length 1
                buffer.push(array_index as u8);
            }
        }
        
        buffer.push(0x1F); // Context tag 1, closing tag
    }
    
    Ok(buffer)
}

/// Parse object list response to extract object identifiers
fn parse_object_list_response(data: &[u8]) -> Result<Vec<ObjectIdentifier>, Box<dyn std::error::Error>> {
    let mut objects = Vec::new();
    let mut pos = 0;
    
    // Simple approach - scan for all object identifiers
    while pos + 5 <= data.len() {
        if data[pos] == 0xC4 { // Application tag for object identifier
            pos += 1;
            let obj_id_bytes = [data[pos], data[pos + 1], data[pos + 2], data[pos + 3]];
            let obj_id = u32::from_be_bytes(obj_id_bytes);
            let (obj_type, instance) = decode_object_id(obj_id);
            
            // Skip the device object itself
            if obj_type == 8 {
                pos += 4;
                continue;
            }
            
            if let Ok(object_type) = ObjectType::try_from(obj_type) {
                objects.push(ObjectIdentifier::new(object_type, instance));
            }
            pos += 4;
        } else {
            pos += 1;
        }
    }
    
    Ok(objects)
}

/// Parse ReadPropertyMultiple response - simplified for this device format
fn parse_rpm_response(data: &[u8], objects: &[ObjectIdentifier]) -> Result<Vec<ObjectInfo>, Box<dyn std::error::Error>> {
    let mut objects_info = Vec::new();
    
    // Create ObjectInfo for each requested object first
    for obj in objects {
        objects_info.push(ObjectInfo::new(*obj));
    }
    
    // Try to parse the response data to extract property values
    let mut pos = 0;
    let mut current_obj_index = 0;
    
    // Debug: comment out for clean output
    // println!("Debug: Parsing RPM response with {} bytes for {} objects", data.len(), objects.len());
    
    while pos < data.len() && current_obj_index < objects_info.len() {
        // Look for object identifier context tag (0x0C)
        while pos < data.len() && data[pos] != 0x0C {
            pos += 1;
        }
        
        if pos >= data.len() {
            break;
        }
        
        pos += 5; // Skip object identifier
        
        // Look for property results opening tag (0x1E)
        while pos < data.len() && data[pos] != 0x1E {
            pos += 1;
        }
        
        if pos >= data.len() {
            break;
        }
        
        pos += 1; // Skip opening tag
        
        // Parse properties sequentially in the order they appear
        // This device seems to send: Object_Name, Present_Value, Units (for analog objects)
        
        // First property: Object_Name (character string)
        if pos < data.len() && data[pos] == 0x29 { // Skip property error/success tag
            pos += 1;
        }
        if pos < data.len() && data[pos] == 0x4D { // Another tag
            pos += 1;
        }
        if pos < data.len() && data[pos] == 0x4E { // Property value opening tag
            pos += 1;
        }
        
        if pos < data.len() && data[pos] == 0x75 { // Character string tag
            if let Some((name, consumed)) = extract_character_string(&data[pos..]) {
                // Debug: comment out for clean output
                // println!("Debug: Extracted object name: '{}'", name);
                objects_info[current_obj_index].object_name = Some(name);
                pos += consumed;
            }
        }
        
        // Skip any intermediate tags and look for present value
        while pos < data.len() && data[pos] != 0x44 && data[pos] != 0x11 && data[pos] != 0x1F {
            pos += 1;
        }
        
        // Present value (real for analog, boolean for binary)
        match objects_info[current_obj_index].object_identifier.object_type {
            ObjectType::AnalogInput | ObjectType::AnalogOutput | ObjectType::AnalogValue => {
                if pos < data.len() && data[pos] == 0x44 { // Real value tag
                    if let Some((value, consumed)) = extract_present_value(&data[pos..], objects_info[current_obj_index].object_identifier.object_type) {
                        // Debug: comment out for clean output
                        // println!("Debug: Extracted present value: '{}'", value);
                        objects_info[current_obj_index].present_value = Some(value);
                        pos += consumed;
                    }
                }
            }
            ObjectType::BinaryInput | ObjectType::BinaryOutput | ObjectType::BinaryValue => {
                if pos < data.len() && data[pos] == 0x11 { // Boolean value tag
                    if let Some((value, consumed)) = extract_present_value(&data[pos..], objects_info[current_obj_index].object_identifier.object_type) {
                        // Debug: comment out for clean output
                        // println!("Debug: Extracted present value: '{}'", value);
                        objects_info[current_obj_index].present_value = Some(value);
                        pos += consumed;
                    }
                }
            }
            _ => {}
        }
        
        // Skip any intermediate content and look for units (enumerated tag 0x91)
        while pos < data.len() && data[pos] != 0x91 && data[pos] != 0x1F {
            pos += 1;
        }
        
        // Units (for analog objects)
        if pos < data.len() && data[pos] == 0x91 { // Enumerated tag
            if let Some((units, consumed)) = extract_units(&data[pos..]) {
                // Debug: comment out for clean output
                // println!("Debug: Extracted units: '{}'", units);
                objects_info[current_obj_index].units = Some(units);
                pos += consumed;
            }
        }
        
        // Find closing tag 0x1F
        while pos < data.len() && data[pos] != 0x1F {
            pos += 1;
        }
        if pos < data.len() && data[pos] == 0x1F {
            pos += 1; // Skip closing tag
        }
        
        current_obj_index += 1;
    }
    
    // Debug: comment out for clean output
    // println!("Debug: Successfully parsed {} objects", current_obj_index);
    Ok(objects_info)
}

/// Extract character string from BACnet encoded data
fn extract_character_string(data: &[u8]) -> Option<(String, usize)> {
    if data.len() < 2 || data[0] != 0x75 { // Character string tag
        return None;
    }
    
    let length = data[1] as usize;
    if data.len() < 2 + length || length == 0 {
        return None;
    }
    
    // Check encoding byte
    let encoding = data[2];
    let string_data = &data[3..2 + length];
    
    let string = match encoding {
        0 => {
            // ANSI X3.4 (ASCII)
            String::from_utf8_lossy(string_data).to_string()
        }
        4 => {
            // UTF-16 (UCS-2) encoding
            if string_data.len() % 2 != 0 {
                return None; // UTF-16 must have even number of bytes
            }
            let mut utf16_chars = Vec::new();
            for chunk in string_data.chunks_exact(2) {
                let char_code = u16::from_be_bytes([chunk[0], chunk[1]]);
                utf16_chars.push(char_code);
            }
            String::from_utf16_lossy(&utf16_chars)
        }
        _ => {
            // Other encodings, fallback to UTF-8
            String::from_utf8_lossy(string_data).to_string()
        }
    };
    
    Some((string, 2 + length))
}

/// Extract present value based on object type
fn extract_present_value(data: &[u8], object_type: ObjectType) -> Option<(String, usize)> {
    if data.is_empty() {
        return None;
    }
    
    match object_type {
        ObjectType::AnalogInput | ObjectType::AnalogOutput | ObjectType::AnalogValue => {
            if data.len() >= 5 && data[0] == 0x44 { // Real value tag
                let bytes = [data[1], data[2], data[3], data[4]];
                let value = f32::from_be_bytes(bytes);
                Some((format!("{:.2}", value), 5))
            } else {
                None
            }
        }
        ObjectType::BinaryInput | ObjectType::BinaryOutput | ObjectType::BinaryValue => {
            if data.len() >= 2 && data[0] == 0x11 { // Boolean tag
                let value = data[1] != 0;
                Some((if value { "Active".to_string() } else { "Inactive".to_string() }, 2))
            } else {
                None
            }
        }
        ObjectType::MultiStateInput | ObjectType::MultiStateOutput | ObjectType::MultiStateValue => {
            if data.len() >= 2 && data[0] == 0x21 { // Unsigned int tag
                let value = data[1];
                Some((format!("State {}", value), 2))
            } else {
                None
            }
        }
        _ => Some(("N/A".to_string(), 1))
    }
}

/// Extract units enumeration
fn extract_units(data: &[u8]) -> Option<(String, usize)> {
    decode_units(data)
}

/// Encode object identifier
fn encode_object_id(object_type: u16, instance: u32) -> u32 {
    ((object_type as u32) << 22) | (instance & 0x3FFFFF)
}

/// Decode object identifier  
fn decode_object_id(encoded: u32) -> (u16, u32) {
    let object_type = ((encoded >> 22) & 0x3FF) as u16;
    let instance = encoded & 0x3FFFFF;
    (object_type, instance)
}

/// Get object type name as string
fn get_object_type_name(object_type: ObjectType) -> &'static str {
    match object_type {
        ObjectType::Device => "Device",
        ObjectType::AnalogInput => "Analog Input",
        ObjectType::AnalogOutput => "Analog Output", 
        ObjectType::AnalogValue => "Analog Value",
        ObjectType::BinaryInput => "Binary Input",
        ObjectType::BinaryOutput => "Binary Output",
        ObjectType::BinaryValue => "Binary Value",
        ObjectType::MultiStateInput => "Multi-State Input",
        ObjectType::MultiStateOutput => "Multi-State Output",
        ObjectType::MultiStateValue => "Multi-State Value",
        ObjectType::Calendar => "Calendar",
        ObjectType::Command => "Command",
        ObjectType::EventEnrollment => "Event Enrollment",
        ObjectType::File => "File",
        ObjectType::Group => "Group",
        ObjectType::Loop => "Loop",
        ObjectType::NotificationClass => "Notification Class",
        ObjectType::Program => "Program",
        ObjectType::Schedule => "Schedule",
        ObjectType::Averaging => "Averaging",
        ObjectType::TrendLog => "Trend Log",
        ObjectType::LifeSafetyPoint => "Life Safety Point",
        ObjectType::LifeSafetyZone => "Life Safety Zone",
        ObjectType::Accumulator => "Accumulator",
        ObjectType::PulseConverter => "Pulse Converter",
        ObjectType::EventLog => "Event Log",
        ObjectType::GlobalGroup => "Global Group",
        ObjectType::TrendLogMultiple => "Trend Log Multiple",
        ObjectType::LoadControl => "Load Control",
        ObjectType::StructuredView => "Structured View",
        ObjectType::AccessDoor => "Access Door",
    }
}