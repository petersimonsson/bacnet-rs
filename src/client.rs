//! BACnet Client Utilities
//!
//! This module provides high-level client utilities for common BACnet operations
//! such as device discovery, object enumeration, and property reading.

#[cfg(feature = "std")]
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeMap as HashMap, string::String, vec::Vec};

use crate::{
    app::{Apdu, MaxApduSize, MaxSegments},
    datalink::bip::BacnetIpDataLink,
    network::Npdu,
    object::{ObjectIdentifier, ObjectType},
    service::{
        ConfirmedServiceChoice, IAmRequest, PropertyReference, ReadAccessSpecification,
        ReadPropertyMultipleRequest, UnconfirmedServiceChoice, WhoIsRequest,
    },
    DataLink, DataLinkAddress,
};

/// High-level BACnet client for device communication
#[cfg(feature = "std")]
pub struct BacnetClient {
    datalink: BacnetIpDataLink,
    timeout: Duration,
}

/// Discovered BACnet device information
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub device_id: u32,
    pub address: SocketAddr,
    pub vendor_id: u32,
    pub vendor_name: String,
    pub max_apdu: u32,
    pub segmentation: u32,
}

/// Object information with common properties
#[derive(Debug, Clone)]
pub struct ObjectInfo {
    pub object_identifier: ObjectIdentifier,
    pub object_name: Option<String>,
    pub description: Option<String>,
    pub present_value: Option<PropertyValue>,
    pub units: Option<String>,
    pub status_flags: Option<Vec<bool>>,
}

/// Decoded property values
#[derive(Debug, Clone)]
pub enum PropertyValue {
    Real(f32),
    Boolean(bool),
    Unsigned(u32),
    Signed(i32),
    CharacterString(String),
    Enumerated(u32),
    Null,
}

#[cfg(feature = "std")]
impl BacnetClient {
    /// Create a new BACnet client
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let datalink = BacnetIpDataLink::new("0.0.0.0:0")?;

        Ok(Self {
            datalink,
            timeout: Duration::from_secs(5),
        })
    }

    /// Discover a device by IP address
    pub fn discover_device(
        &mut self,
        target_addr: SocketAddr,
    ) -> Result<DeviceInfo, Box<dyn std::error::Error>> {
        // Send Who-Is request
        let whois = WhoIsRequest::new();
        let mut buffer = Vec::new();
        whois.encode(&mut buffer)?;

        // Create and send message
        let message = self.create_unconfirmed_message(UnconfirmedServiceChoice::WhoIs, &buffer);
        self.datalink.send_unicast_npdu(&message, target_addr)?;

        // Wait for I-Am response
        let start_time = Instant::now();

        while start_time.elapsed() < self.timeout {
            match self.datalink.receive_frame() {
                Ok((npdu, source)) => {
                    if source == DataLinkAddress::Ip(target_addr) {
                        if let Some(device_info) = self.parse_iam_response(&npdu, target_addr) {
                            return Ok(device_info);
                        }
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }

        Err("Device discovery timeout".into())
    }

    /// Read the device's object list
    pub fn read_object_list(
        &mut self,
        target_addr: SocketAddr,
        device_id: u32,
    ) -> Result<Vec<ObjectIdentifier>, Box<dyn std::error::Error>> {
        let device_object = ObjectIdentifier::new(ObjectType::Device, device_id);
        let property_ref = PropertyReference::new(76); // Object_List property
        let read_spec = ReadAccessSpecification::new(device_object, vec![property_ref]);
        let rpm_request = ReadPropertyMultipleRequest::new(vec![read_spec]);

        let invoke_id = 1;
        let response_data = self.send_confirmed_request(
            target_addr,
            invoke_id,
            ConfirmedServiceChoice::ReadPropertyMultiple,
            &self.encode_rpm_request(&rpm_request)?,
        )?;

        self.parse_object_list_response(&response_data)
    }

    /// Read properties for multiple objects
    pub fn read_objects_properties(
        &mut self,
        target_addr: SocketAddr,
        objects: &[ObjectIdentifier],
    ) -> Result<Vec<ObjectInfo>, Box<dyn std::error::Error>> {
        let mut objects_info = Vec::new();
        let batch_size = 5;

        for (batch_idx, chunk) in objects.chunks(batch_size).enumerate() {
            let mut read_specs = Vec::new();

            for obj in chunk {
                let mut property_refs = Vec::new();

                // Always read basic properties
                property_refs.push(PropertyReference::new(77)); // Object_Name
                property_refs.push(PropertyReference::new(28)); // Description

                // Add Present_Value for input/output/value objects
                match obj.object_type {
                    ObjectType::AnalogInput
                    | ObjectType::AnalogOutput
                    | ObjectType::AnalogValue
                    | ObjectType::BinaryInput
                    | ObjectType::BinaryOutput
                    | ObjectType::BinaryValue
                    | ObjectType::MultiStateInput
                    | ObjectType::MultiStateOutput
                    | ObjectType::MultiStateValue => {
                        property_refs.push(PropertyReference::new(85)); // Present_Value
                        property_refs.push(PropertyReference::new(111)); // Status_Flags
                    }
                    _ => {}
                }

                // Add Units for analog objects
                match obj.object_type {
                    ObjectType::AnalogInput
                    | ObjectType::AnalogOutput
                    | ObjectType::AnalogValue => {
                        property_refs.push(PropertyReference::new(117)); // Units
                    }
                    _ => {}
                }

                read_specs.push(ReadAccessSpecification::new(*obj, property_refs));
            }

            let rpm_request = ReadPropertyMultipleRequest::new(read_specs);
            let invoke_id = (batch_idx + 2) as u8;

            match self.send_confirmed_request(
                target_addr,
                invoke_id,
                ConfirmedServiceChoice::ReadPropertyMultiple,
                &self.encode_rpm_request(&rpm_request)?,
            ) {
                Ok(response_data) => {
                    match self.parse_rpm_response(&response_data, chunk) {
                        Ok(mut batch_info) => objects_info.append(&mut batch_info),
                        Err(_) => {
                            // Add objects with minimal info on parse failure
                            for obj in chunk {
                                objects_info.push(ObjectInfo {
                                    object_identifier: *obj,
                                    object_name: None,
                                    description: None,
                                    present_value: None,
                                    units: None,
                                    status_flags: None,
                                });
                            }
                        }
                    }
                }
                Err(_) => {
                    // Add objects with minimal info on communication failure
                    for obj in chunk {
                        objects_info.push(ObjectInfo {
                            object_identifier: *obj,
                            object_name: None,
                            description: None,
                            present_value: None,
                            units: None,
                            status_flags: None,
                        });
                    }
                }
            }

            // Small delay between requests
            std::thread::sleep(Duration::from_millis(100));
        }

        Ok(objects_info)
    }

    pub fn who_is_scan(&mut self) -> Result<Vec<DeviceInfo>, Box<dyn std::error::Error>> {
        // Send Who-Is request
        let whois = WhoIsRequest::new();
        let mut buffer = Vec::new();
        whois.encode(&mut buffer)?;

        // Create and send message
        let message = self.create_unconfirmed_message(UnconfirmedServiceChoice::WhoIs, &buffer);
        self.datalink.send_broadcast_npdu(&message)?;

        // Wait for I-Am response
        let start_time = Instant::now();
        let mut devices = Vec::new();

        while start_time.elapsed() < self.timeout {
            match self.datalink.receive_frame() {
                Ok((npdu, source)) => {
                    if let DataLinkAddress::Ip(source) = source {
                        if let Some(device_info) = self.parse_iam_response(&npdu, source) {
                            devices.push(device_info);
                        }
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }

        Ok(devices)
    }

    /// Create an unconfirmed message
    fn create_unconfirmed_message(
        &self,
        service_choice: UnconfirmedServiceChoice,
        service_data: &[u8],
    ) -> Vec<u8> {
        // Create NPDU
        let mut npdu = Npdu::new();
        npdu.control.expecting_reply = false;
        npdu.control.priority = 0;
        let mut message = npdu.encode();

        // Create unconfirmed service request APDU
        let apdu = Apdu::UnconfirmedRequest {
            service_choice,
            service_data: service_data.to_owned(),
        };

        // Combine NPDU and APDU
        message.extend_from_slice(&apdu.encode());

        message
    }

    /// Send a confirmed request and wait for response
    fn send_confirmed_request(
        &mut self,
        target_addr: SocketAddr,
        invoke_id: u8,
        service_choice: ConfirmedServiceChoice,
        service_data: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut npdu = Npdu::new();
        npdu.control.expecting_reply = true;
        npdu.control.priority = 0;
        let mut message = npdu.encode();

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

        message.extend_from_slice(&apdu.encode());

        self.datalink.send_unicast_npdu(&message, target_addr)?;

        // Wait for response
        let start_time = Instant::now();

        while start_time.elapsed() < self.timeout {
            match self.datalink.receive_frame() {
                Ok((npdu, source)) => {
                    if source == DataLinkAddress::Ip(target_addr) {
                        if let Some(response_data) =
                            self.process_confirmed_response(&npdu, invoke_id)
                        {
                            return Ok(response_data);
                        }
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }

        Err("Request timeout".into())
    }

    /// Parse I-Am response
    fn parse_iam_response(&self, data: &[u8], source: SocketAddr) -> Option<DeviceInfo> {
        let (_npdu, npdu_len) = Npdu::decode(&data).ok()?;

        // Decode APDU
        let apdu_start = npdu_len;
        let apdu = Apdu::decode(&data[apdu_start..]).ok()?;

        match apdu {
            Apdu::UnconfirmedRequest {
                service_choice: UnconfirmedServiceChoice::IAm,
                service_data,
            } => match IAmRequest::decode(&service_data) {
                Ok(iam) => {
                    let vendor_name = crate::vendor::get_vendor_name(iam.vendor_identifier as u16)
                        .unwrap_or("Unknown Vendor")
                        .to_string();

                    Some(DeviceInfo {
                        device_id: iam.device_identifier.instance,
                        address: source,
                        vendor_id: iam.vendor_identifier,
                        vendor_name,
                        max_apdu: iam.max_apdu_length_accepted,
                        segmentation: iam.segmentation_supported,
                    })
                }
                Err(_) => None,
            },
            _ => None,
        }
    }

    /// Process confirmed response
    fn process_confirmed_response(&self, data: &[u8], expected_invoke_id: u8) -> Option<Vec<u8>> {
        // Check BVLC header
        if data.len() < 4 || data[0] != 0x81 {
            return None;
        }

        let bvlc_length = ((data[2] as u16) << 8) | (data[3] as u16);
        if data.len() != bvlc_length as usize {
            return None;
        }

        // Decode NPDU and APDU
        let npdu_start = 4;
        let (_npdu, npdu_len) = Npdu::decode(&data[npdu_start..]).ok()?;

        let apdu_start = npdu_start + npdu_len;
        let apdu = Apdu::decode(&data[apdu_start..]).ok()?;

        match apdu {
            Apdu::ComplexAck {
                invoke_id,
                service_data,
                ..
            } => {
                if invoke_id == expected_invoke_id {
                    Some(service_data)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Encode ReadPropertyMultiple request
    fn encode_rpm_request(
        &self,
        request: &ReadPropertyMultipleRequest,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut buffer = Vec::new();

        for spec in &request.read_access_specifications {
            // Object identifier - context tag 0
            let object_id = encode_object_id(
                spec.object_identifier.object_type as u16,
                spec.object_identifier.instance,
            );
            buffer.push(0x0C);
            buffer.extend_from_slice(&object_id.to_be_bytes());

            // Property references - context tag 1
            buffer.push(0x1E);
            for prop_ref in &spec.property_references {
                buffer.push(0x09);
                buffer.push(prop_ref.property_identifier as u8);

                if let Some(array_index) = prop_ref.property_array_index {
                    buffer.push(0x19);
                    buffer.push(array_index as u8);
                }
            }
            buffer.push(0x1F);
        }

        Ok(buffer)
    }

    /// Parse object list response
    fn parse_object_list_response(
        &self,
        data: &[u8],
    ) -> Result<Vec<ObjectIdentifier>, Box<dyn std::error::Error>> {
        let mut objects = Vec::new();
        let mut pos = 0;

        // Scan for object identifiers (0xC4 tag)
        while pos + 5 <= data.len() {
            if data[pos] == 0xC4 {
                pos += 1;
                let obj_id_bytes = [data[pos], data[pos + 1], data[pos + 2], data[pos + 3]];
                let obj_id = u32::from_be_bytes(obj_id_bytes);
                let (obj_type, instance) = decode_object_id(obj_id);

                // Skip device object itself
                if obj_type != 8 {
                    if let Ok(object_type) = ObjectType::try_from(obj_type) {
                        objects.push(ObjectIdentifier::new(object_type, instance));
                    }
                }
                pos += 4;
            } else {
                pos += 1;
            }
        }

        Ok(objects)
    }

    /// Parse ReadPropertyMultiple response
    fn parse_rpm_response(
        &self,
        data: &[u8],
        objects: &[ObjectIdentifier],
    ) -> Result<Vec<ObjectInfo>, Box<dyn std::error::Error>> {
        let mut objects_info = Vec::new();

        // Simple implementation - create ObjectInfo for each requested object
        for obj in objects {
            let mut object_info = ObjectInfo {
                object_identifier: *obj,
                object_name: None,
                description: None,
                present_value: None,
                units: None,
                status_flags: None,
            };

            // Parse properties from response data
            // This is a simplified implementation - in practice you'd need more robust parsing
            if let Some(PropertyValue::CharacterString(s)) = extract_property_value(data, 77) {
                object_info.object_name = Some(s);
            }

            if let Some(PropertyValue::CharacterString(s)) = extract_property_value(data, 28) {
                object_info.description = Some(s);
            }

            if let Some(value) = extract_property_value(data, 85) {
                object_info.present_value = Some(value);
            }

            objects_info.push(object_info);
        }

        Ok(objects_info)
    }
}

/// Extract property value from encoded data (simplified implementation)
fn extract_property_value(_data: &[u8], _property_id: u32) -> Option<PropertyValue> {
    // This would need a full implementation based on BACnet encoding rules
    // For now, return None as a placeholder
    None
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

/// Get object type display name
pub fn get_object_type_name(object_type: ObjectType) -> &'static str {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_type_names() {
        assert_eq!(
            get_object_type_name(ObjectType::AnalogInput),
            "Analog Input"
        );
        assert_eq!(get_object_type_name(ObjectType::Device), "Device");
        assert_eq!(
            get_object_type_name(ObjectType::BinaryOutput),
            "Binary Output"
        );
    }

    #[test]
    fn test_object_id_encoding() {
        let encoded = encode_object_id(0, 123);
        let (obj_type, instance) = decode_object_id(encoded);
        assert_eq!(obj_type, 0);
        assert_eq!(instance, 123);

        let encoded = encode_object_id(8, 5047);
        let (obj_type, instance) = decode_object_id(encoded);
        assert_eq!(obj_type, 8);
        assert_eq!(instance, 5047);
    }
}
