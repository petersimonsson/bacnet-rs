//! BACnet Client Utilities
//!
//! This module provides high-level client utilities for common BACnet operations
//! such as device discovery, object enumeration, and property reading.
//!
//! The entry point is [`BacnetClient`]. Construct one with [`BacnetClient::new`]
//! for defaults, or with [`BacnetClient::builder`] to customize the local
//! interface, port, timeout, and retries. All methods return [`ClientError`] on
//! failure.

mod config;
mod error;
mod transaction;

pub use config::{ClientBuilder, ClientConfig, DEFAULT_HOST, DEFAULT_TIMEOUT};
pub use error::ClientError;

use transaction::InvokeIdAllocator;

#[cfg(feature = "std")]
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
#[cfg(feature = "std")]
use std::time::{Duration, Instant};

#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeMap as HashMap, string::String, vec::Vec};

use crate::{
    app::{Apdu, MaxApduSize, MaxSegments},
    network::Npdu,
    object::{EngineeringUnits, ObjectIdentifier, ObjectType, PropertyIdentifier, Segmentation},
    property::PropertyValue,
    service::{
        ConfirmedServiceChoice, IAmRequest, PropertyReference, PropertyResultValue,
        ReadAccessResult, ReadAccessSpecification, ReadPropertyMultipleRequest,
        ReadPropertyMultipleResponse, UnconfirmedServiceChoice, WhoIsRequest,
    },
};

/// High-level BACnet client for device communication
#[cfg(feature = "std")]
pub struct BacnetClient {
    socket: UdpSocket,
    timeout: Duration,
    /// Number of retries after an initial timeout (reserved for future use by
    /// the request paths; not yet applied by the existing methods).
    #[allow(dead_code)]
    retries: u8,
    /// Allocates invoke IDs for confirmed-request transactions.
    invoke_ids: InvokeIdAllocator,
}

/// Discovered BACnet device information
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub device_id: u32,
    pub address: SocketAddr,
    pub vendor_id: u16,
    pub vendor_name: String,
    pub max_apdu: u32,
    pub segmentation: Segmentation,
}

/// Object information with common properties
#[derive(Debug, Clone)]
pub struct ObjectInfo {
    pub object_identifier: ObjectIdentifier,
    pub object_name: Option<String>,
    pub description: Option<String>,
    pub present_value: Option<PropertyValue>,
    pub units: Option<EngineeringUnits>,
    pub status_flags: Option<Vec<bool>>,
}

#[cfg(feature = "std")]
impl BacnetClient {
    /// Create a new BACnet client with default configuration.
    ///
    /// Binds to all interfaces on an OS-assigned ephemeral port with a 5 second
    /// timeout. Use [`BacnetClient::builder`] to customize.
    pub fn new() -> Result<Self, ClientError> {
        Self::from_config(ClientConfig::default())
    }

    /// Create a new BACnet client with a specific local socket address (any
    /// type implementing [`ToSocketAddrs`]).
    pub fn new_with_local_addr<A: ToSocketAddrs>(addr: A) -> Result<Self, ClientError> {
        let socket = UdpSocket::bind(addr)?;
        socket.set_read_timeout(Some(DEFAULT_TIMEOUT))?;

        Ok(Self {
            socket,
            timeout: DEFAULT_TIMEOUT,
            retries: 0,
            invoke_ids: InvokeIdAllocator::new(),
        })
    }

    /// Begin building a client with custom configuration.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// The per-request timeout this client is configured with.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// The local socket address the client is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, ClientError> {
        Ok(self.socket.local_addr()?)
    }

    /// Construct a client from a fully-specified [`ClientConfig`], binding the
    /// UDP socket.
    pub(crate) fn from_config(config: ClientConfig) -> Result<Self, ClientError> {
        let socket = UdpSocket::bind(config.bind_addr())?;
        socket.set_read_timeout(Some(config.timeout))?;

        Ok(Self {
            socket,
            timeout: config.timeout,
            retries: config.retries,
            invoke_ids: InvokeIdAllocator::new(),
        })
    }

    /// Discover a device by IP address
    pub fn discover_device(&self, target_addr: SocketAddr) -> Result<DeviceInfo, ClientError> {
        // Send Who-Is request
        let whois = WhoIsRequest::new();
        let mut buffer = Vec::new();
        whois.encode(&mut buffer)?;

        // Create and send message
        let message =
            self.create_unconfirmed_message(UnconfirmedServiceChoice::WhoIs as u8, &buffer);
        self.socket.send_to(&message, target_addr)?;

        // Wait for I-Am response
        let mut recv_buffer = [0u8; 1500];
        let start_time = Instant::now();

        while start_time.elapsed() < self.timeout {
            match self.socket.recv_from(&mut recv_buffer) {
                Ok((len, source)) => {
                    if source == target_addr {
                        if let Some(device_info) =
                            self.parse_iam_response(&recv_buffer[..len], source)
                        {
                            return Ok(device_info);
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e.into()),
            }
        }

        Err(ClientError::Timeout)
    }

    /// Read the device's object list
    pub fn read_object_list(
        &self,
        target_addr: SocketAddr,
        device_id: u32,
    ) -> Result<Vec<ObjectIdentifier>, ClientError> {
        let device_object = ObjectIdentifier::new(ObjectType::Device, device_id);
        let property_ref = PropertyReference::new(PropertyIdentifier::ObjectList); // Object_List property
        let read_spec = ReadAccessSpecification::new(device_object, vec![property_ref]);
        let rpm_request = ReadPropertyMultipleRequest::new(vec![read_spec]);

        let response_data = self.send_confirmed_request(
            target_addr,
            ConfirmedServiceChoice::ReadPropertyMultiple,
            &self.encode_rpm_request(&rpm_request)?,
        )?;

        // The Object_List property comes back as a list of object identifiers
        // inside the ReadPropertyMultiple result. Prefer the structured decoder;
        // the device object itself is dropped.
        let mut objects = Vec::new();
        if let Ok(response) = ReadPropertyMultipleResponse::decode(&response_data) {
            for access in response.read_access_results {
                for result in access.results {
                    if let PropertyResultValue::Value(values) = result.value {
                        for value in values {
                            if let PropertyValue::ObjectIdentifier(oid) = value {
                                if oid.object_type != ObjectType::Device {
                                    objects.push(oid);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Backstop: if the structured decode produced nothing (e.g. an encoding
        // variant it doesn't yet fully handle), scan the raw response for object
        // identifiers so discovery still works.
        if objects.is_empty() {
            objects = Self::scan_object_identifiers(&response_data);
        }

        Ok(objects)
    }

    /// Scan a raw response buffer for application-tagged object identifiers
    /// (tag `0xC4`), skipping the device object. Used as a fallback when the
    /// structured ReadPropertyMultiple decoder yields nothing.
    fn scan_object_identifiers(data: &[u8]) -> Vec<ObjectIdentifier> {
        let mut objects = Vec::new();
        let mut pos = 0;

        while pos + 5 <= data.len() {
            if data[pos] == 0xC4 {
                let obj_id_bytes = [data[pos + 1], data[pos + 2], data[pos + 3], data[pos + 4]];
                let identifier: ObjectIdentifier = u32::from_be_bytes(obj_id_bytes).into();
                if identifier.object_type != ObjectType::Device {
                    objects.push(identifier);
                }
                pos += 5;
            } else {
                pos += 1;
            }
        }

        objects
    }

    /// Read properties for multiple objects
    pub fn read_objects_properties(
        &self,
        target_addr: SocketAddr,
        objects: &[ObjectIdentifier],
    ) -> Result<Vec<ObjectInfo>, ClientError> {
        let mut objects_info = Vec::new();
        let batch_size = 5;

        for chunk in objects.chunks(batch_size) {
            let mut read_specs = Vec::new();

            for obj in chunk {
                let mut property_refs = Vec::new();

                // Always read basic properties
                property_refs.push(PropertyReference::new(PropertyIdentifier::ObjectName)); // Object_Name
                property_refs.push(PropertyReference::new(PropertyIdentifier::Description)); // Description

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
                        property_refs
                            .push(PropertyReference::new(PropertyIdentifier::PresentValue)); // Present_Value
                        property_refs.push(PropertyReference::new(PropertyIdentifier::StatusFlags));
                        // Status_Flags
                    }
                    _ => {}
                }

                // Add Units for analog objects
                match obj.object_type {
                    ObjectType::AnalogInput
                    | ObjectType::AnalogOutput
                    | ObjectType::AnalogValue => {
                        property_refs.push(PropertyReference::new(PropertyIdentifier::Units));
                    }
                    _ => {}
                }

                read_specs.push(ReadAccessSpecification::new(*obj, property_refs));
            }

            let rpm_request = ReadPropertyMultipleRequest::new(read_specs);

            match self.send_confirmed_request(
                target_addr,
                ConfirmedServiceChoice::ReadPropertyMultiple,
                &self.encode_rpm_request(&rpm_request)?,
            ) {
                Ok(response_data) => {
                    match ReadPropertyMultipleResponse::decode(&response_data) {
                        Ok(response) => {
                            for access in response.read_access_results {
                                objects_info.push(Self::object_info_from_access(access));
                            }
                        }
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

    /// Create an unconfirmed message
    fn create_unconfirmed_message(&self, service_choice: u8, service_data: &[u8]) -> Vec<u8> {
        // Create NPDU
        let mut npdu = Npdu::new();
        npdu.control.expecting_reply = false;
        npdu.control.priority = 0;
        let npdu_buffer = npdu.encode();

        // Create unconfirmed service request APDU
        let mut apdu = vec![0x10]; // Unconfirmed-Request PDU type
        apdu.push(service_choice);
        apdu.extend_from_slice(service_data);

        // Combine NPDU and APDU
        let mut message = npdu_buffer;
        message.extend_from_slice(&apdu);

        // Wrap in BVLC header for BACnet/IP (unicast)
        let mut bvlc_message = vec![0x81, 0x0A, 0x00, 0x00];
        bvlc_message.extend_from_slice(&message);

        // Update BVLC length
        let total_len = bvlc_message.len() as u16;
        bvlc_message[2] = (total_len >> 8) as u8;
        bvlc_message[3] = (total_len & 0xFF) as u8;

        bvlc_message
    }

    /// Send a confirmed request and wait for the matching response.
    ///
    /// A fresh invoke ID is allocated for the transaction. Returns the
    /// ComplexAck service data on success, an empty `Vec` for a SimpleAck, or a
    /// typed [`ClientError`] if the device responds with Error/Reject/Abort or
    /// the request times out.
    fn send_confirmed_request(
        &self,
        target_addr: SocketAddr,
        service_choice: ConfirmedServiceChoice,
        service_data: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        let invoke_id = self.invoke_ids.next_id();
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

        let apdu_data = apdu.encode();
        let mut npdu = Npdu::new();
        npdu.control.expecting_reply = true;
        npdu.control.priority = 0;
        let npdu_data = npdu.encode();

        let mut message = npdu_data;
        message.extend_from_slice(&apdu_data);

        let mut bvlc_message = vec![0x81, 0x0A, 0x00, 0x00];
        bvlc_message.extend_from_slice(&message);

        let total_len = bvlc_message.len() as u16;
        bvlc_message[2] = (total_len >> 8) as u8;
        bvlc_message[3] = (total_len & 0xFF) as u8;

        self.socket.send_to(&bvlc_message, target_addr)?;

        // Wait for response
        let mut recv_buffer = [0u8; 1500];
        let start_time = Instant::now();

        while start_time.elapsed() < self.timeout {
            match self.socket.recv_from(&mut recv_buffer) {
                Ok((len, source)) => {
                    if source == target_addr {
                        // A matching Error/Reject/Abort surfaces as Err here; an
                        // unrelated frame yields None so we keep waiting.
                        if let Some(response_data) =
                            self.interpret_confirmed_response(&recv_buffer[..len], invoke_id)?
                        {
                            return Ok(response_data);
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e.into()),
            }
        }

        Err(ClientError::Timeout)
    }

    /// Parse I-Am response
    fn parse_iam_response(&self, data: &[u8], source: SocketAddr) -> Option<DeviceInfo> {
        // Check BVLC header
        if data.len() < 4 || data[0] != 0x81 {
            return None;
        }

        let bvlc_length = ((data[2] as u16) << 8) | (data[3] as u16);
        if data.len() != bvlc_length as usize {
            return None;
        }

        // Decode NPDU
        let npdu_start = 4;
        let (_npdu, npdu_len) = Npdu::decode(&data[npdu_start..]).ok()?;

        // Decode APDU
        let apdu_start = npdu_start + npdu_len;
        let apdu = &data[apdu_start..];

        if apdu.len() < 2 || apdu[0] != 0x10 || apdu[1] != UnconfirmedServiceChoice::IAm as u8 {
            return None;
        }

        match IAmRequest::decode(&apdu[2..]) {
            Ok(iam) => {
                let vendor_name = crate::vendor::get_vendor_name(iam.vendor_identifier)
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
        }
    }

    /// Interpret a received datalink frame as a response to `expected_invoke_id`.
    ///
    /// Returns:
    /// - `Ok(Some(data))` for the matching ComplexAck (service data) or
    ///   SimpleAck (empty),
    /// - `Err(..)` when the device returned a matching Error / Reject / Abort,
    /// - `Ok(None)` when the frame is unrelated (wrong invoke ID, not a
    ///   response, or unparseable) and the caller should keep waiting.
    fn interpret_confirmed_response(
        &self,
        data: &[u8],
        expected_invoke_id: u8,
    ) -> Result<Option<Vec<u8>>, ClientError> {
        // Check BVLC header
        if data.len() < 4 || data[0] != 0x81 {
            return Ok(None);
        }

        let bvlc_length = ((data[2] as u16) << 8) | (data[3] as u16);
        if data.len() != bvlc_length as usize {
            return Ok(None);
        }

        // Decode NPDU and APDU; a frame we can't parse is simply not our reply.
        let npdu_start = 4;
        let (_npdu, npdu_len) = match Npdu::decode(&data[npdu_start..]) {
            Ok(decoded) => decoded,
            Err(_) => return Ok(None),
        };

        let apdu_start = npdu_start + npdu_len;
        let apdu = match Apdu::decode(&data[apdu_start..]) {
            Ok(apdu) => apdu,
            Err(_) => return Ok(None),
        };

        match apdu {
            Apdu::ComplexAck {
                invoke_id,
                service_data,
                ..
            } if invoke_id == expected_invoke_id => Ok(Some(service_data)),
            Apdu::SimpleAck { invoke_id, .. } if invoke_id == expected_invoke_id => {
                Ok(Some(Vec::new()))
            }
            Apdu::Error {
                invoke_id,
                error_class,
                error_code,
                ..
            } if invoke_id == expected_invoke_id => Err(ClientError::PropertyError {
                class: error_class as u32,
                code: error_code as u32,
            }),
            Apdu::Reject {
                invoke_id,
                reject_reason,
            } if invoke_id == expected_invoke_id => Err(ClientError::Rejected(reject_reason)),
            Apdu::Abort {
                invoke_id,
                abort_reason,
                ..
            } if invoke_id == expected_invoke_id => Err(ClientError::Abort(abort_reason)),
            _ => Ok(None),
        }
    }

    /// Encode ReadPropertyMultiple request
    fn encode_rpm_request(
        &self,
        request: &ReadPropertyMultipleRequest,
    ) -> Result<Vec<u8>, ClientError> {
        let mut buffer = Vec::new();

        request.encode(&mut buffer)?;

        Ok(buffer)
    }

    /// Map a decoded ReadPropertyMultiple result for a single object into the
    /// client's [`ObjectInfo`] view, pulling out the common properties.
    ///
    /// Per-property errors (`PropertyResultValue::Error`) are skipped, leaving
    /// that field `None`.
    fn object_info_from_access(access: ReadAccessResult) -> ObjectInfo {
        let mut info = ObjectInfo {
            object_identifier: access.object_identifier,
            object_name: None,
            description: None,
            present_value: None,
            units: None,
            status_flags: None,
        };

        for result in access.results {
            let values = match result.value {
                PropertyResultValue::Value(values) => values,
                PropertyResultValue::Error(..) => continue,
            };
            let first = values.into_iter().next();

            match result.property_identifier {
                PropertyIdentifier::ObjectName => {
                    if let Some(PropertyValue::CharacterString(s)) = first {
                        info.object_name = Some(s);
                    }
                }
                PropertyIdentifier::Description => {
                    if let Some(PropertyValue::CharacterString(s)) = first {
                        info.description = Some(s);
                    }
                }
                PropertyIdentifier::PresentValue => {
                    info.present_value = first;
                }
                PropertyIdentifier::Units => {
                    if let Some(PropertyValue::Enumerated(units_id)) = first {
                        info.units = Some(EngineeringUnits::from(units_id));
                    }
                }
                PropertyIdentifier::StatusFlags => {
                    if let Some(PropertyValue::BitString(bits)) = first {
                        info.status_flags = Some(bits);
                    }
                }
                _ => {}
            }
        }

        info
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_id_encoding() {
        let object_id = ObjectIdentifier::new(ObjectType::AnalogInput, 123);
        let encoded: u32 = match object_id.try_into() {
            Ok(value) => value,
            Err(_) => panic!("Object identifier encoding failed"),
        };
        let decoded = ObjectIdentifier::from(encoded);
        assert_eq!(decoded.object_type, ObjectType::AnalogInput);
        assert_eq!(decoded.instance, 123);

        let object_id = ObjectIdentifier::new(ObjectType::Device, 5047);
        let encoded: u32 = match object_id.try_into() {
            Ok(value) => value,
            Err(_) => panic!("Object identifier encoding failed"),
        };
        let decoded = ObjectIdentifier::from(encoded);
        assert_eq!(decoded.object_type, ObjectType::Device);
        assert_eq!(decoded.instance, 5047);
    }

    #[test]
    fn test_config_defaults() {
        let config = ClientConfig::default();
        assert_eq!(config.host, DEFAULT_HOST);
        assert_eq!(config.port, 0);
        assert_eq!(config.timeout, DEFAULT_TIMEOUT);
        assert_eq!(config.retries, 0);
        assert_eq!(config.bind_addr(), "0.0.0.0:0");
    }

    #[test]
    fn test_builder_sets_fields() {
        // Bind to loopback on an OS-assigned port so the test is hermetic.
        let client = BacnetClient::builder()
            .local_addr("127.0.0.1")
            .port(0)
            .timeout(Duration::from_millis(250))
            .retries(3)
            .build()
            .expect("client should bind");

        assert_eq!(client.timeout(), Duration::from_millis(250));
        assert_eq!(client.retries, 3);

        let local = client.local_addr().expect("local addr");
        assert!(local.ip().is_loopback());
        assert_ne!(local.port(), 0, "OS should assign a real port");
    }

    #[test]
    fn test_new_uses_defaults() {
        let client = BacnetClient::new().expect("client should bind");
        assert_eq!(client.timeout(), DEFAULT_TIMEOUT);
    }

    #[test]
    fn test_error_display() {
        assert_eq!(ClientError::Timeout.to_string(), "request timed out");
        let pe = ClientError::PropertyError { class: 1, code: 31 };
        assert_eq!(pe.to_string(), "BACnet error (class 1, code 31)");
    }
}
