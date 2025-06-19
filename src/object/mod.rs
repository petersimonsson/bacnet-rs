//! BACnet Object Types Module
//!
//! This module defines BACnet object types and their properties according to ASHRAE 135.
//! Objects are the fundamental modeling concept in BACnet, representing physical inputs,
//! outputs, control values, and software functions.
//!
//! # Overview
//!
//! BACnet objects consist of:
//! - A unique object identifier (type + instance number)
//! - A collection of properties that describe the object's state and behavior
//! - Required properties that must be present
//! - Optional properties that may be present
//!
//! # Standard Object Types
//!
//! Common object types include:
//! - Analog Input/Output/Value
//! - Binary Input/Output/Value
//! - Multi-state Input/Output/Value
//! - Device
//! - Schedule
//! - Calendar
//! - Trend Log
//! - And many more...
//!
//! # Example
//!
//! ```no_run
//! use bacnet_rs::object::*;
//!
//! // Example of creating an object identifier
//! let obj_id = ObjectIdentifier::new(ObjectType::AnalogInput, 1);
//! ```

// TODO: Will be needed for object database
// HashMap is only available with std feature
// For no-std, consider using BTreeMap or a custom implementation
// #[cfg(feature = "std")]
// use std::collections::HashMap;

#[cfg(feature = "std")]
use std::error::Error;

#[cfg(feature = "std")]
use std::fmt;

#[cfg(not(feature = "std"))]
use core::fmt;

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

/// Result type for object operations
#[cfg(feature = "std")]
pub type Result<T> = std::result::Result<T, ObjectError>;

#[cfg(not(feature = "std"))]
pub type Result<T> = core::result::Result<T, ObjectError>;

/// Errors that can occur with object operations
#[derive(Debug)]
pub enum ObjectError {
    /// Object not found
    NotFound,
    /// Property not found
    PropertyNotFound,
    /// Unknown property
    UnknownProperty,
    /// Property not writable
    PropertyNotWritable,
    /// Invalid property type
    InvalidPropertyType,
    /// Invalid property value
    InvalidValue(String),
    /// Write access denied
    WriteAccessDenied,
    /// Invalid object configuration
    InvalidConfiguration(String),
}

impl fmt::Display for ObjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ObjectError::NotFound => write!(f, "Object not found"),
            ObjectError::PropertyNotFound => write!(f, "Property not found"),
            ObjectError::UnknownProperty => write!(f, "Unknown property"),
            ObjectError::PropertyNotWritable => write!(f, "Property not writable"),
            ObjectError::InvalidPropertyType => write!(f, "Invalid property type"),
            ObjectError::InvalidValue(msg) => write!(f, "Invalid value: {}", msg),
            ObjectError::WriteAccessDenied => write!(f, "Write access denied"),
            ObjectError::InvalidConfiguration(msg) => write!(f, "Invalid configuration: {}", msg),
        }
    }
}

#[cfg(feature = "std")]
impl Error for ObjectError {}

/// BACnet object types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ObjectType {
    AnalogInput = 0,
    AnalogOutput = 1,
    AnalogValue = 2,
    BinaryInput = 3,
    BinaryOutput = 4,
    BinaryValue = 5,
    Calendar = 6,
    Command = 7,
    Device = 8,
    EventEnrollment = 9,
    File = 10,
    Group = 11,
    Loop = 12,
    MultiStateInput = 13,
    MultiStateOutput = 14,
    MultiStateValue = 19,
    NotificationClass = 15,
    Program = 16,
    Schedule = 17,
    Averaging = 18,
    TrendLog = 20,
    LifeSafetyPoint = 21,
    LifeSafetyZone = 22,
    Accumulator = 23,
    PulseConverter = 24,
    EventLog = 25,
    GlobalGroup = 26,
    TrendLogMultiple = 27,
    LoadControl = 28,
    StructuredView = 29,
    AccessDoor = 30,
    // ... many more standard types
    // Vendor specific range starts at 128
}

impl TryFrom<u16> for ObjectType {
    type Error = ObjectError;

    fn try_from(value: u16) -> Result<Self> {
        match value {
            0 => Ok(ObjectType::AnalogInput),
            1 => Ok(ObjectType::AnalogOutput),
            2 => Ok(ObjectType::AnalogValue),
            3 => Ok(ObjectType::BinaryInput),
            4 => Ok(ObjectType::BinaryOutput),
            5 => Ok(ObjectType::BinaryValue),
            6 => Ok(ObjectType::Calendar),
            7 => Ok(ObjectType::Command),
            8 => Ok(ObjectType::Device),
            9 => Ok(ObjectType::EventEnrollment),
            10 => Ok(ObjectType::File),
            11 => Ok(ObjectType::Group),
            12 => Ok(ObjectType::Loop),
            13 => Ok(ObjectType::MultiStateInput),
            14 => Ok(ObjectType::MultiStateOutput),
            15 => Ok(ObjectType::NotificationClass),
            16 => Ok(ObjectType::Program),
            17 => Ok(ObjectType::Schedule),
            18 => Ok(ObjectType::Averaging),
            19 => Ok(ObjectType::MultiStateValue),
            20 => Ok(ObjectType::TrendLog),
            21 => Ok(ObjectType::LifeSafetyPoint),
            22 => Ok(ObjectType::LifeSafetyZone),
            23 => Ok(ObjectType::Accumulator),
            24 => Ok(ObjectType::PulseConverter),
            25 => Ok(ObjectType::EventLog),
            26 => Ok(ObjectType::GlobalGroup),
            27 => Ok(ObjectType::TrendLogMultiple),
            28 => Ok(ObjectType::LoadControl),
            29 => Ok(ObjectType::StructuredView),
            30 => Ok(ObjectType::AccessDoor),
            _ => Err(ObjectError::InvalidValue(format!("Unknown object type: {}", value))),
        }
    }
}

/// BACnet property identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum PropertyIdentifier {
    AcceptedModes = 175,
    AckedTransitions = 0,
    AckRequired = 1,
    Action = 2,
    ActionText = 3,
    ActiveText = 4,
    ActiveVtSessions = 5,
    AlarmValue = 6,
    AlarmValues = 7,
    All = 8,
    AllWritesSuccessful = 9,
    ApduSegmentTimeout = 10,
    ApduTimeout = 11,
    ApplicationSoftwareVersion = 12,
    Archive = 13,
    Bias = 14,
    ChangeOfStateCount = 15,
    ChangeOfStateTime = 16,
    // ... many more properties
    DatabaseRevision = 155,
    FirmwareRevision = 44,
    MaxApduLengthAccepted = 62,
    ModelName = 70,
    ObjectIdentifier = 75,
    ObjectList = 76,
    ObjectName = 77,
    ObjectType = 79,
    OutOfService = 81,
    OutputUnits = 82,
    PresentValue = 85,
    ProtocolRevision = 139,
    ProtocolVersion = 98,
    SegmentationSupported = 107,
    SystemStatus = 112,
    VendorIdentifier = 120,
    VendorName = 121,
    Priority = 86,
    PriorityArray = 87,
    ProcessIdentifier = 89,
    ProgramChange = 90,
    ProgramLocation = 91,
    ProgramState = 92,
    ProportionalConstant = 93,
    ProportionalConstantUnits = 94,
    // ... continues with many more properties
}

/// Object identifier (type + instance number)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectIdentifier {
    pub object_type: ObjectType,
    pub instance: u32,
}

impl ObjectIdentifier {
    /// Create a new object identifier
    pub fn new(object_type: ObjectType, instance: u32) -> Self {
        Self {
            object_type,
            instance,
        }
    }

    /// Check if instance number is valid (0-4194302)
    pub fn is_valid(&self) -> bool {
        self.instance <= 0x3FFFFF
    }
}

/// Trait for all BACnet objects
pub trait BacnetObject: Send + Sync {
    /// Get the object identifier
    fn identifier(&self) -> ObjectIdentifier;

    /// Get a property value
    fn get_property(&self, property: PropertyIdentifier) -> Result<PropertyValue>;

    /// Set a property value
    fn set_property(&mut self, property: PropertyIdentifier, value: PropertyValue) -> Result<()>;

    /// Check if property is writable
    fn is_property_writable(&self, property: PropertyIdentifier) -> bool;

    /// Get list of all properties
    fn property_list(&self) -> Vec<PropertyIdentifier>;
}

/// Property values can be of various types
#[derive(Debug, Clone)]
pub enum PropertyValue {
    Null,
    Boolean(bool),
    UnsignedInteger(u32),
    SignedInt(i32),
    Real(f32),
    Double(f64),
    OctetString(Vec<u8>),
    CharacterString(String),
    BitString(Vec<bool>),
    Enumerated(u32),
    Date(Date),
    Time(Time),
    ObjectIdentifier(ObjectIdentifier),
    Array(Vec<PropertyValue>),
    List(Vec<PropertyValue>),
}

/// BACnet date representation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Date {
    pub year: u16,   // 1900-2155, 255 = unspecified
    pub month: u8,   // 1-12, 13 = odd months, 14 = even months, 255 = unspecified
    pub day: u8,     // 1-31, 32 = last day of month, 255 = unspecified
    pub weekday: u8, // 1-7 (Mon-Sun), 255 = unspecified
}

/// BACnet time representation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Time {
    pub hour: u8,       // 0-23, 255 = unspecified
    pub minute: u8,     // 0-59, 255 = unspecified
    pub second: u8,     // 0-59, 255 = unspecified
    pub hundredths: u8, // 0-99, 255 = unspecified
}

// use crate::util::{encode_object_id, decode_object_id}; // TODO: Will be needed for object encoding

/// Device object implementation
#[derive(Debug, Clone)]
pub struct Device {
    /// Object identifier
    pub identifier: ObjectIdentifier,
    /// Object name (required property)
    pub object_name: String,
    /// Object type (always Device)
    pub object_type: ObjectType,
    /// System status
    pub system_status: DeviceStatus,
    /// Vendor name
    pub vendor_name: String,
    /// Vendor identifier
    pub vendor_identifier: u16,
    /// Model name
    pub model_name: String,
    /// Firmware revision
    pub firmware_revision: String,
    /// Application software version
    pub application_software_version: String,
    /// Protocol version (always 1)
    pub protocol_version: u8,
    /// Protocol revision
    pub protocol_revision: u8,
    /// Protocol services supported
    pub protocol_services_supported: ProtocolServicesSupported,
    /// Object types supported
    pub object_types_supported: Vec<ObjectType>,
    /// Maximum APDU length accepted
    pub max_apdu_length_accepted: u16,
    /// Segmentation support
    pub segmentation_supported: Segmentation,
    /// Device address binding (for routing)
    pub device_address_binding: Vec<AddressBinding>,
    /// Database revision
    pub database_revision: u32,
}

impl Device {
    /// Create a new Device object
    pub fn new(instance: u32, object_name: String) -> Self {
        Self {
            identifier: ObjectIdentifier::new(ObjectType::Device, instance),
            object_name,
            object_type: ObjectType::Device,
            system_status: DeviceStatus::Operational,
            vendor_name: String::from("BACnet-RS"),
            vendor_identifier: 999, // TODO: Get official vendor ID
            model_name: String::from("Rust BACnet Device"),
            firmware_revision: String::from("1.0.0"),
            application_software_version: String::from("0.1.0"),
            protocol_version: 1,
            protocol_revision: 22, // Current BACnet protocol revision
            protocol_services_supported: ProtocolServicesSupported::default(),
            object_types_supported: vec![ObjectType::Device],
            max_apdu_length_accepted: 1476,
            segmentation_supported: Segmentation::Both,
            device_address_binding: Vec::new(),
            database_revision: 1,
        }
    }

    /// Add an object type to the supported list
    pub fn add_supported_object_type(&mut self, object_type: ObjectType) {
        if !self.object_types_supported.contains(&object_type) {
            self.object_types_supported.push(object_type);
        }
    }
}

impl BacnetObject for Device {
    fn identifier(&self) -> ObjectIdentifier {
        self.identifier
    }

    fn get_property(&self, property: PropertyIdentifier) -> Result<PropertyValue> {
        match property {
            PropertyIdentifier::ObjectIdentifier => {
                Ok(PropertyValue::ObjectIdentifier(self.identifier))
            }
            PropertyIdentifier::ObjectName => {
                Ok(PropertyValue::CharacterString(self.object_name.clone()))
            }
            PropertyIdentifier::ObjectType => {
                Ok(PropertyValue::Enumerated(self.object_type as u32))
            }
            PropertyIdentifier::SystemStatus => {
                Ok(PropertyValue::Enumerated(self.system_status as u32))
            }
            PropertyIdentifier::VendorName => {
                Ok(PropertyValue::CharacterString(self.vendor_name.clone()))
            }
            PropertyIdentifier::VendorIdentifier => {
                Ok(PropertyValue::UnsignedInteger(self.vendor_identifier as u32))
            }
            PropertyIdentifier::ModelName => {
                Ok(PropertyValue::CharacterString(self.model_name.clone()))
            }
            PropertyIdentifier::FirmwareRevision => {
                Ok(PropertyValue::CharacterString(self.firmware_revision.clone()))
            }
            PropertyIdentifier::ApplicationSoftwareVersion => {
                Ok(PropertyValue::CharacterString(self.application_software_version.clone()))
            }
            PropertyIdentifier::ProtocolVersion => {
                Ok(PropertyValue::UnsignedInteger(self.protocol_version as u32))
            }
            PropertyIdentifier::ProtocolRevision => {
                Ok(PropertyValue::UnsignedInteger(self.protocol_revision as u32))
            }
            PropertyIdentifier::MaxApduLengthAccepted => {
                Ok(PropertyValue::UnsignedInteger(self.max_apdu_length_accepted as u32))
            }
            PropertyIdentifier::SegmentationSupported => {
                Ok(PropertyValue::Enumerated(self.segmentation_supported as u32))
            }
            PropertyIdentifier::DatabaseRevision => {
                Ok(PropertyValue::UnsignedInteger(self.database_revision))
            }
            _ => Err(ObjectError::UnknownProperty),
        }
    }

    fn set_property(&mut self, property: PropertyIdentifier, value: PropertyValue) -> Result<()> {
        match property {
            PropertyIdentifier::ObjectName => {
                if let PropertyValue::CharacterString(name) = value {
                    self.object_name = name;
                    Ok(())
                } else {
                    Err(ObjectError::InvalidPropertyType)
                }
            }
            PropertyIdentifier::VendorName => {
                if let PropertyValue::CharacterString(name) = value {
                    self.vendor_name = name;
                    Ok(())
                } else {
                    Err(ObjectError::InvalidPropertyType)
                }
            }
            PropertyIdentifier::ModelName => {
                if let PropertyValue::CharacterString(name) = value {
                    self.model_name = name;
                    Ok(())
                } else {
                    Err(ObjectError::InvalidPropertyType)
                }
            }
            PropertyIdentifier::FirmwareRevision => {
                if let PropertyValue::CharacterString(revision) = value {
                    self.firmware_revision = revision;
                    Ok(())
                } else {
                    Err(ObjectError::InvalidPropertyType)
                }
            }
            PropertyIdentifier::ApplicationSoftwareVersion => {
                if let PropertyValue::CharacterString(version) = value {
                    self.application_software_version = version;
                    Ok(())
                } else {
                    Err(ObjectError::InvalidPropertyType)
                }
            }
            PropertyIdentifier::DatabaseRevision => {
                if let PropertyValue::UnsignedInteger(revision) = value {
                    self.database_revision = revision;
                    Ok(())
                } else {
                    Err(ObjectError::InvalidPropertyType)
                }
            }
            _ => Err(ObjectError::PropertyNotWritable),
        }
    }

    fn is_property_writable(&self, property: PropertyIdentifier) -> bool {
        matches!(
            property,
            PropertyIdentifier::ObjectName
                | PropertyIdentifier::VendorName
                | PropertyIdentifier::ModelName
                | PropertyIdentifier::FirmwareRevision
                | PropertyIdentifier::ApplicationSoftwareVersion
                | PropertyIdentifier::DatabaseRevision
        )
    }

    fn property_list(&self) -> Vec<PropertyIdentifier> {
        vec![
            PropertyIdentifier::ObjectIdentifier,
            PropertyIdentifier::ObjectName,
            PropertyIdentifier::ObjectType,
            PropertyIdentifier::SystemStatus,
            PropertyIdentifier::VendorName,
            PropertyIdentifier::VendorIdentifier,
            PropertyIdentifier::ModelName,
            PropertyIdentifier::FirmwareRevision,
            PropertyIdentifier::ApplicationSoftwareVersion,
            PropertyIdentifier::ProtocolVersion,
            PropertyIdentifier::ProtocolRevision,
            PropertyIdentifier::MaxApduLengthAccepted,
            PropertyIdentifier::SegmentationSupported,
            PropertyIdentifier::DatabaseRevision,
        ]
    }
}

/// Device status enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DeviceStatus {
    Operational = 0,
    OperationalReadOnly = 1,
    DownloadRequired = 2,
    DownloadInProgress = 3,
    NonOperational = 4,
    BackupInProgress = 5,
}

/// Segmentation support enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Segmentation {
    Both = 0,
    Transmit = 1,
    Receive = 2,
    NoSegmentation = 3,
}

/// Protocol services supported bitfield
#[derive(Debug, Clone)]
pub struct ProtocolServicesSupported {
    pub bits: [u8; 5], // 40 bits for all BACnet services
}

impl Default for ProtocolServicesSupported {
    fn default() -> Self {
        Self { bits: [0; 5] }
    }
}

impl ProtocolServicesSupported {
    /// Set a service as supported
    pub fn set_service(&mut self, service: u8, supported: bool) {
        if service < 40 {
            let byte_index = service / 8;
            let bit_index = service % 8;
            if supported {
                self.bits[byte_index as usize] |= 1 << bit_index;
            } else {
                self.bits[byte_index as usize] &= !(1 << bit_index);
            }
        }
    }

    /// Check if a service is supported
    pub fn is_service_supported(&self, service: u8) -> bool {
        if service < 40 {
            let byte_index = service / 8;
            let bit_index = service % 8;
            (self.bits[byte_index as usize] & (1 << bit_index)) != 0
        } else {
            false
        }
    }
}

/// Address binding for device routing
#[derive(Debug, Clone)]
pub struct AddressBinding {
    pub device_identifier: ObjectIdentifier,
    pub network_address: Vec<u8>,
}

/// Analog object types (AI, AO, AV)
pub mod analog;
/// Binary object types (BI, BO, BV)
pub mod binary;
/// Multi-state object types (MSI, MSO, MSV)
pub mod multistate;
/// File object type
pub mod file;

pub use analog::{AnalogInput, AnalogOutput, AnalogValue, EventState, Reliability, EngineeringUnits};
pub use binary::{BinaryInput, BinaryOutput, BinaryValue, BinaryPV, Polarity};
pub use multistate::{MultiStateInput, MultiStateOutput, MultiStateValue};
pub use file::{File, FileAccessMethod};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_creation() {
        let device = Device::new(123, "Test Device".to_string());
        assert_eq!(device.identifier.instance, 123);
        assert_eq!(device.object_name, "Test Device");
        assert_eq!(device.object_type, ObjectType::Device);
    }

    #[test]
    fn test_device_properties() {
        let mut device = Device::new(456, "Property Test".to_string());
        
        // Test getting properties
        let name = device.get_property(PropertyIdentifier::ObjectName).unwrap();
        if let PropertyValue::CharacterString(n) = name {
            assert_eq!(n, "Property Test");
        } else {
            panic!("Expected CharacterString");
        }

        // Test setting properties
        device
            .set_property(
                PropertyIdentifier::ObjectName,
                PropertyValue::CharacterString("New Name".to_string()),
            )
            .unwrap();
        
        let name = device.get_property(PropertyIdentifier::ObjectName).unwrap();
        if let PropertyValue::CharacterString(n) = name {
            assert_eq!(n, "New Name");
        } else {
            panic!("Expected CharacterString");
        }
    }

    #[test]
    fn test_protocol_services_supported() {
        let mut services = ProtocolServicesSupported::default();
        
        // Set some services as supported
        services.set_service(0, true); // Acknowledge-Alarm
        services.set_service(12, true); // Read-Property
        services.set_service(15, true); // Write-Property
        
        assert!(services.is_service_supported(0));
        assert!(services.is_service_supported(12));
        assert!(services.is_service_supported(15));
        assert!(!services.is_service_supported(1));
        assert!(!services.is_service_supported(13));
    }
}
