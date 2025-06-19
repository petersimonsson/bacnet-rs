#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]

pub mod app;
pub mod datalink;
pub mod encoding;
pub mod network;
pub mod object;
pub mod service;
pub mod transport;
pub mod util;

// Re-export main types without glob imports to avoid conflicts
pub use datalink::{DataLink, DataLinkAddress, DataLinkType};
pub use encoding::{ApplicationTag, EncodingError};
pub use object::{BacnetObject, ObjectType, PropertyIdentifier};
pub use service::{ConfirmedServiceChoice, ServiceError, UnconfirmedServiceChoice};

#[cfg(feature = "std")]
extern crate std;

#[cfg(not(feature = "std"))]
extern crate alloc;

pub const BACNET_PROTOCOL_VERSION: u8 = 1;
pub const BACNET_MAX_APDU: usize = 1476;
pub const BACNET_MAX_MPDU: usize = 1497;

#[cfg(test)]
mod tests {
    use crate::object::ObjectIdentifier;
    use crate::util::{crc16_mstp, decode_object_id, encode_object_id};
    use crate::{ApplicationTag, EncodingError, ObjectType};

    #[cfg(not(feature = "std"))]
    use alloc::format;

    #[test]
    fn test_no_std_types() {
        // Test that our types work in both std and no-std environments
        let tag = ApplicationTag::Boolean;
        assert_eq!(tag as u8, 1);

        let obj_type = ObjectType::AnalogInput;
        assert_eq!(obj_type as u16, 0);

        let obj_id = ObjectIdentifier::new(ObjectType::Device, 123);
        assert_eq!(obj_id.instance, 123);
        assert!(obj_id.is_valid());
    }

    #[test]
    fn test_encoding_error() {
        let err = EncodingError::BufferOverflow;
        // In no-std, we can still format errors
        let _ = format!("{:?}", err);
    }

    #[test]
    fn test_util_functions() {
        // Test CRC calculation
        let data = b"test";
        let crc = crc16_mstp(data);
        assert_ne!(crc, 0);

        // Test object ID encoding/decoding
        let encoded = encode_object_id(8, 123).unwrap();
        let (obj_type, instance) = decode_object_id(encoded);
        assert_eq!(obj_type, 8);
        assert_eq!(instance, 123);
    }
}
