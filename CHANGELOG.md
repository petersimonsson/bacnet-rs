# Changelog

All notable changes to this project will be documented in this file.

## [0.3.0] - 2026-04-13

### Breaking Changes

- `PropertyValue` enum consolidated into a single type in `property.rs`; duplicate in `client.rs` removed
- `PropertyValue::Unsigned` widened from `u32` to `u64`
- `PropertyValue::Signed` widened from `i32` to `i64`
- `PropertyValue::ObjectIdentifier` changed from `(u16, u32)` to `ObjectIdentifier`
- `PropertyReference::new()` takes `PropertyIdentifier` instead of raw `u32`
- `ReadPropertyResponse.property_value` changed from `Vec<u8>` to `Vec<PropertyValue>`
- `ObjectIdentifier.object_type` changed from `u16` to `ObjectType` enum
- `IAmRequest.segmentation_supported` changed to `Segmentation` enum
- `IAmRequest.vendor_identifier` changed to `u16`
- `NetworkLayerMessage::data` changed to `Option<Vec<u8>>`
- `Apdu::ComplexAck` service_choice changed to `ConfirmedServiceChoice`
- `Apdu::Error` now uses `ConfirmedServiceChoice`
- `Apdu::Reject` now uses `RejectReason`
- `ObjectInfo.units` changed from `Option<String>` to `Option<EngineeringUnits>`
- `encode_enumerated` and `encode_application_tag` are now infallible (no longer return `Result`)

### Added

- `generate_custom_enum!` macro for type-safe enums with Custom/Reserved variants
- `ObjectType` enum with full BACnet standard coverage (replaces raw `u16`)
- `PropertyIdentifier` enum with all standard property identifiers
- `EngineeringUnits` rewrite with `bacnet_name()` and `unit_symbol()` per variant (~120 units)
- `EventState`, `Reliability`, `RejectReason` — complete standard enumerations
- `ReadPropertyMultipleResponse`, `ReadAccessResult`, `PropertyResult` structs for RPM response decoding
- `BACnetTag` enum and `decode_tag()` for generic application/context tag decoding
- `encode_unsigned64`, `decode_unsigned64`, `encode_signed64`, `decode_signed64` for 64-bit integers
- `PropertyValue::Double(f64)` and `PropertyValue::OctetString(Vec<u8>)` variants
- `Display` impl for `PropertyValue` (behind `std` feature)
- `encode()`/`decode()` methods on `ReadPropertyMultipleRequest`, `ReadAccessSpecification`, `PropertyReference`,
  `ReadPropertyResponse`
- Serde support (behind `serde` feature) for `NetworkAddress`, `ObjectIdentifier`, `Segmentation`, `Polarity`,
  `PropertyValue`, and all `generate_custom_enum!` types
- `ProtocolServicesSupported` using `bitflags!` macro
- `TryFrom<u8>` for `BvlcFunction` and `NetworkMessageType`
- `TryFrom<u32>` for `Segmentation` and `Polarity`
- `Display` impl for `Segmentation`
- Helper functions `set_source()` and `set_destination()` on `Npdu`
- `NetworkAddress` now implements `Hash`

### Fixed

- `UnconfirmedServiceChoice` conversion from `u8` was incorrect
- `service_choice` was being double-converted in APDU handling
- `Apdu::Error` variant handling was broken
- Removed broken `bincode` dependency
- Pinned `crc` to `3.3.*` for MSRV compatibility

### Changed

- README updated with honest implementation status table and WIP notice
- CI: replaced `cargo install cargo-deny --locked` with `taiki-e/install-action@cargo-deny` (pre-built binary)
- ~450 lines of duplicate/broken unit mapping code removed from `property.rs`
- Duplicate property value decoding functions consolidated into `decode_property_value()`
- `decode_property_value()` now returns `Result` instead of `Option`

## [0.2.2] - 2025-10-02

