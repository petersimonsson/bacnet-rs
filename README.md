# BACnet-RS

A BACnet (Building Automation and Control Networks) protocol stack implementation in Rust.

> **Note:** This library is under active development and not yet production-ready. APIs may change between releases.
> Contributions and feedback are welcome.

## Overview

This library provides an implementation of the BACnet protocol stack in Rust, targeting compliance with ANSI/ASHRAE
Standard 135-2024. It supports multiple data link layers, core BACnet services, and is designed for both embedded and
desktop applications.

## Implementation Status

| Component                  | Status          | Notes                                                   |
|----------------------------|-----------------|---------------------------------------------------------|
| **Encoding/Decoding**      | Working         | ASN.1 application and context tags, all primitive types |
| **BACnet/IP (Annex J)**    | Working         | BVLC, BBMD, Foreign Device registration                 |
| **MS/TP (Clause 9)**       | Working         | Frame encoding, CRC, token-passing                      |
| **Ethernet (Clause 7)**    | Working         | 802.3 frames, LLC headers                               |
| **Who-Is / I-Am**          | Working         | Device discovery                                        |
| **Read Property**          | Working         | Single property read                                    |
| **Read Property Multiple** | Working         | Batch property reads                                    |
| **Write Property**         | Working         | Single property write                                   |
| **Subscribe COV**          | Working         | Change-of-value subscriptions                           |
| **Atomic File Read/Write** | Working         | Stream and record access                                |
| **Time Synchronization**   | Working         | Standard and UTC                                        |
| **Analog Objects**         | Working         | Input, Output, Value with priority arrays               |
| **Binary Objects**         | Working         | Input, Output, Value with priority arrays               |
| **Multistate Objects**     | Working         | Input, Output, Value                                    |
| **File / Device Objects**  | Working         | Basic property support                                  |
| **Client API**             | Partial         | Discovery and read-only via BACnet/IP only              |
| **Segmentation**           | Not implemented | Large message segmentation/reassembly                   |
| **Alarm & Event**          | Not implemented | Intrinsic and algorithmic reporting                     |
| **Trending**               | Not implemented | Trend log objects                                       |
| **Scheduling**             | Not implemented | Schedule and calendar objects                           |
| **BACnet/SC (Annex AB)**   | Not implemented | Secure Connect                                          |

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
bacnet-rs = "0.3"
```

### Feature Flags

- `std` (default): Standard library support with networking capabilities
- `async` (default): Async/await support with Tokio runtime
- `serde` (default): Serialization support for BACnet types

To use without async support:
```toml
bacnet-rs = { version = "0.3", default-features = false, features = ["std"] }
```

## Architecture

The stack is organized into layered modules:

- **Encoding** (`src/encoding/`): BACnet data encoding/decoding, ASN.1 tag handling
- **Datalink** (`src/datalink/`): BACnet/IP, MS/TP, Ethernet implementations
- **Network** (`src/network/`): NPDU handling and routing
- **Service** (`src/service/`): BACnet service request/response implementations
- **Object** (`src/object/`): Standard BACnet object types and database
- **Application** (`src/app/`): APDU handling and segmentation
- **Client** (`src/client.rs`): High-level BACnet client API

## Contributing

Contributions are welcome. Please open an issue or pull request.

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
