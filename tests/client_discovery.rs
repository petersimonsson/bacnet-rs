//! End-to-end test for the high-level client's device discovery.
//!
//! A tiny in-process "device" listens on a loopback UDP port and answers the
//! first packet it receives with a hand-framed I-Am. The client then runs
//! `discover_device` against that address and we assert it parses the I-Am.
//!
//! This exercises the real socket send/recv path, the BVLC/NPDU/APDU framing in
//! `create_unconfirmed_message`, and `parse_iam_response` the parts of the
//! refactored client that unit tests can't reach.

#![cfg(feature = "std")]

use std::net::{SocketAddr, UdpSocket};
use std::thread;
use std::time::Duration;

use bacnet_rs::{
    client::BacnetClient,
    datalink::bip::{BvlcFunction, BvlcHeader},
    network::Npdu,
    object::{ObjectIdentifier, ObjectType, Segmentation},
    service::{IAmRequest, UnconfirmedServiceChoice},
};

const DEVICE_ID: u32 = 4711;
const VENDOR_ID: u16 = 260; // BACnet Stack at SourceForge

/// Build the I-Am datalink frame the fake device replies with.
fn build_iam_frame() -> Vec<u8> {
    let iam = IAmRequest::new(
        ObjectIdentifier::new(ObjectType::Device, DEVICE_ID),
        1476,
        Segmentation::Both,
        VENDOR_ID,
    );

    let mut iam_buffer = Vec::new();
    iam.encode(&mut iam_buffer).expect("encode I-Am");

    let mut message = Npdu::new().encode();
    message.push(0x10); // Unconfirmed-Request PDU
    message.push(UnconfirmedServiceChoice::IAm as u8);
    message.extend_from_slice(&iam_buffer);

    // Wrap in a BVLC Original-Unicast-NPDU header (length includes the 4-byte header).
    let header = BvlcHeader::new(BvlcFunction::OriginalUnicastNpdu, 4 + message.len() as u16);
    let mut frame = header.encode();
    frame.extend_from_slice(&message);
    frame
}

#[test]
fn discover_device_parses_iam_over_loopback() {
    // Fake device bound to an OS-assigned loopback port.
    let device = UdpSocket::bind("127.0.0.1:0").expect("bind device");
    device
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let device_addr: SocketAddr = device.local_addr().unwrap();

    let responder = thread::spawn(move || {
        let mut buf = [0u8; 1500];
        // Answer the first datagram (the client's Who-Is) with our I-Am.
        if let Ok((_len, src)) = device.recv_from(&mut buf) {
            let frame = build_iam_frame();
            device.send_to(&frame, src).expect("send I-Am");
        }
    });

    let client = BacnetClient::builder()
        .local_addr("127.0.0.1")
        .timeout(Duration::from_secs(3))
        .build()
        .expect("build client");

    let info = client
        .discover_device(device_addr)
        .expect("discovery should succeed");

    assert_eq!(info.device_id, DEVICE_ID);
    assert_eq!(info.vendor_id, VENDOR_ID);
    assert_eq!(info.address, device_addr);

    responder.join().unwrap();
}

#[test]
fn discover_device_times_out_when_no_responder() {
    // A bound-but-silent port: nothing ever replies, so discovery must time out
    // rather than hang or error spuriously.
    let silent = UdpSocket::bind("127.0.0.1:0").expect("bind silent port");
    let silent_addr = silent.local_addr().unwrap();

    let client = BacnetClient::builder()
        .local_addr("127.0.0.1")
        .timeout(Duration::from_millis(300))
        .build()
        .expect("build client");

    let err = client
        .discover_device(silent_addr)
        .expect_err("should time out");

    assert!(
        matches!(err, bacnet_rs::client::ClientError::Timeout),
        "expected Timeout, got {err:?}"
    );
}
