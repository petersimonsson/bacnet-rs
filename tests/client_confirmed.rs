//! End-to-end tests for the client's confirmed-request path (ReadProperty /
//! WriteProperty) over loopback.
//!
//! Each test spins up a tiny in-process "device" that receives one confirmed
//! request, extracts its invoke ID, and replies with a frame the test builds
//! using the crate's own encoders. This exercises the real
//! `send_confirmed_request` transaction path: invoke-ID allocation, the
//! BVLC/NPDU/APDU framing, and the ComplexAck / SimpleAck / Error handling added
//! across commits 2-4.

#![cfg(feature = "std")]

use std::net::{SocketAddr, UdpSocket};
use std::thread;
use std::time::Duration;

use bacnet_rs::{
    app::Apdu,
    client::{BacnetClient, ClientError, WriteOutcome},
    network::Npdu,
    object::{ObjectIdentifier, ObjectType, PropertyIdentifier},
    property::PropertyValue,
    service::{ConfirmedServiceChoice, ReadPropertyResponse},
};

/// Extract the invoke ID and service choice from a received confirmed-request
/// frame (BVLC + NPDU + APDU).
fn parse_confirmed_request(frame: &[u8]) -> (u8, ConfirmedServiceChoice) {
    let (_npdu, npdu_len) = Npdu::decode(&frame[4..]).expect("decode NPDU");
    let apdu = Apdu::decode(&frame[4 + npdu_len..]).expect("decode APDU");
    match apdu {
        Apdu::ConfirmedRequest {
            invoke_id,
            service_choice,
            ..
        } => (invoke_id, service_choice),
        other => panic!("expected ConfirmedRequest, got {other:?}"),
    }
}

/// Wrap a response APDU in NPDU + BVLC (Original-Unicast-NPDU) framing.
fn wrap_response(apdu: Apdu) -> Vec<u8> {
    let mut message = Npdu::new().encode();
    message.extend_from_slice(&apdu.encode());

    let mut frame = vec![0x81, 0x0A, 0x00, 0x00];
    frame.extend_from_slice(&message);
    let len = frame.len() as u16;
    frame[2] = (len >> 8) as u8;
    frame[3] = (len & 0xFF) as u8;
    frame
}

/// Spawn a one-shot loopback device: it waits for a single confirmed request
/// and replies with `make_response(invoke_id, service_choice)`. Returns the
/// device's address.
fn spawn_device<F>(make_response: F) -> SocketAddr
where
    F: FnOnce(u8, ConfirmedServiceChoice) -> Apdu + Send + 'static,
{
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind device");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let addr = socket.local_addr().unwrap();

    thread::spawn(move || {
        let mut buf = [0u8; 1500];
        if let Ok((len, src)) = socket.recv_from(&mut buf) {
            let (invoke_id, service_choice) = parse_confirmed_request(&buf[..len]);
            let frame = wrap_response(make_response(invoke_id, service_choice));
            socket.send_to(&frame, src).expect("send response");
        }
    });

    addr
}

/// Like [`spawn_device`] but answers `count` consecutive requests, calling
/// `make_response` for each (so write-then-read-back flows can be tested).
fn spawn_device_multi<F>(count: usize, mut make_response: F) -> SocketAddr
where
    F: FnMut(u8, ConfirmedServiceChoice) -> Apdu + Send + 'static,
{
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind device");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let addr = socket.local_addr().unwrap();

    thread::spawn(move || {
        let mut buf = [0u8; 1500];
        for _ in 0..count {
            if let Ok((len, src)) = socket.recv_from(&mut buf) {
                let (invoke_id, service_choice) = parse_confirmed_request(&buf[..len]);
                let frame = wrap_response(make_response(invoke_id, service_choice));
                socket.send_to(&frame, src).expect("send response");
            }
        }
    });

    addr
}

/// Build a ComplexAck carrying a ReadProperty response with a single value.
fn read_property_ack(invoke_id: u8, object: ObjectIdentifier, value: PropertyValue) -> Apdu {
    let response = ReadPropertyResponse::new(object, PropertyIdentifier::PresentValue, vec![value]);
    let mut service_data = Vec::new();
    response.encode(&mut service_data).expect("encode response");
    Apdu::ComplexAck {
        segmented: false,
        more_follows: false,
        invoke_id,
        sequence_number: None,
        proposed_window_size: None,
        service_choice: ConfirmedServiceChoice::ReadProperty,
        service_data,
    }
}

fn test_client() -> BacnetClient {
    BacnetClient::builder()
        .local_addr("127.0.0.1")
        .timeout(Duration::from_secs(3))
        .build()
        .expect("build client")
}

#[test]
fn read_property_decodes_complex_ack() {
    let object = ObjectIdentifier::new(ObjectType::AnalogValue, 1);

    let addr = spawn_device(move |invoke_id, _service_choice| {
        let response = ReadPropertyResponse::new(
            object,
            PropertyIdentifier::PresentValue,
            vec![PropertyValue::Real(72.5)],
        );
        let mut service_data = Vec::new();
        response.encode(&mut service_data).expect("encode response");

        Apdu::ComplexAck {
            segmented: false,
            more_follows: false,
            invoke_id,
            sequence_number: None,
            proposed_window_size: None,
            service_choice: ConfirmedServiceChoice::ReadProperty,
            service_data,
        }
    });

    let value = test_client()
        .read_property(addr, object, PropertyIdentifier::PresentValue)
        .expect("read should succeed");

    assert_eq!(value, PropertyValue::Real(72.5));
}

#[test]
fn read_property_surfaces_error_pdu() {
    let object = ObjectIdentifier::new(ObjectType::AnalogValue, 99);

    // Error class 1 (object), code 32 (unknown-object) for example.
    let addr = spawn_device(|invoke_id, _service_choice| Apdu::Error {
        invoke_id,
        service_choice: ConfirmedServiceChoice::ReadProperty,
        error_class: 1,
        error_code: 32,
    });

    let err = test_client()
        .read_property(addr, object, PropertyIdentifier::PresentValue)
        .expect_err("device returned an error PDU");

    assert!(
        matches!(err, ClientError::PropertyError { class: 1, code: 32 }),
        "expected PropertyError(1, 32), got {err:?}"
    );
}

#[test]
fn write_property_accepts_simple_ack() {
    let object = ObjectIdentifier::new(ObjectType::AnalogValue, 1);

    let addr = spawn_device(|invoke_id, _service_choice| Apdu::SimpleAck {
        invoke_id,
        service_choice: ConfirmedServiceChoice::WriteProperty as u8,
    });

    test_client()
        .write_property(
            addr,
            object,
            PropertyIdentifier::PresentValue,
            &PropertyValue::Real(50.0),
            Some(8),
        )
        .expect("write should be acknowledged");
}

#[test]
fn write_property_verified_confirms_when_readback_matches() {
    let object = ObjectIdentifier::new(ObjectType::AnalogValue, 1);

    // Two requests: WriteProperty -> SimpleAck, then ReadProperty -> the value
    // we just wrote, so the verify succeeds.
    let addr = spawn_device_multi(2, move |invoke_id, service_choice| match service_choice {
        ConfirmedServiceChoice::WriteProperty => Apdu::SimpleAck {
            invoke_id,
            service_choice: ConfirmedServiceChoice::WriteProperty as u8,
        },
        ConfirmedServiceChoice::ReadProperty => {
            read_property_ack(invoke_id, object, PropertyValue::Real(3.0))
        }
        other => panic!("unexpected service {other:?}"),
    });

    let outcome = test_client()
        .write_property_verified(
            addr,
            object,
            PropertyIdentifier::PresentValue,
            &PropertyValue::Real(3.0),
            Some(8),
        )
        .expect("write+verify should not error");

    assert_eq!(outcome, WriteOutcome::Verified);
}

#[test]
fn write_property_verified_reports_not_effective_when_overridden() {
    let object = ObjectIdentifier::new(ObjectType::AnalogValue, 4);

    // Device accepts the write (SimpleAck) but the read-back still reports the
    // old value 2.0 — e.g. a higher-priority slot is winning.
    let addr = spawn_device_multi(2, move |invoke_id, service_choice| match service_choice {
        ConfirmedServiceChoice::WriteProperty => Apdu::SimpleAck {
            invoke_id,
            service_choice: ConfirmedServiceChoice::WriteProperty as u8,
        },
        ConfirmedServiceChoice::ReadProperty => {
            read_property_ack(invoke_id, object, PropertyValue::Real(2.0))
        }
        other => panic!("unexpected service {other:?}"),
    });

    let outcome = test_client()
        .write_property_verified(
            addr,
            object,
            PropertyIdentifier::PresentValue,
            &PropertyValue::Real(3.0),
            Some(8),
        )
        .expect("write+verify should not error");

    assert_eq!(
        outcome,
        WriteOutcome::NotEffective {
            read_back: PropertyValue::Real(2.0)
        }
    );
}
