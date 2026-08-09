#![no_main]

use buffa::Message;
use libfuzzer_sys::fuzz_target;
use rustyauth::{
    proto::rustyauth::{
        analytics::v1::TelemetryBatchAcknowledgement,
        management::v1::{
            ConnectorFrame, PairingGrant, RealmDiscovery, RealmOperationalSnapshot,
            RemoteMutationRequest, RemoteMutationResult,
        },
    },
    telemetry::validate_management_discovery,
};

fn round_trip<M: Message>(data: &[u8]) {
    if let Ok(decoded) = M::decode_from_slice(data) {
        let encoded = decoded.encode_to_vec();
        let reparsed = M::decode_from_slice(&encoded).expect("an encoded message must decode");
        // Message equality is not a sound round-trip invariant because valid
        // protobuf doubles may contain NaN, and IEEE NaN is not equal to
        // itself. The canonical wire representation must instead become
        // stable after the first successful decode.
        assert_eq!(
            encoded,
            reparsed.encode_to_vec(),
            "protobuf wire representation did not stabilize"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, payload)) = data.split_first() else {
        return;
    };
    // A seed may use `<selector>hex:<protobuf>` so it is reviewable as text.
    // Invalid hex continues through the raw decoder and therefore cannot hide a
    // parser state from the fuzzer.
    let textual_selector = payload.starts_with(b"hex:") && selector.is_ascii_digit();
    let selector = if textual_selector {
        selector - b'0'
    } else {
        selector
    };
    let decoded = payload
        .strip_prefix(b"hex:")
        .and_then(|value| hex::decode(value).ok());
    let payload = decoded.as_deref().unwrap_or(payload);
    match selector % 7 {
        0 => {
            if let Ok(discovery) = RealmDiscovery::decode_from_slice(payload) {
                let _ = validate_management_discovery(&discovery, false);
                let _ = validate_management_discovery(&discovery, true);
            }
            round_trip::<RealmDiscovery>(payload);
        }
        1 => round_trip::<ConnectorFrame>(payload),
        2 => round_trip::<RemoteMutationRequest>(payload),
        3 => round_trip::<RemoteMutationResult>(payload),
        4 => round_trip::<RealmOperationalSnapshot>(payload),
        5 => round_trip::<PairingGrant>(payload),
        _ => round_trip::<TelemetryBatchAcknowledgement>(payload),
    }
});
