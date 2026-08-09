#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Textual hex seeds remain reviewable in git while mutations still reach the
    // binary Protobuf decoder. Any malformed hex falls back to raw bytes so the
    // transformation never narrows libFuzzer's input space.
    let decoded = data.strip_prefix(b"hex:").and_then(|value| hex::decode(value).ok());
    let payload = decoded.as_deref().unwrap_or(data);
    let _ = rustyauth::analytics::decode_and_validate_batch(payload);
});
