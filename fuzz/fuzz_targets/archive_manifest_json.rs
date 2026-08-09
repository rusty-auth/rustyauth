#![no_main]

use libfuzzer_sys::fuzz_target;
use rustyauth::proto::rustyauth::analytics::v1::MetricBucketArchiveManifest;

fuzz_target!(|data: &[u8]| {
    if let Ok(manifest) = serde_json::from_slice::<MetricBucketArchiveManifest>(data) {
        let _ = rustyauth::analytics::validate_archive_manifest(&manifest);
        let _ = rustyauth::analytics::archive_manifest_signing_payload(&manifest);
    }
});
