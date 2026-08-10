//! Opt-in request timing for the isolated benchmark environment.
//!
//! Internal latency is returned only when the caller proves knowledge of the
//! realm bootstrap secret through a separate benchmark-only header. Ordinary
//! callers receive no datastore timing information and pay no per-command
//! measurement cost.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use axum::{
    extract::Request,
    http::{HeaderMap, HeaderValue, header},
    middleware::Next,
    response::Response,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub const BENCHMARK_TIMING_HEADER: &str = "x-rustyauth-benchmark-timing";
const BENCHMARK_TIMING_DOMAIN: &[u8] = b"rustyauth:benchmark-timing:v1\0";

#[derive(Default)]
struct RequestTimings {
    sabledb_nanoseconds: AtomicU64,
    sabledb_round_trips: AtomicU64,
}

tokio::task_local! {
    static ACTIVE_REQUEST_TIMINGS: Arc<RequestTimings>;
}

/// Derives a benchmark-only capability once at process composition time. The
/// root bootstrap secret is never sent in the timing header, and the derived
/// value cannot be used to bootstrap an account.
pub fn benchmark_timing_digest(secret: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(BENCHMARK_TIMING_DOMAIN);
    digest.update(secret.as_bytes());
    digest.finalize().into()
}

#[cfg(test)]
fn benchmark_timing_token(secret: &str) -> String {
    hex::encode(benchmark_timing_digest(secret))
}

/// Records one completed command or pipeline at the API-to-SableDB boundary.
/// Calls outside an explicitly measured request are intentionally no-ops.
pub fn record_sabledb_round_trip(duration: Duration) {
    let _ = ACTIVE_REQUEST_TIMINGS.try_with(|timings| {
        timings.sabledb_nanoseconds.fetch_add(
            duration.as_nanos().min(u128::from(u64::MAX)) as u64,
            Ordering::Relaxed,
        );
        timings.sabledb_round_trips.fetch_add(1, Ordering::Relaxed);
    });
}

pub async fn benchmark_server_timing(
    request: Request,
    next: Next,
    expected_digest: [u8; 32],
) -> Response {
    if !authorized(request.headers(), &expected_digest) {
        return next.run(request).await;
    }

    let timings = Arc::new(RequestTimings::default());
    let started = Instant::now();
    let mut response = ACTIVE_REQUEST_TIMINGS
        .scope(timings.clone(), next.run(request))
        .await;
    let application_ms = started.elapsed().as_secs_f64() * 1_000.0;
    let sabledb_ms = timings.sabledb_nanoseconds.load(Ordering::Relaxed) as f64 / 1_000_000.0;
    let non_store_ms = (application_ms - sabledb_ms).max(0.0);
    let round_trips = timings.sabledb_round_trips.load(Ordering::Relaxed);
    let value = format!(
        "app;dur={application_ms:.3}, sabledb;dur={sabledb_ms:.3};desc=\"{round_trips} round trips\", nonstore;dur={non_store_ms:.3}"
    );
    if let Ok(value) = HeaderValue::from_str(&value) {
        response
            .headers_mut()
            .insert(header::HeaderName::from_static("server-timing"), value);
    }
    response
}

fn authorized(headers: &HeaderMap, expected_digest: &[u8; 32]) -> bool {
    let Some(candidate) = headers
        .get(BENCHMARK_TIMING_HEADER)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let mut candidate_digest = [0_u8; 32];
    if hex::decode_to_slice(candidate, &mut candidate_digest).is_err() {
        return false;
    }
    bool::from(candidate_digest.ct_eq(expected_digest))
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderMap;

    use super::{
        BENCHMARK_TIMING_HEADER, authorized, benchmark_timing_digest, benchmark_timing_token,
    };

    #[test]
    fn internal_timing_requires_the_exact_benchmark_secret() {
        let digest = benchmark_timing_digest("benchmark-secret-longer-than-32-characters");
        let mut headers = HeaderMap::new();
        assert!(!authorized(&headers, &digest));
        headers.insert(BENCHMARK_TIMING_HEADER, "wrong".parse().unwrap());
        assert!(!authorized(&headers, &digest));
        headers.insert(
            BENCHMARK_TIMING_HEADER,
            benchmark_timing_token("benchmark-secret-longer-than-32-characters")
                .parse()
                .unwrap(),
        );
        assert!(authorized(&headers, &digest));
        assert!(
            !headers[BENCHMARK_TIMING_HEADER]
                .to_str()
                .unwrap()
                .contains("benchmark-secret")
        );
    }
}
