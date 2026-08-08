fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("locate vendored protoc");
    // SAFETY: Cargo runs this build script in a dedicated process and this is
    // set before connectrpc-build reads the environment or spawns protoc.
    unsafe { std::env::set_var("PROTOC", protoc) };

    connectrpc_build::Config::new()
        .files(&[
            "proto/rustyauth/events/v1/events.proto",
            "proto/rustyauth/fleet/v1/fleet.proto",
            "proto/rustyauth/identity/v1/identity.proto",
            "proto/rustyauth/management/v1/management.proto",
            "proto/rustyauth/metrics/v1/metrics.proto",
            "proto/rustyauth/organization/v1/organization.proto",
            "proto/rustyauth/service_accounts/v1/service_accounts.proto",
            "proto/rustyauth/webhooks/v1/webhooks.proto",
        ])
        .includes(&["proto/"])
        .include_file("_connectrpc.rs")
        .compile()
        .expect("compile RustyAuth protobuf contracts");
}
