fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("locate vendored protoc");
    // SAFETY: Cargo executes this build script as a single-threaded process and
    // the variable is set before connectrpc-build reads or spawns anything.
    unsafe { std::env::set_var("PROTOC", protoc) };

    connectrpc_build::Config::new()
        .files(&[
            "proto/rustyauth/events/v1/events.proto",
            "proto/rustyauth/identity/v1/identity.proto",
        ])
        .includes(&["proto/"])
        .include_file("_connectrpc.rs")
        .compile()
        .expect("compile RustyAuth protobuf contracts");
}
