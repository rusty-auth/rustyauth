fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("locate vendored protoc");
    // SAFETY: Cargo gives each build script its own process and code generation
    // reads this before spawning protoc.
    unsafe { std::env::set_var("PROTOC", protoc) };

    connectrpc_build::Config::new()
        .files(&["../proto/rustyauth/fleet/v1/fleet.proto"])
        .includes(&["../proto"])
        .include_file("_connectrpc.rs")
        .compile()
        .expect("compile Fleet protobuf contract for the Dioxus client");
}
