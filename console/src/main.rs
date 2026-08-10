#![cfg_attr(
    all(feature = "bundle", target_os = "windows"),
    windows_subsystem = "windows"
)]

mod app;
mod benchmarks;
mod fixtures;
mod fleet_client;
mod models;

mod proto {
    connectrpc::include_generated!();
}

fn main() {
    dioxus::launch(app::App);
}
