mod app;
mod fixtures;
mod fleet_client;
mod models;

mod proto {
    connectrpc::include_generated!();
}

fn main() {
    dioxus::launch(app::App);
}
