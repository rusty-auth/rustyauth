# RustyAuth Helm charts

RustyAuth ships three charts for the deployment boundaries it supports:

| Chart | Installs | Use it for |
| --- | --- | --- |
| [`rustyauth-integrated`](rustyauth-integrated/) | WebAssembly dashboard gateway, Realm API and SableDB | One self-contained application environment |
| [`rustyauth-fleet`](rustyauth-fleet/) | WebAssembly Fleet dashboard gateway, control-plane API and Fleet SableDB | The central management plane |
| [`rustyauth-realm`](rustyauth-realm/) | Realm API and SableDB | Lightweight project/environment realms managed from Fleet |

The Dioxus browser application is compiled to WebAssembly. The small gateway, Rust API and SableDB are native
Linux binaries in scratch containers; Kubernetes cannot run those server processes as browser WebAssembly.

See [the Kubernetes deployment guide](../docs/KUBERNETES.md) for Civo/K3s commands, secret creation, ingress,
storage, upgrades and Fleet topology.
