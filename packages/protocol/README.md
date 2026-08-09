# @rustyauth/protocol

ConnectRPC v2 service descriptors and protobuf message types for RustyAuth TypeScript clients. They are
generated from the repository's `proto/rustyauth` contracts, which are also compiled into the Rust server.

Fleet Analytics compatibility fixtures and the canonical V1 Parquet schema live under `fixtures/analytics` and
`schemas/analytics`. They are published with this package and must change only under the versioning rules in
the Fleet Analytics V1 semantic contract.

```ts
import { createClient } from "@connectrpc/connect";
import { IdentityService } from "@rustyauth/protocol";

const identity = createClient(IdentityService, trustedConnectTransport);
```

The transport must match the boundary: Connect/gRPC-Web plus the secure operator session at the browser edge,
or native gRPC with TLS and a narrowly scoped credential between trusted services. Protobuf is not itself an
authentication or encryption mechanism. The shipped dashboard product path is Dioxus; the protocol package is
UI-framework independent.

Run `deno task gen` at the repository root after changing a protobuf contract. Generated files should not be
edited by hand.

See [`docs/API.md`](../../docs/API.md) for service authorization and
[`docs/FLEET_ANALYTICS_V1.md`](../../docs/FLEET_ANALYTICS_V1.md) for analytics compatibility rules.

## License

Apache-2.0
