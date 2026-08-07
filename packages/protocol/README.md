# @rustyauth/protocol

ConnectRPC v2 service descriptors and protobuf message types for RustyAuth TypeScript clients.
They are generated from the repository's `proto/rustyauth` contracts, which are also compiled into
the Rust server.

```ts
import { createClient } from "@connectrpc/connect";
import { IdentityService } from "@rustyauth/protocol";
import { createConnectSolidTransport } from "@rustyauth/connect-solid";

const identity = createClient(IdentityService, createConnectSolidTransport());
```

Run `deno task gen` at the repository root after changing a protobuf contract. Generated files
should not be edited by hand.

## License

Apache-2.0
