# @rustyauth/protocol

ConnectRPC v2 service descriptors and protobuf message types for RustyAuth TypeScript clients.
They are generated from the repository's `proto/rustyauth` contracts, which are also compiled into
the Rust server.

```ts
import { createClient } from "@connectrpc/connect";
import { createConnectTransport } from "@connectrpc/connect-web";
import { IdentityService } from "@rustyauth/protocol";

const transport = createConnectTransport({
  baseUrl: "https://auth.example.com",
  interceptors: [
    (next) => (request) => {
      request.header.set("authorization", `Bearer ${identityRpcToken}`);
      return next(request);
    },
  ],
});
const identity = createClient(IdentityService, transport);
```

`AUTH_IDENTITY_RPC_TOKEN` is an administrative service secret. Do not embed it in a public browser
bundle. Browser use is appropriate only behind a trusted operator gateway that injects credentials.

Run `deno task gen` at the repository root after changing a protobuf contract. Generated files
should not be edited by hand.

## License

Apache-2.0
