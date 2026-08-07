# @rustyauth/connect-solid

[ConnectRPC](https://connectrpc.com) v2 bindings for SolidJS applications built on `@tanstack/solid-query`.

Connect owns RPC transport and protobuf. Solid Query owns caching, cancellation and query lifecycle. This
package contains only plain option factories, so it composes with Solid's fine-grained reactivity without a
React provider or React hooks.

```ts
import { createClient } from "@connectrpc/connect";
import { createQuery } from "@tanstack/solid-query";
import { connectQueryOptions, createConnectSolidTransport } from "@rustyauth/connect-solid";
import { IdentityService } from "@rustyauth/protocol/rustyauth/identity/v1/identity_pb.ts";

const transport = createConnectSolidTransport({ baseUrl: "/" });
const identity = createClient(IdentityService, transport);

const users = createQuery(() =>
  connectQueryOptions({
    service: IdentityService.typeName,
    method: "SearchUsers",
    input: { displayName: "Ada" },
    call: (input, signal) => identity.searchUsers(input, { signal }),
  })
);
```

`createConnectSolidTransport` includes HttpOnly operator-session cookies and adds a request ID to every call.
Finite server streams have a hard message cap; live streams use `openSubscription` and stay outside the query
cache.

## License

MIT
