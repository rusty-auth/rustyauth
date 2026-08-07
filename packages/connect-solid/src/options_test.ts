import { assertEquals, assertRejects } from "@std/assert";
import { connectMutationOptions, connectQueryOptions, connectStreamOptions } from "./options.ts";

Deno.test("query options preserve RPC identity and forward cancellation", async () => {
  const controller = new AbortController();
  const options = connectQueryOptions({
    service: "rustyauth.identity.v1.IdentityService",
    method: "SearchUsers",
    input: { query: "ada" },
    call: (input, signal) => Promise.resolve({ input, sameSignal: signal === controller.signal }),
  });

  assertEquals(options.queryKey, [
    "rustyauth-rpc",
    "rustyauth.identity.v1.IdentityService",
    "SearchUsers",
    { query: "ada" },
  ]);
  assertEquals(await options.queryFn({ signal: controller.signal }), {
    input: { query: "ada" },
    sameSignal: true,
  });
});

Deno.test("mutation keys do not contain secrets or request payloads", async () => {
  const options = connectMutationOptions({
    service: "rustyauth.service_accounts.v1.ServiceAccountService",
    method: "ExchangeCredential",
    call: (input: { credential: string }) => Promise.resolve(input.credential.length),
  });
  assertEquals(options.mutationKey, [
    "rustyauth-rpc",
    "rustyauth.service_accounts.v1.ServiceAccountService",
    "ExchangeCredential",
  ]);
  assertEquals(await options.mutationFn({ credential: "secret" }), 6);
});

Deno.test("finite streams enforce their message bound", async () => {
  const options = connectStreamOptions({
    service: "rustyauth.events.v1.AuthEventService",
    method: "Subscribe",
    input: {},
    maxMessages: 2,
    call: async function* () {
      yield 1;
      yield 2;
      yield 3;
    },
  });

  await assertRejects(
    () => options.queryFn({ signal: new AbortController().signal }),
    Error,
    "exceeded 2 messages",
  );
});
