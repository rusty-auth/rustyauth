import { assertEquals } from "@std/assert";
import { utf8 } from "./utf8.js";

Deno.test("k6 UTF-8 helper matches the Encoding Standard", () => {
  const samples = [
    "rustyauth.dev",
    "https://rustyauth.dev/realm/café",
    "passkey 🔐",
    "unpaired high \ud800 surrogate",
    "unpaired low \udfff surrogate",
  ];
  const encoder = new TextEncoder();
  for (const sample of samples) {
    assertEquals([...utf8(sample)], [...encoder.encode(sample)]);
  }
});
