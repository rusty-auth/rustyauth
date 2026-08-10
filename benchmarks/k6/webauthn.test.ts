import { assertEquals, assertThrows } from "@std/assert";
import { monotonicSignCount, signCountBytes } from "./webauthn.js";

Deno.test("encodes the WebAuthn sign counter as an unsigned big-endian integer", () => {
  assertEquals([...signCountBytes(0x0102_0304)], [1, 2, 3, 4]);
  assertEquals([...signCountBytes(0xffff_ffff)], [255, 255, 255, 255]);
  assertThrows(() => signCountBytes(-1));
  assertThrows(() => signCountBytes(0x1_0000_0000));
});

Deno.test("derives a counter that advances between benchmark runs", () => {
  assertEquals(monotonicSignCount(1_786_396_970_000), 1_786_396_970);
  assertEquals(monotonicSignCount(1_786_396_971_000), 1_786_396_971);
});
