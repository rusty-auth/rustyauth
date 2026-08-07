import { assertEquals, assertThrows } from "@std/assert";
import { decodeBase64Url, encodeBase64Url } from "./base64url.ts";

Deno.test("encoding is unpadded and URL safe", () => {
  // 0xfb 0xef 0xbe forces '+' and '/' in plain base64 ("++++" / "----").
  assertEquals(encodeBase64Url(new Uint8Array([0xfb, 0xef, 0xbe])), "----");
  assertEquals(encodeBase64Url(new Uint8Array([0xff, 0xff])), "__8");
  assertEquals(encodeBase64Url(new Uint8Array([])), "");
  assertEquals(encodeBase64Url(new Uint8Array([0x68, 0x69])), "aGk");
});

Deno.test("encoding accepts ArrayBuffer and Uint8Array alike", () => {
  const bytes = new Uint8Array([1, 2, 3, 4]);
  assertEquals(encodeBase64Url(bytes.buffer), encodeBase64Url(bytes));
});

Deno.test("decoding inverts encoding for every byte value", () => {
  const bytes = new Uint8Array(256).map((_, index) => index);
  assertEquals(decodeBase64Url(encodeBase64Url(bytes)), bytes);
});

Deno.test("decoding accepts padded and unpadded forms", () => {
  assertEquals(decodeBase64Url("aGk"), new Uint8Array([0x68, 0x69]));
  assertEquals(decodeBase64Url("aGk="), new Uint8Array([0x68, 0x69]));
  assertEquals(decodeBase64Url("----"), new Uint8Array([0xfb, 0xef, 0xbe]));
  assertEquals(decodeBase64Url("__8"), new Uint8Array([0xff, 0xff]));
  assertEquals(decodeBase64Url(""), new Uint8Array([]));
});

Deno.test("decoding rejects input that is not base64url", () => {
  assertThrows(() => decodeBase64Url("not!valid"));
  assertThrows(() => decodeBase64Url("aaaaa"));
});
