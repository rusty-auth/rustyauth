/**
 * Base64url codec for the WebAuthn wire format.
 *
 * RustyAuth serializes every binary WebAuthn field — challenges, user handles,
 * credential IDs, attestation and assertion buffers — as unpadded base64url
 * strings (the `webauthn-rs` `Base64UrlSafeData` encoding). These helpers
 * convert between that encoding and the `ArrayBuffer`s the browser
 * `navigator.credentials` API produces and consumes.
 */

/** Encodes bytes as unpadded base64url, the form RustyAuth emits and accepts. */
export function encodeBase64Url(data: ArrayBuffer | Uint8Array): string {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Decodes base64url into bytes. Padding is optional, matching what servers
 * and authenticators variously emit. Invalid input throws.
 */
export function decodeBase64Url(value: string): Uint8Array {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}
