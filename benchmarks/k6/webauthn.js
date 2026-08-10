export function signCountBytes(counter) {
  if (!Number.isSafeInteger(counter) || counter < 0 || counter > 0xffff_ffff) {
    throw new Error("WebAuthn sign counter must be an unsigned 32-bit integer");
  }
  return new Uint8Array([
    (counter >>> 24) & 0xff,
    (counter >>> 16) & 0xff,
    (counter >>> 8) & 0xff,
    counter & 0xff,
  ]);
}

export function monotonicSignCount(now = Date.now()) {
  const seconds = Math.floor(now / 1_000);
  if (seconds > 0xffff_ffff) {
    throw new Error("current time exceeds the WebAuthn sign-counter range");
  }
  return seconds;
}
