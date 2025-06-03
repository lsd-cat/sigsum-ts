import { describe, expect, it } from "vitest";

import { hashKey, importKey, verifySignature } from "../crypto";
import { RawPublicKey, Signature } from "../types";

const VALID_PUBLIC_KEY = new Uint8Array([
  235, 19, 108, 27, 6, 73, 64, 86, 192, 69, 29, 238, 123, 65, 67, 224, 101, 29,
  252, 40, 19, 100, 69, 16, 20, 107, 207, 165, 169, 155, 37, 250,
]) as RawPublicKey;

const VALID_SIGNATURE = new Uint8Array([
  140, 73, 191, 148, 174, 113, 109, 220, 188, 161, 249, 35, 177, 149, 245, 65,
  158, 51, 120, 251, 158, 34, 237, 205, 237, 88, 184, 141, 20, 128, 74, 71, 0,
  60, 226, 131, 180, 173, 121, 45, 248, 102, 92, 139, 157, 177, 87, 37, 78, 237,
  89, 63, 73, 23, 11, 132, 206, 122, 111, 0, 200, 140, 217, 4,
]) as Signature;

const VALID_MESSAGE = new TextEncoder().encode("hello world");
const INVALID_MESSAGE = new TextEncoder().encode("tampered message");
const EXPECTED_BASE64_HASH = "fY20VJz2TPDYe09gUTGwfN6wiDFdSS9+O+5frwVd36c=";

describe("crypto", () => {
  it("imports a valid Ed25519 raw public key", async () => {
    const key = await importKey(VALID_PUBLIC_KEY);
    expect(key.type).toBe("public");
  });

  it("throws on invalid raw public key length", async () => {
    const badKey = VALID_PUBLIC_KEY.slice(0, 30);
    await expect(importKey(badKey as RawPublicKey)).rejects.toThrow();
  });

  it("returns true for a valid signature", async () => {
    const key = await importKey(VALID_PUBLIC_KEY);
    const ok = await verifySignature(key, VALID_SIGNATURE, VALID_MESSAGE);
    expect(ok).toBe(true);
  });

  it("returns false if message is tampered", async () => {
    const key = await importKey(VALID_PUBLIC_KEY);
    const ok = await verifySignature(key, VALID_SIGNATURE, INVALID_MESSAGE);
    expect(ok).toBe(false);
  });

  it("throws if signature is too short", async () => {
    const key = await importKey(VALID_PUBLIC_KEY);
    const shortSig = new Uint8Array(63);
    await expect(() =>
      verifySignature(key, shortSig as Signature, VALID_MESSAGE),
    ).rejects.toThrow(/64 bytes/);
  });

  it("throws if signature is too long", async () => {
    const key = await importKey(VALID_PUBLIC_KEY);
    const longSig = new Uint8Array(65);
    await expect(() =>
      verifySignature(key, longSig as Signature, VALID_MESSAGE),
    ).rejects.toThrow(/64 bytes/);
  });

  it("returns false for all-zero public key", async () => {
    const zeroKey = await importKey(new Uint8Array(32) as RawPublicKey);
    const ok = await verifySignature(zeroKey, VALID_SIGNATURE, VALID_MESSAGE);
    expect(ok).toBe(false);
  });

  it("returns false for all-0xFF public key", async () => {
    const ffKey = await importKey(
      new Uint8Array(32).fill(0xff) as RawPublicKey,
    );
    const ok = await verifySignature(ffKey, VALID_SIGNATURE, VALID_MESSAGE);
    expect(ok).toBe(false);
  });

  it("returns a valid base64 SHA-256 hash", async () => {
    const key = await importKey(VALID_PUBLIC_KEY);
    const hash = await hashKey(key);

    // Check for valid base64
    expect(hash).toMatch(/^[a-zA-Z0-9+/]+={0,2}$/);
    expect(hash.length).toBeGreaterThan(40);
  });

  it("returns a consistent hash for the same key", async () => {
    const key = await importKey(VALID_PUBLIC_KEY);
    const h1 = await hashKey(key);
    const h2 = await hashKey(key);
    expect(h1).toBe(h2);
  });

  it("returns the expected base64 SHA-256 hash for known key", async () => {
    const key = await importKey(VALID_PUBLIC_KEY);
    const hash = await hashKey(key);
    expect(hash).toBe(EXPECTED_BASE64_HASH);
  });
});
