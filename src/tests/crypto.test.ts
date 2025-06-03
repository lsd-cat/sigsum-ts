import { describe, expect, it } from "vitest";

import {
  hashKey,
  importKey,
  verifySignature,
  verifySignedTreeHead,
} from "../crypto";
import { Uint8ArrayToBase64 } from "../encoding";
import {
  Hash,
  RawPublicKey,
  Signature,
  SignedTreeHead,
  TreeHead,
} from "../types";

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

const LOG_PUBKEY = new Uint8Array([
  0x46, 0x44, 0xaf, 0x2a, 0xbd, 0x40, 0xf4, 0x89, 0x5a, 0x00, 0x3b, 0xca, 0x35,
  0x0f, 0x9d, 0x59, 0x12, 0xab, 0x30, 0x1a, 0x49, 0xc7, 0x7f, 0x13, 0xe5, 0xb6,
  0xd9, 0x05, 0xc2, 0x0a, 0x5f, 0xe6,
]) as RawPublicKey;

const TREEHEAD_ROOT_HASH = new Uint8Array([
  0x22, 0x59, 0x6c, 0x88, 0x2d, 0xcd, 0xfb, 0xfa, 0xba, 0x69, 0x3c, 0xb6, 0x9b,
  0x22, 0x5c, 0x81, 0xa8, 0xa9, 0x80, 0xe8, 0x4b, 0x3a, 0xd5, 0xfc, 0x1f, 0xcd,
  0x6a, 0x25, 0x6e, 0xbd, 0xc2, 0x35,
]) as Hash;

const TREEHEAD_SIGNATURE = new Uint8Array([
  0x3a, 0xec, 0xf6, 0x43, 0xc4, 0x2d, 0x15, 0x86, 0x30, 0x00, 0x57, 0x66, 0x68,
  0x98, 0x01, 0x07, 0xa0, 0x56, 0x98, 0x47, 0xf1, 0xb3, 0xf4, 0x3d, 0xf7, 0x0d,
  0xcb, 0xf0, 0x70, 0x5b, 0xb5, 0x80, 0xda, 0xf6, 0xfa, 0x64, 0xc5, 0x86, 0xf4,
  0xef, 0x78, 0x0a, 0x1b, 0x02, 0x08, 0x50, 0x30, 0xba, 0xb9, 0x3c, 0x84, 0x51,
  0x36, 0xed, 0x1f, 0x9c, 0x78, 0xec, 0x96, 0x13, 0x93, 0xdf, 0xc1, 0x00,
]) as Signature;

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
    const hash = Uint8ArrayToBase64(await hashKey(key));

    expect(hash).toMatch(/^[a-zA-Z0-9+/]+={0,2}$/);
    expect(hash.length).toBeGreaterThan(40);
  });

  it("returns a consistent hash for the same key", async () => {
    const key = await importKey(VALID_PUBLIC_KEY);
    const h1 = Uint8ArrayToBase64(await hashKey(key));
    const h2 = Uint8ArrayToBase64(await hashKey(key));
    expect(h1).toBe(h2);
  });

  it("returns the expected base64 SHA-256 hash for known key", async () => {
    const key = await importKey(VALID_PUBLIC_KEY);
    const hash = Uint8ArrayToBase64(await hashKey(key));
    expect(hash).toBe(EXPECTED_BASE64_HASH);
  });

  it("verifies a valid signed tree head", async () => {
    const publicKey = await importKey(LOG_PUBKEY);
    const logKeyHash = await hashKey(publicKey);

    const treeHead: TreeHead = {
      Size: 899,
      RootHash: TREEHEAD_ROOT_HASH,
    };

    const signedTreeHead: SignedTreeHead = {
      TreeHead: treeHead,
      Signature: TREEHEAD_SIGNATURE,
    };

    const result = await verifySignedTreeHead(
      signedTreeHead,
      publicKey,
      logKeyHash,
    );
    expect(result).toBe(true);
  });
});
