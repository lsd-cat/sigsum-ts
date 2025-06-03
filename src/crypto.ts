import { Uint8ArrayToBase64 } from "./encoding";
import { Base64KeyHash, PublicKey, RawPublicKey, Signature } from "./types";

export async function importKey(
  rawPublicKey: RawPublicKey,
): Promise<PublicKey> {
  // crypto.subtle.importKey is guaranteed to succeed or throw an error
  const imported = await crypto.subtle.importKey(
    "raw",
    rawPublicKey,
    "Ed25519",
    true,
    ["verify"],
  );

  return imported as PublicKey;
}

export async function verifySignature(
  key: PublicKey,
  signature: Signature,
  message: Uint8Array,
): Promise<boolean> {
  if (signature.length !== 64) {
    throw new Error("Signature must be 64 bytes for Ed25519.");
  }

  return await crypto.subtle.verify(
    { name: "Ed25519" },
    key,
    signature,
    message,
  );
}

export async function hashKey(publicKey: PublicKey): Promise<Base64KeyHash> {
  const rawPublicKey = (await crypto.subtle.exportKey(
    "raw",
    publicKey,
  )) as RawPublicKey;
  return Uint8ArrayToBase64(
    await crypto.subtle.digest("SHA-256", rawPublicKey),
  ) as Base64KeyHash;
}
