import { PublicKey, RawPublicKey, Signature } from "./types";

export async function importKey(rawKey: RawPublicKey): Promise<PublicKey> {
  const imported = await crypto.subtle.importKey(
    "raw",
    rawKey,
    "Ed25519",
    true,
    ["verify"],
  );

  if (!imported) {
    throw new Error("Failed to import public key.");
  }

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
