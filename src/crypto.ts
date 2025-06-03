import { stringToUint8Array } from "./encoding";
import { formatCheckpoint } from "./format";
import {
  KeyHash,
  PublicKey,
  RawPublicKey,
  Signature,
  SignedTreeHead,
} from "./types";

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

export async function hashKey(publicKey: PublicKey): Promise<KeyHash> {
  const rawPublicKey = (await crypto.subtle.exportKey(
    "raw",
    publicKey,
  )) as RawPublicKey;
  return new Uint8Array(
    await crypto.subtle.digest("SHA-256", rawPublicKey),
  ) as KeyHash;
}

export async function verifySignedTreeHead(
  signedTreeHead: SignedTreeHead,
  publicKey: PublicKey,
  logKeyHash: KeyHash,
) {
  const checkpoint = formatCheckpoint(signedTreeHead, logKeyHash);
  return await verifySignature(
    publicKey,
    signedTreeHead.Signature,
    stringToUint8Array(checkpoint),
  );
}
