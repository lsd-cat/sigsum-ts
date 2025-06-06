import { prefixInteriorNode } from "./constants";
import { stringToUint8Array } from "./encoding";
import { formatCheckpoint, formatCosignedData } from "./format";
import {
  Cosignature,
  Hash,
  KeyHash,
  PublicKey,
  RawPublicKey,
  Signature,
  SignedTreeHead,
  TreeHead,
} from "./types";

export function constantTimeBufferEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;

  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }

  return diff === 0;
}

export async function importKey(
  rawPublicKey: RawPublicKey,
): Promise<PublicKey> {
  // crypto.subtle.importKey is guaranteed to succeed or throw an error
  return (await crypto.subtle.importKey("raw", rawPublicKey, "Ed25519", true, [
    "verify",
  ])) as PublicKey;
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

export async function hashMessage(message: Uint8Array): Promise<Hash> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", message)) as Hash;
}

export async function verifySignedTreeHead(
  signedTreeHead: SignedTreeHead,
  publicKey: PublicKey,
  logKeyHash: KeyHash,
): Promise<boolean> {
  const checkpoint = formatCheckpoint(signedTreeHead.TreeHead, logKeyHash);
  return await verifySignature(
    publicKey,
    signedTreeHead.Signature,
    stringToUint8Array(checkpoint),
  );
}

export async function verifyCosignedTreeHead(
  treeHead: TreeHead,
  witnessPublicKey: PublicKey,
  logKeyHash: KeyHash,
  cosignature: Cosignature,
): Promise<boolean> {
  const cosignedCheckpoint = formatCosignedData(
    treeHead,
    logKeyHash,
    cosignature.Timestamp,
  );

  return await verifySignature(
    witnessPublicKey,
    cosignature.Signature,
    stringToUint8Array(cosignedCheckpoint),
  );
}

export async function hashInteriorNode(left: Hash, right: Hash): Promise<Hash> {
  const combined = new Uint8Array(1 + left.length + right.length);
  combined.set(prefixInteriorNode, 0);
  combined.set(left, 1);
  combined.set(right, 1 + left.length);

  return new Uint8Array(
    await crypto.subtle.digest("SHA-256", combined),
  ) as Hash;
}

// https://git.glasklar.is/sigsum/core/sigsum-go/-/blob/main/pkg/merkle/verify.go
export async function verifyInclusionProof(
  leafHash: Hash,
  leafIndex: number,
  treeHead: TreeHead,
  path: Hash[],
): Promise<boolean> {
  if (leafIndex > treeHead.Size) {
    throw new Error("proof input is malformed: index out of range");
  }

  // If the path is empty, tree size must be 1
  if (path.length === 0) {
    if (!constantTimeBufferEqual(leafHash, treeHead.RootHash)) {
      throw new Error("tree size is 1 but leaf does not match the root");
    }
  }

  let currentHash = leafHash;
  let currentIndex = leafIndex;
  let lastNodeIndex = treeHead.Size - 1;
  let pathIndex = 0;

  while (lastNodeIndex > 0) {
    const siblingHash = path[pathIndex] as Hash;

    if (currentIndex & 1) {
      currentHash = await hashInteriorNode(siblingHash, currentHash);
    } else if (currentIndex < lastNodeIndex) {
      currentHash = await hashInteriorNode(currentHash, siblingHash);
    }
    pathIndex++;
    currentIndex = currentIndex >> 1;
    lastNodeIndex = lastNodeIndex >> 1;
  }

  if (pathIndex !== path.length) {
    throw new Error("internal error: unused path elements");
  }

  if (!constantTimeBufferEqual(currentHash, treeHead.RootHash)) {
    throw new Error("invalid proof: root hash does not match computed value");
  }

  return true;

  return false;
}
