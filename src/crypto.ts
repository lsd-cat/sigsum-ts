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
  const key = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(rawPublicKey.bytes),
    "Ed25519",
    true,
    ["verify"],
  );

  return new PublicKey(key);
}

export async function verifySignature(
  key: PublicKey,
  signature: Signature,
  message: Uint8Array,
): Promise<boolean> {
  if (signature.bytes.length !== 64) {
    throw new Error("Signature must be 64 bytes for Ed25519.");
  }

  return await crypto.subtle.verify(
    { name: "Ed25519" },
    key.key,
    new Uint8Array(signature.bytes),
    new Uint8Array(message),
  );
}

export async function hashKey(publicKey: PublicKey): Promise<KeyHash> {
  const rawBuffer = await crypto.subtle.exportKey("raw", publicKey.key);
  const raw = new RawPublicKey(new Uint8Array(rawBuffer));
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new Uint8Array(raw.bytes),
  );
  return new KeyHash(new Uint8Array(digest));
}

export async function hashMessage(message: Uint8Array): Promise<Hash> {
  return new Hash(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", new Uint8Array(message)),
    ),
  );
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
  const prefix = prefixInteriorNode;
  const combined = new Uint8Array(1 + left.bytes.length + right.bytes.length);
  combined.set(prefix, 0);
  combined.set(left.bytes, 1);
  combined.set(right.bytes, 1 + left.bytes.length);

  const hashBuffer = await crypto.subtle.digest("SHA-256", combined);
  const hash = new Hash(new Uint8Array(hashBuffer));

  return hash;
}

export async function verifyInclusionProof(
  leafHash: Hash,
  leafIndex: number,
  treeHead: TreeHead,
  path: Hash[],
): Promise<boolean> {
  if (leafIndex > treeHead.Size) {
    throw new Error("proof input is malformed: index out of range");
  }

  if (path.length === 0) {
    if (!constantTimeBufferEqual(leafHash.bytes, treeHead.RootHash.bytes)) {
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
      pathIndex++;
    } else if (currentIndex < lastNodeIndex) {
      currentHash = await hashInteriorNode(currentHash, siblingHash);
      pathIndex++;
    }

    currentIndex >>= 1;
    lastNodeIndex >>= 1;
  }

  if (pathIndex !== path.length) {
    throw new Error("internal error: unused path elements");
  }

  if (!constantTimeBufferEqual(currentHash.bytes, treeHead.RootHash.bytes)) {
    throw new Error("invalid proof: root hash does not match computed value");
  }

  return true;
}
