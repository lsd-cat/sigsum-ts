import { parsePolicyText } from "./config";
import { LeafNamespace } from "./constants";
import {
  constantTimeBufferEqual,
  hashKey,
  hashMessage,
  importKey,
  verifyCosignedTreeHead,
  verifyInclusionProof,
  verifySignature,
  verifySignedTreeHead,
} from "./crypto";
import { Uint8ArrayToBase64 } from "./encoding";
import { attachNamespace } from "./format";
import { Policy } from "./policy";
import { SigsumProof } from "./proof";
import { Base64KeyHash, Hash, KeyHash, PublicKey, RawPublicKey } from "./types";

export async function verify(
  message: Uint8Array,
  submitterRawPublicKey: RawPublicKey,
  policyText: string,
  proofText: string,
): Promise<boolean> {
  const submitterPublicKey: PublicKey = await importKey(submitterRawPublicKey);
  const submitterKeyHash: KeyHash = await hashKey(submitterPublicKey);
  const policy: Policy = await parsePolicyText(policyText);
  const proof: SigsumProof = await SigsumProof.fromAscii(proofText);

  // From https://git.glasklar.is/sigsum/core/sigsum-go/-/blob/main/doc/sigsum-proof.md
  // Step 1 - remember the double hashig (the first hash is the leaf data, and the second the leaf checksum)
  const checksum: Hash = await hashMessage(await hashMessage(message));

  // Step 2
  if (!constantTimeBufferEqual(proof.leaf.KeyHash, submitterKeyHash)) {
    throw new Error("proof key does not match the provided one");
  }

  const log = policy.logs.get(
    Uint8ArrayToBase64(proof.logKeyHash) as Base64KeyHash,
  );

  if (!log) {
    throw new Error("log key not found in policy");
  }

  // Step 3 - verify leaf signature
  if (
    !(await verifySignature(
      submitterPublicKey,
      proof.leaf.Signature,
      attachNamespace(LeafNamespace, checksum),
    ))
  ) {
    throw new Error("invalid message signature");
  }

  // Step 4 - verify tree head log signature
  // It should be fine to use the proof log keyhash value, because it must match the policy one, and we trust the policy
  if (
    !(await verifySignedTreeHead(
      proof.treeHead.SignedTreeHead,
      log.publicKey,
      proof.logKeyHash,
    ))
  ) {
    throw new Error(`failed to verify tree head signature`);
  }

  // Step 5 - verify witnesses cosignatures until the quorum is met
  const present = new Set<Base64KeyHash>();
  let quorum = false;
  for (const [witnessKeyHash, entity] of policy.witnesses) {
    const cosignature = proof.treeHead.Cosignatures[witnessKeyHash];
    if (!cosignature) {
      continue;
    }

    const valid = await verifyCosignedTreeHead(
      proof.treeHead.SignedTreeHead.TreeHead,
      entity.publicKey,
      proof.logKeyHash,
      cosignature,
    );

    if (valid) {
      present.add(witnessKeyHash);

      quorum = policy.quorum.isQuorum(present);
      if (quorum) {
        break;
      }
    }
  }

  if (!quorum) {
    throw new Error(
      `cosignature quorum not satisfied, got ${present.size} valid signatures`,
    );
  }

  // Step 6 - verify the actual inclusion proof
  return await verifyInclusionProof(
    await proof.leaf.toLeaf(checksum).hashLeaf(),
    proof.inclusion.LeafIndex,
    proof.treeHead.SignedTreeHead.TreeHead,
    proof.inclusion.Path,
  );
}
