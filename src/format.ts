import { CheckpointNamePrefix, CosignatureNamespace } from "./constants";
import { Uint8ArrayToBase64, Uint8ArrayToHex } from "./encoding";
import { KeyHash, SignedTreeHead } from "./types";

export function formatCheckpoint(
  signedTreeHead: SignedTreeHead,
  logKeyHash: KeyHash,
): string {
  const origin = CheckpointNamePrefix + Uint8ArrayToHex(logKeyHash);
  const rootHash = Uint8ArrayToBase64(signedTreeHead.TreeHead.RootHash);
  const checkpointStr = `${origin}\n${signedTreeHead.TreeHead.Size}\n${rootHash}\n`;
  return checkpointStr;
}

export function formatCosignedData(
  signedTreeHead: SignedTreeHead,
  logKeyHash: KeyHash,
  timestamp: Date,
): string {
  const checkpointStr = formatCheckpoint(signedTreeHead, logKeyHash);
  const cosignedStr = `${CosignatureNamespace}\ntime ${timestamp}\n${checkpointStr}`;
  return cosignedStr;
}
