import { CheckpointNamePrefix, CosignatureNamespace } from "./constants";
import { Uint8ArrayToBase64 } from "./encoding";
import { KeyHash, TreeHead } from "./types";

function formatCheckpoint(TreeHead: TreeHead, LogKeyHash: KeyHash): string {
  const origin = CheckpointNamePrefix + LogKeyHash;
  const rootHash = Uint8ArrayToBase64(TreeHead.RootHash);
  const checkpointStr = `${origin}\n${TreeHead.Size}\n${rootHash}\n`;
  return checkpointStr;
}

export function formatCosignedData(
  TreeHead: TreeHead,
  LogKeyHash: KeyHash,
  timestamp: Date,
): string {
  const checkpointStr = formatCheckpoint(TreeHead, LogKeyHash);
  const cosignedStr = `${CosignatureNamespace}\ntime ${timestamp}\n${checkpointStr}`;
  return cosignedStr;
}
