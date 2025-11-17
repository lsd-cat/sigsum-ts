import { hexToBase64, hexToUint8Array } from "./encoding";
import {
  Base64KeyHash,
  Cosignature,
  CosignedTreeHead,
  Hash,
  InclusionProof,
  KeyHash,
  ShortLeaf,
  Signature,
  SignedTreeHead,
  TreeHead,
} from "./types";

function parseCosignedTreeHead(lines: string[]): CosignedTreeHead {
  const signedTreeHead: Partial<SignedTreeHead> = {};
  const treeHead: Partial<TreeHead> = {};
  const cosignatures = new Map<Base64KeyHash, Cosignature>();

  for (const line of lines) {
    const trimmed = line.trim();

    if (trimmed.startsWith("cosignature=")) {
      const [_, rest] = trimmed.split("=", 2);
      const parts = rest.trim().split(/\s+/);
      if (parts.length !== 3) throw new Error("invalid cosignature format");

      const [keyHashHex, timeStr, sigHex] = parts;

      const keyHash = new Base64KeyHash(hexToBase64(keyHashHex));
      const timestamp = Number(timeStr);
      const signature = new Signature(hexToUint8Array(sigHex));

      if (!Number.isFinite(timestamp) || timestamp <= 0) {
        throw new Error("invalid cosignature timestamp");
      }

      cosignatures.set(keyHash, {
        Timestamp: timestamp,
        Signature: signature,
      });

      continue;
    }

    // key=value handling
    const [key, value] = trimmed.split("=");
    if (!key || !value) continue;

    if (key === "size") {
      const size = Number(value);
      if (!Number.isFinite(size) || size <= 0) {
        throw new Error("invalid tree size");
      }
      treeHead.Size = size;
      continue;
    }

    if (key === "signature") {
      signedTreeHead.Signature = new Signature(hexToUint8Array(value));
      continue;
    }

    if (key === "root_hash") {
      treeHead.RootHash = new Hash(hexToUint8Array(value));
      continue;
    }
  }

  if (!treeHead.Size || !treeHead.RootHash)
    throw new Error("missing tree_head fields");

  if (!signedTreeHead.Signature) throw new Error("missing tree head signature");

  signedTreeHead.TreeHead = treeHead as TreeHead;

  return {
    SignedTreeHead: signedTreeHead as SignedTreeHead,
    Cosignatures: cosignatures,
  };
}

export function parseInclusionProof(lines: string[]): InclusionProof {
  let leafIndex: number | null = null;
  const path: Hash[] = [];

  for (const line of lines) {
    const trimmed = line.trim();

    const [key, value] = trimmed.split("=");
    if (!key || !value) {
      throw new Error(`invalid line in inclusion proof: ${line}`);
    }

    if (key === "leaf_index") {
      if (leafIndex !== null)
        throw new Error("duplicate leaf_index line in inclusion proof");

      const parsed = parseInt(value, 10);
      if (isNaN(parsed) || parsed < 0) {
        throw new Error("invalid leaf_index value");
      }
      leafIndex = parsed;
    } else if (key === "node_hash") {
      const hash = hexToUint8Array(value);
      if (hash.length !== 32) {
        throw new Error("node_hash must be 32 bytes");
      }
      path.push(new Hash(hash));
    }
  }

  if (leafIndex === null) {
    throw new Error("missing leaf_index line in inclusion proof");
  }

  return {
    LeafIndex: leafIndex,
    Path: path,
  };
}

export class SigsumProof {
  version: number;
  logKeyHash: KeyHash;
  leaf: ShortLeaf;
  treeHead: CosignedTreeHead;
  inclusion: InclusionProof;

  constructor(
    version: number,
    logKeyHash: KeyHash,
    leaf: ShortLeaf,
    treeHead: CosignedTreeHead,
    inclusion: InclusionProof,
  ) {
    this.version = version;
    this.logKeyHash = logKeyHash;
    this.leaf = leaf;
    this.treeHead = treeHead;
    this.inclusion = inclusion;
  }

  static async fromAscii(text: string): Promise<SigsumProof> {
    const lines = text.trim().split(/\r?\n/);

    const versionLine = lines.find((l) => l.startsWith("version="));
    if (!versionLine) throw new Error("missing version line");
    const version = parseInt(versionLine.split("=")[1]);
    if (![1, 2].includes(version)) {
      throw new Error(`unknown proof version ${version}`);
    }

    const logLine = lines.find((l) => l.startsWith("log="));
    if (!logLine) throw new Error("missing log line");
    const logKeyHash = new KeyHash(
      hexToUint8Array(logLine.split("=")[1].trim()),
    );

    const leafLineIndex = lines.findIndex((l) => l.startsWith("leaf="));
    if (leafLineIndex === -1) throw new Error("missing leaf line");

    const leafLine = lines[leafLineIndex];
    const leafParts = leafLine.split("=")[1]?.trim().split(/\s+/);
    if (
      !leafParts ||
      (leafParts.length !== 2 && version === 2) ||
      (leafParts.length !== 3 && version === 1)
    ) {
      throw new Error("invalid leaf line format");
    }

    // Version 2 removed a short checksum at the beginning of the proof
    let keyHashIndex = 0;
    let signatureIndex = 1;
    if (version == 1) {
      keyHashIndex++;
      signatureIndex++;
    }
    const keyHash = new KeyHash(hexToUint8Array(leafParts[keyHashIndex]));
    const signature = new Signature(hexToUint8Array(leafParts[signatureIndex]));
    const leaf = new ShortLeaf(keyHash, signature);

    const treeHeadStart = lines.findIndex((l) => l.startsWith("size="));
    if (treeHeadStart === -1) {
      throw new Error("missing tree head start");
    }

    const treeHeadLines: string[] = [];
    for (let i = treeHeadStart; i < lines.length; i++) {
      const line = lines[i].trim();
      if (line === "") break;
      treeHeadLines.push(lines[i]);
    }

    const cosignedTreeHead = parseCosignedTreeHead(treeHeadLines);

    const leafIndex = lines.findIndex((l) => l.startsWith("leaf_index="));
    const inclusionLines = lines
      .slice(leafIndex)
      .filter((l) => l.startsWith("leaf_index=") || l.startsWith("node_hash="));

    const inclusionProof = parseInclusionProof(inclusionLines);

    return new SigsumProof(
      version,
      logKeyHash,
      leaf,
      cosignedTreeHead,
      inclusionProof,
    );
  }
}
