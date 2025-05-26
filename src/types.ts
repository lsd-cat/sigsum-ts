export type Hash = Uint8Array & { __brand: "Hash" };
export type Signature = Uint8Array & { __brand: "Signature" };
export type KeyHash = string & { __brand: "KeyHash" };
export type RawPublicKey = Uint8Array & { __brand: "RawPublicKey" };
export type PublicKey = CryptoKey;

// https://git.glasklar.is/sigsum/core/sigsum-go/-/blob/main/pkg/types/tree_head.go
export interface Cosignature {
    Timestamp: number;
    Signature: Signature;
}

export interface TreeHead {
    Size: number;
    RootHash: Hash;
}

export interface SignedTreeHead {
    TreeHead: TreeHead;
    Signature: Signature;
}

export interface CosignedTreeHead {
    SignedTreeHead: SignedTreeHead;
    Cosignatures: { [key: KeyHash]: Cosignature };
}

// https://git.glasklar.is/sigsum/core/sigsum-go/-/blob/main/pkg/types/leaf.go
export interface Leaf {
    Checksum: Hash;
    Signature: Signature;
    KeyHash: KeyHash;
}

// https://git.glasklar.is/sigsum/core/sigsum-go/-/blob/main/pkg/types/proof.go
export interface InclusionProof {
    LeafIndex: number;
    Path: Hash[];
}

// See https://git.glasklar.is/sigsum/core/sigsum-go/-/blob/main/doc/sigsum-proof.md
export interface SigsumProof {
    Version: number;
    Log: KeyHash;
    Leaf: Leaf;
    TreeHead: TreeHead;
    InclusionProof: InclusionProof;
}