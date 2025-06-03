// https://egghead.io/blog/using-branded-types-in-typescript
declare const __brand: unique symbol;
type Brand<B> = { [__brand]: B };

export type Branded<T, B> = T & Brand<B>;

export type Hash = Branded<Uint8Array, "Hash">;
export type Signature = Branded<Uint8Array, "Signature">;
export type KeyHash = Branded<Uint8Array, "KeyHash">;
export type Base64KeyHash = Branded<string, "Base64KeyHash">;
export type RawPublicKey = Branded<Uint8Array, "RawPublicKey">;
export type PublicKey = Branded<CryptoKey, "PublicKey">;

// https://git.glasklar.is/sigsum/core/sigsum-go/-/blob/main/pkg/types/tree_head.go
export interface Cosignature {
  Timestamp: Date;
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
  Cosignatures: { [key: Base64KeyHash]: Cosignature };
}

// https://git.glasklar.is/sigsum/core/sigsum-go/-/blob/main/pkg/types/leaf.go
export interface Leaf {
  Checksum: Hash;
  Signature: Signature;
  Base64KeyHash: Base64KeyHash;
}

// https://git.glasklar.is/sigsum/core/sigsum-go/-/blob/main/pkg/types/proof.go
export interface InclusionProof {
  LeafIndex: number;
  Path: Hash[];
}

// See https://git.glasklar.is/sigsum/core/sigsum-go/-/blob/main/pkg/proof/proof.go
export class ShortLeaf {
  Base64KeyHash: Base64KeyHash;
  Signature: Signature;

  constructor(Base64KeyHash: Base64KeyHash, signature: Signature) {
    this.Base64KeyHash = Base64KeyHash;
    this.Signature = signature;
  }

  static fromLeaf(leaf: Leaf): ShortLeaf {
    return new ShortLeaf(leaf.Base64KeyHash, leaf.Signature);
  }

  toLeaf(checksum: Hash): Leaf {
    return {
      Checksum: checksum,
      Base64KeyHash: this.Base64KeyHash,
      Signature: this.Signature,
    };
  }
}
