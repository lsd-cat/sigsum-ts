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
  Cosignatures: { [key: Base64KeyHash]: Cosignature };
}

// https://git.glasklar.is/sigsum/core/sigsum-go/-/blob/main/pkg/types/leaf.go
export class Leaf {
  Checksum: Hash;
  Signature: Signature;
  KeyHash: KeyHash;

  constructor(checksum: Hash, signature: Signature, keyHash: KeyHash) {
    this.Checksum = checksum;
    this.Signature = signature;
    this.KeyHash = keyHash;
  }

  public async hashLeaf(): Promise<Hash> {
    const leafBinary = new Uint8Array(129);
    leafBinary[0] = 0x0; // PrefixLeafNode
    leafBinary.set(this.Checksum, 1);
    leafBinary.set(this.Signature, 33);
    leafBinary.set(this.KeyHash, 97);

    return new Uint8Array(
      await crypto.subtle.digest("SHA-256", leafBinary),
    ) as Hash;
  }
}

// https://git.glasklar.is/sigsum/core/sigsum-go/-/blob/main/pkg/types/proof.go
export interface InclusionProof {
  LeafIndex: number;
  Path: Hash[];
}

// See https://git.glasklar.is/sigsum/core/sigsum-go/-/blob/main/pkg/proof/proof.go
export class ShortLeaf {
  KeyHash: KeyHash;
  Signature: Signature;

  constructor(keyHash: KeyHash, signature: Signature) {
    this.KeyHash = keyHash;
    this.Signature = signature;
  }

  //static fromLeaf(leaf: Leaf): ShortLeaf {
  //  return new ShortLeaf(leaf.KeyHash, leaf.Signature);
  //}

  toLeaf(checksum: Hash): Leaf {
    return new Leaf(checksum, this.Signature, this.KeyHash);
  }
}
