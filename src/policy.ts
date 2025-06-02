// https://git.glasklar.is/sigsum/core/sigsum-go/-/blob/main/pkg/policy/policy.go

import { KeyHash, PublicKey } from "./types";

export interface Entity {
  publicKey: PublicKey;
  url?: string;
}

export type EntityMap = Map<KeyHash, Entity>;

export interface Quorum {
  isQuorum(present: Set<KeyHash>): boolean;
}

export interface Policy {
  logs: EntityMap;
  witnesses: EntityMap;
  quorum: Quorum;
}

export class QuorumSingle implements Quorum {
  constructor(private readonly w: KeyHash) {}

  isQuorum(present: Set<KeyHash>): boolean {
    return present.has(this.w);
  }
}

export class QuorumKofN implements Quorum {
  constructor(
    private readonly subQuorums: Quorum[],
    private readonly k: number,
  ) {}

  isQuorum(present: Set<KeyHash>): boolean {
    let count = 0;
    for (const sq of this.subQuorums) {
      if (sq.isQuorum(present)) count++;
    }
    return count >= this.k;
  }
}
