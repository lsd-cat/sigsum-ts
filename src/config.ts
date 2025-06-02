import { hashKey, importKey } from "./crypto";
import { hexToUint8Array } from "./encoding";
import {
  Entity,
  EntityMap,
  Policy,
  Quorum,
  QuorumKofN,
  QuorumSingle,
} from "./policy";
import { KeyHash, RawPublicKey } from "./types";

export const CONFIG_NONE = "none";

interface ConfigState {
  policy: PolicyImpl;
  names: Map<string, Quorum>;
}

class PolicyImpl implements Policy {
  logs: EntityMap = new Map();
  witnesses: EntityMap = new Map();
  quorum!: Quorum;

  async addLog(entity: Entity): Promise<KeyHash> {
    const hash = await hashKey(entity.publicKey);
    if (this.logs.has(hash)) throw new Error(`Duplicate log key: ${hash}`);
    this.logs.set(hash, entity);
    return hash;
  }

  async addWitness(entity: Entity): Promise<KeyHash> {
    const hash = await hashKey(entity.publicKey);
    if (this.witnesses.has(hash))
      throw new Error(`Duplicate witness key: ${hash}`);
    this.witnesses.set(hash, entity);
    return hash;
  }
}

function parseLine(state: ConfigState, line: string): Promise<void> {
  const commentIndex = line.indexOf("#");
  if (commentIndex >= 0) line = line.slice(0, commentIndex);
  const fields = line.trim().split(/\s+/);
  if (fields.length === 0 || !fields[0]) return Promise.resolve();

  const [type, ...args] = fields;
  switch (type) {
    case "log":
      return parseLog(state, args);
    case "witness":
      return parseWitness(state, args);
    case "group":
      return parseGroup(state, args);
    case "quorum":
      return parseQuorum(state, args);
    default:
      throw new Error(`Unknown keyword: ${type}`);
  }
}

async function parseLog(state: ConfigState, args: string[]): Promise<void> {
  if (args.length < 1 || args.length > 2)
    throw new Error("log line must include pubkey and optional URL");
  const [hexKey, url] = args;
  const key = await importKey(hexToUint8Array(hexKey) as RawPublicKey);
  await state.policy.addLog({ publicKey: key, url });
}

async function parseWitness(state: ConfigState, args: string[]): Promise<void> {
  if (args.length < 2 || args.length > 3)
    throw new Error(
      "witness line must include name and pubkey and optional URL",
    );
  const [name, hexKey, url] = args;
  if (state.names.has(name)) throw new Error(`duplicate name: ${name}`);
  const key = await importKey(hexToUint8Array(hexKey) as RawPublicKey);
  const kh = await state.policy.addWitness({ publicKey: key, url });
  state.names.set(name, new QuorumSingle(kh));
}

async function parseGroup(state: ConfigState, args: string[]): Promise<void> {
  if (args.length < 3)
    throw new Error("group requires name, threshold, and members");
  const [name, thresholdRaw, ...members] = args;
  if (state.names.has(name)) throw new Error(`duplicate group name: ${name}`);

  let k: number;
  if (thresholdRaw === "any") k = 1;
  else if (thresholdRaw === "all") k = members.length;
  else k = parseInt(thresholdRaw);

  if (isNaN(k) || k < 1 || k > members.length)
    throw new Error("invalid threshold");

  const subs: Quorum[] = members.map((m) => {
    const q = state.names.get(m);
    if (!q) throw new Error(`undefined name: ${m}`);
    return q;
  });
  state.names.set(name, new QuorumKofN(subs, k));
}

async function parseQuorum(state: ConfigState, args: string[]): Promise<void> {
  if (args.length !== 1) throw new Error("quorum requires a single name");
  const [name] = args;
  if (state.policy.quorum) throw new Error("quorum can only be set once");
  const q = state.names.get(name);
  if (!q) throw new Error(`undefined name: ${name}`);
  state.policy.quorum = q;
}

export async function parsePolicyText(text: string): Promise<Policy> {
  const state: ConfigState = {
    policy: new PolicyImpl(),
    names: new Map([[CONFIG_NONE, new QuorumKofN([], 0)]]),
  };

  const lines = text.split(/\r?\n/);
  for (const line of lines) {
    await parseLine(state, line);
  }
  if (!state.policy.quorum) throw new Error("no quorum defined");
  return state.policy;
}
