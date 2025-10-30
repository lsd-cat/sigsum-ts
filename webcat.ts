#!/usr/bin/env node
/**
 * WebCAT enrollment generator + canonical hasher
 *
 * Usage:
 *   npx tsx webcat-enroll.ts generate --policy policy.txt \
 *     --keys 0123...,abcd...,deadbeef... \
 *     --threshold 2 \
 *     --expiry 15778800 \
 *     --out enrollment.json
 *
 *   npx tsx webcat-enroll.ts hash --file enrollment.json
 */

import fs from "fs/promises";
import { createHash } from "crypto";
import yargs from "yargs";
import { hideBin } from "yargs/helpers";
import { compilePolicy } from "./src/policyCompiler";
import { hexToUint8Array, Uint8ArrayToBase64 } from "./src/encoding";

const MIN_EXPIRY = 604800;      // 1 week
const MAX_EXPIRY = 63072000;    // 2 years

function canonicalize(obj: any): string {
  if (obj === null || typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return "[" + obj.map(canonicalize).join(",") + "]";
  return (
    "{" +
    Object.keys(obj)
      .sort()
      .map((k) => JSON.stringify(k) + ":" + canonicalize(obj[k]))
      .join(",") +
    "}"
  );
}

function normalizeB64(b64: string): string {
  return b64.replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function sha256Canonical(obj: any): string {
  const canon = canonicalize(obj);
  return createHash("sha256").update(canon).digest("hex");
}

yargs(hideBin(process.argv))
  .command(
    "generate",
    "Generate an enrollment file",
    (y) =>
      y
        .option("policy", {
          type: "string",
          demandOption: true,
          describe: "Path to Sigsum policy text file",
        })
        .option("keys", {
          type: "string",
          demandOption: true,
          describe: "Comma-separated Ed25519 public keys (hex)",
        })
        .option("threshold", {
          type: "number",
          demandOption: true,
          describe: "Threshold (<= number of keys)",
        })
        .option("expiry", {
          type: "number",
          demandOption: true,
          describe: "Max age in seconds (>=1 week, <=2 years)",
        })
        .option("out", {
          type: "string",
          demandOption: true,
          describe: "Output JSON file",
        }),
    async (argv) => {
      const { policy, keys, threshold, expiry, out } = argv;

      if (expiry < MIN_EXPIRY || expiry > MAX_EXPIRY)
        throw new Error("Expiry must be between 604800 (1w) and 63072000 (2y) seconds");

      const policyText = await fs.readFile(policy, "utf8");
      const compiled = await compilePolicy(policyText);

      const keyList = keys.split(",").map((k) => k.trim()).filter(Boolean);

      if (keyList.length === 0) throw new Error("At least one key must be provided");
      if (threshold > keyList.length)
        throw new Error("Threshold cannot exceed number of keys");

      const decodedKeys: Uint8Array[] = [];

      for (const hex of keyList) {
        if (!/^[0-9a-fA-F]+$/.test(hex))
          throw new Error(`Invalid hex in key: ${hex}`);
        if (hex.length !== 64)
          throw new Error(
            `Each Ed25519 public key must be 32 bytes (64 hex chars): got ${hex.length} for ${hex}`
          );

        const raw = hexToUint8Array(hex);
        // Check for duplicates by comparing decoded bytes
        if (decodedKeys.some((k) => k.length === raw.length && k.every((b, i) => b === raw[i])))
          throw new Error("Duplicate Ed25519 public key detected");

        decodedKeys.push(raw);
      }

      const signers = decodedKeys.map((raw) =>
        normalizeB64(Uint8ArrayToBase64(raw))
      );

      const enrollment = {
        signers,
        threshold,
        policy: normalizeB64(Uint8ArrayToBase64(compiled)),
        max_age: expiry,
      };

      const canonical = canonicalize(enrollment);
      const hash = createHash("sha256").update(canonical).digest("hex");

      await fs.writeFile(out, canonical + "\n", "utf8");
    },
  )
  .command(
    "hash",
    "Canonicalize and hash an existing JSON file",
    (y) => y.option("file", { type: "string", demandOption: true }),
    async (argv) => {
      const text = await fs.readFile(argv.file as string, "utf8");
      const obj = JSON.parse(text);
      const canonical = canonicalize(obj);
      const hash = createHash("sha256").update(canonical).digest("hex");
      console.log(`${hash}`);
    },
  )
  .demandCommand(1)
  .strict()
  .help()
  .parse();

