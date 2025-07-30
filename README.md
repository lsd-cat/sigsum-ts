# sigsum-ts

_Note: this library has not been audited, thus its security has not been independently verified._

`sigsum-ts` is a small, (runtime) dependency-free TypeScript library for verifying Sigsum proofs in the browser. It is designed to work with the Sigsum policy format and verify inclusion proofs, Signed Tree Heads, and cosignatures according to quorum rules. The implementation is strictly for verification purposes, and any cryptographic or format error will throw an exception, ensuring that failures are always explicit and must be caught by the caller. It uses only the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API). The library mirrors the logic of the original Go implementation from the Sigsum repository, and aims to be as close in behavior and structure as possible.

`sigsum-ts` has complete test coverage. Its primary use case is as part of [WEBCAT](https://github.com/freedomofpress/webcat), a transparency and integrity layer for web-based applications, where client-side verification of cryptographic proofs is required.

For more information on Sigsum visit the [sigsum.org](https://sigsum.org) or the [development repository](https://git.glasklar.is/sigsum/core/sigsum-go).

## Branded crypto types

To avoid accidental misuse of cryptographic types, `sigsum-ts` uses [branded types](https://egghead.io/blog/using-branded-types-in-typescript). This approach wraps primitive types like `Uint8Array` and `string` in nominal type markers, ensuring that a `Hash`, `Signature`, `KeyHash`, and `RawPublicKey` are not interchangeable, even if they share the same underlying structure. This eliminates a common class of bugs where buffers are passed to the wrong verification or hashing function due to implicit typing.

For example:

```ts
export type Hash = Branded<Uint8Array, "Hash">;
export type Signature = Branded<Uint8Array, "Signature">;
export type KeyHash = Branded<Uint8Array, "KeyHash">;
export type Base64KeyHash = Branded<string, "Base64KeyHash">;
export type RawPublicKey = Branded<Uint8Array, "RawPublicKey">;
export type PublicKey = Branded<CryptoKey, "PublicKey">;
```

As a result, explicit casts or carefully constructed wrappers are required to use these types, which provides a helpful layer of safety when handling cryptographic material.

## Usage

To verify a Sigsum proof, call the verifyMessage() function with the message, the raw submitter public key, a Sigsum policy, and the proof text.

```ts
import { verifyMessage } from "sigsum-ts";

const isValid = await verify(
  messageBytes, // Uint8Array
  submitterRawPublicKey, // Uint8Array as RawPublicKey (32 bytes, Ed25519)
  policyText, // string (Sigsum policy format)
  proofText, // string (Sigsum proof format)
);
```

Sometimes, especially when fetching updates remotely, it could be useful to verify a proof for a hash of a file that has not been obtained yet. `verifyHash` takes the same arguments of `verifyMessage`, except that the first one is expected to be already an hash.

```ts
import { verifyMessage } from "sigsum-ts";

const isValid = await verifyMessage(
  messageHash, // Uint8Array
  submitterRawPublicKey, // Uint8Array as RawPublicKey (32 bytes, Ed25519)
  policyText, // string (Sigsum policy format)
  proofText, // string (Sigsum proof format)
);
```

## Tests

```bash
$ npm run test

> sigsum-ts@0.1 test
> vitest run --coverage


 RUN  v3.2.0 /Users/g/sigsum-ts
      Coverage enabled with v8

 ✓ src/tests/econding.test.ts (8 tests) 3ms
 ✓ src/tests/proof.test.ts (18 tests) 8ms
 ✓ src/tests/crypto.test.ts (23 tests) 25ms
 ✓ src/tests/config.test.ts (17 tests) 36ms
 ✓ src/tests/verify.test.ts (12 tests) 46ms

 Test Files  5 passed (5)
      Tests  78 passed (78)
   Start at  19:39:46
   Duration  472ms (transform 163ms, setup 0ms, collect 300ms, tests 118ms, environment 1ms, prepare 392ms)

 % Coverage report from v8
--------------|---------|----------|---------|---------|-------------------
File          | % Stmts | % Branch | % Funcs | % Lines | Uncovered Line #s
--------------|---------|----------|---------|---------|-------------------
All files     |     100 |      100 |     100 |     100 |
 config.ts    |     100 |      100 |     100 |     100 |
 constants.ts |     100 |      100 |     100 |     100 |
 crypto.ts    |     100 |      100 |     100 |     100 |
 encoding.ts  |     100 |      100 |     100 |     100 |
 format.ts    |     100 |      100 |     100 |     100 |
 policy.ts    |     100 |      100 |     100 |     100 |
 proof.ts     |     100 |      100 |     100 |     100 |
 types.ts     |     100 |      100 |     100 |     100 |
 verify.ts    |     100 |      100 |     100 |     100 |
--------------|---------|----------|---------|---------|-------------------
```
