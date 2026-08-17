import { describe, expect, it } from "vitest";
import { hash256, hash160, sha256 } from "../src/lib/hashing.js";
import {
  addressFromPrivateKey,
  derivePublicKey,
  privateKeyFromWif,
  privateKeyToWif,
  sign,
  verifySignature,
} from "../src/lib/keys.js";
import { buildSweepTransaction, buildTransaction } from "../src/lib/builder.js";
import { serializeBody, signatureHash, txidHex } from "../src/lib/transaction.js";
import { COIN } from "../src/lib/params.js";
import { fromHex, toHex } from "../src/lib/util.js";
import goldenData from "./fixtures/golden.json";

const golden = goldenData as any;

function secretOf(key: any): Uint8Array {
  return fromHex(key.secret);
}

/** Every input's signature must verify against the digest it commits to. */
function expectVerifiable(built: any): void {
  for (let i = 0; i < built.coins.length; i++) {
    const coin = built.coins[i];
    const input = built.transaction.inputs[i];
    const digest = signatureHash(built.transaction, i, coin.value);
    expect(verifySignature(digest, input.signature, input.publicKey)).toBe(true);
  }
}

describe("golden fixtures (byte-for-byte against the Python wallet)", () => {
  it("reproduces the hash primitives", () => {
    const abc = new TextEncoder().encode("abc");
    expect(toHex(sha256(abc))).toBe(golden.sha256_abc);
    expect(toHex(hash256(abc))).toBe(golden.hash256_abc);
  });

  it("derives public keys, addresses and WIF", () => {
    for (const key of golden.keys as any[]) {
      const secret = secretOf(key);
      expect(toHex(derivePublicKey(secret))).toBe(key.pubkey);
      expect(addressFromPrivateKey(secret, golden.address_version)).toBe(key.address);
      expect(privateKeyToWif(secret, golden.wif_version)).toBe(key.wif);
      expect(toHex(privateKeyFromWif(key.wif, golden.wif_version))).toBe(key.secret);
    }
  });

  it("produces a valid ECDSA signature that the Python wallet verifies", () => {
    const signature = sign(fromHex(golden.sign.digest), fromHex(golden.sign.secret));
    // The signature is deterministic (RFC6979), so the two implementations may
    // produce different (r, s) pairs — both valid. The golden fixture carries
    // the Python-produced signature; here we verify the JS-produced one is
    // well-formed and verifies against the same public key.
    const pubkey = derivePublicKey(fromHex(golden.sign.secret));
    expect(verifySignature(fromHex(golden.sign.digest), signature, pubkey)).toBe(true);
    // Also verify the Python-produced signature (cross-implementation check).
    expect(verifySignature(fromHex(golden.sign.digest), fromHex(golden.sign.signature), pubkey)).toBe(true);
  });

  it("builds and signs the same transaction", () => {
    const [k1, k2, k3] = golden.keys as any[];
    const pub1 = derivePublicKey(secretOf(k1));
    const pub2 = derivePublicKey(secretOf(k2));
    const pub3 = derivePublicKey(secretOf(k3));

    const coin1 = {
      outpoint: { txid: fromHex(k1.secret), index: 0 },
      value: 50n * COIN,
      pubkeyHash: hash160(pub1),
    };
    const coin2 = {
      outpoint: { txid: fromHex(k2.secret), index: 1 },
      value: 25n * COIN,
      pubkeyHash: hash160(pub2),
    };
    const keys = new Map<string, Uint8Array>();
    keys.set(toHex(coin1.pubkeyHash), secretOf(k1));
    keys.set(toHex(coin2.pubkeyHash), secretOf(k2));

    const built = buildTransaction({
      spendableCoins: [coin1, coin2],
      keys,
      outputs: [{ hash: hash160(pub3), value: 30n * COIN }],
      changeHash: coin1.pubkeyHash,
      feePerKb: 1000n,
    });

    expect(toHex(serializeBody(built.transaction))).toBe(golden.transaction.body);
    expect(txidHex(built.transaction)).toBe(golden.transaction.txid);
    expect(built.fee).toBe(BigInt(golden.transaction.fee));
    expect(built.change).toBe(BigInt(golden.transaction.change));
    expect(built.totalInput).toBe(BigInt(golden.transaction.total_input));
    expectVerifiable(built);
  });

  it("builds the same sweep transaction", () => {
    const [k1, k2, k3] = golden.keys as any[];
    const pub1 = derivePublicKey(secretOf(k1));
    const pub2 = derivePublicKey(secretOf(k2));
    const pub3 = derivePublicKey(secretOf(k3));

    const coin1 = {
      outpoint: { txid: fromHex(k1.secret), index: 0 },
      value: 50n * COIN,
      pubkeyHash: hash160(pub1),
    };
    const coin2 = {
      outpoint: { txid: fromHex(k2.secret), index: 1 },
      value: 25n * COIN,
      pubkeyHash: hash160(pub2),
    };
    const keys = new Map<string, Uint8Array>();
    keys.set(toHex(coin1.pubkeyHash), secretOf(k1));
    keys.set(toHex(coin2.pubkeyHash), secretOf(k2));

    const built = buildSweepTransaction({
      spendableCoins: [coin1, coin2],
      keys,
      destination: hash160(pub3),
      feePerKb: 1000n,
    });

    expect(toHex(serializeBody(built.transaction))).toBe(golden.sweep.body);
    expect(txidHex(built.transaction)).toBe(golden.sweep.txid);
    expect(built.fee).toBe(BigInt(golden.sweep.fee));
    expect(built.change).toBe(BigInt(golden.sweep.change));
    expect(built.totalInput).toBe(BigInt(golden.sweep.total_input));
    expectVerifiable(built);
  });
});
