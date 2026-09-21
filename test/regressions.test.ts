import { describe, expect, it } from "vitest";
import { b58decode, b58encode } from "../src/lib/base58.js";
import { buildSweepTransactions, estimateSize } from "../src/lib/builder.js";
import { Keystore } from "../src/lib/keystore.js";
import { parseAmount } from "../src/lib/units.js";
import { RpcClient } from "../src/lib/rpc.js";
import { parsePath } from "../src/lib/bip32.js";
import { derivePublicKey } from "../src/lib/keys.js";
import { hash160 } from "../src/lib/hashing.js";
import { foundBlockCount } from "../src/lib/miner.js";
import { signatureHash, signatureHasher, type Transaction } from "../src/lib/transaction.js";
import { COIN } from "../src/lib/params.js";
import { fromHex, toHex } from "../src/lib/util.js";

describe("regressions against the Python wallet", () => {
  it("treats a Python 'path': null address as imported, not as a derivation path", async () => {
    const seed = fromHex("11".repeat(64));
    const source = await Keystore.fromSeed(seed, "regtest");
    const other = await Keystore.create("regtest");
    const wif = other.exportWif(other.defaultAddress());
    source.importWif(wif, "copy");

    const document = await source.toDocument();
    // Python writes `"path": null` for an address that came from import_wif.
    (document.addresses[1] as any).path = null;

    const keystore = await Keystore.fromDocument(document);
    // This used to throw "path must start with m or M, got \"null\"".
    expect(keystore.keysByHash().size).toBe(2);
    expect(keystore.exportWif(other.defaultAddress())).toBe(wif);
  });

  it("estimates transaction size with multi-byte count varints like Python", () => {
    expect(estimateSize(1, 2)).toBe(209);
    expect(estimateSize(252, 2)).toBe(35349);
    expect(estimateSize(253, 2)).toBe(35491);
    expect(estimateSize(300, 2)).toBe(42071);
    expect(estimateSize(1000, 2)).toBe(140071);
    expect(estimateSize(65535, 1)).toBe(9174942);
    expect(estimateSize(65536, 1)).toBe(9175084);
  });

  it("ignores the legacy inflated blocks-found counter", () => {
    const store = new Map<string, string>();
    (globalThis as any).localStorage = {
      getItem: (key: string) => store.get(key) ?? null,
      setItem: (key: string, value: string) => void store.set(key, value),
      removeItem: (key: string) => void store.delete(key),
    };
    // The old code counted side-branch/orphan submissions too; that value must
    // no longer be shown.
    store.set("scarletcoin_blocks_found", "4");
    expect(foundBlockCount()).toBe(0);

    store.set("scarletcoin_blocks_found_v2", JSON.stringify([{ height: 10, hash: "aa" }]));
    expect(foundBlockCount()).toBe(1);

    store.set("scarletcoin_blocks_found_v2", "not json");
    expect(foundBlockCount()).toBe(0);
  });

  it("splits a large sweep into relay-sized transactions", () => {
    const secret = fromHex("01".repeat(32));
    const pubkeyHash = hash160(derivePublicKey(secret));
    const keys = new Map<string, Uint8Array>([[toHex(pubkeyHash), secret]]);
    const coins = Array.from({ length: 50 }, (_, index) => ({
      outpoint: { txid: new Uint8Array(32).fill(index % 256), index },
      value: 1_000_000n,
      pubkeyHash,
    }));

    const built = buildSweepTransactions({
      spendableCoins: coins,
      keys,
      destination: pubkeyHash,
      feePerKb: 1000n,
      maxBlockSize: 10_000, // budget 5000 bytes → ~35 inputs per transaction
    });

    expect(built.length).toBeGreaterThan(1);
    expect(built.reduce((sum, tx) => sum + tx.transaction.inputs.length, 0)).toBe(coins.length);
    // Every chunk must stay under the relay budget.
    for (const tx of built) expect(estimateSize(tx.transaction.inputs.length, 1)).toBeLessThanOrEqual(5000);
  });

  it("matches the Python Base58 primitive for all-'1' strings", () => {
    expect(toHex(b58decode("1"))).toBe("00");
    expect(toHex(b58decode("11"))).toBe("0000");
    expect(b58encode(new Uint8Array(0))).toBe("");
  });

  it("parses the same amount strings as the Python wallet", () => {
    expect(parseAmount("1.000000000")).toBe(COIN);
    expect(parseAmount("1_000")).toBe(1000n * COIN);
    expect(parseAmount("+1")).toBe(COIN);
    expect(() => parseAmount("1 sct")).toThrow();
    expect(() => parseAmount("1.000000001")).toThrow();
  });

  it("skips empty derivation-path components like Python", () => {
    expect(parsePath("m/")).toEqual([]);
    expect(parsePath("m//0")).toEqual([0]);
  });

  it("strips a trailing slash from the node URL", () => {
    expect(new RpcClient("https://example.test/").url).toBe("https://example.test");
    expect(new RpcClient("https://example.test///").url).toBe("https://example.test");
  });

  it("produces the same digest in bulk as one input at a time", () => {
    const tx: Transaction = {
      version: 1,
      inputs: [
        { prevout: { txid: new Uint8Array(32).fill(1), index: 0 }, sequence: 0xffffffff, witness: [] },
        { prevout: { txid: new Uint8Array(32).fill(2), index: 1 }, sequence: 0xffffffff, witness: [] },
        { prevout: { txid: new Uint8Array(32).fill(3), index: 2 }, sequence: 0xffffffff, witness: [] },
      ],
      outputs: [{ type: 0, value: 1234n, pubkeyHash: new Uint8Array(20).fill(9) }],
      lockTime: 0,
      coinbaseData: new Uint8Array(0),
    };
    const hasher = signatureHasher(tx);
    const scriptCode = new Uint8Array([0, ...new Uint8Array(20).fill(9)]);
    for (let index = 0; index < tx.inputs.length; index++) {
      expect(toHex(hasher.digest(index, 999n * BigInt(index + 1), scriptCode))).toBe(
        toHex(signatureHash(tx, index, 999n * BigInt(index + 1), scriptCode)),
      );
    }
  });
});