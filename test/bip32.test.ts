import { describe, expect, it } from "vitest";
import { deriveFromSeed, masterFromSeed } from "../src/lib/bip32.js";
import { addressFromPrivateKey } from "../src/lib/keys.js";
import { fromHex, toHex } from "../src/lib/util.js";

// Reference values produced by scarletcoin.crypto.bip32 (regtest, coin type 1).
const SEED = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
  + "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40";

describe("BIP-0032 derivation", () => {
  it("reproduces the master key", () => {
    const master = masterFromSeed(fromHex(SEED));
    expect(toHex(master.secret)).toBe(
      "795a7ac7dd2f8c87e2b0f4dc389fb71d82697dba86995e51d4b45b1ca2593f21",
    );
    expect(toHex(master.chainCode)).toBe(
      "3478b2edffa426812e7dfcc9ed1447a7ac08807a18223c98d5935e3cca0dbebf",
    );
  });

  it("derives the same addresses as the Python wallet", () => {
    const cases: Array<[string, string]> = [
      ["m/44'/1'/0'/0/0", "tJJ8J4iCNNbL5SsBaccPXmrHu4jJjNupUN"],
      ["m/44'/1'/0'/0/1", "tCU7426iSrWWEvUbfrkT2zEdZ4yLTSurSE"],
      ["m/44'/1'/0'/0/2", "tM16yY61H1Q9RemEHFLtx7bwXiZF2F2fcj"],
    ];
    for (const [path, address] of cases) {
      const secret = deriveFromSeed(fromHex(SEED), path);
      expect(addressFromPrivateKey(secret, 127)).toBe(address);
    }
  });
});
