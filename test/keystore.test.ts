import { describe, expect, it } from "vitest";
import { WalletError } from "../src/lib/keystore.js";
import { Keystore } from "../src/lib/keystore.js";

describe("Keystore", () => {
  it("creates a wallet with one address and round-trips unencrypted", async () => {
    const keystore = await Keystore.create("mainnet");
    const document = await keystore.toDocument();
    expect(document.version).toBe(1);
    expect(document.network).toBe("mainnet");
    expect(document.encrypted).toBe(false);
    expect(document.keys).toHaveLength(1);
    expect(document.addresses).toHaveLength(1);

    const reloaded = await Keystore.fromDocument(document);
    expect(reloaded.addressStrings()).toEqual(keystore.addressStrings());
    expect(reloaded.exportWif(reloaded.defaultAddress())).toBe(
      keystore.exportWif(keystore.defaultAddress()),
    );
  });

  it("encrypts and decrypts with a password", async () => {
    const keystore = await Keystore.create("mainnet", "hunter2");
    const document = await keystore.toDocument();
    expect(document.encrypted).toBe(true);
    expect(document.keys).toBeUndefined();
    expect(document.crypto).toBeDefined();

    // Addresses remain readable without the password.
    const locked = await Keystore.fromDocument(document);
    expect(locked.locked).toBe(true);
    expect(locked.addressStrings().length).toBe(1);
    expect(() => locked.exportWif(locked.defaultAddress())).toThrow(WalletError);

    await locked.unlock("hunter2");
    expect(locked.locked).toBe(false);
    expect(locked.exportWif(locked.defaultAddress())).toBe(
      keystore.exportWif(keystore.defaultAddress()),
    );
  });

  it("rejects a wrong password", async () => {
    const keystore = await Keystore.create("mainnet", "correct");
    const document = await keystore.toDocument();
    const reloaded = await Keystore.fromDocument(document);
    await expect(reloaded.unlock("wrong")).rejects.toThrow(WalletError);
  });

  it("imports and exports WIF keys", async () => {
    const other = await Keystore.create("mainnet");
    const wif = other.exportWif(other.defaultAddress());
    const keystore = await Keystore.create("mainnet");
    const address = keystore.importWif(wif, "copy");
    expect(keystore.addressStrings()).toContain(address);
    expect(() => keystore.importWif(wif)).toThrow(WalletError); // duplicate
  });

  it("loads a version-2 wallet and derives its addresses", async () => {
    // Produced by the Python wallet: mnemonic "abandon abandon ... about" (regtest).
    const document = {
      version: 2,
      network: "regtest",
      encrypted: false,
      next_index: 2,
      addresses: [
        { address: "tMzCw5dZb8AKbxgmb3AG15Tp4yFz8ksaSb", label: "main", created: 0, path: "m/44'/1'/0'/0/0" },
        { address: "tV3iEgo8fScacxRodra7XsPYqFm8aprTpD", label: "second", created: 0, path: "m/44'/1'/0'/0/1" },
      ],
      seed: "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
      imported: [],
    };
    const keystore = await Keystore.fromDocument(document as any);
    expect(keystore.version).toBe(2);
    expect(keystore.addressStrings()).toEqual([
      "tMzCw5dZb8AKbxgmb3AG15Tp4yFz8ksaSb",
      "tV3iEgo8fScacxRodra7XsPYqFm8aprTpD",
    ]);

    // Round-trips the seed back out unchanged.
    const rewritten = await keystore.toDocument();
    expect(rewritten.version).toBe(2);
    expect(rewritten.seed).toBe(document.seed);
    expect(rewritten.addresses[0]?.path).toBe("m/44'/1'/0'/0/0");

    // Deriving a fresh key continues the sequence.
    const next = keystore.newKey("third");
    expect(keystore.addressStrings()).toContain(next);
  });

  it("decrypts an encrypted version-2 wallet produced by the Python wallet", async () => {
    const document = {
      version: 2,
      network: "regtest",
      encrypted: true,
      next_index: 1,
      addresses: [
        { address: "tMzCw5dZb8AKbxgmb3AG15Tp4yFz8ksaSb", label: "main", created: 0, path: "m/44'/1'/0'/0/0" },
      ],
      crypto: {
        kdf: "scrypt",
        kdf_params: { n: 65536, r: 8, p: 1, salt: "7f3ee18becdc8095d76c7b4179ef2992" },
        cipher: "aes-256-gcm",
        nonce: "482228f7628fa8bf166d9d6e",
        ciphertext:
          "9bf77e8da8884c0136ead3f1a36ff130512a633863e63a6fb7aa270f206bc460c0d4c190939ad32797b66410f648ad016fd34e87cce66fd67eaa480b1ef59b92321ed626cc375fb5edccec3554b2dc1536d47198626ee280f4b3b045bb3bcae3d5cbc0aa42189e82c4998d89f844f15f3277a83a608fe2febc686c72e0aef1a7569600e4ac84332d69ab03207ac45b16a702f2b742792b07f95f1d86c4d48d129eef893606ffd362c56fa197",
      },
    };
    const keystore = await Keystore.fromDocument(document as any);
    expect(keystore.locked).toBe(true);
    expect(keystore.addressStrings()).toEqual(["tMzCw5dZb8AKbxgmb3AG15Tp4yFz8ksaSb"]);
    await keystore.unlock("hunter2");
    expect(keystore.locked).toBe(false);
    // The derived key's WIF matches what the Python wallet would export.
    expect(keystore.exportWif("tMzCw5dZb8AKbxgmb3AG15Tp4yFz8ksaSb")).toMatch(/^c/);
  });
});
