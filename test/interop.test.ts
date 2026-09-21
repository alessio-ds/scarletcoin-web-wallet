import { describe, expect, it } from "vitest";
import { Keystore } from "../src/lib/keystore.js";
import { decryptBlob, decodeUtf8, walletAssociatedData } from "../src/lib/encryption.js";

describe("wallet-file interoperability with the Python wallet", () => {
  it("seals an encrypted version-1 wallet so the Python wallet can open it", async () => {
    const keystore = await Keystore.create("regtest", "hunter2");
    const document = await keystore.toDocument();
    expect(document.version).toBe(1);
    expect(document.crypto).toBeDefined();

    // The Python wallet always decrypts with the *current* wallet version's
    // associated data and expects a dict payload, not a bare key list.
    const plaintext = await decryptBlob(
      "hunter2",
      document.crypto!,
      walletAssociatedData("regtest", 2),
    );
    const payload = JSON.parse(decodeUtf8(plaintext));
    expect(Array.isArray(payload)).toBe(false);
    expect(payload.imported).toHaveLength(1);
    expect(typeof payload.imported[0].wif).toBe("string");
  });

  it("reads a version-2 wallet with imported keys but no seed", async () => {
    // This is what the Python wallet writes when it upgrades a legacy key-list
    // wallet: version 2, no seed, just imported keys.
    const source = await Keystore.create("regtest");
    const wif = source.exportWif(source.defaultAddress());
    const document = {
      version: 2,
      network: "regtest",
      encrypted: false,
      next_index: 0,
      addresses: [
        { address: source.defaultAddress(), label: "legacy", created: 0 },
      ],
      imported: [{ wif, label: "legacy", created: 0 }],
    };

    const keystore = await Keystore.fromDocument(document as any);
    expect(keystore.version).toBe(2);
    expect(keystore.addressStrings()).toEqual([source.defaultAddress()]);
    expect(keystore.keysByHash().size).toBe(1);
  });
});