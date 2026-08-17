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
});
