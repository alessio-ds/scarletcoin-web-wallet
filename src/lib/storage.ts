/**
 * Browser persistence: the wallet document and app settings live in IndexedDB.
 * Nothing secret is ever written unless the wallet is encrypted, and then only
 * the scrypt+AES-GCM envelope (which the server never sees).
 */

const DB_NAME = "scarletcoin-web-wallet";
const DB_VERSION = 1;
const STORE = "kv";

export interface AppSettings {
  network: string;
  nodeUrl: string;
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function kvGet<T>(key: string): Promise<T | undefined> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readonly");
    const request = tx.objectStore(STORE).get(key);
    request.onsuccess = () => resolve(request.result as T | undefined);
    request.onerror = () => reject(request.error);
    tx.oncomplete = () => db.close();
  });
}

async function kvSet(key: string, value: unknown): Promise<void> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).put(value, key);
    tx.oncomplete = () => {
      db.close();
      resolve();
    };
    tx.onerror = () => reject(tx.error);
  });
}

async function kvDelete(key: string): Promise<void> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).delete(key);
    tx.oncomplete = () => {
      db.close();
      resolve();
    };
    tx.onerror = () => reject(tx.error);
  });
}

const WALLET_KEY = "wallet";

export async function loadWalletDocument(): Promise<Record<string, unknown> | undefined> {
  return kvGet(WALLET_KEY);
}

export async function saveWalletDocument(document: Record<string, unknown>): Promise<void> {
  await kvSet(WALLET_KEY, document);
}

export async function clearWallet(): Promise<void> {
  await kvDelete(WALLET_KEY);
}

const SETTINGS_KEY = "settings";

export async function loadSettings(): Promise<AppSettings | undefined> {
  return kvGet(SETTINGS_KEY);
}

export async function saveSettings(settings: AppSettings): Promise<void> {
  await kvSet(SETTINGS_KEY, settings);
}
