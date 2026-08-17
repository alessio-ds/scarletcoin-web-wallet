/**
 * The wallet: balances, history and spending on top of a node's RPC interface,
 * matching ``scarletcoin.wallet.wallet``. Keys are held locally; the node only
 * ever sees finished transactions.
 */
import {
  InsufficientFundsError,
  buildSweepTransaction,
  buildTransaction,
  type BuiltTransaction,
  type Coin,
} from "./builder.js";
import { decodeAddress, InvalidKeyError } from "./keys.js";
import { Keystore, WalletError } from "./keystore.js";
import { RpcClient } from "./rpc.js";
import { txidHex, serialize, type OutPoint } from "./transaction.js";
import { fromHex, reverseBytes, toHex } from "./util.js";

export interface Balance {
  confirmed: bigint;
  spendable: bigint;
  immature: bigint;
  utxoCount: number;
}

export interface SendResult extends BuiltTransaction {
  txid: string;
}

export class Wallet {
  constructor(
    public readonly keystore: Keystore,
    public client: RpcClient,
  ) {}

  async height(): Promise<number> {
    return this.client.getBlockCount();
  }

  async coins(spendableOnly = true): Promise<Coin[]> {
    const result: Coin[] = [];
    for (const address of this.keystore.addressStrings()) {
      const pubkeyHash = decodeAddress(address, this.keystore.params.addressVersion).hash;
      const data = await this.client.getUtxos(address);
      for (const item of data.utxos ?? []) {
        if (spendableOnly && !item.spendable) continue;
        result.push({
          outpoint: {
            txid: reverseBytes(fromHex(item.txid)),
            index: Number(item.index),
          } as OutPoint,
          value: BigInt(item.value),
          pubkeyHash,
        });
      }
    }
    return result;
  }

  async balance(): Promise<Balance> {
    let confirmed = 0n;
    let spendable = 0n;
    let immature = 0n;
    let count = 0;
    for (const address of this.keystore.addressStrings()) {
      const data = await this.client.getBalance(address);
      confirmed += BigInt(data.balance ?? 0);
      spendable += BigInt(data.spendable ?? 0);
      immature += BigInt(data.immature ?? 0);
      count += Number(data.utxo_count ?? 0);
    }
    return { confirmed, spendable, immature, utxoCount: count };
  }

  async balancesByAddress(): Promise<Array<{ address: string; label: string; balance: bigint }>> {
    const rows: Array<{ address: string; label: string; balance: bigint }> = [];
    for (const record of this.keystore.addresses()) {
      const data = await this.client.getBalance(record.address);
      rows.push({ address: record.address, label: record.label, balance: BigInt(data.balance ?? 0) });
    }
    return rows;
  }

  async history(limit = 50): Promise<any[]> {
    const entries = new Map<string, any>();
    for (const address of this.keystore.addressStrings()) {
      const data = await this.client.getAddressHistory(address, limit);
      for (const item of data.transactions ?? []) {
        const existing = entries.get(item.txid);
        if (!existing) {
          entries.set(item.txid, { ...item, address });
        } else {
          existing.received = BigInt(existing.received) + BigInt(item.received);
          existing.sent = BigInt(existing.sent) + BigInt(item.sent);
          existing.net = BigInt(existing.received) - BigInt(existing.sent);
        }
      }
    }
    const ordered = [...entries.values()].sort((a, b) => {
      if (a.height !== b.height) return a.height - b.height;
      return a.txid < b.txid ? -1 : a.txid > b.txid ? 1 : 0;
    });
    return ordered.reverse().slice(0, limit);
  }

  defaultFeeRate(): bigint {
    return BigInt(this.keystore.params.minRelayFeePerKb);
  }

  private parseDestination(destination: string): Uint8Array {
    try {
      return decodeAddress(destination, this.keystore.params.addressVersion).hash;
    } catch (error) {
      if (error instanceof InvalidKeyError) throw new WalletError(error.message);
      throw error;
    }
  }

  async send(
    destination: string,
    amount: bigint,
    options: { feePerKb?: bigint; broadcast?: boolean } = {},
  ): Promise<SendResult> {
    const feePerKb = options.feePerKb ?? this.defaultFeeRate();
    const broadcast = options.broadcast ?? true;
    const targetHash = this.parseDestination(destination);
    const keys = this.keystore.keysByHash();
    const changeHash = this.parseDestination(this.keystore.defaultAddress());
    const built = buildTransaction({
      spendableCoins: await this.coins(),
      keys,
      outputs: [{ hash: targetHash, value: amount }],
      changeHash,
      feePerKb,
    });
    return this.finish(built, broadcast);
  }

  async sendEverything(
    destination: string,
    options: { feePerKb?: bigint; broadcast?: boolean } = {},
  ): Promise<SendResult> {
    const feePerKb = options.feePerKb ?? this.defaultFeeRate();
    const broadcast = options.broadcast ?? true;
    const targetHash = this.parseDestination(destination);
    const coins = await this.coins();
    if (coins.length === 0) throw new InsufficientFundsError("this wallet has no spendable coins");
    const built = buildSweepTransaction({
      spendableCoins: coins,
      keys: this.keystore.keysByHash(),
      destination: targetHash,
      feePerKb,
    });
    return this.finish(built, broadcast);
  }

  private async finish(built: BuiltTransaction, broadcast: boolean): Promise<SendResult> {
    let txid = txidHex(built.transaction);
    if (broadcast) {
      txid = await this.client.sendRawTransaction(toHex(serialize(built.transaction)));
    }
    return { ...built, txid };
  }

  newAddress(label = ""): string {
    const address = this.keystore.newKey(label);
    return address;
  }

  importWif(wif: string, label = "imported"): string {
    return this.keystore.importWif(wif, label);
  }

  exportWif(address: string): string {
    return this.keystore.exportWif(address);
  }

  async nodeInfo(): Promise<any> {
    try {
      return await this.client.getInfo();
    } catch (error) {
      return { error: String(error) };
    }
  }
}

export { InsufficientFundsError };