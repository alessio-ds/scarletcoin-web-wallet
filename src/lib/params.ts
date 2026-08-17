/**
 * Network parameters for the wallet, mirroring the values in
 * ``scarletcoin.core.params`` that matter to a light client.
 */
export const COIN = 100_000_000n;
export const MAX_MONEY = 21_000_000n * COIN;

export interface ChainParams {
  name: string;
  addressVersion: number;
  wifVersion: number;
  defaultRpcPort: number;
  minRelayFeePerKb: number;
  publicNodes: string[];
}

export const MAINNET: ChainParams = {
  name: "mainnet",
  addressVersion: 63, // addresses start with "S"
  wifVersion: 191,
  defaultRpcPort: 20332,
  minRelayFeePerKb: 1000,
  publicNodes: ["https://scarletcoin.remotewire.net"],
};

export const TESTNET: ChainParams = {
  name: "testnet",
  addressVersion: 127, // addresses start with "t"
  wifVersion: 239,
  defaultRpcPort: 30332,
  minRelayFeePerKb: 1000,
  publicNodes: [],
};

export const REGTEST: ChainParams = {
  name: "regtest",
  addressVersion: 127,
  wifVersion: 239,
  defaultRpcPort: 40332,
  minRelayFeePerKb: 1000,
  publicNodes: [],
};

export const NETWORKS: Record<string, ChainParams> = {
  mainnet: MAINNET,
  testnet: TESTNET,
  regtest: REGTEST,
};

export function getParams(name: string): ChainParams {
  const params = NETWORKS[name];
  if (!params) {
    throw new Error(`unknown network ${JSON.stringify(name)}; choose one of: ${Object.keys(NETWORKS).join(", ")}`);
  }
  return params;
}