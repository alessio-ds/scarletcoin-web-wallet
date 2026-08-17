/**
 * A small JSON-RPC client, matching the subset of ``scarletcoin.net.client`` the
 * wallet needs. Uses fetch, so it works in the browser against a public node.
 */

export interface RpcError {
  code: number;
  message: string;
}

export class RpcClientError extends Error {
  code: number | null;
  constructor(message: string, code: number | null = null) {
    super(message);
    this.code = code;
  }
}

export class RpcClient {
  constructor(
    public readonly url: string,
    public readonly token: string | null = null,
    private readonly timeoutMs = 30_000,
  ) {}

  async call(method: string, ...params: unknown[]): Promise<any> {
    const payload = {
      jsonrpc: "2.0",
      id: Math.floor(Math.random() * 0xffffffff),
      method,
      params,
    };
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (this.token) headers["Authorization"] = `Bearer ${this.token}`;

    let response: Response;
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);
      response = await fetch(`${this.url}/rpc`, {
        method: "POST",
        headers,
        body: JSON.stringify(payload),
        signal: controller.signal,
      });
      clearTimeout(timer);
    } catch (error) {
      throw new RpcClientError(`cannot reach the node at ${this.url}: ${String(error)}`);
    }

    if (!response.ok) {
      const detail = (await response.text()).slice(0, 200);
      throw new RpcClientError(
        `node returned HTTP ${response.status} for ${method}: ${detail}`,
        response.status,
      );
    }

    let message: any;
    try {
      message = await response.json();
    } catch (error) {
      throw new RpcClientError(`malformed answer from the node: ${String(error)}`);
    }
    if (message && typeof message === "object" && message.error) {
      throw new RpcClientError(String(message.error.message ?? message.error), message.error.code ?? null);
    }
    return message.result;
  }

  async getInfo(): Promise<any> {
    return this.call("getinfo");
  }

  async getBlockCount(): Promise<number> {
    return this.call("getblockcount");
  }

  async getBalance(address: string): Promise<any> {
    return this.call("getbalance", address);
  }

  async getUtxos(address: string): Promise<any> {
    return this.call("getutxos", address);
  }

  async getAddressHistory(address: string, limit = 100): Promise<any> {
    return this.call("getaddresshistory", address, limit);
  }

  async sendRawTransaction(rawHex: string): Promise<string> {
    return this.call("sendrawtransaction", rawHex);
  }

  async getPublicNodes(): Promise<string[]> {
    return this.call("getpublicnodes");
  }

  async validateAddress(address: string): Promise<any> {
    return this.call("validateaddress", address);
  }
}