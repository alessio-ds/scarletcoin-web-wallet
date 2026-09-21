import { describe, expect, it } from "vitest";
import {
  buildCandidateBlock,
  parseBlockTemplate,
  rebuildBlockHex,
  setHeaderNonce,
} from "../src/lib/template.js";
import { hash256 } from "../src/lib/hashing.js";
import { fromHex, toHex } from "../src/lib/util.js";
import miningData from "./fixtures/mining.json";

const mining = miningData as any;

describe("block assembly (byte-for-byte against the Python node)", () => {
  it("reproduces a block built by ScarletCoin's BlockTemplate", () => {
    const template = parseBlockTemplate(mining.template);
    const candidate = buildCandidateBlock(
      template,
      fromHex(mining.pubkey_hash),
      fromHex(mining.extra_nonce),
    );
    const header = setHeaderNonce(candidate.header, mining.nonce);

    expect(toHex(header)).toBe(mining.block_hex.slice(0, 160));
    expect(rebuildBlockHex(header, candidate.transactions)).toBe(mining.block_hex);
    expect(toHex(hash256(header).slice().reverse())).toBe(mining.block_hash);
  });

  it("stamps the header with the template's current_time, not the wall clock", () => {
    const template = parseBlockTemplate(mining.template);
    const candidate = buildCandidateBlock(
      template,
      fromHex(mining.pubkey_hash),
      fromHex(mining.extra_nonce),
    );
    const timestamp = new DataView(candidate.header.buffer).getUint32(68, true);

    // The fixture's current_time is a fixed 2023 instant; if the builder used
    // Date.now() the header (and the block hash) would not match the node, and
    // the node would reject the block as "wrong difficulty".
    expect(timestamp).toBe(mining.template.current_time);
    expect(timestamp).toBe(mining.timestamp);
  });
});