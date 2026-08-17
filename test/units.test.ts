import { describe, expect, it } from "vitest";
import { formatAmount, parseAmount } from "../src/lib/units.js";
import { COIN, MAX_MONEY } from "../src/lib/params.js";

describe("amount formatting", () => {
  it("formats whole and fractional amounts like the Python wallet", () => {
    expect(formatAmount(0n)).toBe("0");
    expect(formatAmount(COIN)).toBe("1");
    expect(formatAmount(12n * COIN + 345_000_00n)).toBe("12.345");
    expect(formatAmount(COIN + 1n)).toBe("1.00000001");
    expect(formatAmount(-COIN)).toBe("-1");
  });

  it("parses decimal strings into scar", () => {
    expect(parseAmount("1")).toBe(COIN);
    expect(parseAmount("12.345")).toBe(12n * COIN + 345_000_00n);
    expect(parseAmount("1.00000001")).toBe(COIN + 1n);
    expect(parseAmount("0.00000001")).toBe(1n);
    expect(parseAmount("1 SCT")).toBe(COIN);
    expect(parseAmount(".5")).toBe(COIN / 2n);
  });

  it("rejects malformed or out-of-range amounts", () => {
    expect(() => parseAmount("")).toThrow();
    expect(() => parseAmount("abc")).toThrow();
    expect(() => parseAmount("-1")).toThrow();
    expect(() => parseAmount("1.000000001")).toThrow();
    expect(() => parseAmount("1.2.3")).toThrow();
    expect(() => parseAmount((MAX_MONEY + 1n).toString())).toThrow();
  });

  it("round-trips formatted amounts", () => {
    for (const text of ["0", "1", "12.345", "100000", "0.00000001", "1234.5678"]) {
      expect(formatAmount(parseAmount(text))).toBe(text);
    }
  });
});
