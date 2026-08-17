/**
 * Converting between ScarletCoin amounts and human-readable strings, matching
 * ``scarletcoin.units``. Amounts are integers internally: one SCT is COIN scar.
 */
import { COIN, MAX_MONEY } from "./params.js";

const PLACES = COIN.toString().length - 1; // 8

export function formatAmount(scar: bigint, symbol = false): string {
  if (typeof scar !== "bigint") throw new TypeError("amounts must be bigints");
  const sign = scar < 0n ? "-" : "";
  const abs = scar < 0n ? -scar : scar;
  const whole = abs / COIN;
  const fraction = abs % COIN;
  let text = `${sign}${whole}`;
  if (fraction !== 0n) {
    text += "." + fraction.toString().padStart(PLACES, "0").replace(/0+$/, "");
  }
  return symbol ? `${text} SCT` : text;
}

export function parseAmount(text: string): bigint {
  let cleaned = text.trim().replace(/SCT$/i, "").trim();
  if (!cleaned) throw new Error("no amount given");
  let sign = 1n;
  if (cleaned.startsWith("-")) {
    sign = -1n;
    cleaned = cleaned.slice(1);
  }
  if (cleaned.split(".").length > 2) throw new Error(`${text} is not a valid amount`);
  const [wholePart, fractionPart] = cleaned.split(".");
  const whole = wholePart ?? "";
  const fraction = fractionPart ?? "";
  if (whole === "" && fraction === "") throw new Error(`${text} is not a valid amount`);
  if (!/^\d*$/.test(whole) || !/^\d*$/.test(fraction)) {
    throw new Error(`${text} is not a valid amount`);
  }
  if (fraction.length > PLACES) {
    throw new Error(`${text} has more than ${PLACES} decimal places`);
  }
  const wholeValue = BigInt(whole || "0");
  const fractionValue = BigInt((fraction + "0".repeat(PLACES - fraction.length)) || "0");
  const scar = sign * (wholeValue * COIN + fractionValue);
  if (scar < 0n) throw new Error("amounts must not be negative");
  if (scar > MAX_MONEY) throw new Error("amount exceeds the maximum money supply");
  return scar;
}