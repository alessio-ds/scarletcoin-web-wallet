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
  // The suffix is matched case-sensitively, as the Python wallet does.
  const cleaned = text.trim().replace(/SCT$/, "").trim();
  if (!cleaned) throw new Error("no amount given");
  // Accept the shapes Python's Decimal does: an optional sign, digits (with the
  // separators Decimal allows) and an optional decimal point.
  if (!/^[+-]?(\d[\d_]*(\.\d*)?|\.\d+)$/.test(cleaned)) {
    throw new Error(`${text} is not a valid amount`);
  }
  const body = cleaned.replace(/^[+-]/, "").replace(/_/g, "");
  const [wholePart = "", fractionPart = ""] = body.split(".");
  // Trailing zeros do not count as decimal places: "1.000000000" is 1 SCT.
  if (fractionPart.replace(/0+$/, "").length > PLACES) {
    throw new Error(`${text} has more than ${PLACES} decimal places`);
  }
  const fraction = (fractionPart + "0".repeat(PLACES)).slice(0, PLACES);
  const magnitude = BigInt(wholePart || "0") * COIN + BigInt(fraction || "0");
  const scar = cleaned.startsWith("-") ? -magnitude : magnitude;
  if (scar < 0n) throw new Error("amounts must not be negative");
  if (scar > MAX_MONEY) throw new Error("amount exceeds the maximum money supply");
  return scar;
}