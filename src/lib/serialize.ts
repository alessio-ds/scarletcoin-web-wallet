/**
 * Deterministic binary serialisation, matching the Python Writer in
 * ``scarletcoin.core.serialize``. All multi-byte integers are little-endian.
 */
export class Writer {
  private parts: Uint8Array[] = [];

  raw(data: Uint8Array): this {
    this.parts.push(new Uint8Array(data));
    return this;
  }

  uint8(value: number): this {
    const buf = new Uint8Array(1);
    const dv = new DataView(buf.buffer);
    dv.setUint8(0, value);
    this.parts.push(buf);
    return this;
  }

  uint16(value: number): this {
    const buf = new Uint8Array(2);
    const dv = new DataView(buf.buffer);
    dv.setUint16(0, value, true);
    this.parts.push(buf);
    return this;
  }

  uint32(value: number): this {
    const buf = new Uint8Array(4);
    const dv = new DataView(buf.buffer);
    dv.setUint32(0, value, true);
    this.parts.push(buf);
    return this;
  }

  uint64(value: bigint | number): this {
    const buf = new Uint8Array(8);
    const dv = new DataView(buf.buffer);
    dv.setBigUint64(0, BigInt(value), true);
    this.parts.push(buf);
    return this;
  }

  varint(value: number): this {
    if (value < 0 || value > 0xffffffffffffffffn) {
      throw new Error(`varint out of range: ${value}`);
    }
    if (value < 0xfd) {
      this.uint8(value);
    } else if (value <= 0xffff) {
      this.uint8(0xfd).uint16(value);
    } else if (value <= 0xffffffff) {
      this.uint8(0xfe).uint32(value);
    } else {
      this.uint8(0xff).uint64(value);
    }
    return this;
  }

  varbytes(data: Uint8Array): this {
    this.varint(data.length);
    this.raw(data);
    return this;
  }

  hash32(digest: Uint8Array): this {
    if (digest.length !== 32) {
      throw new Error(`expected a 32-byte hash, got ${digest.length}`);
    }
    this.raw(digest);
    return this;
  }

  getvalue(): Uint8Array {
    const total = this.parts.reduce((s, p) => s + p.length, 0);
    const result = new Uint8Array(total);
    let offset = 0;
    for (const part of this.parts) {
      result.set(part, offset);
      offset += part.length;
    }
    return result;
  }
}