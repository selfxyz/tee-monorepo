import { toBigInt, getAddress, keccak256, randomBytes } from "ethers";

export class FuzzedNumber {
  static random(): bigint {
    const bytes = randomBytes(32);
    return toBigInt(bytes);
  }

  static randomInRange(min: bigint, max: bigint): bigint {
    if (max <= min) {
      throw new Error("max should be more than min");
    }
    const bytes = randomBytes(32);
    const diff = max - min;
    return toBigInt(bytes) % diff + min;
  }
}

export class FuzzedAddress {
  static random(rand = "123"): string {
    let address = keccak256(Buffer.from(rand + new Date().valueOf().toString()))
      .toString()
      .slice(0, 42);
    return getAddress(address);
  }
}
