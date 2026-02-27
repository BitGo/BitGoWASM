const BTC_DECIMALS = 8;
const SATS_PER_BTC = 100_000_000n;

export function formatBtc(satoshis: bigint): string {
  const negative = satoshis < 0n;
  const abs = negative ? -satoshis : satoshis;
  const whole = abs / SATS_PER_BTC;
  const frac = abs % SATS_PER_BTC;
  const fracStr = frac.toString().padStart(BTC_DECIMALS, "0");
  return `${negative ? "-" : ""}${whole}.${fracStr}`;
}

export function formatAddress(addr: string, chars = 8): string {
  if (addr.length <= chars * 2 + 3) return addr;
  return `${addr.slice(0, chars)}...${addr.slice(-chars)}`;
}
