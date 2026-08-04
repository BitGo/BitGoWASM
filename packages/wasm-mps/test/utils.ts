import crypto from "crypto";
import * as mps from "../js";
import sodium from "libsodium-wrappers-sumo";

/** Clamp a 32-byte LE scalar to Ed25519 format (matching pShare.u). */
export function clampScalar(bytes: Buffer): Buffer {
  const s = Buffer.from(bytes);
  s[0] &= 248; // clear bits 0-2
  s[31] &= 127; // clear bit 255
  s[31] |= 64; // set bit 254
  return s;
}

/**
 * Generate `n` clamped scalars and compute the aggregate Ed25519 public key
 * expected_pk = G × (s_0 + s_1 + ... + s_{n-1}).
 *
 * Uses libsodium:
 *   - crypto_scalarmult_ed25519_base_noclamp to compute each G×s_i
 *   - crypto_core_ed25519_add to sum the resulting points
 */
export function makeImportShares(n = 3): {
  scalars: Buffer[];
  expectedPk: Buffer;
  chainCode: Buffer;
} {
  const scalars = Array.from({ length: n }, () => clampScalar(crypto.randomBytes(32)));

  // G×s_i for each party, then add all points together
  const points = scalars.map((s) => sodium.crypto_scalarmult_ed25519_base_noclamp(s));
  const expectedPk = Buffer.from(points.reduce((acc, p) => sodium.crypto_core_ed25519_add(acc, p)));
  const chainCode = crypto.randomBytes(32);
  return { scalars, expectedPk, chainCode };
}

/** Run the full import DKG (round0_import → round1 → round2) for 3 parties. */
export function runImportDkg(
  keypairs: Array<{ privateKey: Uint8Array; publicKey: Uint8Array }>,
  scalars: Buffer[],
  expectedPk: Buffer,
  chainCode: Buffer,
): mps.Share[] {
  const otherIdx = [
    [1, 2],
    [0, 2],
    [0, 1],
  ];

  const r0 = [0, 1, 2].map((i) =>
    mps.ed25519_dkg_round0_import(
      i,
      keypairs[i].privateKey,
      otherIdx[i].map((j) => keypairs[j].publicKey),
      scalars[i],
      expectedPk,
      chainCode,
    ),
  );

  const r1 = [0, 1, 2].map((i) =>
    mps.ed25519_dkg_round1_process(
      otherIdx[i].map((j) => r0[j].msg),
      r0[i].state,
    ),
  );

  return [0, 1, 2].map((i) =>
    mps.ed25519_dkg_round2_process(
      otherIdx[i].map((j) => r1[j].msg),
      r1[i].state,
    ),
  );
}

/** Run the full 4-round DSG (r0→r3) for parties 0 and 2. Returns both signatures. */
export function runDsg(
  shares: mps.Share[],
  path: string,
  message: Buffer,
): [Uint8Array, Uint8Array] {
  const dsg0 = [0, 2].map((i) => mps.ed25519_dsg_round0_process(shares[i].share, path, message));
  const dsg1 = [0, 1].map((i) => mps.ed25519_dsg_round1_process(dsg0[i ^ 1].msg, dsg0[i].state));
  const dsg2 = [0, 1].map((i) => mps.ed25519_dsg_round2_process(dsg1[i ^ 1].msg, dsg1[i].state));
  const sigs = [0, 1].map((i) => mps.ed25519_dsg_round3_process(dsg2[i ^ 1].msg, dsg2[i].state));
  return [sigs[0], sigs[1]];
}
