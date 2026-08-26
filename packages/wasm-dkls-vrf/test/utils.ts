import * as sl from "@silencelaboratories/dkls-wasm-ll-node";
import crypto from "crypto";
import { VrfDkgSession, HardDeriveSession } from "../js";

/** A protocol message on the wire: `to` is undefined for broadcasts. */
export interface Msg {
  payload: Uint8Array;
  from: number;
  to?: number;
}

export function range(n: number): number[] {
  return Array.from({ length: n }, (_, i) => i);
}

/** Deterministic per-party, per-round seeds so test runs are reproducible. */
export function seed(partyId: number, round: number): Uint8Array {
  const s = new Uint8Array(32);
  s[0] = partyId;
  s[1] = round;
  return s;
}

function toMsg(m: sl.Message): Msg {
  const msg = { payload: m.payload, from: m.from_id, to: m.to_id };
  m.free();
  return msg;
}

/** Messages party `i` should receive: broadcasts from others plus p2p addressed to it. */
function inboxFor(msgs: Msg[], i: number): sl.Message[] {
  return msgs
    .filter((m) => (m.to === undefined ? m.from !== i : m.to === i))
    .map((m) => new sl.Message(m.payload, m.from, m.to));
}

function slRound(sessions: sl.KeygenSession[], msgs: Msg[], commitments?: Uint8Array[]): Msg[] {
  return sessions.flatMap((session, i) =>
    session.handleMessages(inboxFor(msgs, i), commitments).map(toMsg),
  );
}

/**
 * Run Silence Labs' published signing DKG to produce root key shares. This is the
 * package we do *not* wrap - it is here to prove our hard-derivation output stays
 * byte-compatible with their build in both directions.
 */
export function slDkg(n: number, t: number): Uint8Array[] {
  const sessions = range(n).map((i) => new sl.KeygenSession(n, t, i));

  let msgs = sessions.map((s) => toMsg(s.createFirstMessage()));
  msgs = slRound(sessions, msgs);
  const commitments = sessions.map((s) => s.calculateChainCodeCommitment());
  msgs = slRound(sessions, msgs);
  msgs = slRound(sessions, msgs, commitments);
  slRound(sessions, msgs);

  return sessions.map((session) => {
    const keyshare = session.keyshare();
    const bytes = keyshare.toBytes();
    keyshare.free();
    return bytes;
  });
}

/** Sign `messageHash` with Silence Labs' DSG using `keyshares` (one per signer). */
export function slSign(
  keyshares: Uint8Array[],
  chainPath: string,
  messageHash: Uint8Array,
): { r: Uint8Array; s: Uint8Array } {
  const shares = keyshares.map((bytes) => sl.Keyshare.fromBytes(bytes));
  const partyIds = shares.map((share) => share.partyId);
  const sessions = shares.map((share) => new sl.SignSession(share, chainPath));

  // party index within `sessions` is not the party id, so route by party id
  const inbox = (msgs: Msg[], idx: number) =>
    msgs
      .filter((m) => (m.to === undefined ? m.from !== partyIds[idx] : m.to === partyIds[idx]))
      .map((m) => new sl.Message(m.payload, m.from, m.to));

  let msgs = sessions.map((s) => toMsg(s.createFirstMessage()));
  for (let round = 0; round < 3; round++) {
    msgs = sessions.flatMap((session, idx) => session.handleMessages(inbox(msgs, idx)).map(toMsg));
  }

  const last = sessions.map((session) => toMsg(session.lastMessage(messageHash)));
  // `combine` is typed as `Array<any>` by wasm-bindgen; it is `[R, S]`
  const combined: Array<[Uint8Array, Uint8Array]> = sessions.map((session, idx) => {
    const [r, s] = session.combine(inbox(last, idx)) as unknown[];
    return [r as Uint8Array, s as Uint8Array];
  });

  const [r, s] = combined[0];
  for (const [otherR, otherS] of combined.slice(1)) {
    if (
      Buffer.compare(Buffer.from(r), Buffer.from(otherR)) !== 0 ||
      Buffer.compare(Buffer.from(s), Buffer.from(otherS)) !== 0
    ) {
      throw new Error("signers produced different signatures");
    }
  }
  return { r, s };
}

/** Run our VRF DKG for all `n` parties and return the resulting key share bytes. */
export function vrfDkg(n: number, t: number): Uint8Array[] {
  const sessions = range(n).map((i) => new VrfDkgSession(n, t, i, seed(i, 0)));
  const msg1 = sessions.map((s, i) => s.createFirstMessage(seed(i, 1)));
  const msg2 = sessions.map((s, i) => s.handleRound1Messages(msg1, seed(i, 2)));
  return sessions.map((s) => {
    const keyshare = s.handleRound2Messages(msg2);
    const bytes = keyshare.toBytes();
    keyshare.free();
    return bytes;
  });
}

export interface Derived {
  keyshare: Uint8Array;
  publicKey: Uint8Array;
  rootChainCode: Uint8Array;
}

/** Run hard derivation over `quorum` (party ids) and return one result per signer. */
export function hardDerive(
  rootShares: Uint8Array[],
  vrfShares: Uint8Array[],
  quorum: number[],
  path: Uint8Array,
): Derived[] {
  const sessions = quorum.map(
    (i) => new HardDeriveSession(rootShares[i], vrfShares[i], path, seed(i, 3)),
  );
  const msg0 = sessions.map((s) => s.createFirstMessage());
  const msg1 = sessions.map((s, idx) => s.handleRound1Messages(msg0, seed(quorum[idx], 4)));
  return sessions.map((s) => {
    const derived = s.handleRound2Messages(msg1);
    const result = {
      keyshare: derived.keyshare,
      publicKey: derived.publicKey,
      rootChainCode: derived.rootChainCode,
    };
    derived.free();
    return result;
  });
}

// ---------------------------------------------------------------- signature checking

function derLength(len: number): Buffer {
  return len < 0x80 ? Buffer.from([len]) : Buffer.from([0x81, len]);
}

function derWrap(tag: number, body: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), derLength(body.length), body]);
}

function derInteger(value: Uint8Array): Buffer {
  let body = Buffer.from(value);
  while (body.length > 1 && body[0] === 0 && (body[1] & 0x80) === 0) {
    body = body.subarray(1);
  }
  if (body[0] & 0x80) {
    body = Buffer.concat([Buffer.from([0]), body]);
  }
  return derWrap(0x02, body);
}

/** DER-encode an ECDSA signature so node's `crypto.verify` can consume it. */
export function derSignature(r: Uint8Array, s: Uint8Array): Buffer {
  return derWrap(0x30, Buffer.concat([derInteger(r), derInteger(s)]));
}

/** Wrap a compressed secp256k1 point in an SPKI DER blob node can import. */
export function secp256k1PublicKey(compressed: Uint8Array): crypto.KeyObject {
  // AlgorithmIdentifier { id-ecPublicKey, secp256k1 }
  const algorithm = derWrap(
    0x30,
    Buffer.concat([
      derWrap(0x06, Buffer.from([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01])),
      derWrap(0x06, Buffer.from([0x2b, 0x81, 0x04, 0x00, 0x0a])),
    ]),
  );
  const point = derWrap(0x03, Buffer.concat([Buffer.from([0x00]), Buffer.from(compressed)]));
  return crypto.createPublicKey({
    key: derWrap(0x30, Buffer.concat([algorithm, point])),
    format: "der",
    type: "spki",
  });
}

export function verifySignature(
  publicKey: Uint8Array,
  message: Buffer,
  signature: { r: Uint8Array; s: Uint8Array },
): boolean {
  return crypto.verify(
    "sha256",
    message,
    secp256k1PublicKey(publicKey),
    derSignature(signature.r, signature.s),
  );
}
