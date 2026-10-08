// ykchat protocol: frame hashing, Merkle commitments, GPG->WebAuthn key
// binding, and verification of per-epoch WebAuthn-signed statements.
//
// Trust chain:
//   peer GPG fingerprint (pinned out of band)
//     -> clearsigned binding: "WebAuthn credential X (P-256 pubkey) speaks for me"
//       -> per-epoch WebAuthn assertion (YubiKey touch) over sha256(statement)
//         -> statement commits to Merkle root of the exact frames we received

import * as openpgp from "./vendor/openpgp.min.mjs";

export const PROTOCOL_VERSION = 1;
export const BINDING_TYPE = "ykchat-webauthn-binding";
export const ACK_WINDOW = 3; // peer_ack may reference any of our last N statements

const enc = new TextEncoder();
const dec = new TextDecoder();

// ------------------------------------------------------------- encoding

export const utf8 = (s) => enc.encode(s);
export const fromUtf8 = (b) => dec.decode(b);

export function hex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function unhex(s) {
  if (s.length % 2 || /[^0-9a-f]/i.test(s)) throw new Error("bad hex");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}

export function b64url(bytes) {
  let s = "";
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function unb64url(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}

export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

export function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** Deterministic JSON: sorted keys, no whitespace (same as the Python version). */
export function canonical(value) {
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (value && typeof value === "object") {
    return "{" + Object.keys(value).sort()
      .map((k) => JSON.stringify(k) + ":" + canonical(value[k])).join(",") + "}";
  }
  return JSON.stringify(value);
}

export const normFpr = (f) => f.replace(/\s+/g, "").toUpperCase();

// --------------------------------------------------------------- hashing

export async function sha256(...parts) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", concat(...parts)));
}

export function u64(n) {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n));
  return b;
}

// Frames and chat messages share one sequence space; the first byte separates the two leaf types.
export const frameLeaf = (seq, tsMs, jpeg) => sha256(Uint8Array.of(0), u64(seq), u64(tsMs), jpeg);
export const chatLeaf = (seq, tsMs, text) => sha256(Uint8Array.of(2), u64(seq), u64(tsMs), utf8(text));

/** RFC 6962-style domain separation; an odd node is promoted unchanged. */
export async function merkleRoot(leaves) {
  if (leaves.length === 0) return sha256(utf8("empty"));
  let level = leaves;
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i + 1 < level.length; i += 2) next.push(await sha256(Uint8Array.of(1), level[i], level[i + 1]));
    if (level.length % 2) next.push(level[level.length - 1]);
    level = next;
  }
  return level[0];
}

export async function sessionId(fprA, nonceA, fprB, nonceB) {
  const [a, b] = [[fprA, nonceA], [fprB, nonceB]].sort((x, y) => (x[0] < y[0] ? -1 : 1));
  return sha256(utf8("ykchat-session"), utf8(a[0]), a[1], utf8(b[0]), b[1]);
}

/**
 * Short code both sides display and read aloud. Each side commits to its nonce
 * before seeing the other's, so a man in the middle can't grind nonces until the
 * codes of its two separate sessions collide: it gets one 1-in-a-million guess.
 */
export async function safetyCode(sid) {
  const h = await sha256(utf8("ykchat-safety-code"), sid);
  const n = new DataView(h.buffer).getUint32(0) % 1_000_000;
  const d = String(n).padStart(6, "0");
  return `${d.slice(0, 3)} ${d.slice(3)}`;
}

// ---------------------------------------------------------- key binding

export function bindingText({ fpr, rpId, credId, spki }) {
  return canonical({
    type: BINDING_TYPE,
    v: PROTOCOL_VERSION,
    gpg_fpr: normFpr(fpr),
    rp_id: rpId,
    cred_id: credId,          // base64url
    pubkey_spki: b64url(spki), // P-256 SubjectPublicKeyInfo, base64url
    created: new Date().toISOString(),
  });
}

/**
 * Verify that `bindingAsc` (a gpg --clearsign output) was signed by the GPG key
 * in `gpgPublicKey`, whose primary fingerprint must equal `expectedFpr`.
 * Returns the parsed binding plus an imported WebCrypto verification key.
 */
export async function verifyBinding(bindingAsc, gpgPublicKey, expectedFpr) {
  expectedFpr = normFpr(expectedFpr);
  const key = await openpgp.readKey({ armoredKey: gpgPublicKey });
  const fpr = normFpr(key.getFingerprint());
  if (fpr !== expectedFpr) throw new Error(`GPG public key is ${fpr}, expected ${expectedFpr}`);

  const message = await openpgp.readCleartextMessage({ cleartextMessage: bindingAsc });
  const { signatures } = await openpgp.verify({ message, verificationKeys: key, expectSigned: true });
  await signatures[0].verified; // throws if invalid, revoked or expired
  const binding = JSON.parse(message.getText());

  if (binding.type !== BINDING_TYPE || binding.v !== PROTOCOL_VERSION) throw new Error("not a ykchat binding");
  if (normFpr(binding.gpg_fpr) !== expectedFpr) throw new Error("binding names a different GPG key");

  const verifyKey = await crypto.subtle.importKey(
    "spki", unb64url(binding.pubkey_spki), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  return { ...binding, fpr, userIds: key.getUserIDs(), verifyKey };
}

// ------------------------------------------------------------- WebAuthn

/** ASN.1 DER ECDSA signature -> 64-byte r||s as WebCrypto expects. */
function derToRaw(der) {
  if (der[0] !== 0x30) throw new Error("bad DER signature");
  let off = 2;
  const out = new Uint8Array(64);
  for (const slot of [0, 32]) {
    if (der[off] !== 0x02) throw new Error("bad DER integer");
    let len = der[off + 1];
    let start = off + 2;
    off = start + len;
    while (len > 32 && der[start] === 0) { start++; len--; }
    if (len > 32) throw new Error("bad DER integer length");
    out.set(der.subarray(start, start + len), slot + 32 - len);
  }
  return out;
}

/** Ask the authenticator (YubiKey touch) to sign sha256(stmtBytes). */
export async function signWithWebAuthn(binding, stmtBytes) {
  const cred = await navigator.credentials.get({
    publicKey: {
      challenge: await sha256(stmtBytes),
      rpId: binding.rp_id,
      allowCredentials: [{ type: "public-key", id: unb64url(binding.cred_id) }],
      userVerification: "discouraged",
      timeout: 60000,
    },
  });
  const r = cred.response;
  return {
    authenticatorData: b64url(r.authenticatorData),
    clientDataJSON: b64url(r.clientDataJSON),
    signature: b64url(r.signature),
  };
}

/**
 * Verify a WebAuthn assertion over sha256(stmtBytes) against a verified binding.
 * Returns the authenticator's signCount (used to detect cloned credentials).
 */
export async function verifyAssertion(binding, stmtBytes, assertion) {
  const authData = unb64url(assertion.authenticatorData);
  const clientDataBytes = unb64url(assertion.clientDataJSON);
  const clientData = JSON.parse(fromUtf8(clientDataBytes));

  if (clientData.type !== "webauthn.get") throw new Error("not a WebAuthn assertion");
  if (clientData.challenge !== b64url(await sha256(stmtBytes))) throw new Error("assertion is for a different statement");
  if (new URL(clientData.origin).hostname !== binding.rp_id) throw new Error(`assertion from unexpected origin ${clientData.origin}`);
  if (authData.length < 37) throw new Error("authenticatorData too short");
  if (!equalBytes(authData.subarray(0, 32), await sha256(utf8(binding.rp_id)))) throw new Error("rpIdHash mismatch");
  if (!(authData[32] & 0x01)) throw new Error("user presence (touch) flag not set");

  const signed = concat(authData, await sha256(clientDataBytes));
  const ok = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" }, binding.verifyKey, derToRaw(unb64url(assertion.signature)), signed);
  if (!ok) throw new Error("WebAuthn signature invalid");
  return new DataView(authData.buffer, authData.byteOffset + 33, 4).getUint32(0);
}

// ---------------------------------------------------------- statements

/**
 * Verifies the peer's statement chain. Mirrors Session.check_statement in
 * ykchat.py, with a WebAuthn assertion in place of the detached GPG signature.
 */
export class PeerVerifier {
  constructor({ binding, sessionId, myRecent }) {
    this.binding = binding;
    this.sessionId = sessionId;
    this.myRecent = myRecent;        // array of hex hashes of our recent statements (shared, mutated by caller)
    this.leaves = new Map();         // seq -> leaf, for frames not yet covered by a statement
    this.epoch = 0;
    this.prev = hex(sessionId);
    this.nextSeq = 0;
    this.signCount = 0;
  }

  async addFrame(seq, tsMs, jpeg) {
    this.leaves.set(seq, await frameLeaf(seq, tsMs, jpeg));
  }

  async addChat(seq, tsMs, text) {
    this.leaves.set(seq, await chatLeaf(seq, tsMs, text));
  }

  /** Throws with a reason on failure; on success advances the chain. */
  async check(stmtStr, assertion) {
    const body = utf8(stmtStr);
    const signCount = await verifyAssertion(this.binding, body, assertion);
    const stmt = JSON.parse(stmtStr);
    if (canonical(stmt) !== stmtStr) throw new Error("statement not canonical");

    const checks = [
      [stmt.v === PROTOCOL_VERSION, "protocol version"],
      [normFpr(stmt.signer) === this.binding.fpr, "signer field mismatch"],
      [stmt.cred_id === this.binding.cred_id, "credential mismatch"],
      [stmt.session === hex(this.sessionId), "wrong session (replay?)"],
      [stmt.epoch === this.epoch + 1, `epoch ${stmt.epoch} != ${this.epoch + 1}`],
      [stmt.prev === this.prev, "chain broken (prev mismatch)"],
      [stmt.seq_from === this.nextSeq, "frame range gap"],
      [this.myRecent.includes(stmt.peer_ack), "stale: does not ack a recent statement of ours"],
      [signCount === 0 || signCount > this.signCount, "signature counter went backwards (cloned key?)"],
    ];
    for (const [passed, why] of checks) if (!passed) throw new Error(why);

    const leaves = [];
    for (let s = stmt.seq_from; s < stmt.seq_to; s++) {
      if (!this.leaves.has(s)) throw new Error(`missing frame ${s}`);
      leaves.push(this.leaves.get(s));
    }
    if (hex(await merkleRoot(leaves)) !== stmt.root) throw new Error("merkle root does not match received video/chat");

    for (let s = stmt.seq_from; s < stmt.seq_to; s++) this.leaves.delete(s);
    this.epoch = stmt.epoch;
    this.prev = hex(await sha256(body));
    this.nextSeq = stmt.seq_to;
    this.signCount = signCount;
    return stmt;
  }
}
