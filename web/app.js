// ykchat browser client: serverless WebRTC (copy/paste signaling) with
// continuous YubiKey presence proofs. See protocol.js for the crypto.

import {
  ACK_WINDOW, PROTOCOL_VERSION, PeerVerifier, b64url, bindingText, canonical, concat, frameLeaf, fromUtf8, hex,
  merkleRoot, normFpr, sessionId, sha256, signWithWebAuthn, u64, unb64url, unhex, utf8, verifyBinding,
} from "./protocol.js";

const params = new URLSearchParams(location.search);
const CONFIG = {
  epochSec: Number(params.get("epoch") ?? 10),
  graceSec: Number(params.get("grace") ?? 15),
  fps: Number(params.get("fps") ?? 12),
  width: 480,
  height: 360,
};
const CHUNK = 16000;           // safe DataChannel message size across browsers
const MAX_BUFFERED = 4 << 20;  // skip (and don't commit to) frames if the channel is backed up
const IDENTITY_KEY = "ykchat.identity";

const $ = (id) => document.getElementById(id);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function log(msg, cls = "") {
  const line = document.createElement("div");
  line.className = cls;
  line.textContent = `${new Date().toLocaleTimeString()}  ${msg}`;
  $("log").prepend(line);
}

// ------------------------------------------------------------ identity

let identity = JSON.parse(localStorage.getItem(IDENTITY_KEY) || "null");
let draft = null; // credential created but binding not yet signed

const groupFpr = (f) => f.replace(/(.{4})/g, "$1 ").trim();

function renderIdentity() {
  $("id-summary").hidden = !identity;
  $("id-form").hidden = !!identity;
  $("card-identity").classList.toggle("done", !!identity);
  if (identity) {
    $("id-status").textContent = "Ready";
    $("id-status").className = "pill ok";
    $("id-who").textContent = identity.name || "";
    $("id-fpr").textContent = groupFpr(identity.fpr);
    $("id-fpr").title = `WebAuthn credential ${identity.credId.slice(0, 12)}… on ${identity.rpId}`;
    $("fpr").value = identity.fpr;
  } else {
    $("id-status").textContent = "No identity yet";
    $("id-status").className = "pill";
  }
}

async function createCredential() {
  const fpr = normFpr($("fpr").value);
  if (!/^[0-9A-F]{40}$|^[0-9A-F]{64}$/.test(fpr)) throw new Error("enter your full 40-hex GPG fingerprint");
  const cred = await navigator.credentials.create({
    publicKey: {
      rp: { id: location.hostname, name: "ykchat" },
      user: { id: crypto.getRandomValues(new Uint8Array(16)), name: fpr, displayName: `ykchat ${fpr.slice(-16)}` },
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      pubKeyCredParams: [{ type: "public-key", alg: -7 }], // ES256 (P-256)
      authenticatorSelection: {
        authenticatorAttachment: "cross-platform", // a security key, not a platform passkey
        residentKey: "discouraged",
        userVerification: "discouraged",
      },
      attestation: "none",
      timeout: 60000,
    },
  });
  if (cred.response.getPublicKeyAlgorithm() !== -7) throw new Error("authenticator did not create a P-256 key");
  const spki = new Uint8Array(cred.response.getPublicKey());
  draft = { fpr, rpId: location.hostname, credId: b64url(cred.rawId) };
  draft.bindingText = bindingText({ ...draft, spki });

  $("sign-cmd").value =
    `echo '${draft.bindingText}' | gpg --clearsign --local-user ${fpr}\n\ngpg --armor --export ${fpr}`;
  $("enroll-step2").hidden = false;
  log("WebAuthn credential created; now sign the binding with GPG");
  toast("Credential created. Now sign it with GPG.");
}

async function saveIdentity() {
  if (!draft) throw new Error("create a credential first");
  const bindingAsc = $("binding-asc").value.trim();
  const gpgPublicKey = $("gpg-pub").value.trim();
  const b = await verifyBinding(bindingAsc, gpgPublicKey, draft.fpr);
  if (b.cred_id !== draft.credId || b.rp_id !== draft.rpId) throw new Error("signed binding is not for the credential just created");
  identity = { ...draft, bindingAsc, gpgPublicKey, name: b.userIds[0] };
  localStorage.setItem(IDENTITY_KEY, JSON.stringify(identity));
  draft = null;
  $("enroll-step2").hidden = true;
  renderIdentity();
  log(`identity saved: ${b.userIds.join(", ")}`, "ok");
  toast(`Identity saved: ${b.userIds[0] ?? b.fpr}`);
}

// ------------------------------------------------------------ signaling

async function packSignal(desc) {
  const stream = new Blob([JSON.stringify({ type: desc.type, sdp: desc.sdp })]).stream()
    .pipeThrough(new CompressionStream("deflate-raw"));
  return "YK1." + b64url(new Uint8Array(await new Response(stream).arrayBuffer()));
}

async function unpackSignal(code) {
  code = code.trim();
  if (!code.startsWith("YK1.")) throw new Error("not a ykchat code");
  const stream = new Blob([unb64url(code.slice(4))]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
  return JSON.parse(await new Response(stream).text());
}

function iceGatheringDone(pc, timeoutMs = 5000) {
  return new Promise((resolve) => {
    if (pc.iceGatheringState === "complete") return resolve();
    const t = setTimeout(resolve, timeoutMs);
    pc.addEventListener("icegatheringstatechange", () => {
      if (pc.iceGatheringState === "complete") { clearTimeout(t); resolve(); }
    });
  });
}

// ---------------------------------------------------------------- call

let pc = null;
let session = null;
let localStream = null;

async function setupPeer() {
  if (!identity) throw new Error("set up your identity first");
  const peerFpr = normFpr($("peer-fpr").value);
  if (!/^[0-9A-F]{40}$|^[0-9A-F]{64}$/.test(peerFpr)) throw new Error("enter the peer's full GPG fingerprint");
  if (peerFpr === identity.fpr) throw new Error("peer fingerprint is your own");

  try {
    localStream = await navigator.mediaDevices.getUserMedia({ video: { width: 640, height: 480 }, audio: true });
  } catch {
    localStream = await navigator.mediaDevices.getUserMedia({ video: { width: 640, height: 480 } });
    log("no microphone; video only", "warn");
  }
  $("local").srcObject = localStream;
  $("pip").hidden = false;

  const iceServers = $("use-stun").checked ? [{ urls: "stun:stun.l.google.com:19302" }] : [];
  pc = new RTCPeerConnection({ iceServers });
  for (const track of localStream.getAudioTracks()) pc.addTrack(track, localStream);
  pc.ontrack = (ev) => { $("remote-audio").srcObject = ev.streams[0]; };
  pc.onconnectionstatechange = () => log(`connection: ${pc.connectionState}`);
  return peerFpr;
}

function startSession(dc, peerFpr) {
  dc.binaryType = "arraybuffer";
  dc.onopen = () => {
    session = new CallSession({ dc, peerFpr, identity, video: $("local") });
    $("card-connect").classList.add("done");
    $("card-call").scrollIntoView({ behavior: "smooth", block: "start" });
    window.ykchat.session = session;
    session.start();
  };
  dc.onclose = () => { session?.stop("call ended"); };
}

async function hostCall() {
  const peerFpr = await setupPeer();
  const dc = pc.createDataChannel("ykchat", { ordered: true });
  startSession(dc, peerFpr);
  await pc.setLocalDescription(await pc.createOffer());
  await iceGatheringDone(pc);
  $("my-code").value = await packSignal(pc.localDescription);
  $("code-help").textContent = "· send this invite to your peer, then paste their reply below";
  $("btn-accept").hidden = false;
}

async function joinCall() {
  const offer = await unpackSignal($("their-code").value);
  if (offer.type !== "offer") throw new Error("that is not an invite");
  const peerFpr = await setupPeer();
  pc.ondatachannel = (ev) => startSession(ev.channel, peerFpr);
  await pc.setRemoteDescription(offer);
  await pc.setLocalDescription(await pc.createAnswer());
  await iceGatheringDone(pc);
  $("my-code").value = await packSignal(pc.localDescription);
  $("code-help").textContent = "· send this reply back to the person who invited you";
}

async function acceptAnswer() {
  const answer = await unpackSignal($("their-code").value);
  if (answer.type !== "answer") throw new Error("that is not a reply code");
  await pc.setRemoteDescription(answer);
}

// ------------------------------------------------------------- session

class CallSession {
  constructor({ dc, peerFpr, identity, video }) {
    this.dc = dc;
    this.peerFpr = peerFpr;
    this.identity = identity;
    this.video = video;
    this.stopped = false;

    this.myNonce = crypto.getRandomValues(new Uint8Array(32));
    this.seq = 0;
    this.epochSeqFrom = 0;
    this.pendingLeaves = [];
    this.myEpoch = 0;
    this.myPrev = null;
    this.myRecent = [];       // hex hashes the peer may ack; shared with the verifier
    this.signQueue = [];
    this.signing = false;

    this.verifier = null;
    this.peerEpochSec = CONFIG.epochSec;
    this.lastVerified = 0;
    this.lastError = "waiting for peer hello";
    this.rx = Promise.resolve();
    this.rxChunks = [];

    this.canvas = document.createElement("canvas");
    this.canvas.width = CONFIG.width;
    this.canvas.height = CONFIG.height;
  }

  start() {
    this.dc.onmessage = (ev) => this.onChunk(new Uint8Array(ev.data));
    this.sendJson({
      t: "hello", v: PROTOCOL_VERSION, fpr: this.identity.fpr, nonce: hex(this.myNonce),
      epoch: CONFIG.epochSec, binding: this.identity.bindingAsc, gpgPublicKey: this.identity.gpgPublicKey,
    });
    this.statusTimer = setInterval(() => renderStatus(this), 250);
    log("data channel open; sent hello");
  }

  stop(reason) {
    if (this.stopped) return;
    this.stopped = true;
    this.lastError = reason;
    renderStatus(this);
    clearInterval(this.statusTimer);
    log(reason, "warn");
  }

  // -- transport: [type byte][payload], split into chunks prefixed 1=more / 0=last
  send(type, payload) {
    const msg = concat(utf8(type), payload);
    for (let off = 0; off < msg.length; off += CHUNK) {
      const end = Math.min(off + CHUNK, msg.length);
      this.dc.send(concat(Uint8Array.of(end < msg.length ? 1 : 0), msg.subarray(off, end)));
    }
  }

  sendJson(obj) { this.send("J", utf8(JSON.stringify(obj))); }

  onChunk(chunk) {
    this.rxChunks.push(chunk.subarray(1));
    if (chunk[0] !== 0) return;
    const msg = concat(...this.rxChunks);
    this.rxChunks = [];
    // One promise chain keeps frame hashing and statement checks in arrival order.
    this.rx = this.rx.then(() => this.onMessage(msg)).catch((e) => {
      log(`protocol error: ${e.message}`, "bad");
      this.stop(`protocol error: ${e.message}`);
      this.dc.close();
    });
  }

  async onMessage(msg) {
    if (this.stopped) return;
    const type = String.fromCharCode(msg[0]);
    if (type === "F") {
      if (!this.verifier) throw new Error("frame before hello");
      const view = new DataView(msg.buffer, msg.byteOffset + 1, 16);
      const seq = Number(view.getBigUint64(0));
      const ts = Number(view.getBigUint64(8));
      const jpeg = msg.subarray(17);
      await this.verifier.addFrame(seq, ts, jpeg);
      createImageBitmap(new Blob([jpeg], { type: "image/jpeg" }))
        .then((bmp) => {
          $("remote").getContext("2d").drawImage(bmp, 0, 0, CONFIG.width, CONFIG.height);
          $("remote-placeholder").hidden = true;
        })
        .catch(() => {});
    } else if (type === "J") {
      const m = JSON.parse(fromUtf8(msg.subarray(1)));
      if (m.t === "hello") await this.onHello(m);
      else if (m.t === "stmt") await this.onStatement(m);
    }
  }

  async onHello(h) {
    if (this.verifier) throw new Error("duplicate hello");
    if (h.v !== PROTOCOL_VERSION) throw new Error(`peer speaks protocol v${h.v}`);
    if (normFpr(h.fpr) !== this.peerFpr) throw new Error(`peer claims key ${h.fpr}, expected ${this.peerFpr}`);
    const binding = await verifyBinding(h.binding, h.gpgPublicKey, this.peerFpr);
    const sid = await sessionId(this.identity.fpr, this.myNonce, this.peerFpr, unhex(h.nonce));
    this.peerNonce = unhex(h.nonce);
    this.peerEpochSec = Number(h.epoch) || CONFIG.epochSec;
    this.myPrev = hex(sid);
    this.myRecent.push(hex(await sha256(this.myNonce))); // the peer's first statement acks our nonce
    this.verifier = new PeerVerifier({ binding, sessionId: sid, myRecent: this.myRecent });
    this.peerName = binding.userIds.join(", ");
    this.lastError = "waiting for first statement";
    log(`peer identity: ${this.peerName} (${binding.fpr}), WebAuthn credential bound by GPG signature`, "ok");
    log(`session ${hex(sid).slice(0, 16)}`);
    this.captureLoop();
  }

  async onStatement(m) {
    try {
      const stmt = await this.verifier.check(m.stmt, m.assertion);
      this.lastVerified = Date.now();
      this.lastError = "";
      log(`peer epoch ${stmt.epoch} verified: ${stmt.seq_to - stmt.seq_from} frames, key touched`, "ok");
    } catch (e) {
      // The chain cannot recover from a rejected statement; keep the root cause visible.
      this.firstError ??= e.message;
      this.lastError = this.firstError;
      log(`peer statement REJECTED: ${e.message}`, "bad");
    }
  }

  // -- sending side
  async captureLoop() {
    const ctx = this.canvas.getContext("2d");
    const interval = 1000 / CONFIG.fps;
    let epochEnd = Date.now() + CONFIG.epochSec * 1000;
    while (!this.stopped && this.dc.readyState === "open") {
      const t0 = Date.now();
      ctx.drawImage(this.video, 0, 0, CONFIG.width, CONFIG.height);
      const blob = await new Promise((r) => this.canvas.toBlob(r, "image/jpeg", 0.7));
      const jpeg = new Uint8Array(await blob.arrayBuffer());
      if (this.dc.bufferedAmount < MAX_BUFFERED) {
        const seq = this.seq++;
        this.pendingLeaves.push(await frameLeaf(seq, t0, jpeg));
        this.send("F", concat(u64(seq), u64(t0), jpeg));
      }
      if (Date.now() >= epochEnd) {
        epochEnd += CONFIG.epochSec * 1000;
        this.signQueue.push({ seqFrom: this.epochSeqFrom, seqTo: this.seq, leaves: this.pendingLeaves });
        this.epochSeqFrom = this.seq;
        this.pendingLeaves = [];
        this.signLoop();
      }
      await sleep(Math.max(0, interval - (Date.now() - t0)));
    }
  }

  async signLoop() {
    if (this.signing) return;
    this.signing = true;
    try {
      while (this.signQueue.length && !this.stopped) {
        const item = this.signQueue[0];
        const peerAck = this.verifier.epoch ? this.verifier.prev : hex(await sha256(this.peerNonce));
        const stmtStr = canonical({
          v: PROTOCOL_VERSION,
          session: hex(this.verifier.sessionId),
          signer: this.identity.fpr,
          cred_id: this.identity.credId,
          epoch: this.myEpoch + 1,
          seq_from: item.seqFrom,
          seq_to: item.seqTo,
          root: hex(await merkleRoot(item.leaves)),
          prev: this.myPrev,
          peer_ack: peerAck,
          t: Date.now(),
        });
        $("touch-prompt").hidden = false;
        let assertion;
        try {
          assertion = await signWithWebAuthn({ rp_id: this.identity.rpId, cred_id: this.identity.credId }, utf8(stmtStr));
        } catch (e) {
          $("touch-prompt").hidden = true;
          log(`signing failed (${e.name}): click "Prove presence" to retry`, "warn");
          await waitForRetryClick();
          continue; // rebuild with a fresh peer_ack
        }
        $("touch-prompt").hidden = true;
        const h = hex(await sha256(utf8(stmtStr)));
        this.signQueue.shift();
        this.myEpoch += 1;
        this.myPrev = h;
        this.myRecent.push(h);
        if (this.myRecent.length > ACK_WINDOW) this.myRecent.shift();
        this.sendJson({ t: "stmt", stmt: stmtStr, assertion });
      }
    } finally {
      this.signing = false;
    }
  }

  status() {
    const short = this.peerFpr.slice(-16);
    const age = this.lastVerified ? (Date.now() - this.lastVerified) / 1000 : null;
    if (this.stopped) return [false, `NOT VERIFIED ${short}: ${this.lastError}`];
    if (age !== null && !this.lastError && age <= this.peerEpochSec + CONFIG.graceSec) {
      return [true, `KEY PRESENT ${short} · ${this.peerName} · epoch ${this.verifier.epoch} · ${age.toFixed(1)}s ago`];
    }
    return [false, `NOT VERIFIED ${short}: ${this.lastError || `no proof for ${age.toFixed(0)}s`}`];
  }
}

function waitForRetryClick() {
  return new Promise((resolve) => {
    const btn = $("btn-retry");
    btn.hidden = false;
    btn.onclick = () => { btn.hidden = true; resolve(); };
  });
}

function renderStatus(s) {
  const [ok, text] = s.status();
  $("status").textContent = text;
  $("status").className = ok ? "status ok" : "status bad";
  $("remote").className = ok ? "" : "unverified";
}

// ------------------------------------------------------------------ UI

function bind(id, fn) {
  $(id).addEventListener("click", async () => {
    try {
      await fn();
    } catch (e) {
      const msg = `${e.name === "Error" ? "" : e.name + ": "}${e.message}`;
      log(msg, "bad");
      toast(msg, true);
    }
  });
}

let toastTimer;
function toast(msg, bad = false) {
  const t = $("toast");
  t.textContent = msg;
  t.className = bad ? "show bad" : "show";
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.className = t.className.replace("show", "").trim(); }, bad ? 5000 : 2500);
}

// Theme: auto (follow OS) -> light -> dark
const THEMES = { auto: ["◐", "Theme: system"], light: ["☀", "Theme: light"], dark: ["☾", "Theme: dark"] };
function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  localStorage.setItem("ykchat.theme", theme);
  $("btn-theme").textContent = THEMES[theme][0];
  $("btn-theme").title = THEMES[theme][1];
}
$("btn-theme").addEventListener("click", () => {
  const order = Object.keys(THEMES);
  applyTheme(order[(order.indexOf(document.documentElement.dataset.theme) + 1) % order.length]);
});
applyTheme(document.documentElement.dataset.theme in THEMES ? document.documentElement.dataset.theme : "auto");

// Fingerprint help tabs, preselected for this OS
function selectOs(os) {
  for (const el of document.querySelectorAll(".tab")) el.setAttribute("aria-selected", el.dataset.os === os);
  for (const el of document.querySelectorAll(".panel")) el.hidden = el.dataset.os !== os;
}
for (const el of document.querySelectorAll(".tab")) el.addEventListener("click", () => selectOs(el.dataset.os));
const platform = (navigator.userAgentData?.platform || navigator.platform || navigator.userAgent).toLowerCase();
selectOs(platform.includes("win") ? "win" : platform.includes("mac") ? "mac" : "linux");

// Copy buttons: data-copy="<textarea id>", plus one on every command snippet
async function copyText(text) {
  await navigator.clipboard.writeText(text);
  toast("Copied to clipboard");
}
for (const btn of document.querySelectorAll("[data-copy]")) {
  btn.addEventListener("click", () => copyText($(btn.dataset.copy).value).catch((e) => toast(e.message, true)));
}
for (const pre of document.querySelectorAll("pre.cmd")) {
  const btn = document.createElement("button");
  btn.className = "small";
  btn.textContent = "Copy";
  btn.addEventListener("click", () => copyText(pre.firstChild.textContent.trim()).catch((e) => toast(e.message, true)));
  pre.append(btn);
}

// Live fingerprint validation
for (const id of ["fpr", "peer-fpr"]) {
  $(id).addEventListener("input", () => {
    const v = normFpr($(id).value);
    $(id).classList.toggle("valid", /^[0-9A-F]{40}$|^[0-9A-F]{64}$/.test(v));
    $(id).classList.toggle("invalid", v.length > 0 && !/^[0-9A-F]*$/.test(v));
  });
}

window.ykchat = { session: null, CONFIG };
bind("btn-create-cred", createCredential);
bind("btn-save-id", saveIdentity);
bind("btn-reset-id", async () => {
  localStorage.removeItem(IDENTITY_KEY);
  identity = null;
  renderIdentity();
});
bind("btn-host", hostCall);
bind("btn-join", joinCall);
bind("btn-accept", acceptAnswer);
renderIdentity();
if (!window.isSecureContext) log("not a secure context: serve over https or http://localhost", "bad");
log(`epoch ${CONFIG.epochSec}s, grace ${CONFIG.graceSec}s, ${CONFIG.fps} fps`);
$("call-config").textContent = `Proof every ${CONFIG.epochSec}s · ${CONFIG.graceSec}s grace · ${CONFIG.fps} fps`;
