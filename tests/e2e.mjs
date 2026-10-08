// End-to-end test: two Chrome instances, Chrome's virtual WebAuthn
// authenticator in place of a YubiKey, fake cameras, real software GPG keys.
//
//   cd tests && npm install && npm run e2e
//
// Set CHROME=/path/to/chrome to override the browser.

import { execFileSync, spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright-core";

const WEB = join(dirname(fileURLToPath(import.meta.url)), "..", "web");
const PORT = 47123;
const EPOCH = 3;
const URL = `http://localhost:${PORT}/?epoch=${EPOCH}&grace=3&fps=8`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const SHOTS = process.env.SHOTS; // optional directory for screenshots

async function shot(p, name, scheme = "light") {
  if (!SHOTS) return;
  await p.page.emulateMedia({ colorScheme: scheme });
  await sleep(400); // let theme transitions finish
  await p.page.screenshot({ path: join(SHOTS, `${name}-${scheme}.png`), fullPage: true });
}

let failures = 0;
function check(cond, what) {
  console.log(`${cond ? "PASS" : "FAIL"}  ${what}`);
  if (!cond) failures++;
}

function gpg(home, args, input) {
  return execFileSync("gpg", ["--batch", "--quiet", ...args], {
    env: { ...process.env, GNUPGHOME: home }, input, stdio: ["pipe", "pipe", "ignore"],
  }).toString();
}

function makeKey(root, name) {
  const home = join(root, name);
  mkdirSync(home, { mode: 0o700 });
  gpg(home, ["--passphrase", "", "--quick-gen-key", `${name} <${name}@test>`, "ed25519", "sign", "never"]);
  const fpr = gpg(home, ["--with-colons", "-K"]).split("\n").find((l) => l.startsWith("fpr")).split(":")[9];
  return { name, home, fpr };
}

async function openParticipant(key) {
  const browser = await chromium.launch({
    executablePath: process.env.CHROME || "/usr/bin/google-chrome",
    headless: true,
    args: ["--use-fake-device-for-media-stream", "--use-fake-ui-for-media-stream"],
  });
  const context = await browser.newContext({ permissions: ["camera", "microphone"] });
  const page = await context.newPage();
  await page.setViewportSize({ width: 1200, height: 900 });
  page.on("pageerror", (e) => console.log(`[${key.name} pageerror] ${e.message}`));
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2", transport: "usb", hasResidentKey: false,
      hasUserVerification: false, automaticPresenceSimulation: true,
    },
  });
  await cdp.send("Emulation.setFocusEmulationEnabled", { enabled: true });
  await page.goto(URL);
  return { ...key, browser, page };
}

async function enroll(p) {
  await p.page.click("#btn-start");
  await p.page.fill("#fpr", p.fpr);
  await p.page.click("#btn-create-cred");
  await p.page.waitForSelector("#enroll-step2:not([hidden])");
  const cmd = await p.page.inputValue("#sign-cmd");
  const bindingJson = cmd.match(/^echo '(.*)' \|/)[1];
  await p.page.fill("#binding-asc", gpg(p.home, ["--clearsign", "--local-user", p.fpr], bindingJson + "\n"));
  await p.page.fill("#gpg-pub", gpg(p.home, ["--armor", "--export", p.fpr]));
  await p.page.click("#btn-save-id");
  await p.page.waitForSelector("#id-status.ok", { timeout: 5000 });
  await shot(p, `2-identity-${p.name}`);
  await p.page.click("#btn-to-connect");
}

async function connect(host, guest) {
  for (const [me, peer] of [[host, guest], [guest, host]]) {
    await me.page.fill("#peer-fpr", peer.fpr);
    await me.page.uncheck("#use-stun");
  }
  await host.page.click("#btn-host");
  await host.page.waitForFunction(() => document.querySelector("#my-code").value.startsWith("YK1."));
  await shot(host, "3-connect-host");
  await guest.page.click("#role-join");
  await guest.page.fill("#their-code", await host.page.inputValue("#my-code"));
  await guest.page.click("#btn-join");
  await guest.page.waitForFunction(() => document.querySelector("#my-code").value.startsWith("YK1."));
  await host.page.fill("#their-code", await guest.page.inputValue("#my-code"));
  await host.page.click("#btn-accept");
}

const status = (p) => p.page.evaluate(() => ({
  ok: document.querySelector("#status").classList.contains("ok"),
  text: document.querySelector("#status").textContent,
  log: document.querySelector("#log").textContent,
}));

const root = mkdtempSync(join(tmpdir(), "ykchat-e2e-"));
const server = spawn("python3", ["-m", "http.server", "--bind", "localhost", "-d", WEB, String(PORT)], { stdio: "ignore" });
const participants = [];
try {
  await sleep(500);
  const [alice, bob] = await Promise.all([makeKey(root, "alice"), makeKey(root, "bob")].map(openParticipant));
  participants.push(alice, bob);

  await shot(alice, "1-welcome");
  await shot(alice, "1-welcome", "dark");
  await enroll(alice);
  await enroll(bob);
  check(true, "both participants enrolled (GPG-signed WebAuthn binding verified)");

  await connect(alice, bob);
  await alice.page.waitForSelector('[data-screen="call"]:not([hidden])', { timeout: 10000 });
  await alice.page.fill("#chat-input", "Spec is here: https://example.com/spec?v=2. <img src=x onerror=alert(1)>");
  await alice.page.press("#chat-input", "Enter");
  await bob.page.fill("#chat-input", "Got it, thanks!");
  await bob.page.click("#btn-send");
  await sleep((EPOCH * 3 + 2) * 1000);
  await shot(alice, "4-call");
  await shot(alice, "4-call", "dark");
  for (const [me, peer] of [[alice, bob], [bob, alice]]) {
    const s = await status(me);
    check(s.ok && s.text.includes(peer.fpr.slice(-16)), `${me.name} sees ${peer.name}'s key present: ${s.text}`);
    check(/epoch [23] verified/.test(s.log), `${me.name} verified several epochs from ${peer.name}`);
    check(!/REJECTED|protocol error/.test(s.log), `${me.name} saw no rejections`);
  }

  const chat = await bob.page.evaluate(() => {
    const msg = document.querySelector("#chat-list .msg.theirs");
    const a = msg?.querySelector("a");
    return { href: a?.href, rel: a?.rel, imgs: msg?.querySelectorAll("img").length, seal: msg?.querySelector(".seal").textContent };
  });
  check(chat.href === "https://example.com/spec?v=2", `bob sees alice's link as a link: ${chat.href}`);
  check(chat.rel?.includes("noopener") && chat.imgs === 0, "link is noopener and injected HTML stays text");
  check(/verified/.test(chat.seal), `bob's copy of alice's message is verified: ${chat.seal}`);
  const mine = await bob.page.textContent("#chat-list .msg.mine .seal");
  check(/signed/.test(mine), `bob's own message is marked signed: ${mine}`);
  const aliceSeal = await alice.page.textContent("#chat-list .msg.theirs .seal");
  check(/verified/.test(aliceSeal), `alice sees bob's reply verified: ${aliceSeal}`);

  // Bob's client starts altering frames after hashing them.
  await bob.page.evaluate(() => {
    const s = window.ykchat.session;
    const send = s.send.bind(s);
    s.send = (type, payload) => {
      if (type === "F") { payload = payload.slice(); payload[30] ^= 0xff; }
      send(type, payload);
    };
  });
  await sleep((EPOCH * 2 + 1) * 1000);
  const s = await status(alice);
  await shot(alice, "5-tampered", "dark");
  check(!s.ok, `alice flags tampered video: ${s.text}`);
  check(s.text.includes("merkle root does not match received video/chat"), "status shows the Merkle mismatch as the cause");
} finally {
  for (const p of participants) await p.browser.close();
  server.kill();
  rmSync(root, { recursive: true, force: true });
}
console.log(failures ? `\n${failures} check(s) failed` : "\nall checks passed");
process.exit(failures ? 1 : 0);
