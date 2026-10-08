// Renders the link-preview images (Open Graph cards and icons) into web/og/.
//
//   cd tests && npm run cards

import { writeFileSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright-core";

const OUT = join(dirname(fileURLToPath(import.meta.url)), "..", "web", "og");

const LOGO = `<svg viewBox="0 0 64 64" width="100%" height="100%">
  <rect x="6" y="10" width="52" height="36" rx="6" fill="none" stroke="currentColor" stroke-width="4"/>
  <path d="M24 55h16M32 46v9" stroke="currentColor" stroke-width="4" stroke-linecap="round"/>
  <rect x="15" y="21" width="24" height="14" rx="3.5" fill="currentColor"/>
  <rect x="39" y="24.5" width="8" height="7" rx="1.5" fill="currentColor"/>
  <circle cx="23" cy="28" r="4" fill="#f5b300"/></svg>`;

const CARDS = [
  { file: "card.png", eyebrow: "ykchat", title: "Know their key is really there.",
    body: "Peer-to-peer video where each person's YubiKey keeps proving it's present, tied to their GPG identity." },
  { file: "join.png", eyebrow: "Video call invite", title: "You're invited to a verified video call",
    body: "Open the link and touch your YubiKey. Both keys keep proving they're present for the whole call." },
  { file: "contact.png", eyebrow: "GPG contact", title: "Start a verified call with me",
    body: "Opens ykchat with my fingerprint filled in. Confirm it with me before you trust it." },
];

const cardHtml = ({ eyebrow, title, body }) => `<!doctype html><html><head><style>
  * { margin: 0; box-sizing: border-box; }
  body { width: 1200px; height: 630px; overflow: hidden; font-family: Inter, "Noto Sans", "DejaVu Sans", sans-serif;
         background: radial-gradient(900px 500px at 85% 20%, #26346f 0%, transparent 70%), #0d1015; color: #e7eaef;
         display: grid; grid-template-columns: 1fr 360px; align-items: center; padding: 0 88px; gap: 40px; }
  .eyebrow { display: inline-flex; align-items: center; gap: 12px; font-size: 26px; font-weight: 700; color: #93a7ff;
             letter-spacing: .02em; text-transform: uppercase; }
  .eyebrow i { width: 12px; height: 12px; border-radius: 50%; background: #46c27a; box-shadow: 0 0 0 6px rgb(70 194 122 / .2); }
  h1 { font-size: 64px; line-height: 1.08; letter-spacing: -.025em; font-weight: 800; margin-top: 22px; }
  p { font-size: 28px; line-height: 1.4; color: #9ba4b0; margin-top: 22px; }
  .url { position: absolute; left: 88px; bottom: 44px; font-size: 22px; color: #6f7884; font-family: "DejaVu Sans Mono", monospace; }
  .art { width: 360px; height: 360px; border-radius: 72px; background: linear-gradient(145deg, #4a66e8, #2d44b4);
         display: grid; place-items: center; color: #fff; box-shadow: 0 30px 80px rgb(0 0 0 / .5), inset 0 1px 0 rgb(255 255 255 / .2); }
  .art div { width: 240px; height: 240px; }
</style></head><body>
  <div><div class="eyebrow"><i></i>${eyebrow}</div><h1>${title}</h1><p>${body}</p></div>
  <div class="art"><div>${LOGO}</div></div>
  <div class="url">portlandhodl.github.io/ykchat</div>
</body></html>`;

const iconHtml = (size) => `<!doctype html><html><head><style>
  * { margin: 0; } body { width: ${size}px; height: ${size}px; display: grid; place-items: center;
  background: linear-gradient(145deg, #4a66e8, #2d44b4); color: #fff; }
  div { width: ${Math.round(size * 0.7)}px; height: ${Math.round(size * 0.7)}px; }
</style></head><body><div>${LOGO}</div></body></html>`;

const browser = await chromium.launch({ executablePath: process.env.CHROME || "/usr/bin/google-chrome" });
const page = await browser.newPage();
async function render(html, w, h, file) {
  await page.setViewportSize({ width: w, height: h });
  await page.setContent(html);
  writeFileSync(join(OUT, file), await page.screenshot({ type: "png" }));
  console.log(`${file}  ${w}x${h}  ${(statSync(join(OUT, file)).size / 1024).toFixed(0)} KB`);
}
for (const c of CARDS) await render(cardHtml(c), 1200, 630, c.file);
await render(iconHtml(180), 180, 180, "apple-touch-icon.png"); // iMessage, iOS home screen
await render(iconHtml(512), 512, 512, "icon-512.png");
await browser.close();
