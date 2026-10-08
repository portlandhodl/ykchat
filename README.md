# ykchat

Peer-to-peer video chat where each participant continuously proves their
GPG-identified YubiKey is present. Every epoch (default 10 s) each side
signs a statement committing to the Merkle root of the video frames it just
sent, chained to its previous statement and to a recent statement from the
peer (so it cannot be produced in advance). The receiver recomputes the root
from the frames it actually got and shows the peer as **KEY PRESENT** only
while valid, timely statements keep arriving.

## Browser version (`web/`, serverless)

Browsers cannot reach the YubiKey's OpenPGP applet, so the per-epoch
signatures use the YubiKey's FIDO2/WebAuthn applet (touch required for every
signature). Your GPG key signs a one-time binding saying "this WebAuthn
credential speaks for me"; peers verify that binding against your pinned GPG
fingerprint, then verify each epoch's WebAuthn signature.

Hosted: **https://portlandhodl.github.io/ykchat/** (deployed from `web/` by
`.github/workflows/pages.yml` on every push to `main`). Or run locally:

    python3 -m http.server -d web 8000     # then open http://localhost:8000

A WebAuthn credential is tied to the site's hostname, so an identity created
on localhost has to be set up again on the hosted site (and vice versa).

WebAuthn requires a secure context: `http://localhost` works for local
testing; for two machines, host `web/` on any static HTTPS host. There is no
backend. Invite/reply codes are exchanged by hand (chat, email, QR...).
Options via URL: `?epoch=10&grace=15&fps=12`.

1. Enter your GPG fingerprint, create the credential (touch), run the shown
   `gpg --clearsign` and `gpg --armor --export` commands, paste the outputs.
2. Enter the peer's fingerprint (obtained out of band), then one side
   creates an invite, the other pastes it and sends back the reply.
3. Touch the key each epoch. The status bar turns red if the peer's proofs
   stop, arrive late, are signed by another key, or don't match the video.
   The chat sidebar's messages share the video's sequence numbers, so each
   message is marked "verified" once a proof covering it checks out.

Audio is carried by WebRTC but is not covered by the proofs.

Test: `cd tests && npm install && npm run e2e` (Chrome with a virtual
authenticator, fake cameras, throwaway GPG keys).

## Python version (`ykchat.py`, real GPG signatures)

Signs each epoch directly with `gpg` (so with the OpenPGP applet on the
YubiKey). Plain TCP, not encrypted.

    ykman openpgp keys set-touch sig on
    gpg --import peer.asc
    uv run ykchat.py --listen 47000 --key <your fpr> --peer <their fpr>
    uv run ykchat.py --connect host:47000 --key <your fpr> --peer <their fpr>

`--fake-camera --headless -v` for testing without a webcam or display.
