"""ykchat: two-party video chat with continuous GPG key-presence proofs.

Every epoch (default 10s) each side signs, with its GPG key (e.g. on a
YubiKey with touch required), a statement that commits to:

  * the Merkle root of every video frame it sent during that epoch,
  * the hash of its own previous statement (an unbroken chain), and
  * the hash of a recent statement from the *peer* (freshness: it cannot
    have been produced before the peer's statement existed).

The receiver recomputes the Merkle root from the frames it actually got,
verifies the signature against the expected fingerprint, and shows the
peer as VERIFIED only while valid statements keep arriving on time.

Wire format: [u32 length][u8 type][payload]
  H  hello      JSON {"fpr", "nonce"}
  F  frame      u64 seq | u64 ts_ms | JPEG bytes
  S  statement  JSON {"stmt": <canonical JSON str>, "sig": <armored sig>}
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

import cv2
import numpy as np

PROTOCOL_VERSION = 1
ACK_WINDOW = 3  # peer_ack may reference any of our last N statements


def sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def frame_leaf(seq: int, ts_ms: int, jpeg: bytes) -> bytes:
    return sha256(b"\x00", struct.pack(">QQ", seq, ts_ms), jpeg)


def merkle_root(leaves: list[bytes]) -> bytes:
    """RFC 6962-style domain separation; an odd node is promoted unchanged."""
    if not leaves:
        return sha256(b"empty")
    level = leaves
    while len(level) > 1:
        nxt = [sha256(b"\x01", level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def canonical(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def norm_fpr(fpr: str) -> str:
    return fpr.replace(" ", "").upper()


# --------------------------------------------------------------------- gpg


def gpg_sign(data: bytes, fpr: str) -> str:
    # No --batch: a YubiKey may need pinentry for the PIN on first use.
    proc = subprocess.run(
        ["gpg", "--local-user", fpr, "--armor", "--detach-sign", "--output", "-"],
        input=data, capture_output=True, timeout=120,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"gpg sign failed: {proc.stderr.decode(errors='replace').strip()}")
    return proc.stdout.decode()


def gpg_verify(data: bytes, sig: str, expected_fpr: str) -> tuple[bool, str]:
    """Return (ok, reason). ok only if VALIDSIG names the expected key."""
    with tempfile.NamedTemporaryFile("w", suffix=".asc", delete=False) as f:
        f.write(sig)
        sig_path = f.name
    try:
        proc = subprocess.run(
            ["gpg", "--batch", "--status-fd", "1", "--verify", sig_path, "-"],
            input=data, capture_output=True, timeout=30,
        )
    finally:
        os.unlink(sig_path)
    for line in proc.stdout.decode(errors="replace").splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[:2] == ["[GNUPG:]", "VALIDSIG"]:
            # VALIDSIG <signing-key-fpr> ... <primary-key-fpr> (last field)
            if expected_fpr in (norm_fpr(parts[2]), norm_fpr(parts[-1])):
                return True, "ok"
            return False, f"signed by unexpected key {parts[2]}"
    return False, "no valid signature"


# ---------------------------------------------------------------- framing


class Conn:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.wlock = threading.Lock()

    def send(self, mtype: bytes, payload: bytes) -> None:
        with self.wlock:
            self.sock.sendall(struct.pack(">IB", len(payload) + 1, mtype[0]) + payload)

    def _recv_exact(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("peer closed connection")
            buf += chunk
        return bytes(buf)

    def recv(self) -> tuple[bytes, bytes]:
        length, mtype = struct.unpack(">IB", self._recv_exact(5))
        if length > 16 * 1024 * 1024:
            raise ConnectionError("message too large")
        return bytes([mtype]), self._recv_exact(length - 1)


# ----------------------------------------------------------------- camera


class FakeCamera:
    """Synthetic moving test pattern, for testing without a webcam."""

    def __init__(self, label: str):
        self.label = label
        self.t0 = time.time()

    def read(self):
        t = time.time() - self.t0
        img = np.zeros((480, 640, 3), np.uint8)
        x = int((t * 120) % 640)
        cv2.rectangle(img, (x, 0), (x + 40, 480), (0, 180, 255), -1)
        cv2.putText(img, self.label, (20, 60), cv2.FONT_HERSHEY_SIMPLEX, 1.5, (255, 255, 255), 3)
        cv2.putText(img, f"{t:7.2f}s", (20, 440), cv2.FONT_HERSHEY_SIMPLEX, 1.2, (255, 255, 255), 2)
        return True, img

    def release(self):
        pass


# ------------------------------------------------------------------ peer


class Session:
    def __init__(self, args, conn: Conn):
        self.args = args
        self.conn = conn
        self.my_fpr = norm_fpr(args.key)
        self.peer_fpr = norm_fpr(args.peer)
        self.stop = threading.Event()
        self.lock = threading.Lock()

        # Local (sending) state
        self.my_nonce = os.urandom(32)
        self.pending_leaves: list[bytes] = []
        self.seq = 0
        self.epoch_seq_from = 0
        self.my_epoch = 0
        self.my_prev = b""                     # hash of my last statement
        self.my_recent = collections.deque(maxlen=ACK_WINDOW)  # hashes peer may ack
        self.local_frame = None

        # Remote (receiving) state
        self.peer_nonce = b""
        self.session_id = b""
        self.peer_leaves: dict[int, bytes] = {}
        self.peer_next_seq = 0                 # expected seq_from of next stmt
        self.peer_epoch = 0
        self.peer_prev = b""                   # hash of peer's last verified stmt
        self.last_verified = 0.0
        self.last_error = "waiting for first statement"
        self.first_error = ""
        self.remote_frame = None

    # -- handshake ----------------------------------------------------
    def handshake(self) -> None:
        self.conn.send(b"H", canonical({"v": PROTOCOL_VERSION, "fpr": self.my_fpr,
                                        "nonce": self.my_nonce.hex()}).encode())
        mtype, payload = self.conn.recv()
        if mtype != b"H":
            raise ConnectionError("expected hello")
        hello = json.loads(payload)
        if norm_fpr(hello["fpr"]) != self.peer_fpr:
            raise ConnectionError(f"peer claims key {hello['fpr']}, expected {self.peer_fpr}")
        self.peer_nonce = bytes.fromhex(hello["nonce"])
        a, b = sorted([(self.my_fpr, self.my_nonce), (self.peer_fpr, self.peer_nonce)])
        self.session_id = sha256(b"ykchat-session", a[0].encode(), a[1], b[0].encode(), b[1])
        self.my_prev = self.session_id
        self.peer_prev = self.session_id
        # The peer's first statement must ack our hello nonce.
        self.my_recent.append(sha256(self.my_nonce))

    # -- sending ------------------------------------------------------
    def capture_loop(self) -> None:
        if self.args.fake_camera:
            cam = FakeCamera(self.my_fpr[-8:])
        else:
            cam = cv2.VideoCapture(self.args.camera)
            cam.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
            cam.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
        interval = 1.0 / self.args.fps
        epoch_end = time.time() + self.args.epoch
        try:
            while not self.stop.is_set():
                t_start = time.time()
                ok, img = cam.read()
                if not ok:
                    raise RuntimeError("camera read failed")
                img = cv2.resize(img, (640, 480))
                ok, enc = cv2.imencode(".jpg", img, [cv2.IMWRITE_JPEG_QUALITY, 70])
                jpeg = enc.tobytes()
                ts_ms = int(t_start * 1000)
                with self.lock:
                    seq = self.seq
                    self.seq += 1
                    self.pending_leaves.append(frame_leaf(seq, ts_ms, jpeg))
                    self.local_frame = img
                self.conn.send(b"F", struct.pack(">QQ", seq, ts_ms) + jpeg)

                if time.time() >= epoch_end:
                    epoch_end += self.args.epoch
                    with self.lock:
                        leaves, self.pending_leaves = self.pending_leaves, []
                        seq_from, self.epoch_seq_from = self.epoch_seq_from, self.seq
                        seq_to = self.seq
                    self.sign_queue.append((seq_from, seq_to, leaves))
                    self.sign_event.set()

                time.sleep(max(0.0, interval - (time.time() - t_start)))
        finally:
            cam.release()

    def sign_loop(self) -> None:
        while not self.stop.is_set():
            self.sign_event.wait(0.5)
            self.sign_event.clear()
            while self.sign_queue and not self.stop.is_set():
                seq_from, seq_to, leaves = self.sign_queue.popleft()
                with self.lock:
                    peer_ack = self.peer_prev if self.peer_epoch else sha256(self.peer_nonce)
                stmt = {
                    "v": PROTOCOL_VERSION,
                    "session": self.session_id.hex(),
                    "signer": self.my_fpr,
                    "epoch": self.my_epoch + 1,
                    "seq_from": seq_from,
                    "seq_to": seq_to,
                    "root": merkle_root(leaves).hex(),
                    "prev": self.my_prev.hex(),
                    "peer_ack": peer_ack.hex(),
                    "t": round(time.time(), 3),
                }
                body = canonical(stmt).encode()
                if self.args.verbose:
                    print(f"[sign] epoch {stmt['epoch']}: {len(leaves)} frames, touch key if required...",
                          flush=True)
                sig = gpg_sign(body, self.my_fpr)
                h = sha256(body)
                with self.lock:
                    self.my_epoch += 1
                    self.my_prev = h
                    self.my_recent.append(h)
                self.conn.send(b"S", canonical({"stmt": body.decode(), "sig": sig}).encode())

    # -- receiving ----------------------------------------------------
    def recv_loop(self) -> None:
        while not self.stop.is_set():
            mtype, payload = self.conn.recv()
            if mtype == b"F":
                seq, ts_ms = struct.unpack(">QQ", payload[:16])
                jpeg = payload[16:]
                self.peer_leaves[seq] = frame_leaf(seq, ts_ms, jpeg)
                img = cv2.imdecode(np.frombuffer(jpeg, np.uint8), cv2.IMREAD_COLOR)
                with self.lock:
                    self.remote_frame = img
            elif mtype == b"S":
                ok, reason = self.check_statement(payload)
                with self.lock:
                    if ok:
                        self.last_verified = time.time()
                        self.last_error = ""
                    else:
                        # The chain cannot recover; keep the root cause visible.
                        self.first_error = self.first_error or reason
                        self.last_error = self.first_error
                if self.args.verbose or not ok:
                    print(f"[verify] epoch {self.peer_epoch}: {'OK' if ok else 'FAIL ' + reason}", flush=True)

    def check_statement(self, payload: bytes) -> tuple[bool, str]:
        msg = json.loads(payload)
        body = msg["stmt"].encode()
        ok, reason = gpg_verify(body, msg["sig"], self.peer_fpr)
        if not ok:
            return False, reason
        stmt = json.loads(body)
        if canonical(stmt).encode() != body:
            return False, "statement not canonical"
        with self.lock:
            recent = set(self.my_recent)
        checks = [
            (stmt["v"] == PROTOCOL_VERSION, "protocol version"),
            (norm_fpr(stmt["signer"]) == self.peer_fpr, "signer field mismatch"),
            (stmt["session"] == self.session_id.hex(), "wrong session (replay?)"),
            (stmt["epoch"] == self.peer_epoch + 1, f"epoch {stmt['epoch']} != {self.peer_epoch + 1}"),
            (stmt["prev"] == self.peer_prev.hex(), "chain broken (prev mismatch)"),
            (stmt["seq_from"] == self.peer_next_seq, "frame range gap"),
            (bytes.fromhex(stmt["peer_ack"]) in recent, "stale: does not ack a recent statement of ours"),
        ]
        for passed, why in checks:
            if not passed:
                return False, why
        try:
            leaves = [self.peer_leaves.pop(s) for s in range(stmt["seq_from"], stmt["seq_to"])]
        except KeyError as e:
            return False, f"missing frame {e}"
        if merkle_root(leaves).hex() != stmt["root"]:
            return False, "merkle root does not match received video"
        with self.lock:
            self.peer_epoch = stmt["epoch"]
            self.peer_prev = sha256(body)
            self.peer_next_seq = stmt["seq_to"]
        return True, "ok"

    # -- status / UI --------------------------------------------------
    def status(self) -> tuple[bool, str]:
        with self.lock:
            age = time.time() - self.last_verified if self.last_verified else None
            err = self.last_error
            epoch = self.peer_epoch
        deadline = self.args.epoch + self.args.grace
        short = self.peer_fpr[-16:]
        if age is not None and age <= deadline and not err:
            return True, f"KEY PRESENT {short}  epoch {epoch}  {age:4.1f}s ago"
        if age is None:
            return False, f"NOT VERIFIED {short}: {err}"
        return False, f"NOT VERIFIED {short}: {err or f'no statement for {age:.0f}s'}"

    def ui_loop(self) -> None:
        last_print = 0.0
        while not self.stop.is_set():
            ok, text = self.status()
            if self.args.headless:
                if time.time() - last_print >= 1.0:
                    print(("[ OK ] " if ok else "[FAIL] ") + text, flush=True)
                    last_print = time.time()
                time.sleep(0.1)
                continue
            with self.lock:
                remote = None if self.remote_frame is None else self.remote_frame.copy()
                local = None if self.local_frame is None else self.local_frame.copy()
            canvas = remote if remote is not None else np.zeros((480, 640, 3), np.uint8)
            if local is not None:
                canvas[330:470, 450:630] = cv2.resize(local, (180, 140))
            color = (0, 170, 0) if ok else (0, 0, 200)
            cv2.rectangle(canvas, (0, 0), (640, 36), color, -1)
            cv2.putText(canvas, text, (8, 25), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 255), 2)
            if not ok:
                cv2.rectangle(canvas, (0, 0), (639, 479), color, 6)
            cv2.imshow("ykchat", canvas)
            if cv2.waitKey(30) & 0xFF in (ord("q"), 27):
                self.stop.set()

    def run(self) -> None:
        self.handshake()
        print(f"session {self.session_id.hex()[:16]}  me={self.my_fpr[-16:]}  peer={self.peer_fpr[-16:]}",
              flush=True)
        self.sign_queue: collections.deque = collections.deque()
        self.sign_event = threading.Event()

        def guard(fn):
            def wrapped():
                try:
                    fn()
                except Exception as e:  # any worker failure ends the call
                    if not self.stop.is_set():
                        print(f"[{fn.__name__}] {e}", file=sys.stderr, flush=True)
                    self.stop.set()
            return wrapped

        for fn in (self.capture_loop, self.sign_loop, self.recv_loop):
            threading.Thread(target=guard(fn), daemon=True).start()
        try:
            self.ui_loop()
        except KeyboardInterrupt:
            pass
        finally:
            self.stop.set()
            try:
                self.conn.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            if not self.args.headless:
                cv2.destroyAllWindows()


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--listen", metavar="[HOST:]PORT", help="wait for the peer to connect")
    mode.add_argument("--connect", metavar="HOST:PORT", help="connect to a listening peer")
    p.add_argument("--key", required=True, help="your GPG key fingerprint (signing key)")
    p.add_argument("--peer", required=True, help="peer's GPG key fingerprint (must be in your keyring)")
    p.add_argument("--epoch", type=float, default=10.0, help="seconds per signed epoch (default 10)")
    p.add_argument("--grace", type=float, default=15.0,
                   help="extra seconds allowed for signing/touch before NOT VERIFIED (default 15)")
    p.add_argument("--fps", type=float, default=15.0)
    p.add_argument("--camera", type=int, default=0, help="camera device index")
    p.add_argument("--fake-camera", action="store_true", help="use a synthetic test pattern")
    p.add_argument("--headless", action="store_true", help="no window; print status to stdout")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    if args.listen:
        host, _, port = args.listen.rpartition(":")
        srv = socket.create_server((host or "0.0.0.0", int(port)))
        print(f"listening on {host or '0.0.0.0'}:{port}", flush=True)
        sock, addr = srv.accept()
        srv.close()
        print(f"peer connected from {addr[0]}:{addr[1]}", flush=True)
    else:
        host, _, port = args.connect.rpartition(":")
        sock = socket.create_connection((host, int(port)))
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    Session(args, Conn(sock)).run()


if __name__ == "__main__":
    main()
