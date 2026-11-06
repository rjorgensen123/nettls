# SPDX-License-Identifier: MIT OR Apache-2.0
"""A ring node in Python (SPEC-nettls §6.15), on nettls_py.

Run as a subprocess of the ring test. It is `examples/ringnode.rs` in Python:
the same Rust code underneath, the same protocol, the same operations. The node
does not know which language its neighbours are written in.

## The protocol between the nodes

One JSON line in, one JSON line out, over TLS.

| `op` | Meaning |
|---|---|
| `identity` | What I present now, and a pending announcement if I have one |
| `ack` | "I have stored your next certificate" |
| `marker` | Pass the marker on around the ring |

The control channel is stdin and stdout: one JSON command per line in, one
reply per line out. Diagnostics go to stderr, never to stdout.

Run:  python3 ringnode.py <name> <port> <neighbour-port> <ed25519-seed-hex>
"""

from __future__ import annotations

import json
import socket
import ssl
import sys
import threading
import time

import nettls_py as nettls

from nettls_py.announcement import Announcement, AnnouncementJson, IdentityJson, Receipt, ReceiptJson
from nettls_py.announcer import Mode, Schedule
from nettls_py.generations import Generation, Generations, Trust
from nettls_py.signature import from_hex
from nettls_py.stream import Stream


def now() -> int:
    return int(time.time())


def make_material(name: str) -> tuple[str, str, bytes]:
    """A fresh identity: (fingerprint, cert PEM, PKCS#8 key)."""
    params = nettls.SelfSignedParams.new(name, ["localhost", "127.0.0.1"])
    params.valid_days = 30
    m = nettls.TlsMaterial.load(nettls.CertSource.self_signed(params))
    pem = nettls.pem.encode("CERTIFICATE", m.cert_chain()[0]).decode()
    return m.fingerprint_sha256(), pem, m.anchor_pkcs8()


def read_line(tls: Stream) -> bytes:
    data = b""
    while not data.endswith(b"\n"):
        chunk = tls.read()
        if not chunk:
            break
        data += chunk
    return data


class Node:
    def __init__(self, name: str, port: int, neighbour_port: int, seed: bytes) -> None:
        self.name = name
        self.port = port
        self.neighbour_port = neighbour_port
        # The successor's name. Without it the marker path cannot pin.
        self.neighbour_name: str | None = None
        self.seed = seed
        self.lock = threading.Lock()
        # Our own material: (fingerprint, cert PEM, PKCS#8).
        self.current = make_material(name)
        self.previous: tuple[str, str, bytes] | None = None
        # Announced, not yet taken into use: (announcement, cert PEM, PKCS#8).
        self.pending: tuple[Announcement, str, bytes] | None = None
        self.schedule = Schedule([], 0)
        self.peers: dict[str, Trust] = {}
        self.peer_keys: dict[str, bytes] = {}
        self.rotations = 0
        # Who must ack OUR rotations: the consumer is the one who remembers.
        self.ackers: list[str] = []
        self.stop_flag = threading.Event()

    # -- the server side ---------------------------------------------------- #

    def server_config(self):
        """Built per connection from the live material, so a rotation shows at once."""
        with self.lock:
            _, cert, key = self.current
        key_pem = nettls.pem.encode("PRIVATE KEY", key)
        return nettls.TlsMaterial.load(nettls.CertSource.pem(cert.encode(), key_pem)).server_config()

    def serve(self) -> None:
        listener = socket.create_server(("127.0.0.1", self.port))
        listener.settimeout(0.3)
        print(json.dumps({"ready": self.name, "fp": self.current[0]}), flush=True)
        while not self.stop_flag.is_set():
            try:
                sock, _ = listener.accept()
            except TimeoutError:
                continue
            threading.Thread(target=self.serve_one, args=(sock,), daemon=True).start()
        listener.close()

    def serve_one(self, sock: socket.socket) -> None:
        try:
            sock.settimeout(20)
            with Stream.accept(sock, self.server_config()) as tls:
                line = read_line(tls)
                if not line:
                    return
                reply = self.handle(json.loads(line))
                tls.write((json.dumps(reply) + "\n").encode())
        except Exception as e:  # noqa: BLE001
            print(f"[{self.name}] {type(e).__name__}: {e}", file=sys.stderr, flush=True)

    def handle(self, m: dict) -> dict:
        op = m.get("op")
        if op == "identity":
            with self.lock:
                fp, cert, _ = self.current
                pending = self.pending[0] if self.pending else None
            return json.loads(
                IdentityJson.new(f"sha256:{fp}", cert, None, Mode.Rolling, now(), pending).dumps()
            )
        if op == "ack":
            try:
                r = Receipt.from_json(ReceiptJson.loads(json.dumps(m["receipt"])))
            except (ValueError, nettls.TlsError) as e:
                return {"error": str(e)}
            pk = self.peer_keys.get(r.acker())
            if pk is None:
                return {"error": f"receipt from unknown acker {r.acker()!r}: no pinned Ed25519 key"}
            with self.lock:
                expected = self.pending[0].new_fingerprint() if self.pending else r.new_fingerprint()
            try:
                r.verify(pk, expected)
            except nettls.TlsError as e:
                return {"error": str(e)}
            self.schedule.acked(r.acker())
            return {"ok": True}
        if op == "marker":
            skip = int(m["skip"])
            if skip <= 0:
                return {"marker": m["marker"]}
            try:
                reply = self.talk(
                    self.neighbour_port,
                    {"op": "marker", "marker": m["marker"], "skip": skip - 1},
                    self.neighbour_name,
                )
            except Exception as e:  # noqa: BLE001
                return {"error": f"the neighbour did not answer: {e}"}
            return {"marker": reply["marker"]}
        return {"error": f"unknown op: {op}"}

    # -- the client side ---------------------------------------------------- #

    def talk(self, port: int, message: dict, neighbour: str | None) -> dict:
        """One request to a neighbour. A known neighbour is pinned through `Trust`,
        which accepts `current` and `next` and promotes by itself (§6.7)."""
        line = (json.dumps(message) + "\n").encode()
        trust = self.peers.get(neighbour) if neighbour else None
        sock = socket.create_connection(("127.0.0.1", port), timeout=20)
        if trust is None:
            return self.talk_unverified(sock, line)
        with Stream.connect(sock, trust.client_config(), "localhost") as tls:
            tls.write(line)
            return json.loads(read_line(tls))

    @staticmethod
    def talk_unverified(sock: socket.socket, line: bytes) -> dict:
        """Enrollment: fetching an identity before there is anything to pin it to.

        It is unverified on purpose; the approval that follows is what trusts
        it. nettls has no observer client for this, so the node uses Python's
        `ssl` here, as `examples/ringnode.rs` uses a verifier of its own.
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(sock, server_hostname="localhost") as s:
            s.sendall(line)
            data = b""
            while not data.endswith(b"\n"):
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
        return json.loads(data)

    def state_of(self, name: str):
        """The trust in one peer as a comparable value."""
        t = self.peers.get(name)
        if t is None:
            return None
        g = t.state()
        return (
            g.current().fingerprint(),
            g.previous().fingerprint() if g.previous() else None,
            g.next().fingerprint() if g.next() else None,
        )


def control(node: Node, m: dict) -> dict:
    op = m["op"]
    if op == "approve":
        port = int(m["port"])
        try:
            reply = node.talk(port, {"op": "identity"}, None)
        except Exception as e:  # noqa: BLE001
            return {"error": f"the neighbour did not answer: {e}"}
        g = Generation.from_pem(reply["cert_pem"])
        node.peers[m["name"]] = Trust.from_approval(g)
        if port == node.neighbour_port:
            node.neighbour_name = m["name"]
        node.peer_keys[m["name"]] = from_hex(m["ed25519_pub"])
        return {"ok": True, "fp": g.fingerprint()}
    if op == "require_ack_from":
        # Who must ack OUR rotation is whoever pins us, not whoever we pin.
        node.schedule.add_peer(m["name"])
        node.ackers.append(m["name"])
        return {"ok": True}
    if op == "know_key":
        node.peer_keys[m["name"]] = from_hex(m["ed25519_pub"])
        return {"ok": True}
    if op == "prepare":
        t = int(m["now"])
        with node.lock:
            if node.pending:
                return {"ok": True, "new_fp": node.pending[0].new_fingerprint()}
            fp_new, pem_new, key_new = make_material(node.name)
            fp, _, key = node.current
            prev = (node.previous[0], node.previous[2]) if node.previous else None
            k = Announcement.new(node.name, prev, (fp, key), pem_new, t)
            node.pending = (k, pem_new, key_new)
        node.schedule.announced(t)
        return {"ok": True, "new_fp": k.new_fingerprint()}
    if op == "fetch_and_ack":
        name, port = m["name"], int(m["port"])
        try:
            reply = node.talk(port, {"op": "identity"}, name)
        except Exception as e:  # noqa: BLE001
            return {"error": f"the neighbour did not answer: {e}"}
        if not reply.get("announcement"):
            return {"ok": True, "no_announcement": True}
        try:
            k = Announcement.from_json(AnnouncementJson.loads(json.dumps(reply["announcement"])))
            if name in node.peers:
                node.peers[name].receive(k)
        except (ValueError, nettls.TlsError) as e:
            return {"error": str(e)}
        r = Receipt.new(node.name, name, k.new_fingerprint(), int(m["now"]), node.seed)
        node.talk(port, {"op": "ack", "receipt": json.loads(r.to_json().dumps())}, name)
        return {"ok": True, "acked_on": k.new_fingerprint()}
    if op == "roll":
        t = int(m["now"])
        if not node.schedule.can_roll(t):
            return {"ok": True, "rolled": False}
        with node.lock:
            if node.pending is None:
                return {"ok": True, "rolled": False}
            k, pem, key = node.pending
            node.pending = None
            old = node.current[0]
            # Exactly two are kept: generation N-2 is dropped here.
            node.previous = node.current
            node.current = (k.new_fingerprint(), pem, key)
            node.rotations += 1
        node.schedule.rolled(t)
        return {"ok": True, "rolled": True, "old": old}
    if op == "export":
        # The consumer's memory (§6.11b): everything goes out, and everything
        # can be put back, as in the Rust node.
        def mat(x):
            return {"fp": x[0], "cert_pem": x[1], "pkcs8": x[2].hex()}

        with node.lock:
            current, previous, pending = node.current, node.previous, node.pending
        peers = {}
        for name, t in node.peers.items():
            g = t.state()
            peers[name] = {
                "previous": g.previous().der().hex() if g.previous() else None,
                "current": g.current().der().hex(),
                "next": g.next().der().hex() if g.next() else None,
            }
        return {"ok": True, "state": {
            "current": mat(current),
            "previous": mat(previous) if previous else None,
            "pending": {
                "announcement": json.loads(pending[0].to_json().dumps()),
                "cert_pem": pending[1],
                "pkcs8": pending[2].hex(),
            } if pending else None,
            "peers": peers,
            "keys": {k: v.hex() for k, v in node.peer_keys.items()},
            "rotations": node.rotations,
            "ackers": list(node.ackers),
            "waiting_for": node.schedule.waiting_for(),
            "first_announced": node.schedule.first_announced(),
        }}
    if op == "import":
        s = m["state"]

        def mat(v):
            return (v["fp"], v["cert_pem"], from_hex(v["pkcs8"]))

        with node.lock:
            node.current = mat(s["current"])
            node.previous = mat(s["previous"]) if s["previous"] else None
            # The pending key pair must come back: the peer may already have
            # acked it (M-26).
            p = s["pending"]
            node.pending = (
                Announcement.from_json(AnnouncementJson.loads(json.dumps(p["announcement"]))),
                p["cert_pem"],
                from_hex(p["pkcs8"]),
            ) if p else None
        node.peers = {
            name: Trust.from_state(Generations.restore(
                Generation.from_der(from_hex(d["previous"])) if d["previous"] else None,
                Generation.from_der(from_hex(d["current"])),
                Generation.from_der(from_hex(d["next"])) if d["next"] else None,
            ))
            for name, d in s["peers"].items()
        }
        node.peer_keys = {k: from_hex(v) for k, v in s["keys"].items()}
        node.ackers = list(s["ackers"])
        node.schedule = Schedule(node.ackers, 0)
        if node.pending:
            # The promise is binding: the peer may already have acked.
            node.schedule.restore_announced(list(s["waiting_for"]), s["first_announced"] or 0)
        node.rotations = int(s["rotations"])
        return {"ok": True, "fp": node.current[0]}
    if op == "inject":
        # A hostile announcement fed straight into the receive path (§6.15b):
        # it must be rejected, AND the state must be unchanged afterwards.
        name = m["name"]
        before = node.state_of(name)
        reason = None
        try:
            k = Announcement.from_json(AnnouncementJson.loads(json.dumps(m["announcement"])))
            if name not in node.peers:
                raise KeyError(f"unknown peer {name}")
            node.peers[name].receive(k)
        except (ValueError, nettls.TlsError) as e:
            reason = str(e)
        except Exception as e:  # noqa: BLE001
            # A foreign exception type is a finding too: callers catch TlsError.
            reason = f"{type(e).__name__}: {e}"
        return {
            "ok": True,
            "rejected": reason is not None,
            # NOT "error": the control channel reads that as a protocol failure.
            "rejected_reason": reason,
            "unchanged": before == node.state_of(name),
        }
    if op == "marker":
        try:
            reply = node.talk(
                node.neighbour_port,
                {"op": "marker", "marker": m["marker"], "skip": int(m["skip"])},
                node.neighbour_name,
            )
        except Exception as e:  # noqa: BLE001
            return {"error": f"the neighbour did not answer: {e}"}
        return {"ok": True, "marker": reply["marker"]}
    if op == "status":
        peers = {}
        for name in node.peers:
            cur, prev, nxt = node.state_of(name)
            peers[name] = {"current": cur, "previous": prev, "next": nxt}
        return {"ok": True, "fp": node.current[0], "rotations": node.rotations, "peers": peers}
    if op == "stop":
        node.stop_flag.set()
        return {"ok": True}
    return {"error": f"unknown control op: {op}"}


def main() -> None:
    nettls.install_crypto_provider()
    name, port, neighbour_port, seed_hex = sys.argv[1:5]
    node = Node(name, int(port), int(neighbour_port), bytes.fromhex(seed_hex))

    def steer() -> None:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            m = json.loads(line)
            try:
                print(json.dumps(control(node, m)), flush=True)
            except Exception as e:  # noqa: BLE001
                # A reply to a command, so it goes to stdout.
                print(json.dumps({"error": f"{type(e).__name__}: {e}"}), flush=True)

    threading.Thread(target=steer, daemon=True).start()
    node.serve()


if __name__ == "__main__":
    main()
