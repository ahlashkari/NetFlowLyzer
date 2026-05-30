from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Set, Tuple, Optional
import hashlib


Path = Tuple[str, int, str, int]  # (src_ip, src_port, dst_ip, dst_port)


def make_conn_id(
    server_ip: str,
    server_port: int,
    initial_dcid: bytes | None,
    initial_scid: bytes | None,
    version: int | None,
) -> str:
    dc = (initial_dcid or b"").hex()
    sc = (initial_scid or b"").hex()
    v = str(version or "")
    # Human-readable, deterministic
    return f"{server_ip}:{server_port}|dc:{dc}|sc:{sc}|v:{v}"


def make_conn_id_hash(
    server_ip: str,
    server_port: int,
    initial_dcid: bytes | None,
    initial_scid: bytes | None,
    version: int | None,
) -> str:
    s = (
        f"{server_ip}:{server_port}|dc:{(initial_dcid or b'').hex()}|"
        f"sc:{(initial_scid or b'').hex()}|v:{version or ''}"
    )
    return hashlib.sha256(s.encode()).hexdigest()[:16]


@dataclass
class QuicConn:
    conn_id: str
    version: Optional[int]
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    start_ts: float
    end_ts: float

    # Counters
    pkts_total: int = 0
    bytes_total: int = 0

    # DCIDs each peer receives on (unifies directions)
    dcids_client: Set[bytes] = field(default_factory=set)  # used on pkts TO client
    dcids_server: Set[bytes] = field(default_factory=set)  # used on pkts TO server

    # Rotations and migration
    dcid_rotations_client: int = 0
    dcid_rotations_server: int = 0
    address_paths: Set[Path] = field(default_factory=set)
    migration_count: int = 0


class QuicTracker:
    """
    Lightweight, strict flow builder:
    - Start only on Client Initial (v!=0, UDP>=1200)
    - Pair Initial DCID/SCID to unify both directions
    - Accept short headers only if DCID known for the receiver
    - Track rotations and migration; close on idle timeout
    """

    def __init__(self, idle_timeout_sec: int = 15) -> None:
        self.idle = idle_timeout_sec
        self.conns: Dict[str, QuicConn] = {}

        # DCID indexes: (server_ip, dcid) -> conn_id for the receiver side
        self.by_server_dcid: Dict[Tuple[str, bytes], str] = {}  # receiver=server
        self.by_client_dcid: Dict[Tuple[str, bytes], str] = {}  # receiver=client

        # Expectation map for Handshake: server_ip -> {expected_client_dcid (client SCID): conn_id}
        self.expected_client: Dict[str, Dict[bytes, str]] = {}

        # Path index
        self.by_path: Dict[Path, Set[str]] = {}

    # ---- helpers ----

    def _register_path(self, conn: QuicConn, path: Path) -> None:
        if path not in conn.address_paths:
            if len(conn.address_paths) > 0:
                conn.migration_count += 1
            conn.address_paths.add(path)
        self.by_path.setdefault(path, set()).add(conn.conn_id)

    def _idx_add_server_dcid(self, server_ip: str, dcid: bytes, conn_id: str) -> None:
        self.by_server_dcid[(server_ip, dcid)] = conn_id

    def _idx_add_client_dcid(self, server_ip: str, dcid: bytes, conn_id: str) -> None:
        self.by_client_dcid[(server_ip, dcid)] = conn_id

    def _expect_client_dcid(self, server_ip: str, client_scid: bytes, conn_id: str) -> None:
        self.expected_client.setdefault(server_ip, {})[client_scid] = conn_id

    # ---- main API ----

    def observe(
        self,
        ts: float,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        udp_len: int,
        pkt: dict,
    ) -> None:

        is_long = bool(pkt.get("is_long"))
        qtype = str(pkt.get("qtype"))
        version = pkt.get("version")
        dcid: Optional[bytes] = pkt.get("dcid")
        scid: Optional[bytes] = pkt.get("scid")

        # 1) Start only on Client Initial (valid)
        if is_long and qtype == "initial" and isinstance(version, int) and version != 0:
            if udp_len < 1200:
                return
            conn_id = make_conn_id(dst_ip, int(dst_port), dcid, scid, version)
            conn = QuicConn(
                conn_id=conn_id,
                version=version,
                client_ip=src_ip,
                client_port=int(src_port),
                server_ip=dst_ip,
                server_port=int(dst_port),
                start_ts=float(ts),
                end_ts=float(ts),
            )
            # Seed DCID sets
            if dcid:
                conn.dcids_server.add(dcid)  # receiver=server on client->server packets
                self._idx_add_server_dcid(conn.server_ip, dcid, conn_id)
            if scid:
                conn.dcids_client.add(scid)  # receiver=client on server->client packets
                self._expect_client_dcid(conn.server_ip, scid, conn_id)

            # First path and counters
            self._register_path(conn, (src_ip, src_port, dst_ip, dst_port))
            conn.pkts_total += 1
            conn.bytes_total += max(0, udp_len)
            self.conns[conn_id] = conn
            return

        # 2) Server Handshake → attach to expected connection (DCID must equal client SCID)
        if is_long and qtype == "handshake":
            server_ip = src_ip  # server sending
            client_dcid = dcid or b""
            conn = None
            exp = self.expected_client.get(server_ip, {})
            cid = exp.get(client_dcid)
            if cid:
                conn = self.conns.get(cid)
            else:
                # Fallback: unique path candidate
                path = (src_ip, src_port, dst_ip, dst_port)
                cand = list(self.by_path.get(path, set()))
                if len(cand) == 1:
                    conn = self.conns.get(cand[0])
            if not conn:
                return
            # index and counters
            self._idx_add_client_dcid(conn.server_ip, client_dcid, conn.conn_id)
            conn.dcids_client.add(client_dcid)
            self._register_path(conn, (src_ip, src_port, dst_ip, dst_port))
            conn.pkts_total += 1
            conn.bytes_total += max(0, udp_len)
            conn.end_ts = float(ts)
            return

        # 3) Short header: accept only if DCID is known for the receiver
        if not is_long and qtype == "short" and dcid is not None:
            # Try receiver=server first (packet to server)
            server_key = (dst_ip, dcid)
            cid = self.by_server_dcid.get(server_key)
            if cid:
                conn = self.conns.get(cid)
                if not conn:
                    return
                # migration & counters
                self._register_path(conn, (src_ip, src_port, dst_ip, dst_port))
                conn.pkts_total += 1
                conn.bytes_total += max(0, udp_len)
                conn.end_ts = float(ts)
                return

            # Try receiver=client (packet to client)
            client_key = (src_ip, dcid)  # server_ip == src_ip on downlink
            cid = self.by_client_dcid.get(client_key)
            if not cid:
                # Rotation heuristic (downlink): if exactly one active conn on this path, add DCID as new for receiver=client
                path = (src_ip, src_port, dst_ip, dst_port)
                cand = list(self.by_path.get(path, set()))
                if len(cand) == 1:
                    conn = self.conns.get(cand[0])
                    if conn:
                        # Add rotation on downlink
                        if dcid not in conn.dcids_client and len(conn.dcids_client) > 0:
                            conn.dcid_rotations_client += 1
                        conn.dcids_client.add(dcid)
                        self._idx_add_client_dcid(conn.server_ip, dcid, conn.conn_id)
                        self._register_path(conn, path)
                        conn.pkts_total += 1
                        conn.bytes_total += max(0, udp_len)
                        conn.end_ts = float(ts)
                        return

                # Rotation heuristic (uplink): single-conn path => add DCID as new for receiver=server
                path = (src_ip, src_port, dst_ip, dst_port)
                cand = list(self.by_path.get(path, set()))
                if len(cand) == 1:
                    conn = self.conns.get(cand[0])
                    if conn:
                        if dcid not in conn.dcids_server and len(conn.dcids_server) > 0:
                            conn.dcid_rotations_server += 1
                        conn.dcids_server.add(dcid)
                        self._idx_add_server_dcid(conn.server_ip, dcid, conn.conn_id)
                        self._register_path(conn, path)
                        conn.pkts_total += 1
                        conn.bytes_total += max(0, udp_len)
                        conn.end_ts = float(ts)
                        return
                return
            # Found receiver=client mapping
            conn = self.conns.get(cid)
            if not conn:
                return
            self._register_path(conn, (src_ip, src_port, dst_ip, dst_port))
            conn.pkts_total += 1
            conn.bytes_total += max(0, udp_len)
            conn.end_ts = float(ts)
            return

        # 4) Long 0-RTT / Retry etc. (do not start flows from these; attach only if indexed)
        if is_long and qtype in ("0rtt", "retry"):
            # Attach if DCID is indexed on either side
            conn = None
            cid = self.by_server_dcid.get((dst_ip, dcid or b""))
            if cid:
                conn = self.conns.get(cid)
            if not conn:
                cid = self.by_client_dcid.get((src_ip, dcid or b""))
                if cid:
                    conn = self.conns.get(cid)
            if not conn:
                return
            self._register_path(conn, (src_ip, src_port, dst_ip, dst_port))
            conn.pkts_total += 1
            conn.bytes_total += max(0, udp_len)
            conn.end_ts = float(ts)
            return

        # 5) Ignore Version Negotiation / unknowns for flow starts
        return

    def iter_rows(self):
        for c in self.conns.values():
            duration = max(0.0, c.end_ts - c.start_ts)

            def hx(s: Set[bytes]) -> str:
                return ";".join(x.hex() for x in s) if s else ""

            yield {
                "conn_id": c.conn_id,
                "client_ip": c.client_ip,
                "client_port": c.client_port,
                "server_ip": c.server_ip,
                "server_port": c.server_port,
                "version": c.version if c.version is not None else "",
                "start_ts": float(c.start_ts),
                "end_ts": float(c.end_ts),
                "duration_s": duration,
                "pkts_total": c.pkts_total,
                "bytes_total": c.bytes_total,
                "migration_count": c.migration_count,
                "paths_count": len(c.address_paths),
                "dcid_rotations_client": c.dcid_rotations_client,
                "dcid_rotations_server": c.dcid_rotations_server,
                "dcids_client_hex": hx(c.dcids_client),
                "dcids_server_hex": hx(c.dcids_server),
            }


