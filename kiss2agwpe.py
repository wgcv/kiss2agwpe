#!/usr/bin/env python3
"""
kiss2agwpe.py - Bridge between KISS TCP and AGWPE protocol
Connects to a KISS TCP server (bt_kiss_bridge) and exposes AGWPE to PAT.

Usage:
    python3 kiss2agwpe.py [--kiss-host HOST] [--kiss-port PORT] [--agwpe-port PORT]

Defaults:
    KISS server: localhost:8001  (bt_kiss_bridge output)
    AGWPE port:  localhost:8000  (PAT input)
"""

import socket
import struct
import threading
import logging
import argparse
import time

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
log = logging.getLogger(__name__)

# KISS constants
KISS_FEND  = 0xC0
KISS_FESC  = 0xDB
KISS_TFEND = 0xDC
KISS_TFESC = 0xDD
KISS_DATA  = 0x00

def agwpe_header(kind: bytes, call_from: str, call_to: str, data_len: int, port: int = 0, pid: int = 0) -> bytes:
    cf = call_from.encode().ljust(10, b'\x00')[:10]
    ct = call_to.encode().ljust(10, b'\x00')[:10]
    return struct.pack('<B3sc1sBx10s10sI4x',
        port, b'\x00\x00\x00', kind, b'\x00', pid, cf, ct, data_len)

def encode_call(callsign: str, last: bool = False) -> bytes:
    """Encode a callsign into 7-byte AX.25 address field (AX.25 §3.12 / ax25lib)."""
    parts = callsign.upper().split('-')
    call = parts[0].ljust(6)[:6]
    ssid = int(parts[1]) if len(parts) > 1 else 0
    encoded = bytes([ord(c) << 1 for c in call])
    flags = 0x60 | ((ssid << 1) & 0x1E)  # reserved bits + SSID nibble
    if last:
        flags |= 0x01
    log.debug(f"encode_call({callsign!r}) ssid={ssid} flags=0x{flags:02x} last={last}")
    return encoded + bytes([flags])

def decode_call_field(raw: bytes) -> str:
    call = ''.join(chr(x >> 1) for x in raw[:6]).rstrip()
    ssid = (raw[6] >> 1) & 0x0F
    return f"{call}-{ssid}" if ssid else call

def parse_ax25_frame(frame: bytes):
    """Return dst, src, control offset, control byte, and via path."""
    if len(frame) < 15:
        return 'NOCALL', 'NOCALL', -1, 0, []
    try:
        dst = decode_call_field(frame[0:7])
        off = 7
        via = []
        while True:
            chunk = frame[off:off + 7]
            if len(chunk) < 7:
                return 'NOCALL', 'NOCALL', -1, 0, []
            call = decode_call_field(chunk)
            last = (chunk[6] & 0x01) != 0
            if off == 7:
                src = call
            else:
                via.append(call)
            off += 7
            if last:
                break
        if off >= len(frame):
            return src, dst, -1, 0, via
        ctrl = frame[off]
        return src, dst, off, ctrl, via
    except Exception:
        return 'NOCALL', 'NOCALL', -1, 0, []

def build_ax25_path(src: str, dst: str, via=None) -> bytes:
    """Build AX.25 address field (dst, src, optional digipeaters)."""
    vias = via if isinstance(via, list) else ([via] if via else [])
    path = [encode_call(dst, False), encode_call(src, len(vias) == 0)]
    for i, v in enumerate(vias):
        path.append(encode_call(v, i == len(vias) - 1))
    return b''.join(path)

def build_ax25_sabm(src: str, dst: str, via=None) -> bytes:
    """Build an AX.25 SABM frame (connect request) with P bit set."""
    return build_ax25_path(src, dst, via) + bytes([0x3F])

def build_ax25_disc(src: str, dst: str, via=None) -> bytes:
    """Build an AX.25 DISC frame (disconnect) with P bit set."""
    return build_ax25_path(src, dst, via) + bytes([0x53])

def build_ax25_iframe(src: str, dst: str, payload: bytes, via=None, ns: int = 0, nr: int = 0, pid: int = 0xF0) -> bytes:
    ctrl = ((nr & 7) << 5) | ((ns & 7) << 1)
    return build_ax25_path(src, dst, via) + bytes([ctrl, pid & 0xFF]) + payload

def build_ax25_rr(src: str, dst: str, nr: int = 0, pf: bool = False, via=None) -> bytes:
    """Build AX.25 RR supervisory frame (ack / poll response)."""
    ctrl = 0x01 | ((nr & 7) << 5)
    if pf:
        ctrl |= 0x10
    return build_ax25_path(src, dst, via) + bytes([ctrl])

def build_ax25_ui(src: str, dst: str, payload: bytes, pid: int = 0xF0) -> bytes:
    return build_ax25_path(src, dst) + bytes([0x03, pid & 0xFF]) + payload

def ax25_frame_type(ctrl: int) -> str:
    if ctrl in (0x63, 0x73):
        return 'UA'
    if ctrl in (0x0F, 0x1F):
        return 'DM'
    if ctrl in (0x43, 0x53):
        return 'DISC'
    if ctrl in (0x3F, 0x2F):
        return 'SABM'
    if (ctrl & 0xEF) == 0x03:
        return 'UI'
    if (ctrl & 0x01) == 0:
        return 'I'
    if (ctrl & 0x03) == 0x01:
        names = ('RR', 'RNR', 'REJ', 'SREJ')
        return names[(ctrl >> 2) & 3]
    return f'ctrl=0x{ctrl:02x}'


class Ax25Session:
    """Minimal AX.25 link state (Direwolf does this inside AGWPE)."""
    def __init__(self):
        self.connected = False
        self.local = ''
        self.remote = ''
        self.via = []
        self.vs = 0   # next I-frame NS to send
        self.vr = 0   # next I-frame NS expected from peer
        self.va = 0   # oldest unacknowledged NS (peer NR acks up to here)

    def reset(self):
        self.connected = False
        self.local = ''
        self.remote = ''
        self.via = []
        self.vs = 0
        self.vr = 0
        self.va = 0

    def on_connect(self, local: str, remote: str, via=None):
        self.connected = True
        self.local = local
        self.remote = remote
        self.via = list(via or [])
        self.vs = 0
        self.vr = 0
        self.va = 0

    def ack_from_peer(self, peer_nr: int):
        """Peer NR acknowledges all I-frames before peer_nr."""
        self.va = peer_nr & 7

    def outstanding(self) -> int:
        """I-frames sent but not yet acknowledged by peer."""
        return (self.vs - self.va) & 7

def kiss_unescape(data: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(data):
        b = data[i]
        if b == KISS_FESC:
            i += 1
            if i < len(data):
                nb = data[i]
                if nb == KISS_TFEND:
                    out.append(KISS_FEND)
                elif nb == KISS_TFESC:
                    out.append(KISS_FESC)
                else:
                    out.append(nb)
        else:
            out.append(b)
        i += 1
    return bytes(out)

def kiss_escape(data: bytes) -> bytes:
    out = bytearray()
    for b in data:
        if b == KISS_FEND:
            out += bytes([KISS_FESC, KISS_TFEND])
        elif b == KISS_FESC:
            out += bytes([KISS_FESC, KISS_TFESC])
        else:
            out.append(b)
    return bytes(out)

def parse_callsign_field(raw: bytes) -> str:
    return raw.rstrip(b'\x00').decode(errors='replace').strip()

def port_capabilities_bytes() -> bytes:
    # Matches wl2k-go agwpe.portCapabilities (12 bytes)
    return bytes([0, 0xFF, 30, 10, 63, 10, 7, 0]) + struct.pack('<I', 0)


class KissReader:
    """Reads KISS frames from a TCP socket."""
    def __init__(self, sock):
        self.sock = sock

    def read_frame(self):
        while True:
            while True:
                chunk = self._recv(1)
                if not chunk:
                    return None
                if chunk[0] == KISS_FEND:
                    break
            frame_raw = bytearray()
            while True:
                chunk = self._recv(1)
                if not chunk:
                    return None
                b = chunk[0]
                if b == KISS_FEND:
                    break
                frame_raw.append(b)
            if len(frame_raw) < 2:
                continue
            cmd = frame_raw[0]
            if (cmd & 0x0F) != KISS_DATA:
                continue
            return kiss_unescape(bytes(frame_raw[1:]))

    def _recv(self, n):
        try:
            return self.sock.recv(n)
        except Exception:
            return b''


class AGWClient:
    """Wrapper around a socket that stores AX.25 connection state."""
    def __init__(self, sock):
        self.sock = sock
        self.ax25_src = ''
        self.ax25_dst = ''
        self.ax25_via = []
        self.connect_gen = 0

    def sendall(self, data):
        self.sock.sendall(data)

    def recv(self, n):
        return self.sock.recv(n)

    def close(self):
        self.sock.close()

    def fileno(self):
        return self.sock.fileno()


class Bridge:
    def __init__(self, kiss_host, kiss_port, agwpe_port):
        self.kiss_host = kiss_host
        self.kiss_port = kiss_port
        self.agwpe_port = agwpe_port
        self.kiss_sock = None
        self.agwpe_clients = []
        self.lock = threading.Lock()
        self._stop = False
        self.session = Ax25Session()

    def connect_kiss(self):
        while not self._stop:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((self.kiss_host, self.kiss_port))
                self.kiss_sock = s
                log.info(f"Connected to KISS server at {self.kiss_host}:{self.kiss_port}")
                return True
            except Exception as e:
                log.warning(f"Cannot connect to KISS server: {e} — retrying in 3s")
                time.sleep(3)
        return False

    def _send_to_clients(self, packet: bytes):
        dead = []
        with self.lock:
            clients = list(self.agwpe_clients)
        for c in clients:
            try:
                c.sendall(packet)
            except Exception:
                dead.append(c)
        if dead:
            with self.lock:
                for d in dead:
                    if d in self.agwpe_clients:
                        self.agwpe_clients.remove(d)

    def kiss_reader_thread(self):
        while not self._stop:
            if not self.kiss_sock:
                if not self.connect_kiss():
                    break
            reader = KissReader(self.kiss_sock)
            try:
                while not self._stop:
                    frame = reader.read_frame()
                    if frame is None:
                        log.warning("KISS connection lost, reconnecting...")
                        self.kiss_sock = None
                        break
                    src, dst, ctrl_off, ctrl, via = parse_ax25_frame(frame)
                    if ctrl_off >= 0:
                        ftype = ax25_frame_type(ctrl)
                        extra = ''
                        if ftype == 'I':
                            extra = f" NS={(ctrl>>1)&7} NR={(ctrl>>5)&7}"
                        elif ftype in ('RR', 'RNR', 'REJ', 'SREJ'):
                            extra = f" NR={(ctrl>>5)&7}" + (' P/F' if ctrl & 0x10 else '')
                        log.info(f"KISS RX: {src} -> {dst} [{ftype}{extra}]" +
                                 (f" via {','.join(via)}" if via else ""))
                    else:
                        log.info(f"KISS RX: {len(frame)} bytes (short/truncated)")
                    self.handle_ax25_rx(frame)
            except Exception as e:
                log.warning(f"KISS reader error: {e}")
                self.kiss_sock = None

    def _reply_rr(self, pf: bool = False):
        """Send RR to peer — required to keep AX.25 session alive."""
        if not self.session.connected:
            return
        rr = build_ax25_rr(
            self.session.local, self.session.remote,
            nr=self.session.vr, pf=pf, via=self.session.via or None)
        self.send_kiss(rr)
        log.debug(f"AX.25 TX RR(NR={self.session.vr}{' P/F' if pf else ''})")

    def handle_ax25_rx(self, ax25_frame: bytes):
        src, dst, ctrl_off, ctrl, via = parse_ax25_frame(ax25_frame)
        if ctrl_off < 0:
            hdr = agwpe_header(b'U', src, dst, len(ax25_frame))
            self._send_to_clients(hdr + ax25_frame)
            return

        # UA — connection established
        if ctrl in (0x63, 0x73):
            local = dst
            remote = src
            self.session.on_connect(local, remote, via)
            msg = f"*** CONNECTED With {remote}\r".encode()
            hdr = agwpe_header(b'C', local, remote, len(msg))
            self._send_to_clients(hdr + msg)
            with self.lock:
                for c in self.agwpe_clients:
                    if c.ax25_src:
                        c.connect_gen += 1
            log.info(f"AX.25 UA (connected): {local} <-> {remote}")
            return

        # DISC / DM — disconnected or connect refused
        if ctrl in (0x43, 0x53, 0x0F, 0x1F):
            local = dst
            remote = src
            if ctrl in (0x0F, 0x1F):
                log.info(f"AX.25 DM (refused): {remote} -> {local}")
            else:
                log.info(f"AX.25 DISC: {local} <-> {remote}")
            msg = f"*** DISCONNECTED From {remote}\r".encode()
            hdr = agwpe_header(b'd', local, remote, len(msg))
            self._send_to_clients(hdr + msg)
            self.session.reset()
            with self.lock:
                for c in self.agwpe_clients:
                    if c.ax25_src:
                        c.connect_gen += 1
            return

        if not self.session.connected:
            hdr = agwpe_header(b'U', src, dst, len(ax25_frame))
            self._send_to_clients(hdr + ax25_frame)
            return

        # I-frame — payload for PAT
        if (ctrl & 0x01) == 0:
            ns = (ctrl >> 1) & 7
            peer_nr = (ctrl >> 5) & 7
            self.session.ack_from_peer(peer_nr)
            if ns == self.session.vr:
                pid = ax25_frame[ctrl_off + 1] if len(ax25_frame) > ctrl_off + 1 else 0xF0
                payload = ax25_frame[ctrl_off + 2:] if len(ax25_frame) > ctrl_off + 2 else b''
                self.session.vr = (self.session.vr + 1) & 7
                hdr = agwpe_header(b'D', src, dst, len(payload), pid=pid)
                self._send_to_clients(hdr + payload)
                log.info(f"AGWPE D-frame {src}->{dst} {len(payload)}b")
                self._reply_rr(pf=bool(ctrl & 0x10))
            else:
                log.warning(f"I-frame out of seq: got NS={ns} expected {self.session.vr}")
                self._reply_rr(pf=bool(ctrl & 0x10))
            return

        # S-frame: RR, RNR, REJ — track acks and respond to polls
        if (ctrl & 0x03) == 0x01:
            peer_nr = (ctrl >> 5) & 7
            pf = bool(ctrl & 0x10)
            stype = ax25_frame_type(ctrl)
            self.session.ack_from_peer(peer_nr)
            log.debug(f"AX.25 S-frame {stype} NR={peer_nr} (outstanding={self.session.outstanding()})")
            if pf:
                self._reply_rr(pf=True)
                log.info(f"AX.25 TX RR(NR={self.session.vr} P/F) — answered {stype} poll")
            elif self.session.outstanding() > 0:
                log.info(f"Peer ack NR={peer_nr}, outstanding now {self.session.outstanding()}")
            return

        # Other U-frames — monitor only
        hdr = agwpe_header(b'U', src, dst, len(ax25_frame))
        self._send_to_clients(hdr + ax25_frame)
        log.debug(f"AGWPE monitor frame {src}->{dst} {len(ax25_frame)}b")

    def agwpe_client_thread(self, raw_conn, addr):
        conn = AGWClient(raw_conn)
        log.info(f"AGWPE client connected: {addr}")
        with self.lock:
            self.agwpe_clients.append(conn)
        try:
            while not self._stop:
                hdr_raw = self._recvall(conn, 36)
                if not hdr_raw or len(hdr_raw) < 36:
                    break
                port = hdr_raw[0]
                data_len = struct.unpack_from('<I', hdr_raw, 28)[0]
                kind = chr(hdr_raw[4])
                data = b''
                if data_len > 0:
                    data = self._recvall(conn, data_len)
                    if data is None:
                        break

                log.debug(f"AGWPE rx kind='{kind}' datalen={data_len}")

                if kind == 'R':
                    ver_data = struct.pack('<II', 2, 1)
                    conn.sendall(agwpe_header(b'R', '', '', len(ver_data), port=port) + ver_data)

                elif kind == 'G':
                    info = b'1;Port1 TH-D75 via BT KISS\x00'
                    conn.sendall(agwpe_header(b'G', '', '', len(info), port=port) + info)

                elif kind == 'g':
                    caps = port_capabilities_bytes()
                    conn.sendall(agwpe_header(b'g', '', '', len(caps), port=port) + caps)

                elif kind in ('k', 'm'):
                    conn.sendall(agwpe_header(kind, '', '', 0, port=port))

                elif kind == 'y':
                    n = self.session.outstanding()
                    count = struct.pack('<I', n)
                    conn.sendall(agwpe_header(b'y', '', '', len(count), port=port) + count)
                    log.debug(f"AGWPE Y reply: {n} outstanding I-frames")

                elif kind == 'Y':
                    call_from = parse_callsign_field(hdr_raw[8:18])
                    call_to = parse_callsign_field(hdr_raw[18:28])
                    n = self.session.outstanding()
                    count = struct.pack('<I', n)
                    conn.sendall(agwpe_header(b'Y', call_from, call_to, len(count), port=port) + count)
                    log.debug(f"AGWPE Y reply: {n} outstanding I-frames")

                elif kind == 'C':
                    call_from = parse_callsign_field(hdr_raw[8:18])
                    call_to = parse_callsign_field(hdr_raw[18:28])
                    log.info(f"AX.25 connect (direct): {call_from} -> {call_to}")
                    conn.ax25_src = call_from
                    conn.ax25_dst = call_to
                    conn.ax25_via = []
                    self.send_connect(conn, call_from, call_to)

                elif kind == 'v':
                    call_from = parse_callsign_field(hdr_raw[8:18])
                    call_to = parse_callsign_field(hdr_raw[18:28])
                    digis = []
                    if data:
                        n = data[0]
                        pos = 1
                        for _ in range(n):
                            digis.append(parse_callsign_field(data[pos:pos + 10]))
                            pos += 10
                    log.info(f"AX.25 connect via: {call_from} -> {call_to}" +
                             (f" via {','.join(digis)}" if digis else ""))
                    conn.ax25_src = call_from
                    conn.ax25_dst = call_to
                    conn.ax25_via = digis
                    self.send_connect(conn, call_from, call_to, digis)

                elif kind == 'd':
                    conn.connect_gen += 1  # stop SABM retries
                    if conn.ax25_src and conn.ax25_dst:
                        log.info(f"AX.25 disconnect: {conn.ax25_src} -> {conn.ax25_dst}")
                        disc = build_ax25_disc(conn.ax25_src, conn.ax25_dst, conn.ax25_via)
                        self.send_kiss(disc)
                        msg = b"*** DISCONNECTED\r"
                        conn.sendall(agwpe_header(b'd', conn.ax25_src, conn.ax25_dst, len(msg), port=port) + msg)
                    conn.ax25_src = ''
                    conn.ax25_dst = ''
                    conn.ax25_via = []

                elif kind == 'D':
                    call_from = parse_callsign_field(hdr_raw[8:18])
                    call_to = parse_callsign_field(hdr_raw[18:28])
                    pid = hdr_raw[6] or 0xF0
                    if data and self.kiss_sock and self.session.connected:
                        iframe = build_ax25_iframe(
                            call_from, call_to, data,
                            via=self.session.via or None,
                            ns=self.session.vs, nr=self.session.vr, pid=pid)
                        self.session.vs = (self.session.vs + 1) & 7
                        self.send_kiss(iframe)
                        log.info(f"AX.25 TX I-frame NS={(self.session.vs - 1) & 7} "
                                 f"NR={self.session.vr} ({len(data)}b) -> KISS")
                    elif data and not self.session.connected:
                        log.warning("D-frame from PAT but AX.25 not connected yet")

                elif kind == 'M':
                    call_from = parse_callsign_field(hdr_raw[8:18])
                    call_to = parse_callsign_field(hdr_raw[18:28])
                    pid = hdr_raw[6] or 0xF0
                    if data and self.kiss_sock:
                        ui = build_ax25_ui(call_from, call_to, data, pid=pid)
                        self.send_kiss(ui)
                        log.debug(f"Forwarded UI frame ({len(data)}b) to KISS")

                elif kind == 'K':
                    if data and self.kiss_sock:
                        self.send_kiss(data)
                        log.debug(f"Forwarded raw AX.25 ({len(data)}b) to KISS")

                elif kind == 'X':
                    call = parse_callsign_field(hdr_raw[8:18])
                    log.info(f"AGWPE register call: {call}")
                    resp = agwpe_header(b'X', call, '', 1, port=port) + b'\x01'
                    conn.sendall(resp)

                elif kind == 'x':
                    call = parse_callsign_field(hdr_raw[8:18])
                    log.info(f"AGWPE unregister call: {call}")
                    conn.sendall(agwpe_header(b'x', call, '', 1, port=port) + b'\x01')

                elif kind == 'P':
                    pass

                else:
                    log.debug(f"Unhandled AGWPE kind='{kind}' — ignoring")

        except Exception as e:
            log.warning(f"AGWPE client {addr} error: {e}")
        finally:
            with self.lock:
                if conn in self.agwpe_clients:
                    self.agwpe_clients.remove(conn)
            conn.close()
            log.info(f"AGWPE client disconnected: {addr}")

    def send_connect(self, conn, src, dst, via=None, interval=6.0):
        """Keep sending SABM until UA/DM, PAT disconnect, or new connect request."""
        conn.connect_gen += 1
        gen = conn.connect_gen
        sabm = build_ax25_sabm(src, dst, via)
        via_s = f" via {','.join(via)}" if via else ""

        def retry():
            n = 0
            while not self._stop and conn.connect_gen == gen:
                n += 1
                log.info(f"SABM attempt {n}: {src} -> {dst}{via_s}")
                self.send_kiss(sabm)
                # Listen between attempts (half-duplex radio needs time to RX UA)
                for _ in range(int(interval * 10)):
                    if self._stop or conn.connect_gen != gen:
                        return
                    time.sleep(0.1)
            if conn.connect_gen == gen:
                log.warning(f"Connect to {dst} stopped")

        threading.Thread(target=retry, daemon=True).start()

    def send_kiss(self, ax25_frame: bytes):
        try:
            payload = bytes([KISS_FEND, KISS_DATA]) + kiss_escape(ax25_frame) + bytes([KISS_FEND])
            self.kiss_sock.sendall(payload)
            log.debug(f"Sent KISS frame: {len(ax25_frame)} bytes")
        except Exception as e:
            log.warning(f"KISS send error: {e}")
            self.kiss_sock = None

    def _recvall(self, sock, n):
        buf = bytearray()
        while len(buf) < n:
            try:
                chunk = sock.recv(n - len(buf))
                if not chunk:
                    return None
                buf.extend(chunk)
            except Exception:
                return None
        return bytes(buf)

    def run(self):
        t = threading.Thread(target=self.kiss_reader_thread, daemon=True)
        t.start()

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('localhost', self.agwpe_port))
        server.listen(5)
        log.info(f"AGWPE server listening on localhost:{self.agwpe_port}")
        log.info(f"Configure PAT: engine=agwpe, addr=localhost:{self.agwpe_port}")
        log.info("Waiting for PAT to connect...")

        try:
            while not self._stop:
                server.settimeout(1.0)
                try:
                    conn, addr = server.accept()
                    ct = threading.Thread(target=self.agwpe_client_thread, args=(conn, addr), daemon=True)
                    ct.start()
                except socket.timeout:
                    continue
        except KeyboardInterrupt:
            log.info("Shutting down.")
        finally:
            self._stop = True
            server.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='KISS TCP -> AGWPE bridge for PAT')
    parser.add_argument('--kiss-host', default='localhost', help='KISS server host (default: localhost)')
    parser.add_argument('--kiss-port', type=int, default=8001, help='KISS server port (default: 8001)')
    parser.add_argument('--agwpe-port', type=int, default=8000, help='AGWPE listen port for PAT (default: 8000)')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    print("=" * 55)
    print("  KISS TCP -> AGWPE Bridge for PAT + TH-D75")
    print("=" * 55)
    print(f"  KISS source : {args.kiss_host}:{args.kiss_port}")
    print(f"  AGWPE server: localhost:{args.agwpe_port}")
    print("=" * 55)

    Bridge(args.kiss_host, args.kiss_port, args.agwpe_port).run()
