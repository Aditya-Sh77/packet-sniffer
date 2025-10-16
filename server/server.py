#!/usr/bin/env python3
"""
ws_server_sniffer.py

Run this as root (or with capabilities to capture packets).
It starts a WebSocket server on ws://0.0.0.0:8080 and broadcasts alerts to all connected clients.
"""

import argparse
import asyncio
import json
import re
import threading
import time
from datetime import datetime
from queue import Queue, Empty
from typing import Dict, Any
import uuid
import binascii
import string
from scapy.all import sniff, IP, TCP, UDP, Raw
import websockets
import random
# -------------------------
# Configuration / signatures
# -------------------------
BAD_IPS = {"1.2.3.4", "198.51.100.5", "117.193.86.141",
    "59.97.177.136",
    "110.172.18.6",
    "117.196.138.140",
    "122.172.80.205",
    "122.162.151.157",
    "117.204.31.9",
    "116.74.8.239",
    "115.187.61.214",
    "59.93.241.255",
    "117.205.106.158",
    "122.162.151.137",
    "59.93.218.211",
    "115.187.36.52",
    "122.161.50.166",
    "124.123.81.104",
    "122.162.150.122",
    "117.201.189.91",
    "117.194.243.7" } 

PAYLOAD_PATTERNS = [
    re.compile(br"(?i)password"),
    re.compile(br"(?i)pass=|pwd=|passwd="),
    re.compile(br"(?i)cmd\.exe"),
    re.compile(br"(?i)\/bin\/sh"),
    re.compile(br"(?i)token=|access_token=|auth_token=|bearer\s+[A-Za-z0-9\-\._~\+/]+=*"),
    re.compile(br"(?i)authorization:\s*basic|authorization:\s*bearer"),
    re.compile(br"(?i)ssh-rsa|ssh-ed25519|ssh-dss|-----BEGIN (RSA|OPENSSH|PRIVATE) KEY-----"),
    re.compile(br"(?i)aws_access_key_id|aws_secret_access_key|aws_session_token"),
    re.compile(br"(?i)azure.*(connectionstring|accesskey|sharedaccesskey)"),
    re.compile(br"(?i)mongodb:\/\/|mongodb\+srv:\/\/"),
    re.compile(br"(?i)postgresql:\/\/|mysql:\/\/|redis:\/\/"),
    re.compile(br"(?i)\bUNION\b\s+\bSELECT\b"),
    re.compile(br"(?i)\bDROP\b\s+\bTABLE\b|\bALTER\b\s+\bTABLE\b|\bTRUNCATE\b"),
    re.compile(br"(?i)'?\s*or\s+'?1'?\s*=\s*'1'"),            # classic SQLi fingerprint
    re.compile(br"(?i)xp_cmdshell|sp_executesql|sysobjects|information_schema"),
    re.compile(br"(?i)\/\.\.\/|\.\.\\\\"),                    # directory traversal
    re.compile(br"(?i)\/etc\/passwd|\/etc\/shadow"),
    re.compile(br"(?i)<script\b|<\/script>|onerror=|onload="), # XSS artifacts
    re.compile(br"(?i)eval\(|base64_decode\(|gzinflate\("),
    re.compile(br"(?i)wget\s+(http|https):\/\/|curl\s+(-s|--silent)?\s+(http|https):\/\/"),
    re.compile(br"(?i)\bnc\s+(-e|-c)?\b|netcat\b|bash\s+-i\b"), # reverse shell tooling
    re.compile(br"(?i)\bchmod\s+[0-7]{3,4}\b|\bchown\s+\w+:\w+\b"),
    re.compile(br"(?i)\bpasswd\b:|root:"),
    re.compile(br"(?i)authorization:\s*\"?basic\s+[A-Za-z0-9=+/]+\"?"), # Basic auth header
    re.compile(br"(?i)BEGIN PGP PRIVATE KEY BLOCK|-----BEGIN PGP PRIVATE KEY-----"),
    re.compile(br"(?i)aws_secret|secret_key|private_key|client_secret"),
    re.compile(br"(?i)password\s*[:=]\s*['\"]?[^\s'\"\\]{4,}['\"]?"),  # suspicious inline password
]
OVERSIZE_THRESHOLD = 5000  # bytes -> heuristic for suspicious large packets
_alert_queue: Queue = Queue()


#-------------------------
#Helper Fuctions
#-------------------------


# How many bytes to preview
PREVIEW_BYTES = 128

def is_likely_tls(payload_bytes: bytes, sport: int | None, dport: int | None) -> bool:
    """Heuristic: TLS often starts with record type 0x16 (Handshake) + version 0x03.
       Also treat common TLS ports (443, 8443, 9443) as likely encrypted.
    """
    if not payload_bytes:
        return False
    # common TLS ports
    try:
        ports = {443, 8443, 9443, 7443}
        if (sport in ports) or (dport in ports):
            return True
    except Exception:
        pass

    # TLS record: 0x16 0x03 0x01/0x02/0x03 (Handshake + TLS1.0/1.1/1.2/1.3)
    if len(payload_bytes) >= 3 and payload_bytes[0] == 0x16 and payload_bytes[1] == 0x03:
        return True

    # QUIC (HTTP/3) uses UDP and begins with random bytes; can't reliably detect here.
    return False

def format_payload_preview(payload_bytes: bytes, sport: int | None, dport: int | None, max_bytes: int = PREVIEW_BYTES):
    """
    Return a dict: {label, ascii, hex}
    - label: 'TLS/ENCRYPTED' | 'TEXT' | 'BINARY'
    - ascii: printable ASCII with '.' for non-printables (max max_bytes)
    - hex: hex string of max max_bytes bytes
    """
    if not payload_bytes:
        return {"label": "EMPTY", "ascii": "", "hex": ""}

    data = payload_bytes[:max_bytes]
    hex_preview = binascii.hexlify(data).decode("ascii")

    # If the payload is likely TLS, label and return only hex
    if is_likely_tls(payload_bytes, sport, dport):
        return {"label": "TLS/ENCRYPTED", "ascii": "", "hex": hex_preview}

    # Build ASCII preview: printable ascii characters show, others are '.'
    printable = []
    for b in data:
        if 32 <= b <= 126:  # printable ASCII range
            printable.append(chr(b))
        else:
            printable.append(".")
    ascii_preview = "".join(printable)

    # Heuristic: if more than ~60% of preview is printable, call it TEXT
    printable_ratio = sum(1 for c in ascii_preview if c != ".") / max(1, len(ascii_preview))
    label = "TEXT" if printable_ratio > 0.6 else "BINARY"

    return {"label": label, "ascii": ascii_preview, "hex": hex_preview}

# -------------------------
# Packet inspection
# -------------------------
def inspect_packet(pkt) -> Dict[str, Any] | None:
    try:
        if IP not in pkt:
            return None
        ip_layer = pkt[IP]
        src, dst = ip_layer.src, ip_layer.dst
        proto, sport, dport, payload_bytes = None, None, None, b""

        if TCP in pkt:
            proto, sport, dport = "TCP", pkt[TCP].sport, pkt[TCP].dport
            if Raw in pkt:
                payload_bytes = bytes(pkt[Raw].load)
        elif UDP in pkt:
            proto, sport, dport = "UDP", pkt[UDP].sport, pkt[UDP].dport
            if Raw in pkt:
                payload_bytes = bytes(pkt[UDP].load)
        else:
            proto = str(ip_layer.proto)

        if src in BAD_IPS or dst in BAD_IPS:
            return make_alert("bad_ip", src, dst, proto, sport, dport,
                              "Matched bad IP list", payload_bytes)

        for pat in PAYLOAD_PATTERNS:
            if payload_bytes and pat.search(payload_bytes):
                return make_alert("bad_payload", src, dst, proto, sport, dport,
                                  f"Matched payload pattern: {pat.pattern.decode(errors='ignore')}", payload_bytes)

        if len(bytes(pkt)) > OVERSIZE_THRESHOLD:
            return make_alert("oversize", src, dst, proto, sport, dport,
                              f"Packet size {len(bytes(pkt))} > {OVERSIZE_THRESHOLD}", payload_bytes)

        return None
    except Exception as e:
        print("inspect_packet error:", e)
        return None

def make_alert(kind, src, dst, proto, sport, dport, reason, payload_bytes):
    pid = str(uuid.uuid4())+str(random.randint(1000,9999))  # full UUID for guaranteed uniqueness
    preview = format_payload_preview(payload_bytes or b"", sport, dport, PREVIEW_BYTES)
    payload_preview = payload_bytes.decode(errors='replace')[:PREVIEW_BYTES]

    return {
        "id": pid,
        "kind": kind,
        "time": datetime.now().isoformat() + "Z",
        "src": src,
        "dst": dst,
        "protocol": proto,
        "src_port": sport or 0,
        "dst_port": dport or 0,
        "severity": severity_for_kind(kind),
        "reason": reason,
        "payload_label": preview["label"],         # TLS/ENCRYPTED | TEXT | BINARY | EMPTY
        "payload_ascii": preview["ascii"],         # safe ascii (dots for non-printable)
        "payload_hex": preview["hex"],             # hex string
        "payload_preview": payload_preview,          # only show for TEXT
        "raw_hex": payload_bytes.hex() if payload_bytes else ""
    }

def severity_for_kind(kind: str) -> str:
    if kind in ("bad_ip", "bad_payload"):
        return "high"
    if kind == "oversize":
        return "medium"
    return "low"

# -------------------------
# Sniffer thread
# -------------------------
stop_sniffer = threading.Event()

def sniffer_thread(iface: str | None, pcap_file: str | None):
    if pcap_file:
        from scapy.all import rdpcap
        print(f"[sniffer] Replaying pcap {pcap_file}")
        packets = rdpcap(pcap_file)
        for pkt in packets:
            if stop_sniffer.is_set():
                break
            alert = inspect_packet(pkt)
            if alert:
                _alert_queue.put(alert)
        print("[sniffer] Finished replaying pcap")
        return

    print(f"[sniffer] Starting live capture on iface={iface} (requires root)")
    sniff(iface=iface, prn=lambda pkt: _handle_pkt(pkt), store=False, stop_filter=lambda _: stop_sniffer.is_set())

def _handle_pkt(pkt):
    alert = inspect_packet(pkt)
    if alert:
        _alert_queue.put(alert)

# -------------------------
# WebSocket server (async)
# -------------------------
CONNECTED = set()
sniffer_thread_obj = None

async def broadcast_alerts():
    while True:
        try:
            alert = _alert_queue.get(timeout=0.5)
        except Empty:
            await asyncio.sleep(0.1)
            continue

        if not CONNECTED:
            # wait until a client reconnects, don't drop alert
            _alert_queue.put(alert)
            await asyncio.sleep(0.2)
            continue

        message = json.dumps({"type": "alert", "data": alert})
        coros = []
        for ws in list(CONNECTED):
            try:
                coros.append(ws.send(message))
            except Exception:
                CONNECTED.remove(ws)
        if coros:
            await asyncio.gather(*coros, return_exceptions=True)
        print("[bcast] Sent alert:", alert["id"], alert["reason"])

async def handler(websocket):
    global sniffer_thread_obj
    print("[ws] Client connected")
    CONNECTED.add(websocket)

    # Start sniffer only on first connection
    if sniffer_thread_obj is None:
        stop_sniffer.clear()
        sniffer_thread_obj = threading.Thread(
            target=sniffer_thread, args=(args.iface, args.pcap), daemon=True
        )
        sniffer_thread_obj.start()
        print("[ws] Sniffer started")

    try:
        async for msg in websocket:
            try:
                m = json.loads(msg)
                if m.get("type") == "ack":
                    print("[ws] Ack from client:", m.get("id"))
                elif m.get("type") == "clear":
                    print("[ws] Client requested clear")
                    with _alert_queue.mutex:
                        _alert_queue.queue.clear()
            except Exception:
                pass
    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        CONNECTED.remove(websocket)
        print("[ws] Client disconnected")

        # Stop sniffer if no clients left
        if not CONNECTED:
            print("[ws] No clients left, stopping sniffer...")
            stop_sniffer.set()
            sniffer_thread_obj = None

# -------------------------
# Main
# -------------------------
def main():
    global args
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--iface", help="interface to sniff", default=None)
    parser.add_argument("--pcap", help="pcap file to replay", default=None)
    parser.add_argument("--host", help="websocket host", default="127.0.0.1")
    parser.add_argument("--port", help="websocket port", type=int, default=8080)
    args = parser.parse_args()

    async def runner():
        async with websockets.serve(handler, args.host, args.port):
            print(f"[ws] WebSocket server listening on ws://{args.host}:{args.port}")
            await broadcast_alerts()

    try:
        asyncio.run(runner())
    except KeyboardInterrupt:
        print("Shutting down...")
        stop_sniffer.set()

if __name__ == "__main__":
    main()
