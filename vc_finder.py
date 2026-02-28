"""
network_analyzer.py
────────────────────────────────────────────────────────────────────
Network monitoring using psutil and packet capture (tcpdump/tshark).
Works on Windows (tshark) and Linux (tcpdump).
CCNA concepts covered in this module:
  ✅ TCP vs UDP traffic distribution
  ✅ TCP connection states
  ✅ Port-to-protocol mapping
  ✅ Bandwidth calculation (Kbps)
  ✅ Packets per second (PPS)
  ✅ Telegram Data Center IP detection
  ✅ Connection delta tracking
  ✅ Peak bandwidth & average PPS
  ✅ Packet error and drop counters
"""

import time
import psutil
import subprocess
import os
import sys
import platform
from collections import Counter
from datetime import datetime


# ─── Telegram Data Center IP map ─────────────────────────────────────────────
TELEGRAM_DCS: dict[str, str] = {
    "149.154.175.50":  "DC1 🇺🇸 US-Virginia",
    "149.154.175.53":  "DC1 🇺🇸 US-Virginia",
    "149.154.167.40":  "DC2 🇳🇱 Netherlands",
    "149.154.167.41":  "DC2 🇳🇱 Netherlands",
    "149.154.167.51":  "DC2 🇳🇱 Netherlands",   # most common
    "149.154.175.100": "DC3 🇺🇸 US-Miami",
    "149.154.167.91":  "DC4 🇳🇱 Netherlands",
    "149.154.167.92":  "DC4 🇳🇱 Netherlands",
    "91.108.56.100":   "DC5 🇸🇬 Singapore",
    "91.108.56.130":   "DC5 🇸🇬 Singapore",
    "91.108.56.149":   "DC5 🇸🇬 Singapore",
    "91.108.4.0":      "DC5 🇸🇬 Singapore (alt)",
    "91.105.192.0":    "TG-CDN 🌐 Media",
    "95.161.76.0":     "TG-CDN 🌐 Media",
}

# ─── Well-known port → protocol name ─────────────────────────────────────────
PORT_PROTOCOLS: dict[int, str] = {
    80:    "HTTP",
    443:   "HTTPS/TLS",       # MTProto rides over this
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    53:    "DNS",
    853:   "DNS-over-TLS",
    3478:  "STUN",            # NAT traversal for UDP voice
    3479:  "STUN-Alt",
    5349:  "TURNS",           # STUN over TLS
    19302: "STUN-Google",
    5222:  "MTProto-Proxy",
    1080:  "SOCKS5",
    22:    "SSH",
    21:    "FTP",
}

# ─── TCP state plain-English descriptions ────────────────────────────────────
STATE_DESCRIPTIONS: dict[str, str] = {
    "ESTABLISHED": "Active session — data flowing",
    "TIME_WAIT":   "Graceful close — waiting for delayed packets (2×MSL)",
    "CLOSE_WAIT":  "Remote closed — local side still open",
    "SYN_SENT":    "3-way handshake: SYN sent, awaiting SYN-ACK",
    "SYN_RECV":    "3-way handshake: SYN received",
    "FIN_WAIT1":   "FIN sent — half-close initiated",
    "FIN_WAIT2":   "FIN acknowledged — waiting for remote FIN",
    "LAST_ACK":    "Waiting for final ACK before closing",
    "LISTEN":      "Server socket accepting connections",
    "CLOSING":     "Simultaneous close from both sides",
}


def identify_port(port: int) -> str:
    """Map port number to protocol name."""
    if port in PORT_PROTOCOLS:
        return PORT_PROTOCOLS[port]
    if port >= 49152:
        return "Ephemeral"      # OS-assigned client port
    if port >= 1024:
        return f"Registered:{port}"
    return f"Well-known:{port}"


# ─── Packet Capture (cross‑platform) ─────────────────────────────────────────

class PacketCapture:
    """Manages packet capture subprocess (tcpdump on Linux, tshark on Windows)."""
    def __init__(self, output_file="capture.pcap"):
        self.output_file = output_file
        self.process = None
        self.cap_interface = None

    def _find_interface(self):
        """Pick first non‑loopback interface."""
        for iface, stats in psutil.net_if_stats().items():
            if stats.isup and not iface.startswith(("lo", "Loopback")):
                return iface
        return "eth0"  # fallback

    def start(self):
        """Start capture process. Returns True if successful."""
        if platform.system() == "Windows":
            # Use tshark (Wireshark)
            cmd = [
                "tshark", "-i", self._find_interface(),
                "-f", "udp",
                "-w", self.output_file,
                "-F", "pcapng"
            ]
            # Hide window on Windows
            kwargs = {"creationflags": subprocess.CREATE_NO_WINDOW} if sys.platform == "win32" else {}
        else:
            # Linux: use tcpdump
            cmd = [
                "sudo", "tcpdump", "-i", self._find_interface(),
                "-U", "-w", self.output_file,
                "-s", "0", "udp"
            ]
            kwargs = {}
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                **kwargs
            )
            return True
        except FileNotFoundError as e:
            tool = "tshark" if platform.system() == "Windows" else "tcpdump"
            print(f"⚠️ {tool} not found. Install it and ensure it's in PATH.")
            return False
        except PermissionError:
            print("⚠️ Permission denied. Run with sudo (Linux) or as administrator (Windows).")
            return False

    def stop(self):
        if self.process:
            self.process.terminate()
            self.process.wait()
            self.process = None


# ─── Main NetworkCapture class ───────────────────────────────────────────────

class NetworkCapture:
    """
    Captures and analyses network activity using psutil and optional packet capture.
    """

    def __init__(self, duration: int = 60, capture_packets: bool = True):
        self.duration = duration
        self.capture_packets = capture_packets
        self.start_time: float | None = None
        self.is_running: bool = False

        # Aggregated counters (accumulate across all snapshots)
        self.connection_states: Counter = Counter()
        self.protocol_counter:  Counter = Counter()   # TCP / UDP
        self.port_protocols:    Counter = Counter()   # TLS, STUN, DNS…
        self.dc_connections:    dict    = {}           # ip → label

        # Raw snapshot list
        self.snapshots: list[dict] = []

        # Bandwidth samples for timeline
        self._bw_samples: list[dict] = []

        # Baseline I/O counters
        self.initial_net_io = None
        self.final_net_io   = None

        # For delta tracking
        self._prev_conn_set: set = set()

        # Events log
        self.events: list[dict] = []

        # Packet capture
        self.packet_capture = None
        if capture_packets:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            pcap_file = f"capture_{timestamp}.pcap"
            self.packet_capture = PacketCapture(output_file=pcap_file)

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _read_connections(self) -> list[dict]:
        result = []
        try:
            conns = psutil.net_connections(kind="inet")
        except Exception:
            return result

        for c in conns:
            try:
                proto      = "TCP" if c.type == 1 else "UDP"
                remote_ip  = c.raddr.ip   if c.raddr else ""
                remote_pt  = c.raddr.port if c.raddr else 0
                local_ip   = c.laddr.ip   if c.laddr else ""
                local_pt   = c.laddr.port if c.laddr else 0
                status     = (getattr(c, "status", "") or "").strip() or "NONE"

                if not remote_ip:
                    continue

                port_proto = identify_port(remote_pt)
                is_tg      = remote_ip in TELEGRAM_DCS

                conn = {
                    "protocol":      proto,
                    "local":         f"{local_ip}:{local_pt}",
                    "remote":        f"{remote_ip}:{remote_pt}",
                    "remote_ip":     remote_ip,
                    "remote_port":   remote_pt,
                    "status":        status,
                    "port_protocol": port_proto,
                    "is_telegram":   is_tg,
                    "dc_label":      TELEGRAM_DCS.get(remote_ip, ""),
                }
                result.append(conn)

                self.protocol_counter[proto] += 1
                self.connection_states[status] += 1
                self.port_protocols[port_proto] += 1

                if is_tg:
                    self.dc_connections[remote_ip] = TELEGRAM_DCS[remote_ip]

            except Exception:
                continue

        return result

    def _take_snapshot(self, event_type: str = "periodic") -> dict:
        ts    = time.time()
        net   = psutil.net_io_counters()
        conns = self._read_connections()

        current_set  = {c["remote"] for c in conns}
        new_conns    = list(current_set - self._prev_conn_set)
        dropped      = list(self._prev_conn_set - current_set)
        self._prev_conn_set = current_set

        snap = {
            "timestamp":           ts,
            "event_type":          event_type,
            "connections":         conns,
            "new_connections":     new_conns,
            "dropped_connections": dropped,
            "net_io": {
                "bytes_sent":   net.bytes_sent,
                "bytes_recv":   net.bytes_recv,
                "packets_sent": net.packets_sent,
                "packets_recv": net.packets_recv,
                "errin":        net.errin,
                "errout":       net.errout,
                "dropin":       net.dropin,
                "dropout":      net.dropout,
            },
        }
        self.snapshots.append(snap)

        self._bw_samples.append({
            "ts":    ts,
            "bsent": net.bytes_sent,
            "brecv": net.bytes_recv,
            "psent": net.packets_sent,
            "precv": net.packets_recv,
        })

        return snap

    # ── Public API ────────────────────────────────────────────────────────────

    def log_event(self, event_name: str, details: str = ""):
        """Log a significant event and immediately take a snapshot."""
        self.events.append({
            "timestamp": time.time(),
            "event":     event_name,
            "details":   details,
        })
        self._take_snapshot(event_type=event_name)

    def start_capture(self):
        """Blocking capture loop — run via executor (thread)."""
        self.start_time     = time.time()
        self.is_running     = True
        self.initial_net_io = psutil.net_io_counters()
        self.log_event("capture_start", "Network monitoring started")

        if self.packet_capture:
            if not self.packet_capture.start():
                self.packet_capture = None  # disable on failure

        end_time = self.start_time + self.duration
        while time.time() < end_time and self.is_running:
            self._take_snapshot("periodic")
            time.sleep(2.0)

        self.final_net_io = psutil.net_io_counters()
        self.is_running   = False
        self.log_event("capture_end", "Capture complete")
        if self.packet_capture:
            self.packet_capture.stop()

    def stop_capture(self):
        self.is_running = False
        if not self.final_net_io:
            self.final_net_io = psutil.net_io_counters()
        if self.packet_capture:
            self.packet_capture.stop()

    def _bandwidth_series(self) -> list[dict]:
        series = []
        for i in range(1, len(self._bw_samples)):
            p, c = self._bw_samples[i-1], self._bw_samples[i]
            dt   = c["ts"] - p["ts"]
            if dt <= 0:
                continue
            series.append({
                "time_offset": c["ts"] - self.start_time,
                "kbps_up":     (c["bsent"] - p["bsent"]) * 8 / dt / 1000,
                "kbps_dn":     (c["brecv"] - p["brecv"]) * 8 / dt / 1000,
                "pps_up":      (c["psent"] - p["psent"]) / dt,
                "pps_dn":      (c["precv"] - p["precv"]) / dt,
            })
        return series

    def get_pcap_file(self):
        if self.packet_capture and os.path.exists(self.packet_capture.output_file):
            return self.packet_capture.output_file
        return None

    def get_report(self) -> dict:
        if not self.start_time:
            return {"error": "Capture never started"}

        elapsed = time.time() - self.start_time

        if self.initial_net_io and self.final_net_io:
            b_sent  = self.final_net_io.bytes_sent   - self.initial_net_io.bytes_sent
            b_recv  = self.final_net_io.bytes_recv   - self.initial_net_io.bytes_recv
            p_sent  = self.final_net_io.packets_sent - self.initial_net_io.packets_sent
            p_recv  = self.final_net_io.packets_recv - self.initial_net_io.packets_recv
            errin   = self.final_net_io.errin  - self.initial_net_io.errin
            errout  = self.final_net_io.errout - self.initial_net_io.errout
            dropin  = self.final_net_io.dropin - self.initial_net_io.dropin
            avg_bw  = (b_sent + b_recv) * 8 / elapsed / 1000 if elapsed else 0
        else:
            b_sent = b_recv = p_sent = p_recv = 0
            errin = errout = dropin = avg_bw = 0

        series   = self._bandwidth_series()
        peak_up  = max((s["kbps_up"] for s in series), default=0)
        peak_dn  = max((s["kbps_dn"] for s in series), default=0)
        avg_pps  = (sum(s["pps_up"] + s["pps_dn"] for s in series) / len(series)
                    if series else 0)

        all_new, all_dropped = [], []
        unique = set()
        for snap in self.snapshots:
            for c in snap["connections"]:
                unique.add(c["remote"])
            all_new.extend(snap.get("new_connections", []))
            all_dropped.extend(snap.get("dropped_connections", []))

        return {
            "duration":           elapsed,
            "start_time":         self.start_time,
            "bytes_sent":         b_sent,
            "bytes_recv":         b_recv,
            "total_bytes":        b_sent + b_recv,
            "packets_sent":       p_sent,
            "packets_recv":       p_recv,
            "total_packets":      p_sent + p_recv,
            "errors_in":          errin,
            "errors_out":         errout,
            "drops_in":           dropin,
            "bandwidth_kbps":     avg_bw,
            "peak_kbps_up":       peak_up,
            "peak_kbps_dn":       peak_dn,
            "avg_pps":            avg_pps,
            "protocols":          dict(self.protocol_counter),
            "port_protocols":     dict(self.port_protocols),
            "connection_states":  dict(self.connection_states),
            "dc_connections":     self.dc_connections,
            "unique_connections": len(unique),
            "new_connections":    list(set(all_new)),
            "dropped_connections":list(set(all_dropped)),
            "total_snapshots":    len(self.snapshots),
            "bw_series":          series,
            "events":             self.events,
        }

    def export_to_file(self, filename: str):
        r = self.get_report()

        with open(filename, "w", encoding="utf-8") as f:
            W = f.write

            def section(title: str):
                W("\n" + "─" * 70 + "\n")
                W(f"  {title}\n")
                W("─" * 70 + "\n")

            W("═" * 70 + "\n")
            W("  TG_NETWORK_capturer — FULL CAPTURE REPORT\n")
            W(f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            W("═" * 70 + "\n")

            section("CAPTURE OVERVIEW")
            W(f"  Duration         : {r['duration']:.2f} s\n")
            W(f"  Start Time       : {datetime.fromtimestamp(r['start_time']).strftime('%Y-%m-%d %H:%M:%S')}\n")
            W(f"  Total Snapshots  : {r['total_snapshots']}\n")
            W(f"  Unique Endpoints : {r['unique_connections']}\n")

            section("BANDWIDTH STATISTICS")
            W(f"  Total Data       : {r['total_bytes'] / 1024:.2f} KB\n")
            W(f"  ↑ Uploaded       : {r['bytes_sent'] / 1024:.2f} KB\n")
            W(f"  ↓ Downloaded     : {r['bytes_recv'] / 1024:.2f} KB\n")
            W(f"  Avg Bandwidth    : {r['bandwidth_kbps']:.2f} Kbps\n")
            W(f"  Peak ↑ Upload    : {r['peak_kbps_up']:.2f} Kbps\n")
            W(f"  Peak ↓ Download  : {r['peak_kbps_dn']:.2f} Kbps\n")
            W(f"  Total Packets    : {r['total_packets']}\n")
            W(f"  ↑ Sent           : {r['packets_sent']}\n")
            W(f"  ↓ Received       : {r['packets_recv']}\n")
            W(f"  Avg PPS          : {r['avg_pps']:.1f} pkts/sec\n")
            W(f"  Errors In        : {r['errors_in']}\n")
            W(f"  Errors Out       : {r['errors_out']}\n")
            W(f"  Drops In         : {r['drops_in']}\n")

            section("BANDWIDTH OVER TIME")
            W(f"  {'Time(s)':>8}  {'↑ Kbps':>10}  {'↓ Kbps':>10}  {'↑ PPS':>7}  {'↓ PPS':>7}\n")
            W("  " + "-" * 50 + "\n")
            for s in r["bw_series"]:
                W(f"  {s['time_offset']:>8.1f}  {s['kbps_up']:>10.2f}  {s['kbps_dn']:>10.2f}"
                  f"  {s['pps_up']:>7.1f}  {s['pps_dn']:>7.1f}\n")

            section("TELEGRAM DATA CENTERS DETECTED")
            if r["dc_connections"]:
                for ip, dc in r["dc_connections"].items():
                    W(f"  • {ip:20} → {dc}\n")
                W("\n  [CCNA] Your voice call is routed to the above DC.\n")
                W("  Traffic to these IPs uses MTProto inside TLS (port 443)\n")
                W("  and UDP for real-time voice frames.\n")
            else:
                W("  ⚠️  No Telegram DC IPs detected directly.\n")
                W("  Possible causes: VPN, proxy, or NAT masking the real IP.\n")

            section("TRANSPORT PROTOCOL DISTRIBUTION (TCP vs UDP)")
            total = sum(r["protocols"].values()) or 1
            for proto, cnt in sorted(r["protocols"].items(), key=lambda x: -x[1]):
                pct = cnt / total * 100
                bar = "█" * int(pct / 5)
                W(f"  {proto:5}  {cnt:5} ({pct:5.1f}%)  {bar}\n")
            W("\n  [CCNA] TCP  = connection-oriented, reliable, 3-way handshake\n")
            W("         UDP  = connectionless, low latency, preferred for VoIP\n")
            W("         Voice frames use UDP; signalling/auth uses TCP/TLS.\n")

            section("APPLICATION LAYER PROTOCOLS (by port number)")
            top = sorted(r["port_protocols"].items(), key=lambda x: -x[1])[:15]
            for proto, cnt in top:
                W(f"  • {proto:25} {cnt:5} occurrences\n")
            W("\n  [CCNA] Port 443 = HTTPS/TLS (MTProto encrypted inside)\n")
            W("         STUN 3478 = NAT traversal — lets voice UDP punch through router\n")
            W("         Ephemeral = OS-assigned client ports (49152-65535 on Windows)\n")
            W("         DNS  53   = hostname lookups to find DC IPs\n")

            section("TCP CONNECTION STATES")
            for state, cnt in sorted(r["connection_states"].items(), key=lambda x: -x[1]):
                desc = STATE_DESCRIPTIONS.get(state, "")
                W(f"  • {state:15}  {cnt:5}   {desc}\n")
            W("\n  [CCNA] ESTABLISHED = active TCP session (data can flow)\n")
            W("         TIME_WAIT   = after graceful close, OS waits 2×MSL (~60s)\n")
            W("         Watch TIME_WAIT count increase after leave_voice_chat event!\n")

            section("CONNECTION CHANGES PER INTERVAL")
            W(f"  Total new endpoints seen    : {len(r['new_connections'])}\n")
            W(f"  Total dropped endpoints     : {len(r['dropped_connections'])}\n")
            W("\n  New:\n")
            for ep in r["new_connections"][:20]:
                W(f"    + {ep}\n")
            if len(r["new_connections"]) > 20:
                W(f"    ... and {len(r['new_connections']) - 20} more\n")
            W("\n  Dropped:\n")
            for ep in r["dropped_connections"][:20]:
                W(f"    - {ep}\n")

            section("EVENT TIMELINE")
            W(f"  {'Time':>10}  {'Offset':>8}  {'Event':<25}  Details\n")
            W("  " + "-" * 65 + "\n")
            for ev in r["events"]:
                ts_s   = datetime.fromtimestamp(ev["timestamp"]).strftime("%H:%M:%S.%f")[:-3]
                offset = ev["timestamp"] - r["start_time"]
                W(f"  {ts_s}  +{offset:>6.1f}s  {ev['event']:<25}  {ev['details']}\n")

            section("SNAPSHOT DETAILS (all connections every 2 seconds)")
            for i, snap in enumerate(self.snapshots, 1):
                ts_s   = datetime.fromtimestamp(snap["timestamp"]).strftime("%H:%M:%S.%f")[:-3]
                offset = snap["timestamp"] - self.start_time
                W(f"\n  ─ Snapshot #{i:02d}  [{ts_s}]  +{offset:.1f}s  [{snap['event_type']}]\n")
                W(f"    Active: {len(snap['connections'])}  "
                  f"New: {len(snap.get('new_connections',[]))}  "
                  f"Dropped: {len(snap.get('dropped_connections',[]))}\n")
                for c in snap["connections"][:12]:
                    tg  = " ◄ TG" if c["is_telegram"] else ""
                    W(f"    [{c['protocol']:3}] {c['local']:22} ↔ {c['remote']:22}"
                      f"  {c['port_protocol']:15}  {c['status']}{tg}\n")
                if len(snap["connections"]) > 12:
                    W(f"    ... +{len(snap['connections'])-12} more connections\n")

            section("CCNA STUDY NOTES")
            notes = [
                ("TCP",          "Layer 4 — connection-oriented, reliable delivery via sequence numbers"),
                ("UDP",          "Layer 4 — connectionless, no retransmit (ideal for real-time voice)"),
                ("MTProto",      "Layer 7 — Telegram's own encrypted protocol, tunnelled over TLS"),
                ("TLS 1.3",      "Layer 4-7 — encrypts MTProto; you see the connection but not content"),
                ("STUN",         "Layer 5-7 — NAT traversal: discovers external IP:port for UDP voice"),
                ("3-way HS",     "SYN → SYN-ACK → ACK: TCP connection setup (join = new handshake)"),
                ("FIN handshake","FIN → FIN-ACK → FIN → ACK: graceful TCP close (leave = triggers this)"),
                ("TIME_WAIT",    "TCP state after close: OS holds port 2×MSL to catch delayed packets"),
                ("Ephemeral",    "Ports >49152: OS-assigned source ports for each new outbound connection"),
                ("Bandwidth",    "Total bits/sec = (bytes_sent + bytes_recv) × 8 / elapsed_seconds"),
                ("PPS",          "Packets/sec: spikes when mic is ON (50 pkts/s), drops when muted"),
                ("DC IPs",       "Telegram routes via 5 DCs; closest DC handles your voice call"),
            ]
            for term, note in notes:
                W(f"  {term:15} — {note}\n")

            W("\n" + "═" * 70 + "\n")
            W("  END OF REPORT\n")
            W("═" * 70 + "\n")