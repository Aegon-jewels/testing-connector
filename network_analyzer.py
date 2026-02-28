"""
network_analyzer.py
────────────────────────────────────────────────────────────────────
Network monitoring using psutil and packet capture (tcpdump/tshark).
Works on Windows (tshark) and Linux (tcpdump).
CCNA concepts covered:
  ✅ TCP vs UDP traffic distribution
  ✅ TCP connection states
  ✅ Port-to-protocol mapping
  ✅ Bandwidth calculation (Kbps)
  ✅ Packets per second (PPS)
  ✅ Telegram Data Center IP detection (IPv4 + IPv6)
  ✅ Connection delta tracking
  ✅ Peak bandwidth & average PPS
  ✅ Packet error and drop counters
"""

import json
import time
import psutil
import subprocess
import os
import sys
import platform
from collections import Counter
from datetime import datetime


# ─── Telegram Data Center IP map (IPv4 + IPv6) ───────────────────────────────
TELEGRAM_DCS: dict[str, str] = {
    # ── IPv4 ──────────────────────────────────────────────────────────────────
    "149.154.175.50":   "DC1 🇺🇸 US-Virginia",
    "149.154.175.53":   "DC1 🇺🇸 US-Virginia",
    "149.154.167.40":   "DC2 🇳🇱 Netherlands",
    "149.154.167.41":   "DC2 🇳🇱 Netherlands",
    "149.154.167.51":   "DC2 🇳🇱 Netherlands",   # most common
    "149.154.175.100":  "DC3 🇺🇸 US-Miami",
    "149.154.167.91":   "DC4 🇳🇱 Netherlands",
    "149.154.167.92":   "DC4 🇳🇱 Netherlands",
    "91.108.56.100":    "DC5 🇸🇬 Singapore",
    "91.108.56.130":    "DC5 🇸🇬 Singapore",
    "91.108.56.149":    "DC5 🇸🇬 Singapore",
    "91.108.4.0":       "DC5 🇸🇬 Singapore (alt)",
    "91.105.192.0":     "TG-CDN 🌐 Media",
    "95.161.76.0":      "TG-CDN 🌐 Media",
    # ── IPv6 ──────────────────────────────────────────────────────────────────
    "2001:b28:f23d:f001::a": "DC1 🇺🇸 US-Virginia  [IPv6]",
    "2001:b28:f23d:f001::e": "DC1 🇺🇸 US-Virginia  [IPv6 alt]",
    "2001:67c:4e8:f002::a":  "DC2 🇳🇱 Netherlands  [IPv6]",
    "2001:67c:4e8:f002::e":  "DC2 🇳🇱 Netherlands  [IPv6 alt]",
    "2001:b28:f23d:f003::a": "DC3 🇺🇸 US-Miami     [IPv6]",
    "2001:b28:f23d:f003::e": "DC3 🇺🇸 US-Miami     [IPv6 alt]",
    "2001:67c:4e8:f004::a":  "DC4 🇳🇱 Netherlands  [IPv6]",
    "2001:67c:4e8:f004::e":  "DC4 🇳🇱 Netherlands  [IPv6 alt]",
    "2001:b28:f23f:f005::a": "DC5 🇸🇬 Singapore   [IPv6]",
    "2001:b28:f23f:f005::e": "DC5 🇸🇬 Singapore   [IPv6 alt]",
}

# ─── Well-known port → protocol name ─────────────────────────────────────────
PORT_PROTOCOLS: dict[int, str] = {
    80:    "HTTP",
    443:   "HTTPS/TLS",       # MTProto rides over this
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    53:    "DNS",
    853:   "DNS-over-TLS",
    3478:  "STUN",            # standard NAT traversal
    3479:  "STUN-Alt",
    1400:  "STUN-Telegram",   # Telegram-specific STUN port
    5349:  "TURNS",
    19302: "STUN-Google",
    5222:  "MTProto-Proxy",
    1080:  "SOCKS5",
    22:    "SSH",
    21:    "FTP",
    596:   "TG-Voice",        # Telegram encrypted voice media
    597:   "TG-Voice",
    598:   "TG-Voice",
    599:   "TG-Voice",
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
        return "Ephemeral"
    if port >= 1024:
        return f"Registered:{port}"
    return f"Well-known:{port}"


def _strip_zone(ip: str) -> str:
    """Strip IPv6 zone ID suffix (e.g. fe80::1%eth0 → fe80::1)."""
    return ip.split("%")[0] if ip else ip


# ─── Packet Capture (cross‑platform) ─────────────────────────────────────────

class PacketCapture:
    """Manages packet capture subprocess (tcpdump on Linux, tshark on Windows)."""
    def __init__(self, output_file="capture.pcap"):
        self.output_file = output_file
        self.process     = None

    def _find_interface(self):
        """Pick first non‑loopback interface."""
        for iface, stats in psutil.net_if_stats().items():
            if stats.isup and not iface.startswith(("lo", "Loopback")):
                return iface
        return "eth0"

    def start(self):
        """Start capture process. Returns True if successful."""
        if platform.system() == "Windows":
            cmd = [
                "tshark", "-i", self._find_interface(),
                "-f", "udp",
                "-w", self.output_file,
                "-F", "pcapng"
            ]
            kwargs = {"creationflags": subprocess.CREATE_NO_WINDOW} if sys.platform == "win32" else {}
        else:
            # Capture all UDP including IPv6; no port filter so we get all voice traffic
            cmd = [
                "sudo", "tcpdump", "-i", self._find_interface(),
                "-U", "-w", self.output_file,
                "-s", "0",
                "udp or (ip6 and udp)"
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
        except FileNotFoundError:
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
    IPv4 + IPv6 aware.
    """

    def __init__(self, duration: int = 60, capture_packets: bool = True):
        self.duration        = duration
        self.capture_packets = capture_packets
        self.start_time: float | None = None
        self.is_running: bool         = False

        self.connection_states: Counter = Counter()
        self.protocol_counter:  Counter = Counter()
        self.port_protocols:    Counter = Counter()
        self.dc_connections:    dict    = {}

        self.snapshots:    list[dict] = []
        self._bw_samples:  list[dict] = []
        self.initial_net_io = None
        self.final_net_io   = None
        self._prev_conn_set: set = set()
        self.events: list[dict] = []

        self.packet_capture = None
        if capture_packets:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            pcap_file = f"capture_{timestamp}.pcap"
            self.packet_capture = PacketCapture(output_file=pcap_file)

    # ── Internal helpers ───────────────────────────────────────────────────────────

    def _read_connections(self) -> list[dict]:
        result = []
        try:
            # kind='all' captures IPv4 TCP/UDP AND IPv6 TCP/UDP
            conns = psutil.net_connections(kind="all")
        except Exception:
            return result

        for c in conns:
            try:
                proto      = "TCP" if c.type == 1 else "UDP"
                remote_ip  = _strip_zone(c.raddr.ip)   if c.raddr else ""
                remote_pt  = c.raddr.port               if c.raddr else 0
                local_ip   = _strip_zone(c.laddr.ip)   if c.laddr else ""
                local_pt   = c.laddr.port               if c.laddr else 0
                status     = (getattr(c, "status", "") or "").strip() or "NONE"

                if not remote_ip:
                    continue

                port_proto = identify_port(remote_pt)
                is_tg      = remote_ip in TELEGRAM_DCS
                ip_ver     = "IPv6" if ":" in remote_ip else "IPv4"

                conn = {
                    "protocol":      proto,
                    "ip_version":    ip_ver,
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

                self.protocol_counter[proto]    += 1
                self.connection_states[status]  += 1
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

        current_set         = {c["remote"] for c in conns}
        new_conns           = list(current_set - self._prev_conn_set)
        dropped             = list(self._prev_conn_set - current_set)
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

    # ── Public API ────────────────────────────────────────────────────────────────

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
                self.packet_capture = None

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
            W(f"  {'Time(s)':>8}  {'\u2191 Kbps':>10}  {'\u2193 Kbps':>10}  {'\u2191 PPS':>7}  {'\u2193 PPS':>7}\n")
            W("  " + "-" * 50 + "\n")
            for s in r["bw_series"]:
                W(f"  {s['time_offset']:>8.1f}  {s['kbps_up']:>10.2f}  {s['kbps_dn']:>10.2f}"
                  f"  {s['pps_up']:>7.1f}  {s['pps_dn']:>7.1f}\n")

            section("TELEGRAM DATA CENTERS DETECTED")
            if r["dc_connections"]:
                for ip, dc in r["dc_connections"].items():
                    proto = "IPv6" if ":" in ip else "IPv4"
                    W(f"  • [{proto}] {ip:40} → {dc}\n")
                W("\n  [CCNA] Voice call is routed to the above DC.\n")
                W("  Traffic uses MTProto inside TLS (port 443)\n")
                W("  and UDP 596/597/598/599 for real-time voice frames.\n")
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
            W("         Voice frames use UDP 596-599; signalling uses TCP/TLS.\n")

            section("APPLICATION LAYER PROTOCOLS (by port number)")
            top = sorted(r["port_protocols"].items(), key=lambda x: -x[1])[:15]
            for proto, cnt in top:
                W(f"  • {proto:25} {cnt:5} occurrences\n")
            W("\n  [CCNA] Port 443  = HTTPS/TLS (MTProto encrypted inside)\n")
            W("         STUN 3478/1400 = NAT traversal for UDP voice\n")
            W("         TG-Voice 596-599 = encrypted Telegram voice media\n")
            W("         DNS  53  = hostname lookups\n")

            section("TCP CONNECTION STATES")
            for state, cnt in sorted(r["connection_states"].items(), key=lambda x: -x[1]):
                desc = STATE_DESCRIPTIONS.get(state, "")
                W(f"  • {state:15}  {cnt:5}   {desc}\n")

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

            section("CCNA STUDY NOTES")
            notes = [
                ("TCP",            "Layer 4 — connection-oriented, reliable delivery via sequence numbers"),
                ("UDP",            "Layer 4 — connectionless, no retransmit (ideal for real-time voice)"),
                ("MTProto",        "Layer 7 — Telegram's own encrypted protocol, tunnelled over TLS"),
                ("TLS 1.3",        "Layer 4-7 — encrypts MTProto; connection visible, content not"),
                ("STUN",           "Layer 5-7 — NAT traversal on port 3478 or 1400"),
                ("TG Voice",       "UDP ports 596/597/598/599 — encrypted Telegram voice media"),
                ("3-way HS",       "SYN → SYN-ACK → ACK: TCP connection setup"),
                ("FIN handshake",  "FIN → FIN-ACK → FIN → ACK: graceful TCP close"),
                ("TIME_WAIT",      "TCP state after close: OS holds port 2×MSL to catch delayed packets"),
                ("Ephemeral",      "Ports >49152: OS-assigned source ports for outbound connections"),
                ("Bandwidth",      "Total bits/sec = (bytes_sent + bytes_recv) × 8 / elapsed_seconds"),
                ("PPS",            "Packets/sec: spikes when mic is ON, drops when muted"),
                ("DC IPs",         "Telegram routes via 5 DCs; closest DC handles your voice call"),
            ]
            for term, note in notes:
                W(f"  {term:15} — {note}\n")

            W("\n" + "═" * 70 + "\n")
            W("  END OF REPORT\n")
            W("═" * 70 + "\n")

    def export_analysis_json(self, filename: str):
        """
        Export the full capture report as a JSON file.
        Suitable for programmatic consumption / further analysis.
        """
        r = self.get_report()
        # Ensure the dict is JSON-serialisable (convert sets to lists etc.)
        safe = {
            "generated":           datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "duration":            r["duration"],
            "start_time":          r["start_time"],
            "bytes_sent":          r["bytes_sent"],
            "bytes_recv":          r["bytes_recv"],
            "total_bytes":         r["total_bytes"],
            "packets_sent":        r["packets_sent"],
            "packets_recv":        r["packets_recv"],
            "total_packets":       r["total_packets"],
            "errors_in":           r["errors_in"],
            "errors_out":          r["errors_out"],
            "drops_in":            r["drops_in"],
            "bandwidth_kbps":      r["bandwidth_kbps"],
            "peak_kbps_up":        r["peak_kbps_up"],
            "peak_kbps_dn":        r["peak_kbps_dn"],
            "avg_pps":             r["avg_pps"],
            "protocols":           r["protocols"],
            "port_protocols":      r["port_protocols"],
            "connection_states":   r["connection_states"],
            "dc_connections":      r["dc_connections"],
            "unique_connections":  r["unique_connections"],
            "new_connections":     list(r["new_connections"]),
            "dropped_connections": list(r["dropped_connections"]),
            "total_snapshots":     r["total_snapshots"],
            "bw_series":           r["bw_series"],
            "events":              r["events"],
        }
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(safe, f, indent=2, ensure_ascii=False)
