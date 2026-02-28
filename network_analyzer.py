"""
network_analyzer.py
────────────────────────────────────────────────────────────────────
Network monitoring using psutil and packet capture (tcpdump/tshark).
Full IPv4 + IPv6 support:
  • TELEGRAM_DCS includes IPv6 DC addresses
  • psutil captures both IPv4 and IPv6 connections (kind='all')
  • STUN extraction handles both stun.att.ipv4.xord and stun.att.ipv6.xord
  • pcap STUN tshark command uses pipe separator and ipv6 fields
"""

import time
import psutil
import subprocess
import os
import sys
import platform
import json
from collections import Counter
from datetime import datetime


# ─── Telegram Data Center IP map (IPv4 + IPv6) ───────────────────────────────
TELEGRAM_DCS: dict[str, str] = {
    # ── IPv4 ──────────────────────────────────────────────────────────────────
    "149.154.175.50":   "DC1 🇺🇸 US-Virginia",
    "149.154.175.53":   "DC1 🇺🇸 US-Virginia",
    "149.154.167.40":   "DC2 🇳🇱 Netherlands",
    "149.154.167.41":   "DC2 🇳🇱 Netherlands",
    "149.154.167.51":   "DC2 🇳🇱 Netherlands",
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
    443:   "HTTPS/TLS",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    53:    "DNS",
    853:   "DNS-over-TLS",
    3478:  "STUN",
    3479:  "STUN-Alt",
    5349:  "TURNS",
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
    if port in PORT_PROTOCOLS:
        return PORT_PROTOCOLS[port]
    if port >= 49152:
        return "Ephemeral"
    if port >= 1024:
        return f"Registered:{port}"
    return f"Well-known:{port}"


def _strip_zone(ip: str) -> str:
    """Remove IPv6 zone ID suffix (e.g. fe80::1%eth0 → fe80::1)."""
    return ip.split("%")[0] if ip else ip


# ─── Packet Capture (cross‑platform) ─────────────────────────────────────────

class PacketCapture:
    """Manages packet capture subprocess (tcpdump on Linux, tshark on Windows)."""
    def __init__(self, output_file="capture.pcap"):
        self.output_file = output_file
        self.process     = None

    def _find_interface(self):
        for iface, stats in psutil.net_if_stats().items():
            if stats.isup and not iface.startswith(("lo", "Loopback")):
                return iface
        for iface in ["eth0", "ens3", "ens5", "enp0s3"]:
            if iface in psutil.net_if_stats():
                return iface
        return "eth0"

    def start(self):
        if platform.system() == "Windows":
            cmd    = ["tshark", "-i", self._find_interface(),
                      "-f", "udp", "-w", self.output_file, "-F", "pcapng"]
            kwargs = {"creationflags": subprocess.CREATE_NO_WINDOW} if sys.platform == "win32" else {}
        else:
            # Capture both IPv4 and IPv6 UDP traffic
            cmd    = ["sudo", "tcpdump", "-i", self._find_interface(),
                      "-U", "-w", self.output_file, "-s", "0",
                      "udp or (ip6 and udp)"]
            kwargs = {}
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                **kwargs,
            )
            return True
        except FileNotFoundError:
            tool = "tshark" if platform.system() == "Windows" else "tcpdump"
            print(f"⚠️  {tool} not found. Install it and ensure it's in PATH.")
            return False
        except PermissionError:
            print("⚠️  Permission denied. Run with sudo (Linux) or as administrator (Windows).")
            return False

    def stop(self):
        if self.process:
            self.process.terminate()
            self.process.wait()
            self.process = None


# ─── Main NetworkCapture class ───────────────────────────────────────────────

class NetworkCapture:
    """
    Captures and analyses network activity using psutil + optional packet capture.
    Supports both IPv4 and IPv6.
    """

    def __init__(self, duration: int = 60, capture_packets: bool = True):
        self.duration       = duration
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
            timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
            pcap_file  = f"capture_{timestamp}.pcap"
            self.packet_capture = PacketCapture(output_file=pcap_file)

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _read_connections(self) -> list[dict]:
        result = []
        try:
            # kind='all' → IPv4 TCP, IPv4 UDP, IPv6 TCP, IPv6 UDP
            conns = psutil.net_connections(kind="all")
        except Exception:
            return result

        for c in conns:
            try:
                proto     = "TCP" if c.type == 1 else "UDP"
                remote_ip = _strip_zone(c.raddr.ip)   if c.raddr else ""
                remote_pt = c.raddr.port               if c.raddr else 0
                local_ip  = _strip_zone(c.laddr.ip)   if c.laddr else ""
                local_pt  = c.laddr.port               if c.laddr else 0
                status    = (getattr(c, "status", "") or "").strip() or "NONE"

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

                self.protocol_counter[proto]       += 1
                self.connection_states[status]     += 1
                self.port_protocols[port_proto]    += 1

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

    # ── Public API ────────────────────────────────────────────────────────────

    def log_event(self, event_name: str, details: str = ""):
        self.events.append({"timestamp": time.time(), "event": event_name, "details": details})
        self._take_snapshot(event_type=event_name)

    def start_capture(self):
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

    def _analyze_pcap(self) -> dict:
        """Run tshark on the captured pcap — extracts STUN (IPv4+IPv6) and RTP."""
        if not self.packet_capture or not os.path.exists(self.packet_capture.output_file):
            return {}

        pcap   = self.packet_capture.output_file
        result = {}

        # ── 1. UDP conversations ──────────────────────────────────────────────
        try:
            out = subprocess.check_output(
                ["tshark", "-r", pcap, "-q", "-z", "conv,udp"],
                stderr=subprocess.DEVNULL, text=True
            )
            result["udp_conversations"] = out
        except Exception:
            result["udp_conversations"] = "Could not extract UDP conversations."

        # ── 2. STUN packets — both IPv4 and IPv6 fields ───────────────────────
        # Use pipe separator so IPv6 colons don't break parsing
        cmd = [
            "tshark", "-r", pcap,
            "-Y", "stun",
            "-T", "fields",
            "-E", "separator=|",
            "-e", "ip.src",                # IPv4 source      (empty for IPv6 pkt)
            "-e", "ip.dst",                # IPv4 destination (empty for IPv6 pkt)
            "-e", "ipv6.src",              # IPv6 source      (empty for IPv4 pkt)
            "-e", "ipv6.dst",              # IPv6 destination (empty for IPv4 pkt)
            "-e", "udp.srcport",
            "-e", "udp.dstport",
            "-e", "stun.att.ipv4.xord",   # XOR-MAPPED-ADDRESS (IPv4)
            "-e", "stun.att.ipv6.xord",   # XOR-MAPPED-ADDRESS (IPv6)
        ]
        try:
            out   = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
            lines = out.strip().split("\n")
            stun_entries = []
            for line in lines:
                if not line.strip():
                    continue
                p = line.split("|")
                if len(p) < 8:
                    continue
                # Prefer IPv6 addresses when present
                src_ip   = p[2].strip() if p[2].strip() else p[0].strip()
                dst_ip   = p[3].strip() if p[3].strip() else p[1].strip()
                xored_ip = p[7].strip() if p[7].strip() else (p[6].strip() or "N/A")
                ip_ver   = "IPv6" if ":" in src_ip else "IPv4"
                stun_entries.append({
                    "ip_version": ip_ver,
                    "src_ip":     src_ip,
                    "dst_ip":     dst_ip,
                    "src_port":   p[4].strip(),
                    "dst_port":   p[5].strip(),
                    "xored_ip":   xored_ip,
                })
            result["stun_packets"] = stun_entries
        except Exception:
            result["stun_packets"] = []

        # ── 3. RTP streams ───────────────────────────────────────────────────
        try:
            out = subprocess.check_output(
                ["tshark", "-r", pcap, "-q", "-z", "rtp,streams"],
                stderr=subprocess.DEVNULL, text=True
            )
            result["rtp_streams"] = out
        except Exception:
            result["rtp_streams"] = "No RTP streams detected or could not parse."

        return result

    def get_report(self) -> dict:
        if not self.start_time:
            return {"error": "Capture never started"}

        elapsed = time.time() - self.start_time

        if self.initial_net_io and self.final_net_io:
            b_sent = self.final_net_io.bytes_sent   - self.initial_net_io.bytes_sent
            b_recv = self.final_net_io.bytes_recv   - self.initial_net_io.bytes_recv
            p_sent = self.final_net_io.packets_sent - self.initial_net_io.packets_sent
            p_recv = self.final_net_io.packets_recv - self.initial_net_io.packets_recv
            errin  = self.final_net_io.errin  - self.initial_net_io.errin
            errout = self.final_net_io.errout - self.initial_net_io.errout
            dropin = self.final_net_io.dropin - self.initial_net_io.dropin
            avg_bw = (b_sent + b_recv) * 8 / elapsed / 1000 if elapsed else 0
        else:
            b_sent = b_recv = p_sent = p_recv = errin = errout = dropin = avg_bw = 0

        series  = self._bandwidth_series()
        peak_up = max((s["kbps_up"] for s in series), default=0)
        peak_dn = max((s["kbps_dn"] for s in series), default=0)
        avg_pps = (sum(s["pps_up"] + s["pps_dn"] for s in series) / len(series)
                   if series else 0)

        all_new, all_dropped = [], []
        unique = set()
        for snap in self.snapshots:
            for c in snap["connections"]:
                unique.add(c["remote"])
            all_new.extend(snap.get("new_connections", []))
            all_dropped.extend(snap.get("dropped_connections", []))

        pcap_analysis = self._analyze_pcap()

        return {
            "duration":            elapsed,
            "start_time":          self.start_time,
            "bytes_sent":          b_sent,
            "bytes_recv":          b_recv,
            "total_bytes":         b_sent + b_recv,
            "packets_sent":        p_sent,
            "packets_recv":        p_recv,
            "total_packets":       p_sent + p_recv,
            "errors_in":           errin,
            "errors_out":          errout,
            "drops_in":            dropin,
            "bandwidth_kbps":      avg_bw,
            "peak_kbps_up":        peak_up,
            "peak_kbps_dn":        peak_dn,
            "avg_pps":             avg_pps,
            "protocols":           dict(self.protocol_counter),
            "port_protocols":      dict(self.port_protocols),
            "connection_states":   dict(self.connection_states),
            "dc_connections":      self.dc_connections,
            "unique_connections":  len(unique),
            "new_connections":     list(set(all_new)),
            "dropped_connections": list(set(all_dropped)),
            "total_snapshots":     len(self.snapshots),
            "bw_series":           series,
            "events":              self.events,
            "pcap_analysis":       pcap_analysis,
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
            W("  TG_NETWORK_capturer — FULL CAPTURE REPORT (IPv4 + IPv6)\n")
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

            section("TELEGRAM DATA CENTERS DETECTED (IPv4 + IPv6)")
            if r["dc_connections"]:
                for ip, dc in r["dc_connections"].items():
                    proto = "IPv6" if ":" in ip else "IPv4"
                    W(f"  • [{proto}] {ip:40} → {dc}\n")
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

            section("APPLICATION LAYER PROTOCOLS (by port number)")
            top = sorted(r["port_protocols"].items(), key=lambda x: -x[1])[:15]
            for proto, cnt in top:
                W(f"  • {proto:25} {cnt:5} occurrences\n")

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

            section("SNAPSHOT DETAILS")
            for i, snap in enumerate(self.snapshots, 1):
                ts_s   = datetime.fromtimestamp(snap["timestamp"]).strftime("%H:%M:%S.%f")[:-3]
                offset = snap["timestamp"] - self.start_time
                W(f"\n  ─ Snapshot #{i:02d}  [{ts_s}]  +{offset:.1f}s  [{snap['event_type']}]\n")
                W(f"    Active: {len(snap['connections'])}  "
                  f"New: {len(snap.get('new_connections',[]))}  "
                  f"Dropped: {len(snap.get('dropped_connections',[]))}\n")
                for c in snap["connections"][:12]:
                    tg  = " ◄ TG" if c["is_telegram"] else ""
                    ver = c.get("ip_version", "")
                    W(f"    [{c['protocol']:3}/{ver:4}] {c['local']:30} ↔ {c['remote']:40}"
                      f"  {c['port_protocol']:15}  {c['status']}{tg}\n")
                if len(snap["connections"]) > 12:
                    W(f"    ... +{len(snap['connections'])-12} more connections\n")

            section("UDP + STUN PACKET ANALYSIS (IPv4 + IPv6)")
            pcap = r.get("pcap_analysis", {})
            W("  STUN Packets (NAT traversal):\n")
            for stun in pcap.get("stun_packets", []):
                W(f"    [{stun.get('ip_version','?'):4}] "
                  f"{stun['src_ip']}:{stun['src_port']} → "
                  f"{stun['dst_ip']}:{stun['dst_port']}  "
                  f"XOR‑IP: {stun['xored_ip']}\n")
            if not pcap.get("stun_packets"):
                W("    No STUN packets found.\n")
            W("\n  UDP Conversations:\n")
            W(pcap.get("udp_conversations", "N/A"))
            W("\n  RTP Streams:\n")
            W(pcap.get("rtp_streams", "N/A"))

            section("CCNA STUDY NOTES")
            notes = [
                ("TCP",           "Layer 4 — connection-oriented, reliable delivery via sequence numbers"),
                ("UDP",           "Layer 4 — connectionless, no retransmit (ideal for real-time voice)"),
                ("MTProto",       "Layer 7 — Telegram's own encrypted protocol, tunnelled over TLS"),
                ("TLS 1.3",       "Layer 4-7 — encrypts MTProto; you see the connection but not content"),
                ("STUN",          "Layer 5-7 — NAT traversal: discovers external IP:port for UDP voice"),
                ("IPv6 STUN",     "stun.att.ipv6.xord — XOR-MAPPED-ADDRESS for IPv6 participants"),
                ("AF_INET6",      "Python socket family for IPv6; dest tuple = (ip, port, flowinfo, scope)"),
                ("3-way HS",      "SYN → SYN-ACK → ACK: TCP connection setup"),
                ("FIN handshake", "FIN → FIN-ACK → FIN → ACK: graceful TCP close"),
                ("TIME_WAIT",     "TCP state after close: OS holds port 2×MSL to catch delayed packets"),
                ("Ephemeral",     "Ports >49152: OS-assigned source ports for each new outbound connection"),
                ("Bandwidth",     "Total bits/sec = (bytes_sent + bytes_recv) × 8 / elapsed_seconds"),
                ("PPS",           "Packets/sec: spikes when mic is ON (50 pkts/s), drops when muted"),
                ("DC IPs",        "Telegram routes via 5 DCs; now tracked for both IPv4 and IPv6"),
            ]
            for term, note in notes:
                W(f"  {term:15} — {note}\n")

            W("\n" + "═" * 70 + "\n")
            W("  END OF REPORT\n")
            W("═" * 70 + "\n")

    def export_analysis_json(self, filename: str):
        r            = self.get_report()
        pcap_analysis = r.get("pcap_analysis", {})
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(pcap_analysis, f, indent=2)
