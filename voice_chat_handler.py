"""
voice_chat_handler.py
────────────────────────────────────────────────────────────────────
Compatible with py-tgcalls 2.x (latest).

API changes from 1.x → 2.x:
  mute_call(chat_id)   → pause(chat_id)
  unmute_call(chat_id) → resume(chat_id)

All other methods (play, leave_call, start) are unchanged.
"""

import asyncio
import os
import wave
import struct
import tempfile

from pytgcalls import PyTgCalls
from pytgcalls.types import MediaStream, AudioQuality

_SILENT_WAV = os.path.join(tempfile.gettempdir(), "tg_silent_stream.wav")


def _create_silent_wav(path: str, duration_seconds: int = 3600):
    """Generate a 1-hour silent (all-zeros) WAV file — created once on first run."""
    sample_rate  = 48000
    num_channels = 1
    sample_width = 2
    silent_frame = struct.pack("<h", 0)

    with wave.open(path, "wb") as wf:
        wf.setnchannels(num_channels)
        wf.setsampwidth(sample_width)
        wf.setframerate(sample_rate)
        chunk_size = sample_rate
        for _ in range(duration_seconds):
            wf.writeframes(silent_frame * chunk_size)
    return path


class VoiceChatHandler:
    def __init__(self, pyrogram_client):
        self.tgcalls  = PyTgCalls(pyrogram_client)
        self._started = False

        if not os.path.exists(_SILENT_WAV):
            print("⏳ Generating silent audio stream file (one-time setup)…")
            _create_silent_wav(_SILENT_WAV, duration_seconds=3600)
            print(f"✅ Silent WAV created: {_SILENT_WAV}")

    async def start(self):
        """Start the PyTgCalls engine (call once at bot startup)."""
        if not self._started:
            await self.tgcalls.start()
            self._started = True

    async def join_voice_chat(self, chat_id: int) -> bool:
        """
        Join the group voice chat in silent listener mode.
        Works with py-tgcalls 2.x.
        """
        await self.start()
        try:
            await self.tgcalls.play(
                chat_id,
                MediaStream(
                    _SILENT_WAV,
                    audio_parameters=AudioQuality.STUDIO,
                )
            )
        except Exception as exc:
            err = str(exc).lower()
            if "already" in err or "playing" in err:
                pass  # already in call — fine
            elif "no active" in err or "not found" in err or "groupcall" in err:
                raise RuntimeError(
                    "No active voice chat in this group/channel.\n"
                    "Make sure a voice chat is currently live."
                ) from exc
            else:
                raise RuntimeError(f"Join failed: {exc}") from exc

        # Pause immediately after joining — we start as silent listeners
        await asyncio.sleep(0.8)
        try:
            await self._pause(chat_id)
        except Exception:
            pass
        return True

    async def leave_voice_chat(self, chat_id: int):
        """Gracefully leave the voice chat."""
        try:
            await self.tgcalls.leave_call(chat_id)
        except Exception:
            pass

    async def toggle_mic(self, chat_id: int, muted: bool = True):
        """
        Toggle microphone mute state.
        muted=True  → pause stream  (fewer UDP packets — PPS drops)
        muted=False → resume stream (more UDP packets  — PPS spikes)
        """
        try:
            if muted:
                await self._pause(chat_id)
            else:
                await self._resume(chat_id)
        except Exception:
            pass

    # ── Internal helpers (handles 2.x and 1.x API differences) ─────────────────

    async def _pause(self, chat_id: int):
        """
        Pause audio stream (py-tgcalls 2.x) with fallback to
        mute_call (py-tgcalls 1.x) for backwards compatibility.
        """
        try:
            await self.tgcalls.pause(chat_id)          # 2.x API
        except AttributeError:
            await self.tgcalls.mute_call(chat_id)      # 1.x API fallback

    async def _resume(self, chat_id: int):
        """
        Resume audio stream (py-tgcalls 2.x) with fallback to
        unmute_call (py-tgcalls 1.x) for backwards compatibility.
        """
        try:
            await self.tgcalls.resume(chat_id)         # 2.x API
        except AttributeError:
            await self.tgcalls.unmute_call(chat_id)    # 1.x API fallback
