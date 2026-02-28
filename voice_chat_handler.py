"""
voice_chat_handler.py
────────────────────────────────────────────────────────────────────
Original working version – no extraction attempts.
Handles joining / leaving Telegram Group Calls using py-tgcalls 2.x.
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
    """Generate a silent (all-zeros) WAV file."""
    sample_rate   = 48000
    num_channels  = 1
    sample_width  = 2
    silent_frame  = struct.pack("<h", 0)

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
        self.tgcalls = PyTgCalls(pyrogram_client)
        self._started = False

        # Generate silent WAV if it doesn't exist
        if not os.path.exists(_SILENT_WAV):
            print("⏳ Generating silent audio stream file (one-time setup)…")
            _create_silent_wav(_SILENT_WAV, duration_seconds=3600)
            print(f"✅ Silent WAV created: {_SILENT_WAV}")

    async def start(self):
        """Start the PyTgCalls engine once at bot startup."""
        if not self._started:
            await self.tgcalls.start()
            self._started = True

    async def join_voice_chat(self, chat_id: int) -> bool:
        """
        Join the group voice chat in silent listener mode.
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
                # Already in call – fine
                pass
            elif "no active" in err or "not found" in err or "groupcall" in err:
                raise RuntimeError(
                    "No active voice chat in this group/channel.\n"
                    "Make sure a voice chat is currently live."
                ) from exc
            else:
                raise RuntimeError(f"Join failed: {exc}") from exc

        # Mute immediately – we're silent listeners
        await asyncio.sleep(0.8)
        try:
            await self.tgcalls.mute_call(chat_id)
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
        """Toggle microphone mute state."""
        try:
            if muted:
                await self.tgcalls.mute_call(chat_id)
            else:
                await self.tgcalls.unmute_call(chat_id)
        except Exception:
            pass
