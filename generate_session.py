"""
generate_session.py
────────────────────────────────────────────────────────────────────
Run this ONCE to generate a Pyrogram String Session.
Paste the output STRING_SESSION= line into your .env file.

Usage:
    python generate_session.py
"""

import asyncio
import os

from dotenv import load_dotenv
from pyrogram import Client  # comes from pyrofork

load_dotenv()

API_ID   = int(os.getenv("API_ID", "0"))
API_HASH = os.getenv("API_HASH", "")

if not API_ID or not API_HASH:
    print("❌ Set API_ID and API_HASH in your .env file first!")
    print("   Get them from: https://my.telegram.org/apps")
    exit(1)


async def generate():
    print("=" * 60)
    print("  TG Network Capturer — Session Generator")
    print("=" * 60)
    print()
    print("Enter your phone number and the login code Telegram sends you.")
    print("This is handled securely by Telegram — no credentials are stored.")
    print()

    async with Client(
        name="temp_session",
        api_id=API_ID,
        api_hash=API_HASH,
    ) as app:
        session_string = await app.export_session_string()

    print()
    print("=" * 60)
    print("✅ SUCCESS — Copy the line below into your .env file:")
    print("=" * 60)
    print()
    print(f"STRING_SESSION={session_string}")
    print()
    print("=" * 60)
    print("⚠️  Keep this string SECRET — it gives full account access!")
    print("=" * 60)

    for f in ["temp_session.session", "temp_session.session-journal"]:
        if os.path.exists(f):
            os.remove(f)


if __name__ == "__main__":
    asyncio.run(generate())
