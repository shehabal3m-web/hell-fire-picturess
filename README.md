import discord
import aiohttp
import io
import os
import struct
from discord.ext import commands

# ─── Configuration ────────────────────────────────────────────
TOKEN = os.getenv("DISCORD_TOKEN")

intents = discord.Intents.default()
intents.message_content = True
intents.messages = True
intents.guilds = True

bot = commands.Bot(command_prefix="!", intents=intents)

# ─── Security Check (Malware / Exploit Detection) ─────────────
def check_image_security(data: bytes, filename: str) -> list[str]:
    threats = []

    # 1) Fake extension check — e.g. file named .jpg but contains EXE
    magic_signatures = {
        b"\x4d\x5a": "EXE/DLL",
        b"\x7fELF": "ELF Binary",
        b"\x50\x4b\x03\x04": "ZIP/Archive",
        b"\x52\x61\x72\x21": "RAR Archive",
        b"\x25\x50\x44\x46": "PDF",
        b"\xd0\xcf\x11\xe0": "MS Office Document",
        b"\x1f\x8b": "GZIP Archive",
    }
    for sig, label in magic_signatures.items():
        if data.startswith(sig):
            threats.append(f"⚠️ Suspicious file signature detected: `{label}` inside an image!")

    # 2) Hidden code inside the image (PHP, JS, HTML injections)
    suspicious_strings = [
        b"<?php", b"<script", b"javascript:",
        b"eval(", b"base64_decode(", b"exec(", b"system("
    ]
    for s in suspicious_strings:
        if s in data:
            threats.append(f"⚠️ Hidden malicious code found: `{s.decode(errors='replace')}`")

    # 3) PNG chunk analysis (Zip Bomb / chunk exploit)
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        try:
            offset = 8
            known_chunks = {
                "IHDR", "IDAT", "IEND", "tEXt", "zTXt", "iTXt",
                "cHRM", "gAMA", "sRGB", "bKGD", "pHYs", "sPLT",
                "tIME", "hIST", "sBIT"
            }
            while offset < len(data) - 12:
                length = struct.unpack(">I", data[offset:offset + 4])[0]
                chunk_type = data[offset + 4:offset + 8].decode(errors="replace")
                if chunk_type not in known_chunks:
                    threats.append(f"⚠️ Unknown PNG chunk: `{chunk_type}` — possible exploit")
                if length > 50_000_000:
                    threats.append("⚠️ PNG chunk is too large — possible Zip Bomb")
                offset += 12 + length
        except Exception:
            threats.append("⚠️ Could not fully parse PNG file structure")

    # 4) File size check
    if len(data) > 20 * 1024 * 1024:
        threats.append("⚠️ File size exceeds 20MB — possible Zip Bomb")

    return threats


# ─── Bot Events ───────────────────────────────────────────────
@bot.event
async def on_ready():
    print(f"✅ Bot is online: {bot.user}")


@bot.event
async def on_message(message: discord.Message):
    # Ignore bot messages
    if message.author.bot:
        return

    if not message.attachments:
        await bot.process_commands(message)
        return

    image_extensions = (".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".tiff", ".svg")
    image_attachments = [
        a for a in message.attachments
        if any(a.filename.lower().endswith(ext) for ext in image_extensions)
    ]

    if not image_attachments:
        await bot.process_commands(message)
        return

    channel = message.channel
    sender = message.author

    async with aiohttp.ClientSession() as session:
        for attachment in image_attachments:

            # Download the image
            async with session.get(attachment.url) as resp:
                if resp.status != 200:
                    continue
                data = await resp.read()

            filename = attachment.filename

            # Run security checks
            security_issues = check_image_security(data, filename)

            # Delete the original message
            try:
                await message.delete()
            except discord.Forbidden:
                await channel.send("❌ I don't have permission to delete messages!")
                return
            except discord.NotFound:
                pass

            # If threats found: block the image, send warning
            if security_issues:
                issues_text = "\n".join(security_issues)
                await channel.send(
                    f"🚨 {sender.mention} | **Image blocked due to security threats!**\n"
                    f"```\n{issues_text}\n```"
                )
                print(f"[SECURITY] Blocked suspicious image from {sender} in #{channel.name}")
                continue

            # Re-send the image with a mention
            file = discord.File(io.BytesIO(data), filename=filename)
            await channel.send(
                content=f"📸 Image sent by {sender.mention}",
                file=file
            )

    await bot.process_commands(message)


# ─── Run the Bot ──────────────────────────────────────────────
bot.run(TOKEN)
