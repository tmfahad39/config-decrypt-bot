#!/usr/bin/env python3
"""Telegram config-decrypt bot.

Users send .hc / .dark / .ssc files; the bot replies with the decoded JSON.
If a file is password protected, the bot asks for the password in a reply.

Only decode configs you own or are authorized to handle.
"""

import asyncio
import html
import json
import logging
import os
import re
from pathlib import Path
import sys
import tempfile

from telegram import (
    CopyTextButton,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Update,
)
from telegram.constants import ChatAction, ParseMode
from telegram.ext import (
    Application,
    ApplicationBuilder,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    level=getattr(logging, LOG_LEVEL, logging.INFO),
)
# httpx logs full request URLs, which contain the bot token.
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger("config-decrypt-bot")

DECODER = Path(__file__).with_name("vpn_decoder.py")
SUPPORTED = {".hc", ".dark", ".ssc"}
MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MB
DECODE_TIMEOUT = 30  # seconds

# prompt message id -> {chat_id, name, data}
PENDING_PASSWORD = {}


def is_password_error(text: str) -> bool:
    lowered = text.lower()
    if "password-protected" in lowered:
        return True
    if "wrong password" in lowered:
        return True
    if "hwid" in lowered and "password" in lowered:
        return True
    return "provide" in lowered and "password" in lowered


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.effective_message.reply_text(
        "Send me a VPN config file (.hc, .dark or .ssc) and I'll send back "
        "the decrypted JSON.\n\nIf a file is password protected I'll ask you "
        "for the password in a reply.\n\nUse /help for details."
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.effective_message.reply_text(
        "Config Decrypt Bot\n\n"
        "Supported files: .hc, .dark, .ssc\n"
        "Send a file as a document and I will reply with the decoded JSON.\n"
        "Password protected files: reply to my password prompt with the "
        "password.\n\n"
        "Commands:\n"
        "/start - introduction\n"
        "/help  - this message\n\n"
        "Only decode configs you own or are authorized to handle.",
    )


async def run_decoder(data: bytes, name: str, password: str | None = None):
    """Run the decoder on data. Returns (ok, text)."""
    with tempfile.TemporaryDirectory(prefix="cfgdec_") as tmp:
        workdir = Path(tmp)
        target = workdir / name
        target.write_bytes(data)
        command = [sys.executable, str(DECODER), str(target), "--stdout"]
        if password is not None:
            command += ["--password-value", password]
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(workdir),
            )
        except Exception as exc:
            return False, f"{type(exc).__name__}: {exc}"
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=DECODE_TIMEOUT
            )
        except asyncio.TimeoutError:
            process.kill()
            asyncio.ensure_future(process.communicate())
            return False, "Decoding timed out."
    if process.returncode != 0:
        error = stderr.decode("utf-8", "replace").strip() or "unknown error"
        return False, error
    return True, stdout.decode("utf-8", "replace").strip()


BOX_TOP = "\u2554" + "\u2550" * 24 + "\u2557"
BOX_BOTTOM = "\u255a" + "\u2550" * 24 + "\u255d"
SEPARATOR = "\u2500" * 24


def _clean(value, limit=300):
    text = html.unescape(str(value))
    if "<" in text and ">" in text:
        text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit] + "\u2026" if len(text) > limit else text


def _get(cfg, *keys, default=""):
    for key in keys:
        value = cfg.get(key)
        if value not in (None, ""):
            return value
    return default


def _profiles(data):
    if isinstance(data, dict):
        for key in ("config", "CONFIGS"):
            value = data.get(key)
            if isinstance(value, list) and value:
                return [item for item in value if isinstance(item, dict)] or [data]
        ssh = data.get("SshConfig")
        if isinstance(ssh, dict):
            profile = dict(ssh)
            for section in ("meta", "V2RayConfig"):
                extra = data.get(section)
                if isinstance(extra, dict):
                    for key, value in extra.items():
                        if not isinstance(value, (dict, list)) and value not in (None, ""):
                            profile.setdefault(key, value)
            return [profile]
        return [data]
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)] or [{"value": data}]
    return [{"value": data}]


def _scalar_fields(cfg, limit=18):
    lines = []
    pairs = []
    for key, value in cfg.items():
        if isinstance(value, (dict, list)) or value in (None, ""):
            continue
        text = str(value).strip()
        if text.startswith("{") or "<" in text:
            continue
        cleaned = _clean(value, limit=160)
        if not cleaned:
            continue
        lines.append(
            f"{html.escape(str(key)):<20}: <code>{html.escape(cleaned)}</code>"
        )
        pairs.append((str(key), cleaned))
        if len(lines) >= limit:
            break
    return lines, pairs


def _copy_rows(pairs):
    rows = []
    for index in range(0, len(pairs), 3):
        row = []
        for label, value in pairs[index:index + 3]:
            text = str(value)
            if not text:
                continue
            row.append(
                InlineKeyboardButton(
                    f"Copy {label}", copy_text=CopyTextButton(text=text)
                )
            )
        if row:
            rows.append(row)
    return rows


def _ssh_block(cfg, stem):
    user = _get(cfg, "username", "USERNAME", "user", "User")
    password = _get(cfg, "password", "PASSWORD", "pass", "Pass")
    host = _get(cfg, "host", "HOST", "SNI_OR_HOST", "serverAddress", "server", "Server")
    port = _get(cfg, "port", "PORT", "sshPort", "SSH_PORT")
    ns = _get(cfg, "ns", "NS_SERVER")
    dns = _get(cfg, "dns", "DNS")
    pubkey = _get(cfg, "pubKey", "PUBKEY")
    mode = _get(cfg, "mode", "MODE")
    link_user = str(user).lstrip("@")
    link = f"{host}:{port}@{link_user}:{password}"

    def value(text):
        return f"<code>{html.escape(_clean(text))}</code>"

    detail_lines = [
        f"\U0001f6a8 NAME: {html.escape(_clean(stem))}",
        "",
        f"\U0001f50c SSH PORT        : {value(port)}",
        f"\U0001f464 SSH USER        : {value(user)}",
        f"\U0001f511 SSH PASS        : {value(password)}",
        f"\U0001f310 DNS SERVER NAME : {value(ns)}",
        f"\U0001f30d DNS RESOLVER    : {value(dns)}",
        f"\U0001f510 DNS PUBLIC KEY  : {value(pubkey)}",
    ]
    if str(mode).strip():
        detail_lines.append(f"\U0001f9e9 MODE            : {value(mode)}")
    details = "\n".join(detail_lines)
    body = "\n".join(
        [
            f"<blockquote>{details}</blockquote>",
            "",
            SEPARATOR,
            "\U0001f510 SSH READY LINK:",
            SEPARATOR,
            "",
            f"<code>{html.escape(link)}</code>",
        ]
    )
    pairs = [
        ("PORT", port),
        ("USER", user),
        ("PASS", password),
        ("NS", ns),
        ("DNS", dns),
        ("PUBKEY", pubkey),
        ("LINK", link),
    ]
    return body, link, pairs


def _title(cfg, stem, proto):
    blob = " ".join(
        str(cfg.get(key, "")) for key in ("methods", "TUNNEL_TYPE", "tunnel", "protocol")
    ).lower()
    if "slowdns" in blob or "slow dns" in blob:
        return "SLOW DNS EXTRACTED INFO"
    tunnel = _clean(_get(cfg, "TUNNEL_TYPE", "tunnel", "protocol", "protocol"), limit=20)
    if tunnel and tunnel.upper() not in ("SSH", "1", ""):
        return f"{tunnel.upper()} EXTRACTED INFO"
    if proto:
        return f"{proto} EXTRACTED INFO"
    return "EXTRACTED INFO"


def format_result(result, stem):
    try:
        data = json.loads(result) if isinstance(result, str) else result
    except Exception:
        return f"<code>{html.escape(str(result)[:3500])}</code>", []

    blocks = []
    pairs = []
    profiles = _profiles(data)
    for cfg in profiles[:1]:
        proto = str(_get(cfg, "protocol", "PROTOCOL", "type", "TYPE", default="")).upper()
        user = _get(cfg, "username", "USERNAME", "user", "User")
        password = _get(cfg, "password", "PASSWORD", "pass", "Pass")
        host = _get(cfg, "host", "HOST", "SNI_OR_HOST", "serverAddress", "server", "Server")

        if user and password and host:
            body, _, pairs = _ssh_block(cfg, stem)
        else:
            fields, pairs = _scalar_fields(cfg)
            details = "\n".join(
                [f"\U0001f6a8 NAME: {html.escape(_clean(stem))}", ""] + fields
            )
            body = f"<blockquote>{details}</blockquote>"

        blocks.append(f"{BOX_TOP}\n   {_title(cfg, stem, proto)}\n{BOX_BOTTOM}\n\n{body}")

    if len(profiles) > 1:
        blocks.append(f"\u2026 and {len(profiles) - 1} more config(s)")

    return "\n\n".join(blocks)[:4000], [p for p in pairs if str(p[1]).strip()]


async def send_result(message, name: str, result: str) -> None:
    text, pairs = format_result(result, Path(name).stem)
    rows = _copy_rows(pairs)
    markup = InlineKeyboardMarkup(rows) if rows else None
    await message.reply_text(text, parse_mode=ParseMode.HTML, reply_markup=markup)


async def decode_file(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.effective_message
    document = message.document
    if document is None:
        return

    name = document.file_name or "config"
    suffix = Path(name).suffix.lower()
    if suffix not in SUPPORTED:
        await message.reply_text(
            f"Unsupported file type: {suffix or '(none)'}. "
            "Send a .hc, .dark or .ssc file."
        )
        return

    if document.file_size and document.file_size > MAX_FILE_BYTES:
        await message.reply_text("That file is too large (limit: 5 MB).")
        return

    await message.reply_chat_action(ChatAction.UPLOAD_DOCUMENT)
    try:
        telegram_file = await document.get_file()
        data = bytes(await telegram_file.download_as_bytearray())
    except Exception as exc:
        logger.exception("Could not download %s", name)
        await message.reply_text(f"Could not download the file: {exc}")
        return

    ok, text = await run_decoder(data, name)
    if ok:
        await send_result(message, name, text)
        return

    if is_password_error(text):
        prompt = await message.reply_text(
            "\U0001f512 Password Protected\n\nReply with password."
        )
        PENDING_PASSWORD[prompt.message_id] = {
            "chat_id": message.chat_id,
            "name": name,
            "data": data,
        }
        return

    logger.warning("Decode failed for %s: %s", name, text)
    await message.reply_text(f"Could not decode {name}:\n{text[:1000]}")


async def handle_password_reply(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    message = update.effective_message
    if not message or not message.reply_to_message:
        return
    pending = PENDING_PASSWORD.get(message.reply_to_message.message_id)
    if pending is None:
        return

    password = (message.text or "").strip()
    if not password:
        return

    await message.reply_chat_action(ChatAction.UPLOAD_DOCUMENT)
    ok, text = await run_decoder(
        pending["data"], pending["name"], password=password
    )
    if ok:
        await send_result(message, pending["name"], text)
        PENDING_PASSWORD.pop(message.reply_to_message.message_id, None)
        return

    if is_password_error(text):
        await message.reply_text(
            "\U0001f512 Wrong password.\n\nReply with password.",
            reply_to_message_id=message.reply_to_message.message_id,
        )
        return

    logger.warning("Decode failed for %s: %s", pending["name"], text)
    await message.reply_text(f"Could not decode {pending['name']}:\n{text[:1000]}")
    PENDING_PASSWORD.pop(message.reply_to_message.message_id, None)


async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.exception("Unhandled error while processing an update", exc_info=context.error)


def main() -> None:
    token = os.environ.get("BOT_TOKEN")
    if not token:
        raise SystemExit("BOT_TOKEN is not set. Get it from @BotFather on Telegram.")
    if not DECODER.exists():
        raise SystemExit(f"Decoder not found: {DECODER}")

    application: Application = ApplicationBuilder().token(token).build()
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(MessageHandler(filters.Document.ALL, decode_file))
    application.add_handler(
        MessageHandler(filters.REPLY & filters.TEXT & ~filters.COMMAND, handle_password_reply)
    )
    application.add_error_handler(on_error)

    logger.info("Starting config-decrypt bot with long polling")
    application.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
