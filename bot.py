#!/usr/bin/env python3
"""Telegram config-decrypt bot.

Users send .hc / .dark / .ssc / .ehi / .1ftnl / .nm files; the bot replies with the decoded JSON.
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
from urllib.parse import quote

from telegram import (
    CopyTextButton,
    ForceReply,
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
    CallbackQueryHandler,
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
SUPPORTED = {".hc", ".dark", ".ssc", ".ehi", ".1ftnl", ".nm"}
MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MB
REQUIRED_CHANNEL = "@ultimatedecryption"
REQUIRED_CHANNEL_URL = "https://t.me/ultimatedecryption"
DECODE_TIMEOUT = 30  # seconds

# (chat id, prompt message id) -> pending file and uploader
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




async def is_member(context, user_id):
    try:
        member = await context.bot.get_chat_member(REQUIRED_CHANNEL, user_id)
        return member.status in ("member", "administrator", "creator", "restricted")
    except Exception as exc:
        logger.warning("Could not verify membership for %s: %s", user_id, exc)
        return None


def join_group_markup():
    return InlineKeyboardMarkup(
        [[InlineKeyboardButton("Join Group", url=REQUIRED_CHANNEL_URL)]]
    )


def join_gate_markup():
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("Join Channel", url=REQUIRED_CHANNEL_URL)],
            [InlineKeyboardButton("Verify", callback_data="verify_join")],
        ]
    )


async def send_join_gate(message):
    await message.reply_text(
        "Please join our channel to use this bot:\n"
        f"{REQUIRED_CHANNEL_URL}\n\n"
        "After joining, click Verify.",
        reply_markup=join_gate_markup(),
        do_quote=message.chat.type in ("group", "supergroup"),
    )

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.effective_message.reply_text(
        "Send me a VPN config file (.hc, .dark, .ssc, .ehi, .1ftnl or .nm) and I'll send back "
        "the decoded details.\n\nIf a file is password protected I'll ask you "
        "for the password in a reply.\n\nUse /help for details.",
        reply_markup=join_group_markup(),
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.effective_message.reply_text(
        "Config Decrypt Bot\n\n"
        "Supported files: .hc, .dark, .ssc, .ehi, .1ftnl, .nm\n"
        "Send a file as a document and I will reply with formatted details.\n"
        "Password protected files: reply to my password prompt with the "
        "password. Only the uploader can answer the password prompt.\n\n"
        "Groups: add me and disable privacy mode in @BotFather using "
        "/setprivacy so I can receive files. Decoded credentials are "
        "visible to everyone in the group.\n\n"
        "Commands:\n"
        "/start - introduction\n"
        "/help  - this message\n\n"
        "Only decode configs you own or are authorized to handle.",
        reply_markup=join_group_markup(),
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


def _set_if_empty(profile, key, value):
    if value in (None, ""):
        return
    if profile.get(key) in (None, ""):
        profile[key] = value


def _flatten_outbound(profile):
    if not isinstance(profile, dict):
        return profile
    outbounds = profile.get("outbounds")
    if not (isinstance(outbounds, list) and outbounds and isinstance(outbounds[0], dict)):
        # handle V2Ray-style outbound inside profile if present
        pass
    # V2Ray outbounds (may be nested under profile already)
    obs = outbounds if isinstance(outbounds, list) else profile.get("outbounds")
    if isinstance(obs, list) and obs and isinstance(obs[0], dict):
        ob = obs[0]
        protocol = ob.get("protocol")
        if protocol:
            profile["protocol"] = str(protocol)
        settings = ob.get("settings")
        if isinstance(settings, dict):
            vnext = settings.get("vnext")
            if isinstance(vnext, list) and vnext and isinstance(vnext[0], dict):
                v0 = vnext[0]
                _set_if_empty(profile, "address", v0.get("address"))
                _set_if_empty(profile, "port", v0.get("port"))
                users = v0.get("users")
                if isinstance(users, list) and users and isinstance(users[0], dict):
                    u0 = users[0]
                    _set_if_empty(profile, "id", u0.get("id"))
                    _set_if_empty(profile, "uuid", u0.get("id"))
                    _set_if_empty(profile, "alterId", u0.get("alterId"))
                    _set_if_empty(profile, "aid", u0.get("alterId"))
                    _set_if_empty(profile, "encryption", u0.get("encryption"))
                    _set_if_empty(profile, "encryption", u0.get("security"))
                    _set_if_empty(profile, "flow", u0.get("flow"))
            servers = settings.get("servers")
            if isinstance(servers, list) and servers and isinstance(servers[0], dict):
                s0 = servers[0]
                _set_if_empty(profile, "address", s0.get("address"))
                _set_if_empty(profile, "port", s0.get("port"))
                _set_if_empty(profile, "password", s0.get("password"))
            for key, value in settings.items():
                if isinstance(value, (dict, list)) or value in (None, ""):
                    continue
                _set_if_empty(profile, key, value)
        stream = ob.get("streamSettings")
        if isinstance(stream, dict):
            net = stream.get("network")
            _set_if_empty(profile, "transport", net)
            _set_if_empty(profile, "net", net)
            sec = stream.get("security")
            _set_if_empty(profile, "tls", sec)
            _set_if_empty(profile, "security", sec)
            for key in ("wsSettings", "tcpSettings", "kcpSettings", "grpcSettings", "httpSettings", "h2Settings"):
                st = stream.get(key)
                if isinstance(st, dict):
                    if st.get("path") not in (None, ""):
                        _set_if_empty(profile, "path", st.get("path"))
                    host = st.get("host")
                    if isinstance(host, list) and host:
                        _set_if_empty(profile, "host_header", host[0])
                    elif host not in (None, ""):
                        _set_if_empty(profile, "host_header", host)
            tls_settings = stream.get("tlsSettings")
            if isinstance(tls_settings, dict):
                sni = tls_settings.get("serverName")
                _set_if_empty(profile, "sni", sni)
            for key in ("rawSettings", "tcpSettings"):
                st = stream.get(key)
                if isinstance(st, dict):
                    header = st.get("header")
                    if isinstance(header, dict) and header.get("type") not in (None, ""):
                        _set_if_empty(profile, "headerType", header.get("type"))

    # InjectConfig-derived fields
    _set_if_empty(profile, "inject", profile.get("Mode"))
    _set_if_empty(profile, "Mode", profile.get("Mode"))
    if profile.get("ProxyHost") not in (None, "") and profile.get("ProxyPort") not in (None, ""):
        _set_if_empty(profile, "proxy", f"{profile.get('ProxyHost')}:{profile.get('ProxyPort')}")
    _set_if_empty(profile, "sni", profile.get("ServerNameIndication"))
    if profile.get("DnsttDnsHost") not in (None, ""):
        dns_host = profile.get("DnsttDnsHost")
        dns_port = profile.get("DnsttDnsPort")
        if dns_port not in (None, ""):
            _set_if_empty(profile, "dns", f"{dns_host}:{dns_port}")
        else:
            _set_if_empty(profile, "dns", dns_host)
    _set_if_empty(profile, "payload", profile.get("Payload"))
    _set_if_empty(profile, "ns", profile.get("DnsttServerName") or profile.get("slowDnsNs"))
    _set_if_empty(profile, "pubKey", profile.get("DnsttPubkey") or profile.get("slowDnsPubKey"))

    # host fallback
    if profile.get("host") in (None, "") and profile.get("address") not in (None, ""):
        profile["host"] = profile.get("address")
    if profile.get("address") in (None, "") and profile.get("host") not in (None, ""):
        profile["address"] = profile.get("host")

    return profile


def _profiles(data):
    if isinstance(data, dict):
        for key in ("config", "CONFIGS"):
            value = data.get(key)
            if isinstance(value, list) and value:
                return [_flatten_outbound(item) if isinstance(item, dict) else item for item in value if isinstance(item, dict)] or [_flatten_outbound(data)]
        sections = []
        for sec in ("meta", "InjectConfig", "SshConfig", "V2RayConfig"):
            val = data.get(sec)
            if isinstance(val, dict):
                sections.append(val)
        if sections:
            profile = {}
            for sec in sections:
                for key, value in sec.items():
                    if str(key).lower() == "config":
                            cfgval = value
                            if isinstance(cfgval, str):
                                attempts = [
                                    cfgval,
                                    cfgval.replace("$MUX_ENABLED", "false")
                                          .replace("$SOCKS5_LISTEN_HOST", '"0.0.0.0"')
                                          .replace("$SOCKS5_LISTEN_PORT", "1080")
                                          .replace("$HTTP_LISTEN_HOST", '"0.0.0.0"')
                                          .replace("$HTTP_LISTEN_PORT", "1081"),
                                ]
                                for att in attempts:
                                    try:
                                        cfgval = json.loads(att)
                                        break
                                    except Exception:
                                        cfgval = None
                                if cfgval is None:
                                    m = re.search(r'"outbounds"\s*:\s*(\[.*\])', value, re.S)
                                    if m:
                                        snippet = m.group(1).replace("$MUX_ENABLED", "false")
                                        try:
                                            cfgval = {"outbounds": json.loads(snippet)}
                                        except Exception:
                                            cfgval = None
                            if isinstance(cfgval, dict):
                                for k, v in cfgval.items():
                                    if k.lower() == "outbounds" and isinstance(v, list):
                                        profile["outbounds"] = v
                                    elif not isinstance(v, (dict, list)) and v not in (None, ""):
                                        profile.setdefault(k, v)
                    elif value not in (None, ""):
                        profile.setdefault(key, value)
            for key, value in data.items():
                if key in ("meta", "InjectConfig", "SshConfig", "V2RayConfig"):
                    continue
                if not isinstance(value, (dict, list)) and value not in (None, ""):
                    profile.setdefault(key, value)
            if profile:
                return [_flatten_outbound(profile)]
        return [_flatten_outbound(data)]
    if isinstance(data, list):
        return [_flatten_outbound(item) if isinstance(item, dict) else item for item in data if isinstance(item, dict)] or [_flatten_outbound({"value": data})]
    return [{"value": data}]


def _tokenize_key(key):
    # Split camelCase / snake_case / kebab into lowercase words.
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(key))
    text = re.sub(r"[_\-]+", " ", text)
    return [w.lower() for w in text.split() if w]


def _emoji_for_key(key):
    tokens = _tokenize_key(key)
    token_str = " ".join(tokens)
    mapping = [
        (["slow", "dns", "dns"], "\U0001f30d"),
        (["slow", "dns", "ns"], "\U0001f310"),
        (["slow", "dns", "pub", "key"], "\U0001f510"),
        (["slow", "dns", "pubkey"], "\U0001f510"),
        (["slow", "dns"], "\U0001f40c"),
        (["slow", "dns", "handling"], "\U0001f40c"),
        (["password"], "\U0001f511"),
        (["pass"], "\U0001f511"),
        (["username"], "\U0001f464"),
        (["user"], "\U0001f464"),
        (["public", "key"], "\U0001f510"),
        (["pubkey"], "\U0001f510"),
        (["host"], "\U0001f310"),
        (["address"], "\U0001f310"),
        (["server"], "\U0001f5a5"),
        (["sni"], "\U0001f512"),
        (["ssl"], "\U0001f512"),
        (["port"], "\U0001f50c"),
        (["protocol"], "\U0001f6e1"),
        (["proxy"], "\U0001f500"),
        (["payload"], "\U0001f4e6"),
        (["dns"], "\U0001f30d"),
        (["ns"], "\U0001f310"),
        (["mode"], "\U0001f9e9"),
        (["enabled"], "\u2705"),
        (["bypass"], "\U0001f6ab"),
        (["window"], "\U0001fa9f"),
        (["kcp"], "\u26a1"),
        (["transport"], "\U0001f680"),
        (["handling"], "\U0001f527"),
        (["method"], "\u2699"),
        (["selection"], "\u2699"),
        (["version"], "\u2699"),
        (["type"], "\U0001f3f7"),
        (["name"], "\U0001f6a8"),
    ]

    def is_subseq(needle, haystack):
        # contiguous subsequence
        n = len(needle)
        for i in range(len(haystack) - n + 1):
            if haystack[i:i + n] == needle:
                return True
        return False

    for needle, emoji in mapping:
        if is_subseq(needle, tokens):
            return emoji
    return "\U0001f539"


def _pretty_value(value):
    text = str(value).strip()
    lowered = text.lower()
    if lowered == "true":
        return "\u2705 True"
    if lowered == "false":
        return "\u274c False"
    return text


def _scalar_fields(cfg, limit=18):
    lines = []
    pairs = []
    for key, value in cfg.items():
        if isinstance(value, (dict, list)) or value in (None, ""):
            continue
        if _tokenize_key(key) == ["name"]:
            continue
        text = str(value).strip()
        if text.startswith("{") or "<" in text:
            continue
        cleaned = _clean(value, limit=160)
        if not cleaned:
            continue
        cleaned = _pretty_value(cleaned)
        emoji = _emoji_for_key(key)
        lines.append(
            f"{emoji} {html.escape(str(key)):<24}: <code>{html.escape(cleaned)}</code>"
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
    user = _get(cfg, "username", "USERNAME", "user", "User", "Username")
    password = _get(cfg, "password", "PASSWORD", "pass", "Pass", "Password")
    host = _get(cfg, "host", "HOST", "Host", "SNI_OR_HOST", "serverAddress", "server", "Server")
    port = _get(cfg, "port", "PORT", "Port", "sshPort", "SSH_PORT")
    ns = _get(cfg, "ns", "NS", "NS_SERVER", "nsServer", "slowDnsNs", "slowDnsNS")
    dns = _get(cfg, "dns", "DNS", "Dns", "dnsResolver", "slowDnsDns", "slowDnsDNS")
    pubkey = _get(cfg, "pubKey", "PUBKEY", "PubKey", "publicKey", "slowDnsPubKey", "slowDnsPUBKEY")
    mode = _get(cfg, "mode", "MODE", "Mode")
    link_user = str(user).lstrip("@")
    link = f"{host}:{port}@{link_user}:{password}"

    def value(text):
        return f"<code>{html.escape(_clean(text))}</code>"

    is_netmod = str(cfg.get("source", "")).strip().lower() == "netmod"
    if is_netmod:
        detail_lines = [
            f"\U0001f6a8 NAME: {html.escape(_clean(stem))}",
            "",
            f"\U0001f310 HOST    : {value(host)}",
            f"\U0001f50c PORT    : {value(port)}",
            f"\U0001f464 USER    : {value(user)}",
            f"\U0001f511 PASS    : {value(password)}",
        ]
    else:
        detail_lines = [
            f"\U0001f6a8 NAME: {html.escape(_clean(stem))}",
            "",
            f"\U0001f310 SSH HOST        : {value(host)}",
            f"\U0001f50c SSH PORT        : {value(port)}",
            f"\U0001f464 SSH USER        : {value(user)}",
            f"\U0001f511 SSH PASS        : {value(password)}",
        ]
    inject = _get(cfg, "inject", "INJECT", "Mode", "mode", default="")
    proxy = _get(cfg, "proxy", "PROXY", default="")
    if is_netmod:
        # NetMod profiles carry a numeric mode, not a readable inject
        # label; other bots render this as e.g. "NetMod SSH".
        proto_label = str(
            _get(cfg, "protocol", "PROTOCOL", "type", "TYPE", default="SSH")
        ).upper()
        detail_lines.append(
            f"\U0001f9e9 INJECT  : {value('NetMod ' + proto_label)}"
        )
    elif str(inject).strip():
        detail_lines.append(f"\U0001f9e9 INJECT  : {value(inject)}")
    if str(proxy).strip():
        detail_lines.append(f"\U0001f9ed PROXY   : {value(proxy)}")
    if str(ns).strip():
        detail_lines.append(f"\U0001f310 DNS SERVER NAME : {value(ns)}")
    if str(dns).strip():
        detail_lines.append(f"\U0001f30d DNS RESOLVER    : {value(dns)}")
    if str(pubkey).strip():
        detail_lines.append(f"\U0001f510 DNS PUBLIC KEY  : {value(pubkey)}")
    if not is_netmod and str(mode).strip() and str(mode).strip() != str(inject).strip():
        detail_lines.append(f"\U0001f9e9 MODE            : {value(mode)}")
    payload = _get(cfg, "payload", "PAYLOAD", "Payload", default="")
    if str(payload).strip():
        detail_lines.append("")
        detail_lines.append("\U0001f4e6 PAYLOAD:")
        detail_lines.append(value(payload))
    details = "\n".join(detail_lines)
    body = "\n".join(
        [
            f"<blockquote>{details}</blockquote>",
            "",
            SEPARATOR,
            "\U0001f510 SSH READY LINK:",
            SEPARATOR,
            "",
            f"<pre><code>{html.escape(link)}</code></pre>",
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


def _proxy_block(cfg, stem):
    address = _get(cfg, "address", "ADDRESS", "add", "host", "HOST", "serverAddress", "server", "Server", "ip", "IP")
    host = _get(cfg, "host_header", "HOST", "host", "sni", default="")
    sni = _get(cfg, "sni", "SNI", "serverName", "ServerNameIndication", default="")
    proxy = _get(cfg, "proxy", "PROXY", default="")
    payload = _get(cfg, "payload", "PAYLOAD", "Payload", default="")
    uuid = _get(cfg, "uuid", "UUID", "id", "ID", "userId", "user_id")
    password = _get(cfg, "password", "PASSWORD", "pass", "Pass", "Password")
    path = _get(cfg, "path", "PATH", "Path", "wsPath", "ws_path")
    port = _get(cfg, "port", "PORT", "Port")
    tls_raw = str(_get(cfg, "tls", "TLS", "ssl", "SSL", default="")).strip().lower()
    tls_on = tls_raw in ("1", "true", "tls", "on", "yes", "ssl")
    tls_text = "ON \u2705" if tls_on else "OFF \u274c"
    transport = _get(cfg, "transport", "TRANSPORT", "net", "NET", "network", "type", "TYPE")
    alter_id = _get(cfg, "alterId", "ALTER_ID", "alter_id", "aid", "AID", default="0")
    security = _get(cfg, "security", "SECURITY", default="none")
    encryption = _get(cfg, "encryption", "ENCRYPTION", "cipher", "scy", "security", default="auto")
    inject = _get(cfg, "inject", "INJECT", "injectMode", "InjectMode", "Mode", "mode", default="0")
    ns = _get(cfg, "ns", "NS_SERVER", "nsServer", "slowDnsNs", "slowDnsNS", "NS")
    dns = _get(cfg, "dns", "DNS", "dnsResolver", "slowDnsDns", "slowDnsDNS")
    pubkey = _get(cfg, "pubKey", "PUBKEY", "publicKey", "slowDnsPubKey", "slowDnsPUBKEY")
    mode = _get(cfg, "mode", "MODE", "Mode")
    proto = str(_get(cfg, "protocol", "PROTOCOL", "type", "TYPE", default="")).upper()
    if not proto or proto in ("SSH", "1", ""):
        if uuid and not password:
            proto = "VLESS"
        elif password and not uuid:
            proto = "TROJAN"
        else:
            proto = "VMESS"

    def value(text):
        return f"<code>{html.escape(_clean(text))}</code>"

    detail_lines = [
        f"\U0001f6a8 NAME: {html.escape(_clean(stem))}",
        "",
        f"\U0001f4cd ADDRESS : {value(address)}",
    ]
    if host:
        detail_lines.append(f"\U0001f310 HOST    : {value(host)}")
    if uuid:
        detail_lines.append(f"\U0001f511 UUID    : {value(uuid)}")
    if sni:
        detail_lines.append(f"\U0001f517 SNI     : {value(sni)}")
    if proxy:
        detail_lines.append(f"\U0001f9ed PROXY   : {value(proxy)}")
    if password and not uuid:
        detail_lines.append(f"\U0001f511 PASSWORD: {value(password)}")
    if str(path).strip():
        detail_lines.append(f"\U0001f4c1 PATH    : {value(path)}")
    detail_lines.append(f"\U0001f50c PORT    : {value(port)}")
    detail_lines.append(f"\U0001f6e1 TLS     : {value(tls_text)}")
    detail_lines.append(f"\U0001f6a6 TRANSPORT: {value(transport)}")
    detail_lines.append(f"\U0001f522 ALTER ID: {value(alter_id)}")
    detail_lines.append(f"\U0001f512 SECURITY: {value(security)}")
    detail_lines.append(f"\U0001f9e9 INJECT  : {value(inject)}")
    if payload:
        detail_lines.append("")
        detail_lines.append("\U0001f4e6 PAYLOAD:")
        detail_lines.append(value(payload))
    if ns:
        detail_lines.append(f"\U0001f310 DNS SERVER NAME : {value(ns)}")
    if dns:
        detail_lines.append(f"\U0001f30d DNS RESOLVER    : {value(dns)}")
    if pubkey:
        detail_lines.append(f"\U0001f510 DNS PUBLIC KEY  : {value(pubkey)}")
    if str(mode).strip():
        detail_lines.append(f"\U0001f9e9 MODE            : {value(mode)}")
    details = "\n".join(detail_lines)

    # Build ready link
    name_q = quote(stem, safe="")
    addr_q = quote(str(address), safe="")
    path_q = quote(str(path), safe="") if path else ""
    if proto == "VMESS":
        import base64 as _b64, json as _json
        vmess_obj = {
            "v": "2",
            "ps": stem,
            "add": str(address),
            "port": str(port),
            "id": str(uuid),
            "aid": str(alter_id or 0),
            "net": str(transport or "tcp"),
            "type": "none",
            "host": str(host or address),
            "path": str(path or ""),
            "tls": "tls" if tls_on else "",
            "scy": str(encryption or "auto"),
            "sni": str(sni or ""),
        }
        link = "vmess://" + _b64.b64encode(_json.dumps(vmess_obj).encode()).decode()
    elif proto == "TROJAN":
        params = []
        if transport:
            params.append("type=" + quote(str(transport), safe=""))
        if security:
            params.append("security=" + quote(str(security), safe=""))
        if path:
            params.append("path=" + quote(str(path), safe=""))
        query = "&".join(params)
        link = f"trojan://{password}@{address}:{port}"
        if query:
            link += "?" + query
        link += "#" + addr_q
    else:
        params = []
        if transport:
            params.append("type=" + quote(str(transport), safe=""))
        sec = security if security and security.lower() != "none" else ("tls" if tls_on else "none")
        params.append("security=" + quote(str(sec), safe=""))
        if path:
            params.append("path=" + quote(str(path), safe=""))
        query = "&".join(params)
        link = f"vless://{uuid}@{address}:{port}"
        if query:
            link += "?" + query
        link += "#" + addr_q

    body = "\n".join(
        [
            f"<blockquote>{details}</blockquote>",
            "",
            SEPARATOR,
            "\U0001f517 READY LINK:",
            SEPARATOR,
            "",
            f"<pre><code>{html.escape(link)}</code></pre>",
        ]
    )
    pairs = [
        ("ADDRESS", address),
    ]
    if uuid:
        pairs.append(("UUID", uuid))
    if password and not uuid:
        pairs.append(("PASSWORD", password))
    pairs += [
        ("PATH", path),
        ("PORT", port),
        ("TLS", tls_text),
        ("TRANSPORT", transport),
        ("ALTER_ID", alter_id),
        ("SECURITY", security),
        ("INJECT", inject),
        ("NS", ns),
        ("DNS", dns),
        ("PUBKEY", pubkey),
        ("LINK", link),
        ("Code", link),
    ]
    return body, link, [p for p in pairs if str(p[1]).strip()]

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
        user = _get(cfg, "username", "USERNAME", "user", "User", "Username")
        password = _get(cfg, "password", "PASSWORD", "pass", "Pass", "Password")
        host = _get(cfg, "host", "HOST", "Host", "SNI_OR_HOST", "serverAddress", "server", "Server")

        is_proxy = (
            proto in ("VLESS", "VMESS", "TROJAN")
            or (_get(cfg, "uuid", "UUID", "id", "ID") and (_get(cfg, "transport", "TRANSPORT", "net", "NET", "network") or _get(cfg, "path", "PATH", "Path")))
            or (_get(cfg, "password", "PASSWORD", "pass", "Pass") and _get(cfg, "address", "ADDRESS", "add", "host", "HOST") and _get(cfg, "transport", "TRANSPORT", "net", "NET", "network"))
        )
        # NetMod results carry their real profile name inside the file;
        # other bots show that name, not the (often renamed) file name.
        display_stem = stem
        if str(cfg.get("source", "")).strip().lower() == "netmod":
            display_stem = _get(cfg, "name", "ps", default="") or stem
        if not is_proxy and user and password and host and proto not in (
                "SSH", "VLESS", "VMESS", "TROJAN"):
            proto = "SSH"
        if is_proxy:
            body, _, pairs = _proxy_block(cfg, display_stem)
        elif user and password and host:
            body, _, pairs = _ssh_block(cfg, display_stem)
        else:
            fields, pairs = _scalar_fields(cfg)
            details = "\n".join(
                [f"\U0001f6a8 NAME: {html.escape(_clean(display_stem))}", ""] + fields
            )
            body = f"<blockquote>{details}</blockquote>"

        blocks.append(f"{BOX_TOP}\n   {_title(cfg, display_stem, proto)}\n{BOX_BOTTOM}\n\n{body}")

    if len(profiles) > 1:
        blocks.append(f"\u2026 and {len(profiles) - 1} more config(s)")

    return "\n\n".join(blocks)[:4000], [p for p in pairs if str(p[1]).strip()]


async def send_result(message, name: str, result: str, reply_to_message_id=None) -> None:
    text, pairs = format_result(result, Path(name).stem)
    kwargs = dict(parse_mode=ParseMode.HTML, reply_markup=join_group_markup())
    if reply_to_message_id is not None:
        kwargs["reply_to_message_id"] = reply_to_message_id
    else:
        kwargs["do_quote"] = message.chat.type in ("group", "supergroup")
    await message.reply_text(text, **kwargs)


async def decode_file(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.effective_message
    document = message.document
    if document is None:
        return
    user_id = message.from_user.id if message.from_user else None
    if user_id is not None:
        status = await is_member(context, user_id)
        if status is not True:
            await send_join_gate(message)
            return

    name = document.file_name or "config"
    suffix = Path(name).suffix.lower()
    if suffix not in SUPPORTED:
        lowered = name.lower()
        for cand in SUPPORTED:
            if cand in lowered:
                suffix = cand
                break
    if suffix not in SUPPORTED:
        if message.chat.type in ("group", "supergroup"):
            return
        await message.reply_text(
            f"Unsupported file type: {suffix or '(none)'}. "
            "Send a .hc, .dark, .ssc, .ehi, .1ftnl or .nm file.",
            reply_markup=join_group_markup(),
        )
        return

    if document.file_size and document.file_size > MAX_FILE_BYTES:
        await message.reply_text("That file is too large (limit: 5 MB).", reply_markup=join_group_markup())
        return

    await message.reply_chat_action(ChatAction.UPLOAD_DOCUMENT)
    try:
        telegram_file = await document.get_file()
        data = bytes(await telegram_file.download_as_bytearray())
    except Exception as exc:
        logger.exception("Could not download %s", name)
        await message.reply_text(f"Could not download the file: {exc}", reply_markup=join_group_markup())
        return

    ok, text = await run_decoder(data, name)
    if ok:
        await send_result(message, name, text, reply_to_message_id=message.message_id)
        return

    if is_password_error(text):
        prompt = await message.reply_text(
            f"\U0001f512 Password Protected: {html.escape(name)}\n\nReply with password.",
            reply_markup=ForceReply(selective=True),
            do_quote=True,
        )
        PENDING_PASSWORD[(message.chat_id, prompt.message_id)] = {
            "chat_id": message.chat_id,
            "user_id": message.from_user.id if message.from_user else None,
            "name": name,
            "data": data,
            "message_id": message.message_id,
        }
        return

    logger.warning("Decode failed for %s: %s", name, text)
    await message.reply_text(f"Could not decode {name}:\n{text[:1000]}", reply_markup=join_group_markup())


async def handle_password_reply(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    message = update.effective_message
    if not message or not message.reply_to_message:
        return
    pending_key = (message.chat_id, message.reply_to_message.message_id)
    pending = PENDING_PASSWORD.get(pending_key)
    if pending is None:
        return
    if message.from_user is None or message.from_user.id != pending["user_id"]:
        return
    if message.from_user is not None:
        status = await is_member(context, message.from_user.id)
        if status is not True:
            await send_join_gate(message)
            return

    password = (message.text or "").strip()
    if not password:
        return

    await message.reply_chat_action(ChatAction.UPLOAD_DOCUMENT)
    ok, text = await run_decoder(
        pending["data"], pending["name"], password=password
    )
    if ok:
        await send_result(
            message, pending["name"], text,
            reply_to_message_id=pending.get("message_id"),
        )
        PENDING_PASSWORD.pop(pending_key, None)
        return

    if is_password_error(text):
        await message.reply_text(
            f"\U0001f512 Wrong password: {html.escape(pending['name'])}\n\nReply with password.",
            reply_to_message_id=message.reply_to_message.message_id,
            reply_markup=join_group_markup(),
        )
        return

    logger.warning("Decode failed for %s: %s", pending["name"], text)
    await message.reply_text(f"Could not decode {pending['name']}:\n{text[:1000]}")
    PENDING_PASSWORD.pop(pending_key, None)



async def verify_join(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if query is None:
        return
    await query.answer()
    user_id = query.from_user.id if query.from_user else None
    if user_id is None:
        return
    status = await is_member(context, user_id)
    if status is True:
        deleted = False
        try:
            if query.message is not None:
                await query.message.delete()
                deleted = True
        except Exception as exc:
            logger.warning("Could not delete gate message: %s", exc)
        if not deleted:
            try:
                await query.edit_message_text("\u2705 Verified! You can now use the bot.", reply_markup=None)
            except Exception:
                try:
                    await query.edit_message_reply_markup(reply_markup=None)
                except Exception:
                    pass
        try:
            chat_id = query.message.chat_id if query.message is not None else None
            if chat_id is None and query.from_user is not None:
                chat_id = query.from_user.id
            if chat_id is not None:
                await context.bot.send_message(chat_id=chat_id, text="\u2705 Verified")
        except Exception as exc:
            logger.warning("Could not send verification confirmation: %s", exc)
    else:
        try:
            await query.answer("Not joined", show_alert=True)
        except Exception:
            pass


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
    application.add_handler(CallbackQueryHandler(verify_join, pattern="^verify_join$"))
    application.add_error_handler(on_error)

    logger.info("Starting config-decrypt bot with long polling")
    application.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
