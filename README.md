# Config Decrypt Bot

Telegram bot that decrypts `.hc`, `.dark`, `.ssc`, `.ehi`, `.1ftnl` and `.nm` VPN config files and
replies with the decoded JSON. Password-protected files get a
"🔒 Password Protected — Reply with password." prompt, then decode on reply.

Uses `vpn_decoder.py` as the decoding engine.

Only decode configs you own or are authorized to handle.

## Local run

```bash
cd ~/telegram-bot
pip install -r requirements.txt
cp .env.example .env   # edit and paste your bot token
export BOT_TOKEN="123456:YOUR_TOKEN"
python bot.py
```

Then send a `.hc` / `.dark` / `.ssc` / `.ehi` / `.1ftnl` / `.nm` file to your bot in Telegram.

## Get a bot token

1. Open Telegram and message [@BotFather](https://t.me/BotFather).
2. Send `/newbot`, follow the prompts, and choose a unique username
   (e.g. `yourname_config_decrypt_bot`).
3. Copy the token BotFather gives you — that is `BOT_TOKEN`.
   Your `api_id` / `api_hash` from `my.telegram.org` are **not** used by bots.

## Deploy to Render (Worker + long polling)

1. Push this folder to a GitHub repo (include `bot.py`, `vpn_decoder.py`,
   `requirements.txt` and `render.yaml`).
2. In Render, create a **Blueprint** from that repo, or create a new
   **Background Worker** manually with:
   - Build: `pip install -r requirements.txt`
   - Start: `python bot.py`
3. Add environment variable `BOT_TOKEN` with the token from BotFather.
4. Worker services are a paid Render plan; long polling needs a persistent
   process, which a free sleeping Web Service cannot provide.

## Files

- `bot.py` — Telegram handlers, file download, timeout/size limits, reply.
- `vpn_decoder.py` — offline decoder for `.hc`, `.dark`, `.ssc`, `.ehi`, `.1ftnl`, `.nm`.
- `render.yaml` — Render Blueprint for a Worker service.
