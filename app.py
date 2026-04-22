import json
import logging
import os
import re
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

from telegram import ChatPermissions, Message, Update, User
from telegram.constants import ChatMemberStatus
from telegram.ext import (
    Application,
    CallbackContext,
    ChatMemberHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

# =========================
# CONFIG
# =========================
BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
PORT = int(os.getenv("PORT", "10000"))

DATA_FILE = Path("bot_data.json")

DEFAULT_SETTINGS = {
    "link_block_enabled": True,
    "delete_spam_enabled": True,
    "flood_limit": 5,          # max messages
    "flood_window_sec": 10,    # within N seconds
    "mute_minutes_default": 10,
    "warn_limit": 3,
    "banned_words": [
        "scam",
        "casino",
        "porn",
        "sex",
        "18+",
        "เครดิตฟรี",
    ],
}

if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN missing")

logging.basicConfig(
    format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

# =========================
# SIMPLE HEALTH SERVER FOR RENDER
# =========================
class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"Anti Spam Bot is running")

    def log_message(self, format, *args):
        return


def run_health_server() -> None:
    server = HTTPServer(("0.0.0.0", PORT), HealthHandler)
    logger.info("Health server running on port %s", PORT)
    server.serve_forever()


# =========================
# SIMPLE JSON STORAGE
# =========================
def load_data() -> dict[str, Any]:
    if not DATA_FILE.exists():
        return {"chats": {}, "warnings": {}}
    try:
        return json.loads(DATA_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {"chats": {}, "warnings": {}}


def save_data(data: dict[str, Any]) -> None:
    DATA_FILE.write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


DB = load_data()

# in-memory flood tracker
USER_MESSAGE_LOGS: dict[str, deque[datetime]] = defaultdict(deque)

# =========================
# HELPERS
# =========================
LINK_REGEX = re.compile(
    r"(https?://\S+|t\.me/\S+|www\.\S+|telegram\.me/\S+)",
    re.IGNORECASE,
)


def get_chat_key(chat_id: int) -> str:
    return str(chat_id)


def get_user_key(user_id: int) -> str:
    return str(user_id)


def get_chat_settings(chat_id: int) -> dict[str, Any]:
    chat_key = get_chat_key(chat_id)
    chats = DB.setdefault("chats", {})
    if chat_key not in chats:
        chats[chat_key] = DEFAULT_SETTINGS.copy()
        save_data(DB)
    else:
        merged = DEFAULT_SETTINGS.copy()
        merged.update(chats[chat_key])
        chats[chat_key] = merged
    return chats[chat_key]


def get_user_warnings(chat_id: int, user_id: int) -> int:
    return (
        DB.get("warnings", {})
        .get(get_chat_key(chat_id), {})
        .get(get_user_key(user_id), 0)
    )


def set_user_warnings(chat_id: int, user_id: int, count: int) -> None:
    warnings = DB.setdefault("warnings", {})
    chat_warnings = warnings.setdefault(get_chat_key(chat_id), {})
    chat_warnings[get_user_key(user_id)] = max(0, count)
    save_data(DB)


def add_warning(chat_id: int, user_id: int) -> int:
    current = get_user_warnings(chat_id, user_id)
    current += 1
    set_user_warnings(chat_id, user_id, current)
    return current


def mention_name(user: User) -> str:
    return user.mention_html()


async def is_admin(update: Update, user_id: int) -> bool:
    member = await update.effective_chat.get_member(user_id)
    return member.status in (
        ChatMemberStatus.ADMINISTRATOR,
        ChatMemberStatus.OWNER,
    )


async def ensure_admin(update: Update) -> bool:
    user = update.effective_user
    if not user:
        return False
    if await is_admin(update, user.id):
        return True
    if update.effective_message:
        await update.effective_message.reply_text("ဒီ command ကို admin ပဲသုံးလို့ရပါတယ်။")
    return False


def extract_target_user(message: Message) -> User | None:
    if message.reply_to_message and message.reply_to_message.from_user:
        return message.reply_to_message.from_user
    return None


async def delete_message_safe(message: Message) -> None:
    try:
        await message.delete()
    except Exception as exc:
        logger.warning("Failed to delete message: %s", exc)


async def mute_user(chat_id: int, user_id: int, minutes: int, context: ContextTypes.DEFAULT_TYPE) -> None:
    until_date = datetime.utcnow() + timedelta(minutes=minutes)
    permissions = ChatPermissions(
        can_send_messages=False,
        can_send_audios=False,
        can_send_documents=False,
        can_send_photos=False,
        can_send_videos=False,
        can_send_video_notes=False,
        can_send_voice_notes=False,
        can_send_polls=False,
        can_send_other_messages=False,
        can_add_web_page_previews=False,
        can_change_info=False,
        can_invite_users=False,
        can_pin_messages=False,
    )
    await context.bot.restrict_chat_member(
        chat_id=chat_id,
        user_id=user_id,
        permissions=permissions,
        until_date=until_date,
    )


async def unmute_user(chat_id: int, user_id: int, context: ContextTypes.DEFAULT_TYPE) -> None:
    permissions = ChatPermissions(
        can_send_messages=True,
        can_send_audios=True,
        can_send_documents=True,
        can_send_photos=True,
        can_send_videos=True,
        can_send_video_notes=True,
        can_send_voice_notes=True,
        can_send_polls=True,
        can_send_other_messages=True,
        can_add_web_page_previews=True,
        can_change_info=False,
        can_invite_users=True,
        can_pin_messages=False,
    )
    await context.bot.restrict_chat_member(
        chat_id=chat_id,
        user_id=user_id,
        permissions=permissions,
    )


# =========================
# COMMANDS
# =========================
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (
        "🛡️ Anti Spam Bot Ready!\n\n"
        "ဒီ bot က group ထဲမှာ spam, links, banned words, flood messages တွေကို စစ်ပေးမယ်။\n\n"
        "✅ Auto spam delete\n"
        "✅ Link block\n"
        "✅ Warn system\n"
        "✅ /mute /unmute\n"
        "✅ /ban /unban\n\n"
        "⚙️ အသုံးပြုနည်း\n"
        "1️⃣ Bot ကို group ထဲ add လုပ်ပါ\n"
        "2️⃣ Admin ပေးပါ\n"
        "3️⃣ Spam message တွေကို auto စစ်ပေးပါမယ်\n\n"
        "📌 Admin Commands:\n"
        "/mute 10\n"
        "/unmute\n"
        "/ban\n"
        "/unban\n"
        "/warn\n"
        "/warnings\n"
        "/links on|off\n"
        "/delspam on|off"
    )
    await update.effective_message.reply_text(text)


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await start(update, context)


async def links_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await ensure_admin(update):
        return
    if not context.args or context.args[0].lower() not in {"on", "off"}:
        await update.effective_message.reply_text("အသုံးပြုနည်း: /links on  သို့ /links off")
        return

    settings = get_chat_settings(update.effective_chat.id)
    settings["link_block_enabled"] = context.args[0].lower() == "on"
    save_data(DB)

    await update.effective_message.reply_text(
        f"🔗 Link block {'ဖွင့်ပြီးပါပြီ' if settings['link_block_enabled'] else 'ပိတ်ပြီးပါပြီ'}"
    )


async def delspam_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await ensure_admin(update):
        return
    if not context.args or context.args[0].lower() not in {"on", "off"}:
        await update.effective_message.reply_text("အသုံးပြုနည်း: /delspam on  သို့ /delspam off")
        return

    settings = get_chat_settings(update.effective_chat.id)
    settings["delete_spam_enabled"] = context.args[0].lower() == "on"
    save_data(DB)

    await update.effective_message.reply_text(
        f"🧹 Spam delete {'ဖွင့်ပြီးပါပြီ' if settings['delete_spam_enabled'] else 'ပိတ်ပြီးပါပြီ'}"
    )


async def warn_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await ensure_admin(update):
        return

    message = update.effective_message
    if not message:
        return

    target = extract_target_user(message)
    if not target:
        await message.reply_text("ဒီ command ကို user message ကို reply လုပ်ပြီးသုံးပါ။")
        return

    count = add_warning(update.effective_chat.id, target.id)
    settings = get_chat_settings(update.effective_chat.id)

    reply = f"⚠️ {target.full_name} ကို warning ပေးပြီးပါပြီ။ Total warnings: {count}"
    if count >= settings["warn_limit"]:
        await mute_user(
            update.effective_chat.id,
            target.id,
            settings["mute_minutes_default"],
            context,
        )
        reply += f"\n🔇 Warn limit ပြည့်သွားလို့ {settings['mute_minutes_default']} mins mute လုပ်ပြီးပါပြီ။"

    await message.reply_text(reply)


async def warnings_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.effective_message
    if not message:
        return

    target = extract_target_user(message) or update.effective_user
    if not target:
        return

    count = get_user_warnings(update.effective_chat.id, target.id)
    await message.reply_text(f"⚠️ {target.full_name} warnings: {count}")


async def mute_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await ensure_admin(update):
        return

    message = update.effective_message
    if not message:
        return

    target = extract_target_user(message)
    if not target:
        await message.reply_text("ဒီ command ကို user message ကို reply လုပ်ပြီးသုံးပါ။\nဥပမာ: /mute 15")
        return

    minutes = 10
    if context.args:
        try:
            minutes = max(1, int(context.args[0]))
        except ValueError:
            await message.reply_text("Minutes က number ဖြစ်ရပါမယ်။ ဥပမာ: /mute 10")
            return

    await mute_user(update.effective_chat.id, target.id, minutes, context)
    await message.reply_text(f"🔇 {target.full_name} ကို {minutes} mins mute လုပ်ပြီးပါပြီ။")


async def unmute_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await ensure_admin(update):
        return

    message = update.effective_message
    if not message:
        return

    target = extract_target_user(message)
    if not target:
        await message.reply_text("ဒီ command ကို user message ကို reply လုပ်ပြီးသုံးပါ။")
        return

    await unmute_user(update.effective_chat.id, target.id, context)
    await message.reply_text(f"🔊 {target.full_name} ကို unmute လုပ်ပြီးပါပြီ။")


async def ban_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await ensure_admin(update):
        return

    message = update.effective_message
    if not message:
        return

    target = extract_target_user(message)
    if not target:
        await message.reply_text("ဒီ command ကို user message ကို reply လုပ်ပြီးသုံးပါ။")
        return

    await context.bot.ban_chat_member(
        chat_id=update.effective_chat.id,
        user_id=target.id,
    )
    await message.reply_text(f"⛔ {target.full_name} ကို ban လုပ်ပြီးပါပြီ။")


async def unban_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await ensure_admin(update):
        return

    message = update.effective_message
    if not message:
        return

    target = extract_target_user(message)
    if not target:
        await message.reply_text("ဒီ command ကို banned user message ကို reply လုပ်ပြီးမသုံးနိုင်ပါဘူး။ user ID နဲ့ပဲလုပ်ရပါမယ်။")
        return

    await context.bot.unban_chat_member(
        chat_id=update.effective_chat.id,
        user_id=target.id,
        only_if_banned=True,
    )
    await message.reply_text(f"✅ {target.full_name} ကို unban လုပ်ပြီးပါပြီ။")


# =========================
# SPAM CHECK
# =========================
def contains_link(text: str) -> bool:
    return bool(LINK_REGEX.search(text))


def contains_banned_word(text: str, banned_words: list[str]) -> bool:
    text_lower = text.lower()
    return any(word.lower() in text_lower for word in banned_words)


def is_flood(chat_id: int, user_id: int, settings: dict[str, Any]) -> bool:
    key = f"{chat_id}:{user_id}"
    now = datetime.utcnow()
    logs = USER_MESSAGE_LOGS[key]

    while logs and (now - logs[0]).total_seconds() > settings["flood_window_sec"]:
        logs.popleft()

    logs.append(now)
    return len(logs) > settings["flood_limit"]


async def moderate_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.effective_message
    chat = update.effective_chat
    user = update.effective_user

    if not message or not chat or not user:
        return
    if not message.text:
        return

    try:
        member = await chat.get_member(user.id)
        if member.status in (ChatMemberStatus.ADMINISTRATOR, ChatMemberStatus.OWNER):
            return
    except Exception:
        pass

    settings = get_chat_settings(chat.id)
    text = message.text

    spam_reason = None

    if settings["link_block_enabled"] and contains_link(text):
        spam_reason = "link"
    elif contains_banned_word(text, settings["banned_words"]):
        spam_reason = "banned_word"
    elif is_flood(chat.id, user.id, settings):
        spam_reason = "flood"

    if not spam_reason:
        return

    if settings["delete_spam_enabled"]:
        await delete_message_safe(message)

    warn_count = add_warning(chat.id, user.id)

    if warn_count >= settings["warn_limit"]:
        await mute_user(chat.id, user.id, settings["mute_minutes_default"], context)
        await context.bot.send_message(
            chat_id=chat.id,
            text=(
                f"🚫 {user.full_name} spam detected ({spam_reason}).\n"
                f"⚠️ Warnings: {warn_count}\n"
                f"🔇 {settings['mute_minutes_default']} mins mute လုပ်ပြီးပါပြီ။"
            ),
        )
    else:
        await context.bot.send_message(
            chat_id=chat.id,
            text=(
                f"⚠️ {user.full_name} spam detected ({spam_reason}).\n"
                f"Warnings: {warn_count}/{settings['warn_limit']}"
            ),
        )


# =========================
# OPTIONAL JOIN NOTICE
# =========================
async def member_update(update: Update, context: CallbackContext) -> None:
    cm = update.chat_member
    if not cm:
        return

    old_status = cm.old_chat_member.status
    new_status = cm.new_chat_member.status
    user = cm.new_chat_member.user

    was_member = old_status in {
        ChatMemberStatus.MEMBER,
        ChatMemberStatus.ADMINISTRATOR,
        ChatMemberStatus.OWNER,
        ChatMemberStatus.RESTRICTED,
    }
    is_member_now = new_status in {
        ChatMemberStatus.MEMBER,
        ChatMemberStatus.ADMINISTRATOR,
        ChatMemberStatus.OWNER,
        ChatMemberStatus.RESTRICTED,
    }

    if not was_member and is_member_now:
        await context.bot.send_message(
            chat_id=cm.chat.id,
            text=(
                "👋 Welcome!\n\n"
                f"🆔 ID - {user.id}\n"
                f"👤 Username - @{user.username}" if user.username else f"👤 Username - No Username"
            ),
        )


# =========================
# MAIN
# =========================
def main() -> None:
    threading.Thread(target=run_health_server, daemon=True).start()

    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("links", links_command))
    app.add_handler(CommandHandler("delspam", delspam_command))
    app.add_handler(CommandHandler("warn", warn_command))
    app.add_handler(CommandHandler("warnings", warnings_command))
    app.add_handler(CommandHandler("mute", mute_command))
    app.add_handler(CommandHandler("unmute", unmute_command))
    app.add_handler(CommandHandler("ban", ban_command))
    app.add_handler(CommandHandler("unban", unban_command))

    app.add_handler(ChatMemberHandler(member_update, ChatMemberHandler.CHAT_MEMBER))
    app.add_handler(
        MessageHandler(
            filters.TEXT & ~filters.COMMAND,
            moderate_message,
        )
    )

    logger.info("Starting Anti Spam Bot with polling...")
    app.run_polling(
        allowed_updates=["message", "chat_member"],
        drop_pending_updates=True,
    )


if __name__ == "__main__":
    main()
