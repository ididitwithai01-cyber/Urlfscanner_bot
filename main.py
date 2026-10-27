import os
import time
import requests
from telegram import Update
from telegram.ext import ApplicationBuilder, ContextTypes, MessageHandler, filters, CommandHandler

# --- PASTE YOUR KEYS BELOW ---
TELEGRAM_BOT_TOKEN = "8998227287:AAFxkFR8hIvb_ylYX1XPxPE5-c_fJSbJkK8"
VT_API_KEY = "67ed8fd102f808da6a422e770601ba935da26f3a94f9085ce9eb457bdda1c618"
URLSCAN_API_KEY = "01a17d78-25e3-710c-9fe8-6c1113b9e49e"
# -----------------------------

def scan_virustotal(target_url: str):
    headers = {"x-apikey": VT_API_KEY}
    if not VT_API_KEY: return {"engine": "VirusTotal", "error": "No Key"}
    try:
        submit_res = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": target_url}, timeout=10)
        if submit_res.status_code != 200: return {"engine": "VirusTotal", "error": "Failed"}
        analysis_id = submit_res.json()["data"]["id"]
        for i in range(6):
            time.sleep(5)
            report_res = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers, timeout=10)
            if report_res.status_code == 200:
                data = report_res.json()
                if data["data"]["attributes"]["status"] == "completed":
                    stats = data["data"]["attributes"]["stats"]
                    return {"engine": "VirusTotal", "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0)}
        return {"engine": "VirusTotal", "error": "Timeout"}
    except Exception as e:
        return {"engine": "VirusTotal", "error": str(e)}

def scan_urlscan(target_url: str):
    headers = {"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"}
    if not URLSCAN_API_KEY: return {"engine": "URLScan.io", "error": "No Key"}
    try:
        response = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json={"url": target_url, "visibility": "public"}, timeout=10)
        if response.status_code == 200:
            uuid = response.json().get("uuid")
            return {"engine": "URLScan.io", "link": f"https://urlscan.io/result/{uuid}/"}
        return {"engine": "URLScan.io", "error": "Failed"}
    except Exception as e:
        return {"engine": "URLScan.io", "error": str(e)}

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_text = update.message.text.strip()
    urls = [word for word in user_text.split() if word.startswith("http")]
    if not urls:
        await update.message.reply_text("👋 Send me a link to scan!")
        return
    target_url = urls[0]
    status_msg = await update.message.reply_text(f"🔍 Scanning `{target_url}`...")
    vt_result = scan_virustotal(target_url)
    urlscan_result = scan_urlscan(target_url)
    report = f"🛡️ *Report*\n\n🔗 `{target_url}`\n\n"
    if "malicious" in vt_result:
        m = vt_result["malicious"]
        report += f"🔴 *VT:* Dangerous ({m})\n" if m > 0 else f"🟢 *VT:* Clean\n"
    else:
        report += f"⚠️ *VT:* Error\n"
    if "link" in urlscan_result:
        report += f"🟢 *URLScan:* [View Report]({urlscan_result['link']})\n"
    else:
        report += f"⚠️ *URLScan:* Error\n"
    await status_msg.edit_text(report, parse_mode="Markdown", disable_web_page_preview=True)

#async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
  #  await update.message.reply_text("🛡️ *URL Scanner Bot*\nSend me any link to check if it's safe!", parse_mode="Markdown")
#
#if __name__ == "__main__":
  #  app = ApplicationBuilder().token(TELEGRAM_BOT_TOKEN).build()
  #  app.add_handler(MessageHandler(filters.TEXT & (~filters.COMMAND), handle_message))
  #  app.add_handler(CommandHandler("start", start_command))
  #  print("🤖 Bot Running on Cloud...")
   # app.run_polling()#
    
import threading
from http.server import SimpleHTTPRequestHandler, HTTPServer

def run_dummy_server():
    # Automatically pulls Render's required port allocation
    port = int(os.environ.get("PORT", 8080))
    server = HTTPServer(("0.0.0.0", port), SimpleHTTPRequestHandler)
    print(f"Dummy port server listening on port {port}")
    server.serve_forever()

if __name__ == "__main__":
    # 1. Start a fake background web server to satisfy Render's port checks
    server_thread = threading.Thread(target=run_dummy_server, daemon=True)
    server_thread.start()

    # 2. Start the Telegram bot loop normally
    app = ApplicationBuilder().token(TELEGRAM_BOT_TOKEN).build()
    app.add_handler(MessageHandler(filters.TEXT & (~filters.COMMAND), handle_message))
    app.add_handler(CommandHandler("start", start_command))
    print("🤖 Bot Running on Cloud...")
    app.run_polling()
    
