# Step "notify_send": deliver the summary to Slack, Teams and/or e-mail.
import smtplib
from email.message import EmailMessage

N = load(r"""$notify_filter.message""")
SLACK = cfg("$slack_webhook_url")
TEAMS = cfg("$teams_webhook_url")
SMTP_HOST = cfg("$smtp_host")
SMTP_PORT = as_int(cfg("$smtp_port", "587"), 587)
SMTP_USER = cfg("$smtp_user")
SMTP_PASSWORD = cfg("$smtp_password")
MAIL_FROM = cfg("$mail_from")
MAIL_TO = csv(cfg("$mail_to"))
DASHBOARD = cfg("$dashboard_url")

facts = [("Rule", str(N.get("rule_id"))), ("Agent", N.get("agent")), ("Time", N.get("timestamp")),
         ("Groups", N.get("groups")), ("Alert ID", str(N.get("alert_id")))]
text = "*%s*\n%s\n```%s```%s" % (
    N.get("title"), "\n".join("%s: %s" % f for f in facts), N.get("full_log", ""),
    "\n" + DASHBOARD if DASHBOARD else "")
out = {}

if SLACK:
    r = requests.post(SLACK, json={"text": text}, timeout=15)
    out["slack"] = r.status_code

if TEAMS:  # Teams "Workflows" incoming webhook (adaptive card)
    card = {"type": "AdaptiveCard", "version": "1.4",
            chr(36) + "schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "body": [{"type": "TextBlock", "size": "Medium", "weight": "Bolder", "text": N.get("title"), "wrap": True},
                     {"type": "FactSet", "facts": [{"title": k, "value": v or "-"} for k, v in facts]},
                     {"type": "TextBlock", "text": N.get("full_log", ""), "wrap": True, "fontType": "Monospace"}]}
    r = requests.post(TEAMS, json={"type": "message", "attachments": [
        {"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]}, timeout=15)
    out["teams"] = r.status_code

if SMTP_HOST and MAIL_TO:
    msg = EmailMessage()
    msg["Subject"] = "[Wazuh] " + str(N.get("title"))
    msg["From"] = MAIL_FROM or SMTP_USER
    msg["To"] = ", ".join(MAIL_TO)
    msg.set_content(text.replace("*", "").replace("```", "\n"))
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as s:
            s.starttls()
            if SMTP_USER:
                s.login(SMTP_USER, SMTP_PASSWORD)
            s.send_message(msg)
        out["email"] = "sent"
    except Exception as exc:
        out["email"] = "failed: %s" % str(exc)[:200]
emit(out)
