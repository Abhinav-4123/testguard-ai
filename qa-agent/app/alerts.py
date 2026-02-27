"""
Alerting System - Slack, Email, and Webhook notifications
"""
import os
import asyncio
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from typing import Dict, List, Optional
import httpx

logger = logging.getLogger("testguard.alerts")


class AlertManager:
    def __init__(self):
        self.slack_webhook = os.getenv("SLACK_WEBHOOK_URL")
        self.smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_user = os.getenv("SMTP_USER")
        self.smtp_pass = os.getenv("SMTP_PASS")
        self.from_email = os.getenv("FROM_EMAIL", self.smtp_user)

    async def send_alert(
        self,
        test_id: str,
        client_name: str,
        url: str,
        status: str,
        summary: Dict,
        screenshots: List[str] = None,
        slack_webhook: str = None,
        email: str = None
    ):
        """Send alerts to all configured channels"""
        tasks = []

        if slack_webhook or self.slack_webhook:
            tasks.append(self._send_slack(
                webhook=slack_webhook or self.slack_webhook,
                test_id=test_id,
                client_name=client_name,
                url=url,
                status=status,
                summary=summary
            ))

        if email:
            tasks.append(self._send_email(
                to=email,
                test_id=test_id,
                client_name=client_name,
                url=url,
                status=status,
                summary=summary,
                screenshots=screenshots
            ))

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.error("Alert channel %d failed: %s", i, result)

    async def _send_slack(
        self,
        webhook: str,
        test_id: str,
        client_name: str,
        url: str,
        status: str,
        summary: Dict
    ):
        """Send Slack notification"""
        is_failure = status == "failed" or summary.get("failed", 0) > 0

        color = "#ff0000" if is_failure else "#00ff88"
        emoji = ":x:" if is_failure else ":white_check_mark:"
        status_text = "FAILED" if is_failure else "PASSED"

        errors_text = ""
        if summary.get("errors"):
            errors_text = "\n".join([f"• {e.get('error', 'Unknown')}" for e in summary["errors"][:5]])

        app_url = os.getenv("APP_URL", "https://app.vibesecurity.in")

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} QA Test {status_text}"
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Client:*\n{client_name}"},
                    {"type": "mrkdwn", "text": f"*URL:*\n{url}"},
                    {"type": "mrkdwn", "text": f"*Test ID:*\n`{test_id}`"},
                    {"type": "mrkdwn", "text": f"*Steps Passed:*\n{summary.get('passed', 0)}"}
                ]
            }
        ]

        if errors_text:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Errors Found:*\n```{errors_text}```"
                }
            })

        blocks.append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "View Full Report"},
                    "url": f"{app_url}/report/{test_id}"
                }
            ]
        })

        payload = {
            "attachments": [{
                "color": color,
                "blocks": blocks
            }]
        }

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(webhook, json=payload)
                resp.raise_for_status()
                logger.info("Slack alert sent for test %s", test_id)
        except httpx.HTTPError as e:
            logger.error("Slack webhook failed for test %s: %s", test_id, e)
            raise

    async def _send_email(
        self,
        to: str,
        test_id: str,
        client_name: str,
        url: str,
        status: str,
        summary: Dict,
        screenshots: List[str] = None
    ):
        """Send email notification"""
        if not self.smtp_user or not self.smtp_pass:
            logger.warning("SMTP not configured, skipping email alert for test %s", test_id)
            return

        is_failure = status == "failed" or summary.get("failed", 0) > 0
        status_text = "FAILED" if is_failure else "PASSED"

        subject = f"QA Test {status_text}: {client_name}"

        errors_html = ""
        if summary.get("errors"):
            errors_html = "<ul>" + "".join([
                f"<li>{e.get('error', 'Unknown')}</li>"
                for e in summary["errors"][:10]
            ]) + "</ul>"

        app_url = os.getenv("APP_URL", "https://app.vibesecurity.in")

        html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: {'#ff4444' if is_failure else '#00cc66'}; color: white; padding: 20px; text-align: center;">
                <h1 style="margin: 0;">QA Test {status_text}</h1>
            </div>
            <div style="padding: 20px; background: #f5f5f5;">
                <table style="width: 100%;">
                    <tr><td><strong>Client:</strong></td><td>{client_name}</td></tr>
                    <tr><td><strong>URL:</strong></td><td>{url}</td></tr>
                    <tr><td><strong>Test ID:</strong></td><td><code>{test_id}</code></td></tr>
                    <tr><td><strong>Steps Passed:</strong></td><td>{summary.get('passed', 0)}</td></tr>
                    <tr><td><strong>Steps Failed:</strong></td><td>{summary.get('failed', 0)}</td></tr>
                </table>
            </div>
            {f'<div style="padding: 20px;"><h3>Errors Found:</h3>{errors_html}</div>' if errors_html else ''}
            <div style="padding: 20px; text-align: center;">
                <a href="{app_url}/report/{test_id}"
                   style="background: #00cc66; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px;">
                    View Full Report
                </a>
            </div>
            <div style="padding: 20px; text-align: center; color: #888; font-size: 12px;">
                <p>TestGuard AI - Autonomous QA Testing</p>
            </div>
        </body>
        </html>
        """

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self.from_email
        msg["To"] = to
        msg.attach(MIMEText(html, "html"))

        if screenshots:
            for i, screenshot_path in enumerate(screenshots[:3]):
                try:
                    with open(screenshot_path, "rb") as f:
                        img = MIMEImage(f.read())
                        img.add_header("Content-ID", f"<screenshot{i}>")
                        img.add_header("Content-Disposition", "attachment", filename=f"screenshot_{i}.png")
                        msg.attach(img)
                except FileNotFoundError:
                    logger.warning("Screenshot not found: %s", screenshot_path)
                except Exception as e:
                    logger.warning("Failed to attach screenshot %s: %s", screenshot_path, e)

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._send_smtp, msg, to)

    def _send_smtp(self, msg: MIMEMultipart, to: str):
        """Send email via SMTP (synchronous)"""
        try:
            server = smtplib.SMTP(self.smtp_host, self.smtp_port)
            server.starttls()
            server.login(self.smtp_user, self.smtp_pass)
            server.sendmail(self.from_email, to, msg.as_string())
            server.quit()
            logger.info("Email sent to %s", to)
        except Exception as e:
            logger.error("Failed to send email to %s: %s", to, e)


# Daily summary email template
DAILY_SUMMARY_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; }
        .header { background: #1a1a1a; color: white; padding: 30px; text-align: center; }
        .stats { display: flex; justify-content: space-around; padding: 20px; background: #f5f5f5; }
        .stat { text-align: center; }
        .stat-value { font-size: 36px; font-weight: bold; }
        .stat-label { color: #666; }
        .passed { color: #00cc66; }
        .failed { color: #ff4444; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f5f5f5; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Daily QA Summary</h1>
        <p>{date}</p>
    </div>
    <div class="stats">
        <div class="stat"><div class="stat-value">{total}</div><div class="stat-label">Total Tests</div></div>
        <div class="stat"><div class="stat-value passed">{passed}</div><div class="stat-label">Passed</div></div>
        <div class="stat"><div class="stat-value failed">{failed}</div><div class="stat-label">Failed</div></div>
        <div class="stat"><div class="stat-value">{success_rate}%</div><div class="stat-label">Success Rate</div></div>
    </div>
    <table>
        <thead><tr><th>Client</th><th>URL</th><th>Objective</th><th>Status</th></tr></thead>
        <tbody>{rows}</tbody>
    </table>
</body>
</html>
"""
