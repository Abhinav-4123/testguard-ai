"""
Daily Test Scheduler
Runs configured tests every morning and sends reports
"""
import os
import asyncio
import logging
import httpx
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import List, Dict

logger = logging.getLogger("testguard.scheduler")

API_URL = os.getenv("API_URL", "http://localhost:8000")

# Configure your clients' tests here
DAILY_TESTS = [
    {
        "client": "Acme Corp",
        "url": "https://app.acme.com",
        "objective": "login",
        "credentials": {
            "username": "qa-test@acme.com",
            "password": "QaTest123!"
        },
        "notify_email": "dev@acme.com",
        "notify_slack": "https://hooks.slack.com/services/xxx/yyy/zzz"
    },
    # Add more clients here
]


async def run_daily_tests():
    """Run all configured daily tests"""
    logger.info("Daily QA Test Run - %s", datetime.now().strftime("%Y-%m-%d %H:%M"))

    results = []

    async with httpx.AsyncClient(timeout=300) as client:
        for test_config in DAILY_TESTS:
            logger.info("Testing: %s - %s", test_config['client'], test_config['url'])

            try:
                # Start test
                payload = {
                    "url": test_config["url"],
                    "objective": test_config["objective"]
                }
                if test_config.get("credentials"):
                    payload["credentials"] = test_config["credentials"]

                response = await client.post(f"{API_URL}/test", json=payload)
                test_data = response.json()
                test_id = test_data["test_id"]

                # Wait for completion
                while True:
                    status_response = await client.get(f"{API_URL}/test/{test_id}")
                    status = status_response.json()

                    if status["status"] in ["completed", "failed"]:
                        break

                    await asyncio.sleep(5)

                # Get report
                report_response = await client.get(f"{API_URL}/report/{test_id}")
                report = report_response.json().get("report", "No report available")

                result = {
                    "client": test_config["client"],
                    "url": test_config["url"],
                    "status": status["status"],
                    "summary": status.get("summary", {}),
                    "report": report,
                    "config": test_config
                }
                results.append(result)

                # Send notifications
                if status["status"] == "failed" or status.get("summary", {}).get("failed", 0) > 0:
                    await send_alert(result)
                else:
                    await send_success_notification(result)

            except Exception as e:
                logger.error("Error testing %s: %s", test_config['client'], e)
                results.append({
                    "client": test_config["client"],
                    "url": test_config["url"],
                    "status": "error",
                    "error": str(e)
                })

    # Generate daily summary
    await generate_summary(results)

    return results


async def send_alert(result: Dict):
    """Send alert for failed tests"""
    config = result["config"]

    message = f"""
QA ALERT: {result['client']}

URL: {result['url']}
Status: FAILED

Issues Found:
{result.get('summary', {}).get('errors', ['Unknown error'])}

Full Report:
{result.get('report', 'No report available')[:1000]}
"""

    # Send Slack notification
    if config.get("notify_slack"):
        try:
            async with httpx.AsyncClient() as client:
                await client.post(config["notify_slack"], json={
                    "text": f":x: QA Test Failed for {result['client']}",
                    "blocks": [
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": f"*QA Test Failed*\n*Client:* {result['client']}\n*URL:* {result['url']}"
                            }
                        }
                    ]
                })
        except Exception as e:
            logger.error("Failed to send Slack alert: %s", e)

    # Send email
    if config.get("notify_email"):
        await send_email(
            to=config["notify_email"],
            subject=f"QA ALERT: {result['client']} - Test Failed",
            body=message
        )


async def send_success_notification(result: Dict):
    """Send success notification (optional, can be disabled)"""
    config = result["config"]

    # Only send to Slack on success (less intrusive)
    if config.get("notify_slack"):
        try:
            async with httpx.AsyncClient() as client:
                await client.post(config["notify_slack"], json={
                    "text": f":white_check_mark: QA Test Passed for {result['client']}"
                })
        except Exception as e:
            logger.warning("Slack notification failed: %s", e)


async def send_email(to: str, subject: str, body: str):
    """Send email notification"""
    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASS")
    from_email = os.getenv("FROM_EMAIL", smtp_user)

    if not smtp_user or not smtp_pass:
        logger.warning("Email not configured, skipping email notification")
        return

    msg = MIMEMultipart()
    msg["From"] = from_email
    msg["To"] = to
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP(smtp_host, smtp_port)
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.sendmail(from_email, to, msg.as_string())
        server.quit()
        logger.info("Email sent to %s", to)
    except Exception as e:
        logger.error("Failed to send email: %s", e)


async def generate_summary(results: List[Dict]):
    """Generate and save daily summary"""
    timestamp = datetime.now()

    passed = len([r for r in results if r["status"] == "completed" and not r.get("summary", {}).get("failed")])
    failed = len(results) - passed

    summary = f"""
# Daily QA Summary - {timestamp.strftime('%Y-%m-%d')}

## Overview
- Total Tests: {len(results)}
- Passed: {passed}
- Failed: {failed}
- Success Rate: {(passed/len(results)*100) if results else 0:.1f}%

## Results

| Client | URL | Status |
|--------|-----|--------|
"""
    for r in results:
        status = "PASS" if r["status"] == "completed" and not r.get("summary", {}).get("failed") else "FAIL"
        summary += f"| {r['client']} | {r['url'][:40]} | {status} |\n"

    # Save summary
    os.makedirs("reports", exist_ok=True)
    with open(f"reports/daily_summary_{timestamp.strftime('%Y%m%d')}.md", "w") as f:
        f.write(summary)

    logger.info("Daily summary:\n%s", summary)


if __name__ == "__main__":
    asyncio.run(run_daily_tests())
