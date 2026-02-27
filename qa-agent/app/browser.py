"""
Browser Controller - Playwright-based browser automation
"""
import os
import asyncio
import logging
from datetime import datetime
from typing import Optional
from playwright.async_api import async_playwright, Browser, Page, BrowserContext

logger = logging.getLogger("testguard.browser")


class BrowserController:
    def __init__(self, headless: bool = True, screenshots_dir: str = "screenshots"):
        self.headless = headless
        self.screenshots_dir = screenshots_dir
        self.playwright = None
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None

        os.makedirs(screenshots_dir, exist_ok=True)

    async def start(self):
        """Start the browser"""
        self.playwright = await async_playwright().start()

        # Use Chromium for best compatibility
        self.browser = await self.playwright.chromium.launch(
            headless=self.headless,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--disable-dev-shm-usage",
                "--no-sandbox"
            ]
        )

        # Create context with realistic settings
        self.context = await self.browser.new_context(
            viewport={"width": 1920, "height": 1080},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            locale="en-US",
            timezone_id="America/New_York"
        )

        self.page = await self.context.new_page()

        # Set default timeout
        self.page.set_default_timeout(30000)

    async def stop(self):
        """Stop the browser"""
        try:
            if self.browser:
                await self.browser.close()
            if self.playwright:
                await self.playwright.stop()
        except Exception as e:
            logger.warning("Error stopping browser: %s", e)

    async def navigate(self, url: str):
        """Navigate to a URL"""
        try:
            await self.page.goto(url, wait_until="networkidle", timeout=30000)
        except Exception as e:
            logger.warning("Navigation to %s failed with networkidle, retrying with load: %s", url, e)
            await self.page.goto(url, wait_until="load", timeout=30000)

    async def click(self, selector: str, by_text: bool = False):
        """Click an element"""
        if by_text:
            # Find by visible text
            element = self.page.get_by_text(selector, exact=False).first
            await element.click()
        else:
            # Try CSS selector first
            try:
                await self.page.click(selector, timeout=5000)
            except Exception:
                # Fallback to text search
                element = self.page.get_by_text(selector, exact=False).first
                await element.click()

    async def type_text(self, selector: str, text: str, clear_first: bool = True):
        """Type text into an input field"""
        if clear_first:
            await self.page.fill(selector, text)
        else:
            await self.page.type(selector, text)

    async def screenshot(self, name: str) -> str:
        """Take a screenshot"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{name}_{timestamp}.png"
        path = os.path.join(self.screenshots_dir, filename)
        await self.page.screenshot(path=path, full_page=False)
        return path

    async def wait(self, seconds: float):
        """Wait for a specified time"""
        await asyncio.sleep(seconds)

    async def wait_for_element(self, selector: str, timeout: int = 10000):
        """Wait for an element to appear"""
        await self.page.wait_for_selector(selector, timeout=timeout)

    async def get_page_content(self) -> str:
        """Get page content as structured text"""
        # Get visible text content
        content = await self.page.evaluate("""() => {
            function getVisibleText(element) {
                if (!element) return '';

                const style = window.getComputedStyle(element);
                if (style.display === 'none' || style.visibility === 'hidden') {
                    return '';
                }

                let text = '';

                // Handle specific elements
                if (element.tagName === 'INPUT') {
                    const type = element.type || 'text';
                    const placeholder = element.placeholder || '';
                    const value = element.value || '';
                    return `[INPUT:${type} placeholder="${placeholder}" value="${value}"]`;
                }
                if (element.tagName === 'BUTTON') {
                    return `[BUTTON: ${element.innerText.trim()}]`;
                }
                if (element.tagName === 'A') {
                    return `[LINK: ${element.innerText.trim()} -> ${element.href}]`;
                }
                if (element.tagName === 'IMG') {
                    return `[IMAGE: ${element.alt || 'no alt'}]`;
                }

                for (const child of element.childNodes) {
                    if (child.nodeType === Node.TEXT_NODE) {
                        const trimmed = child.textContent.trim();
                        if (trimmed) text += trimmed + ' ';
                    } else if (child.nodeType === Node.ELEMENT_NODE) {
                        text += getVisibleText(child);
                    }
                }

                return text;
            }

            return getVisibleText(document.body);
        }""")

        # Also get the page structure
        structure = await self.page.evaluate("""() => {
            const forms = document.querySelectorAll('form');
            const buttons = document.querySelectorAll('button, input[type="submit"], [role="button"]');
            const inputs = document.querySelectorAll('input, textarea, select');
            const links = document.querySelectorAll('a[href]');

            return {
                title: document.title,
                url: window.location.href,
                forms: forms.length,
                buttons: Array.from(buttons).slice(0, 10).map(b => ({
                    text: b.innerText || b.value || 'unnamed',
                    selector: b.id ? '#' + b.id : (b.className ? '.' + b.className.split(' ')[0] : b.tagName)
                })),
                inputs: Array.from(inputs).slice(0, 10).map(i => ({
                    type: i.type || 'text',
                    name: i.name || i.id || 'unnamed',
                    placeholder: i.placeholder || '',
                    selector: i.id ? '#' + i.id : (i.name ? `[name="${i.name}"]` : i.tagName)
                })),
                mainLinks: Array.from(links).slice(0, 10).map(a => ({
                    text: a.innerText.trim().slice(0, 50),
                    href: a.href
                }))
            };
        }""")

        return f"""
PAGE: {structure['title']}
URL: {structure['url']}

FORMS: {structure['forms']}

BUTTONS:
{chr(10).join([f"  - {b['text'][:30]} ({b['selector']})" for b in structure['buttons']])}

INPUTS:
{chr(10).join([f"  - {i['name']} [{i['type']}] placeholder='{i['placeholder']}' selector={i['selector']}" for i in structure['inputs']])}

LINKS:
{chr(10).join([f"  - {l['text'][:40]}" for l in structure['mainLinks']])}

VISIBLE TEXT:
{content[:2000]}
"""

    async def check_element(self, selector: str) -> bool:
        """Check if an element exists and is visible"""
        try:
            element = await self.page.query_selector(selector)
            if element:
                return await element.is_visible()
            return False
        except Exception as e:
            logger.debug("check_element failed for %s: %s", selector, e)
            return False

    async def get_screenshot_base64(self) -> str:
        """Get screenshot as base64 for API responses"""
        import base64
        screenshot_bytes = await self.page.screenshot()
        return base64.b64encode(screenshot_bytes).decode()
