"""
QA Agent - AI-powered test execution
Supports: Gemini, OpenAI, and Anthropic (auto-fallback)
"""
import os
import json
from datetime import datetime
from typing import Optional, List, Dict, Any
from .browser import BrowserController
from .llm_provider import get_llm_client, MultiLLMProvider

# The core QA Agent system prompt
QA_SYSTEM_PROMPT = """You are a Senior QA Engineer with 10+ years of experience testing web applications.

## Your Mission
Test the web application thoroughly by executing the specified objective. You must:
1. Navigate the application like a real user would
2. Identify broken flows, UI bugs, and UX issues
3. Document everything you find with screenshots
4. Never give up - try alternative approaches if something fails

## Your Capabilities
You can use these tools:
- `navigate(url)`: Go to a URL
- `click(selector)`: Click an element (CSS selector or text content)
- `type_text(selector, text)`: Type text into an input field
- `screenshot(name)`: Take a screenshot
- `wait(seconds)`: Wait for page to load
- `get_page_content()`: Get the full page HTML
- `check_element(selector)`: Check if element is visible

## Testing Strategies

### For Login Flow:
1. Navigate to the login page
2. Look for username/email and password fields
3. Enter credentials
4. Click the login/submit button
5. Verify successful login (look for dashboard, user menu, or welcome message)
6. Screenshot the result

### For Signup Flow:
1. Find the signup/register link
2. Fill all required fields (use test data)
3. Handle any verification steps
4. Complete registration
5. Verify account creation

### For Checkout Flow:
1. Find a product to add to cart
2. Add to cart
3. Go to cart/checkout
4. Fill shipping/billing info
5. Attempt to reach payment (stop before actual payment)
6. Document any errors or broken steps

## Error Handling
- If a button doesn't work, try clicking by text content
- If a form fails, check for validation errors
- If page doesn't load, wait and retry
- Always take screenshots of errors
- Document the exact error message and element

## Output Format
After each action, report:
- ACTION: What you did
- RESULT: What happened
- STATUS: SUCCESS / FAILURE / WARNING
- NEXT: What you'll do next

When finished, provide a summary with:
- Total steps completed
- Failures found
- Screenshots taken
- Recommendations
"""

# Test data for automated testing
TEST_DATA = {
    "email": "qatest_{timestamp}@testmail.com",
    "password": "TestPass123!",
    "first_name": "Test",
    "last_name": "User",
    "phone": "555-123-4567",
    "address": "123 Test Street",
    "city": "Test City",
    "zip": "12345",
    "card_number": os.getenv("TEST_CARD_NUMBER", "4111111111111111"),
    "card_exp": os.getenv("TEST_CARD_EXP", "12/28"),
    "card_cvv": os.getenv("TEST_CARD_CVV", "123"),
}


class QAAgent:
    """
    AI-powered QA testing agent.

    Supports multiple LLM providers with automatic fallback:
    - Gemini (default, cheapest)
    - OpenAI (GPT-4o)
    - Anthropic (Claude)

    Set LLM_PROVIDER env var to: "gemini", "openai", "anthropic", or "auto"
    """

    def __init__(
        self,
        gemini_api_key: str = None,
        openai_api_key: str = None,
        anthropic_api_key: str = None,
        preferred_provider: str = None
    ):
        # Set API keys if provided
        if gemini_api_key:
            os.environ["GEMINI_API_KEY"] = gemini_api_key
        if openai_api_key:
            os.environ["OPENAI_API_KEY"] = openai_api_key
        if anthropic_api_key:
            os.environ["ANTHROPIC_API_KEY"] = anthropic_api_key

        # Initialize multi-provider LLM client
        self.llm = get_llm_client(preferred_provider)
        self.browser = None
        self.screenshots = []
        self.actions_log = []
        self.errors = []

    async def run_test(
        self,
        url: str,
        objective: str,
        credentials: Optional[Dict] = None,
        custom_steps: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Execute a QA test for the given URL and objective.
        """
        self.browser = BrowserController()
        await self.browser.start()

        try:
            # Build the task prompt
            task_prompt = self._build_task_prompt(
                url, objective, credentials, custom_steps
            )

            # Run the AI agent loop
            results = await self._agent_loop(task_prompt)

            # Add provider info to results
            results["llm_provider"] = self.llm.get_active_provider()

            return results

        finally:
            await self.browser.stop()

    def _build_task_prompt(
        self,
        url: str,
        objective: str,
        credentials: Optional[Dict],
        custom_steps: Optional[List[str]]
    ) -> str:
        """Build the task-specific prompt for the agent"""

        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        test_data = {k: v.format(timestamp=timestamp) if "{timestamp}" in str(v) else v
                     for k, v in TEST_DATA.items()}

        prompt = f"""
## Test Configuration
- **Target URL**: {url}
- **Objective**: {objective}
- **Timestamp**: {datetime.now().isoformat()}

## Credentials
"""
        if credentials and credentials.get("username"):
            prompt += f"- Username: {credentials['username']}\n"
            prompt += f"- Password: {credentials['password']}\n"
            if credentials.get("login_url"):
                prompt += f"- Login URL: {credentials['login_url']}\n"
        else:
            prompt += "- No credentials provided. Use test data if signup is needed.\n"

        prompt += f"""
## Test Data Available
{json.dumps(test_data, indent=2)}

## Your Task
"""
        if custom_steps:
            prompt += "Execute these specific steps:\n"
            for i, step in enumerate(custom_steps, 1):
                prompt += f"{i}. {step}\n"
        else:
            objective_tasks = {
                "login": """
1. Navigate to the target URL
2. Find and click the login link/button
3. Enter the provided credentials
4. Submit the login form
5. Verify successful login
6. Take screenshots at each step
""",
                "signup": """
1. Navigate to the target URL
2. Find the signup/register option
3. Fill out the registration form with test data
4. Submit the form
5. Handle any verification steps
6. Verify account creation
7. Take screenshots at each step
""",
                "checkout": """
1. Navigate to the target URL
2. Browse products and select one
3. Add the product to cart
4. Proceed to checkout
5. Fill shipping information
6. Proceed to payment (DO NOT complete actual payment)
7. Document the checkout flow
8. Take screenshots at each step
""",
                "full_flow": """
1. Navigate to the target URL
2. Complete signup with test data
3. Login with created account
4. Perform a core user action (browse, add to cart, etc.)
5. Document the entire flow
6. Take screenshots at each step
"""
            }
            prompt += objective_tasks.get(objective, objective_tasks["login"])

        prompt += """
## Important
- Take a screenshot after EVERY significant action
- If something fails, try an alternative approach
- Document ALL errors you encounter
- Be thorough but efficient
"""
        return prompt

    async def _agent_loop(self, task_prompt: str) -> Dict[str, Any]:
        """
        Main agent loop - uses LLM to decide actions and execute them
        """
        messages = [{"role": "user", "content": task_prompt}]
        max_iterations = 30
        iteration = 0

        while iteration < max_iterations:
            iteration += 1

            # Get LLM decision (works with any provider)
            response = await self.llm.chat(
                messages=messages,
                system_prompt=QA_SYSTEM_PROMPT,
                tools=self._get_tools()
            )

            # Process the response
            assistant_content = []
            tool_results = []

            for block in response["content"]:
                if block["type"] == "text":
                    assistant_content.append({"type": "text", "text": block["text"]})
                    self.actions_log.append({
                        "iteration": iteration,
                        "type": "reasoning",
                        "content": block["text"]
                    })

                elif block["type"] == "tool_use":
                    assistant_content.append({
                        "type": "tool_use",
                        "id": block["id"],
                        "name": block["name"],
                        "input": block["input"]
                    })

                    # Execute the tool
                    result = await self._execute_tool(block["name"], block["input"])

                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block["id"],
                        "content": result
                    })

                    self.actions_log.append({
                        "iteration": iteration,
                        "type": "tool",
                        "tool": block["name"],
                        "input": block["input"],
                        "result": result
                    })

            # Add assistant message
            messages.append({"role": "assistant", "content": assistant_content})

            # Add tool results if any
            if tool_results:
                messages.append({"role": "user", "content": tool_results})

            # Check if done
            if response["stop_reason"] == "end_turn" and not tool_results:
                break

        # Compile results
        return {
            "passed": len([a for a in self.actions_log if "SUCCESS" in str(a.get("result", ""))]),
            "failed": len(self.errors),
            "steps_completed": [a for a in self.actions_log if a["type"] == "tool"],
            "errors": self.errors,
            "screenshots": self.screenshots,
            "full_log": self.actions_log
        }

    def _get_tools(self) -> List[Dict]:
        """Define the tools available to the agent"""
        return [
            {
                "name": "navigate",
                "description": "Navigate to a URL",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "The URL to navigate to"}
                    },
                    "required": ["url"]
                }
            },
            {
                "name": "click",
                "description": "Click on an element. Use CSS selector or text content.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "selector": {"type": "string", "description": "CSS selector or text to click"},
                        "by_text": {"type": "boolean", "description": "If true, find element by visible text", "default": False}
                    },
                    "required": ["selector"]
                }
            },
            {
                "name": "type_text",
                "description": "Type text into an input field",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "selector": {"type": "string", "description": "CSS selector of the input"},
                        "text": {"type": "string", "description": "Text to type"},
                        "clear_first": {"type": "boolean", "description": "Clear field before typing", "default": True}
                    },
                    "required": ["selector", "text"]
                }
            },
            {
                "name": "screenshot",
                "description": "Take a screenshot of the current page",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Name for the screenshot"}
                    },
                    "required": ["name"]
                }
            },
            {
                "name": "wait",
                "description": "Wait for a specified time or for an element",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "seconds": {"type": "number", "description": "Seconds to wait"},
                        "for_selector": {"type": "string", "description": "Wait for this element to appear"}
                    }
                }
            },
            {
                "name": "get_page_content",
                "description": "Get the current page's visible text content and structure",
                "input_schema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "check_element",
                "description": "Check if an element exists and is visible",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "selector": {"type": "string", "description": "CSS selector to check"}
                    },
                    "required": ["selector"]
                }
            },
            {
                "name": "complete_test",
                "description": "Mark the test as complete and provide summary",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "status": {"type": "string", "enum": ["PASSED", "FAILED", "PARTIAL"]},
                        "summary": {"type": "string", "description": "Test summary"},
                        "issues_found": {"type": "array", "items": {"type": "string"}}
                    },
                    "required": ["status", "summary"]
                }
            }
        ]

    async def _execute_tool(self, tool_name: str, inputs: Dict) -> str:
        """Execute a tool and return the result"""
        try:
            if tool_name == "navigate":
                await self.browser.navigate(inputs["url"])
                return f"SUCCESS: Navigated to {inputs['url']}"

            elif tool_name == "click":
                by_text = inputs.get("by_text", False)
                await self.browser.click(inputs["selector"], by_text=by_text)
                return f"SUCCESS: Clicked on '{inputs['selector']}'"

            elif tool_name == "type_text":
                await self.browser.type_text(
                    inputs["selector"],
                    inputs["text"],
                    clear_first=inputs.get("clear_first", True)
                )
                return f"SUCCESS: Typed text into '{inputs['selector']}'"

            elif tool_name == "screenshot":
                path = await self.browser.screenshot(inputs["name"])
                self.screenshots.append(path)
                return f"SUCCESS: Screenshot saved as '{path}'"

            elif tool_name == "wait":
                if inputs.get("for_selector"):
                    await self.browser.wait_for_element(inputs["for_selector"])
                    return f"SUCCESS: Element '{inputs['for_selector']}' appeared"
                else:
                    await self.browser.wait(inputs.get("seconds", 2))
                    return f"SUCCESS: Waited {inputs.get('seconds', 2)} seconds"

            elif tool_name == "get_page_content":
                content = await self.browser.get_page_content()
                return f"SUCCESS: Page content:\n{content[:3000]}..."

            elif tool_name == "check_element":
                exists = await self.browser.check_element(inputs["selector"])
                if exists:
                    return f"SUCCESS: Element '{inputs['selector']}' exists and is visible"
                else:
                    return f"FAILURE: Element '{inputs['selector']}' not found"

            elif tool_name == "complete_test":
                return f"TEST COMPLETE: {inputs['status']}\nSummary: {inputs['summary']}"

            else:
                return f"ERROR: Unknown tool '{tool_name}'"

        except Exception as e:
            error_msg = f"ERROR in {tool_name}: {str(e)}"
            self.errors.append({"tool": tool_name, "error": str(e), "inputs": inputs})
            return error_msg
