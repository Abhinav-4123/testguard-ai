"""
Multi-LLM Provider - Supports Gemini, OpenAI, and Anthropic
Auto-fallback: tries each provider in order until one works
"""
import os
import json
import logging
from typing import List, Dict, Any, Optional
from abc import ABC, abstractmethod

logger = logging.getLogger("testguard.llm")


class LLMProvider(ABC):
    """Base class for LLM providers"""

    @abstractmethod
    async def chat(
        self,
        messages: List[Dict],
        system_prompt: str,
        tools: List[Dict]
    ) -> Dict[str, Any]:
        """Send a chat request and return response with tool calls"""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this provider is configured"""
        pass


class GeminiProvider(LLMProvider):
    """Google Gemini API provider"""

    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        self.model = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
        self.client = None

        if self.api_key:
            try:
                import google.generativeai as genai
                genai.configure(api_key=self.api_key)
                self.client = genai
            except ImportError:
                pass

    def is_available(self) -> bool:
        return self.client is not None and self.api_key is not None

    def _convert_tools_to_gemini(self, tools: List[Dict]) -> List[Dict]:
        """Convert OpenAI-style tools to Gemini format"""
        from google.generativeai.protos import FunctionDeclaration, Schema, Type

        def convert_schema(schema: Dict) -> Schema:
            """Convert JSON Schema to Gemini Schema"""
            type_mapping = {
                "object": Type.OBJECT,
                "string": Type.STRING,
                "number": Type.NUMBER,
                "integer": Type.INTEGER,
                "boolean": Type.BOOLEAN,
                "array": Type.ARRAY,
            }

            schema_type = schema.get("type", "object")
            gemini_type = type_mapping.get(schema_type, Type.OBJECT)

            schema_kwargs = {"type": gemini_type}

            if "description" in schema:
                schema_kwargs["description"] = schema["description"]

            if "properties" in schema:
                props = {}
                for name, prop_schema in schema["properties"].items():
                    prop_type = prop_schema.get("type", "string")
                    props[name] = Schema(
                        type=type_mapping.get(prop_type, Type.STRING),
                        description=prop_schema.get("description", "")
                    )
                schema_kwargs["properties"] = props

            if "required" in schema:
                schema_kwargs["required"] = schema["required"]

            return Schema(**schema_kwargs)

        gemini_tools = []
        for tool in tools:
            func_decl = FunctionDeclaration(
                name=tool["name"],
                description=tool["description"],
                parameters=convert_schema(tool["input_schema"])
            )
            gemini_tools.append(func_decl)
        return gemini_tools

    def _convert_messages_to_gemini(self, messages: List[Dict]) -> List[Dict]:
        """Convert messages to Gemini format"""
        gemini_messages = []
        for msg in messages:
            if msg["role"] == "user":
                if isinstance(msg["content"], str):
                    gemini_messages.append({"role": "user", "parts": [msg["content"]]})
                elif isinstance(msg["content"], list):
                    # Handle tool results
                    parts = []
                    for item in msg["content"]:
                        if item.get("type") == "tool_result":
                            parts.append({
                                "function_response": {
                                    "name": item.get("tool_use_id", "unknown"),
                                    "response": {"result": item["content"]}
                                }
                            })
                        else:
                            parts.append(str(item))
                    gemini_messages.append({"role": "user", "parts": parts})
            elif msg["role"] == "assistant":
                if isinstance(msg["content"], list):
                    parts = []
                    for item in msg["content"]:
                        if item.get("type") == "text":
                            parts.append(item["text"])
                        elif item.get("type") == "tool_use":
                            parts.append({
                                "function_call": {
                                    "name": item["name"],
                                    "args": item["input"]
                                }
                            })
                    gemini_messages.append({"role": "model", "parts": parts})
                else:
                    gemini_messages.append({"role": "model", "parts": [msg["content"]]})
        return gemini_messages

    async def chat(
        self,
        messages: List[Dict],
        system_prompt: str,
        tools: List[Dict]
    ) -> Dict[str, Any]:
        """Send chat request to Gemini"""
        from google.generativeai.protos import Tool

        gemini_func_decls = self._convert_tools_to_gemini(tools)
        gemini_messages = self._convert_messages_to_gemini(messages)

        # Wrap function declarations in a Tool object
        gemini_tool = Tool(function_declarations=gemini_func_decls)

        model = self.client.GenerativeModel(
            model_name=self.model,
            system_instruction=system_prompt,
            tools=[gemini_tool]
        )

        chat = model.start_chat(history=gemini_messages[:-1] if len(gemini_messages) > 1 else [])
        response = chat.send_message(gemini_messages[-1]["parts"] if gemini_messages else "Start the test")

        # Parse response
        result = {
            "content": [],
            "stop_reason": "end_turn"
        }

        for part in response.parts:
            if hasattr(part, "text") and part.text:
                result["content"].append({
                    "type": "text",
                    "text": part.text
                })
            elif hasattr(part, "function_call"):
                fc = part.function_call
                # Convert MapComposite/protobuf args to proper dict
                args_dict = {}
                try:
                    # Method 1: For protobuf Struct objects
                    if hasattr(fc, 'args') and fc.args is not None:
                        # The args in google-generativeai are returned as a MapComposite
                        # which behaves like a dict but needs explicit conversion
                        raw_args = fc.args

                        # Try direct key access (MapComposite supports this)
                        if hasattr(raw_args, 'keys'):
                            for key in raw_args.keys():
                                args_dict[key] = raw_args[key]
                        elif hasattr(raw_args, '__iter__'):
                            # Iterate as dict-like
                            for key in raw_args:
                                args_dict[key] = raw_args[key]
                        else:
                            # Last resort: type conversion
                            args_dict = dict(raw_args) if raw_args else {}
                except Exception as e:
                    logger.warning("Failed to parse Gemini function call args: %s", e)
                    args_dict = {}

                result["content"].append({
                    "type": "tool_use",
                    "id": f"call_{fc.name}_{id(fc)}",
                    "name": fc.name,
                    "input": args_dict
                })
                result["stop_reason"] = "tool_use"

        return result


class OpenAIProvider(LLMProvider):
    """OpenAI API provider"""

    def __init__(self):
        self.api_key = os.getenv("OPENAI_API_KEY")
        self.model = os.getenv("OPENAI_MODEL", "gpt-4o")
        self.client = None

        if self.api_key:
            try:
                from openai import AsyncOpenAI
                self.client = AsyncOpenAI(api_key=self.api_key)
            except ImportError:
                pass

    def is_available(self) -> bool:
        return self.client is not None and self.api_key is not None

    def _convert_tools_to_openai(self, tools: List[Dict]) -> List[Dict]:
        """Convert to OpenAI function calling format"""
        openai_tools = []
        for tool in tools:
            openai_tools.append({
                "type": "function",
                "function": {
                    "name": tool["name"],
                    "description": tool["description"],
                    "parameters": tool["input_schema"]
                }
            })
        return openai_tools

    def _convert_messages_to_openai(self, messages: List[Dict], system_prompt: str) -> List[Dict]:
        """Convert messages to OpenAI format"""
        openai_messages = [{"role": "system", "content": system_prompt}]

        for msg in messages:
            if msg["role"] == "user":
                if isinstance(msg["content"], str):
                    openai_messages.append({"role": "user", "content": msg["content"]})
                elif isinstance(msg["content"], list):
                    # Handle tool results
                    for item in msg["content"]:
                        if item.get("type") == "tool_result":
                            openai_messages.append({
                                "role": "tool",
                                "tool_call_id": item["tool_use_id"],
                                "content": item["content"]
                            })
            elif msg["role"] == "assistant":
                if isinstance(msg["content"], list):
                    text_content = ""
                    tool_calls = []
                    for item in msg["content"]:
                        if item.get("type") == "text":
                            text_content += item["text"]
                        elif item.get("type") == "tool_use":
                            tool_calls.append({
                                "id": item["id"],
                                "type": "function",
                                "function": {
                                    "name": item["name"],
                                    "arguments": json.dumps(item["input"])
                                }
                            })
                    msg_obj = {"role": "assistant", "content": text_content or None}
                    if tool_calls:
                        msg_obj["tool_calls"] = tool_calls
                    openai_messages.append(msg_obj)
                else:
                    openai_messages.append({"role": "assistant", "content": msg["content"]})

        return openai_messages

    async def chat(
        self,
        messages: List[Dict],
        system_prompt: str,
        tools: List[Dict]
    ) -> Dict[str, Any]:
        """Send chat request to OpenAI"""
        openai_tools = self._convert_tools_to_openai(tools)
        openai_messages = self._convert_messages_to_openai(messages, system_prompt)

        response = await self.client.chat.completions.create(
            model=self.model,
            messages=openai_messages,
            tools=openai_tools,
            tool_choice="auto"
        )

        # Parse response
        result = {
            "content": [],
            "stop_reason": response.choices[0].finish_reason
        }

        message = response.choices[0].message

        if message.content:
            result["content"].append({
                "type": "text",
                "text": message.content
            })

        if message.tool_calls:
            result["stop_reason"] = "tool_use"
            for tc in message.tool_calls:
                result["content"].append({
                    "type": "tool_use",
                    "id": tc.id,
                    "name": tc.function.name,
                    "input": json.loads(tc.function.arguments)
                })

        return result


class AnthropicProvider(LLMProvider):
    """Anthropic Claude API provider"""

    def __init__(self):
        self.api_key = os.getenv("ANTHROPIC_API_KEY")
        self.model = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")
        self.client = None

        if self.api_key:
            try:
                from anthropic import Anthropic
                self.client = Anthropic(api_key=self.api_key)
            except ImportError:
                pass

    def is_available(self) -> bool:
        return self.client is not None and self.api_key is not None

    async def chat(
        self,
        messages: List[Dict],
        system_prompt: str,
        tools: List[Dict]
    ) -> Dict[str, Any]:
        """Send chat request to Anthropic"""
        response = self.client.messages.create(
            model=self.model,
            max_tokens=4096,
            system=system_prompt,
            messages=messages,
            tools=tools
        )

        # Parse response (already in our format)
        result = {
            "content": [],
            "stop_reason": response.stop_reason
        }

        for block in response.content:
            if block.type == "text":
                result["content"].append({
                    "type": "text",
                    "text": block.text
                })
            elif block.type == "tool_use":
                result["content"].append({
                    "type": "tool_use",
                    "id": block.id,
                    "name": block.name,
                    "input": block.input
                })

        return result


class MultiLLMProvider:
    """
    Multi-provider LLM client with automatic fallback.
    Tries providers in order: configured preference > Gemini > OpenAI > Anthropic
    """

    def __init__(self, preferred_provider: str = None):
        self.providers = {
            "gemini": GeminiProvider(),
            "openai": OpenAIProvider(),
            "anthropic": AnthropicProvider()
        }

        # Determine provider order
        self.preferred = preferred_provider or os.getenv("LLM_PROVIDER", "auto")
        self.active_provider = None

    def get_available_providers(self) -> List[str]:
        """Get list of available providers"""
        return [name for name, provider in self.providers.items() if provider.is_available()]

    def _get_provider_order(self) -> List[str]:
        """Get providers in priority order"""
        if self.preferred != "auto" and self.preferred in self.providers:
            # Put preferred first, then others
            order = [self.preferred]
            order.extend([p for p in ["gemini", "openai", "anthropic"] if p != self.preferred])
            return order
        else:
            # Default order: Gemini (cheapest) > OpenAI > Anthropic
            return ["gemini", "openai", "anthropic"]

    async def chat(
        self,
        messages: List[Dict],
        system_prompt: str,
        tools: List[Dict]
    ) -> Dict[str, Any]:
        """
        Send chat request, trying each provider until one succeeds.
        """
        errors = []

        for provider_name in self._get_provider_order():
            provider = self.providers[provider_name]

            if not provider.is_available():
                continue

            try:
                self.active_provider = provider_name
                result = await provider.chat(messages, system_prompt, tools)
                return result

            except Exception as e:
                error_detail = f"{provider_name}: {str(e)}"
                logger.error("LLM provider %s failed: %s", provider_name, e, exc_info=True)
                errors.append(error_detail)
                continue

        # All providers failed
        raise Exception(f"All LLM providers failed: {'; '.join(errors)}")

    def get_active_provider(self) -> str:
        """Get the currently active provider name"""
        return self.active_provider


def get_llm_client(preferred_provider: str = None) -> MultiLLMProvider:
    """Factory function to create LLM client"""
    return MultiLLMProvider(preferred_provider)
