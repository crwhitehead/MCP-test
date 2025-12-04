"""
Multi-Model Support for MCP Testing
Supports: Gemini, OpenAI GPT, and Custom Endpoints
"""
import os
import asyncio
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
import google.generativeai as genai
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


class ModelAdapter(ABC):
    """Base class for model adapters"""

    def __init__(self, model_name: str, api_key: str = None):
        self.model_name = model_name
        self.api_key = api_key or self._get_default_api_key()
        self.mcp_session = None
        self.exit_stack = None
        self.payload_log = []

    @abstractmethod
    def _get_default_api_key(self) -> str:
        """Get default API key from environment"""
        pass

    @abstractmethod
    async def send_message(self, message: str, tools: List[Dict] = None) -> Any:
        """Send a message to the model"""
        pass

    @abstractmethod
    async def send_function_response(self, function_name: str, response_content: str) -> Any:
        """Send function response back to model"""
        pass

    @abstractmethod
    def extract_function_call(self, response: Any) -> Dict:
        """Extract function call from model response"""
        pass

    @abstractmethod
    def extract_text_response(self, response: Any) -> str:
        """Extract text from model response"""
        pass

    def _log_payload(self, stage: str, payload: Any):
        """Record the exact payload we sent to the LLM for auditing."""
        self.payload_log.append({"stage": stage, "payload": payload})

    async def connect_to_mcp_server(self, server_script_path: str, env: Optional[Dict[str, str]] = None):
        """Connect to MCP server (shared across all adapters)"""
        from contextlib import AsyncExitStack
        import sys

        python_path = sys.executable
        server_params = StdioServerParameters(
            command=python_path,
            args=[server_script_path],
            env=env
        )

        self.exit_stack = AsyncExitStack()
        await self.exit_stack.__aenter__()

        stdio_transport = await self.exit_stack.enter_async_context(stdio_client(server_params))
        stdio, write = stdio_transport
        self.mcp_session = await self.exit_stack.enter_async_context(ClientSession(stdio, write))

        await self.mcp_session.initialize()

        # List available tools
        response = await self.mcp_session.list_tools()
        return response.tools

    async def call_mcp_tool(self, tool_name: str, arguments: Dict[str, Any]) -> str:
        """Call an MCP tool"""
        result = await self.mcp_session.call_tool(tool_name, arguments)
        if hasattr(result, 'content') and result.content:
            content_parts = []
            for item in result.content:
                if hasattr(item, 'text'):
                    content_parts.append(item.text)
            return '\n'.join(content_parts)
        return str(result)

    async def cleanup(self):
        """Clean up connections"""
        if self.exit_stack:
            await self.exit_stack.__aexit__(None, None, None)


class GeminiAdapter(ModelAdapter):
    """Adapter for Google Gemini models"""

    def __init__(self, model_name: str = "gemini-2.5-flash", api_key: str = None):
        super().__init__(model_name, api_key)
        genai.configure(api_key=self.api_key)
        self.model = genai.GenerativeModel(model_name)
        self.chat = None

    def _get_default_api_key(self) -> str:
        return os.environ.get('GEMINI_API_KEY', '')

    def _send_message_blocking(self, message: str, tools: List[Dict] = None) -> Any:
        if self.chat is None:
            self.chat = self.model.start_chat(enable_automatic_function_calling=False)

        if tools:
            payload = {
                "contents": [{"role": "user", "parts": [{"text": message}]}],
                "tools": [{"function_declarations": tools}],
            }
            self._log_payload("initial_prompt", payload)
            return self.chat.send_message(
                message,
                tools=[{'function_declarations': tools}]
            )
        self._log_payload("initial_prompt", {"contents": [{"role": "user", "parts": [{"text": message}]}]})
        return self.chat.send_message(message)

    async def send_message(self, message: str, tools: List[Dict] = None) -> Any:
        """Send message to Gemini (offloaded to a thread)."""
        return await asyncio.to_thread(self._send_message_blocking, message, tools)

    def _send_function_response_blocking(self, function_name: str, response_content: str) -> Any:
        parts = [
            genai.protos.Part(
                function_response=genai.protos.FunctionResponse(
                    name=function_name,
                    response={'result': response_content}
                )
            )
        ]

        content_obj = genai.protos.Content(parts=parts)
        self._log_payload(
            "function_response",
            {"function_response": {"name": function_name, "response": {"result": response_content}}},
        )
        return self.chat.send_message(content_obj)

    async def send_function_response(self, function_name: str, response_content: str) -> Any:
        """Send function response to Gemini (offloaded to a thread)."""
        return await asyncio.to_thread(self._send_function_response_blocking, function_name, response_content)

    def extract_function_call(self, response: Any) -> Dict:
        """Extract function call from Gemini response"""
        if not response.candidates:
            return None

        candidate = response.candidates[0]
        if not hasattr(candidate.content, 'parts') or not candidate.content.parts:
            return None

        for part in candidate.content.parts:
            if hasattr(part, 'function_call') and part.function_call and part.function_call.name:
                return {
                    'name': part.function_call.name,
                    'arguments': dict(part.function_call.args) if part.function_call.args else {}
                }

        return None

    def extract_text_response(self, response: Any) -> str:
        """Extract text from Gemini response"""
        if response and response.candidates:
            candidate = response.candidates[0]
            if hasattr(candidate, 'content') and candidate.content:
                if hasattr(candidate.content, 'parts') and candidate.content.parts:
                    text_parts = [
                        part.text for part in candidate.content.parts
                        if hasattr(part, 'text') and part.text
                    ]
                    return '\n'.join(text_parts) if text_parts else "[No text in response]"
        return "[No response]"


class OpenAIAdapter(ModelAdapter):
    """Adapter for OpenAI GPT models"""

    def __init__(self, model_name: str = "gpt-4o", api_key: str = None):
        super().__init__(model_name, api_key)
        try:
            import openai
            self.openai = openai
            base_url = os.environ.get("OPENAI_BASE_URL")
            client_kwargs = {"api_key": self.api_key}
            if base_url:
                client_kwargs["base_url"] = base_url
            self.client = openai.OpenAI(**client_kwargs)
        except ImportError:
            raise ImportError("openai package not installed. Run: pip install openai")

        self.messages = []
        self.tools_schema = None

    def _get_default_api_key(self) -> str:
        return os.environ.get('OPENAI_API_KEY', '')

    def _convert_mcp_tools_to_openai(self, tools: List[Dict]) -> List[Dict]:
        """Convert MCP tool format to OpenAI function calling format"""
        openai_tools = []
        for tool in tools:
            openai_tools.append({
                'type': 'function',
                'function': {
                    'name': tool['name'],
                    'description': tool['description'],
                    'parameters': tool['parameters']
                }
            })
        return openai_tools

    async def send_message(self, message: str, tools: List[Dict] = None) -> Any:
        """Send message to OpenAI"""
        self.messages.append({'role': 'user', 'content': message})

        kwargs = {
            'model': self.model_name,
            'messages': self.messages
        }

        if tools:
            self.tools_schema = self._convert_mcp_tools_to_openai(tools)
            kwargs['tools'] = self.tools_schema
            kwargs['tool_choice'] = 'auto'

        self._log_payload("initial_prompt", kwargs)
        response = await asyncio.to_thread(self.client.chat.completions.create, **kwargs)

        # Add assistant response to history
        self.messages.append(response.choices[0].message.model_dump())

        return response

    async def send_function_response(self, function_name: str, response_content: str) -> Any:
        """Send function response to OpenAI"""
        # Add tool response to messages
        self.messages.append({
            'role': 'tool',
            'tool_call_id': self.messages[-1].get('tool_calls', [{}])[0].get('id', 'call_0'),
            'name': function_name,
            'content': response_content
        })

        payload = {
            "model": self.model_name,
            "messages": self.messages,
        }

        if self.tools_schema:
            payload["tools"] = self.tools_schema

        self._log_payload("function_response", payload)

        response = await asyncio.to_thread(self.client.chat.completions.create, **payload)

        # Add to history
        self.messages.append(response.choices[0].message.model_dump())

        return response

    def extract_function_call(self, response: Any) -> Dict:
        """Extract function call from OpenAI response"""
        choice = response.choices[0]
        if choice.message.tool_calls:
            tool_call = choice.message.tool_calls[0]
            import json
            return {
                'name': tool_call.function.name,
                'arguments': json.loads(tool_call.function.arguments)
            }
        return None

    def extract_text_response(self, response: Any) -> str:
        """Extract text from OpenAI response"""
        choice = response.choices[0]
        if choice.message.content:
            return choice.message.content
        return "[No text response]"


class CustomEndpointAdapter(ModelAdapter):
    """Adapter for custom API endpoints (like gpt-5-nano)"""

    def __init__(self, model_name: str, endpoint_url: str, api_key: str = None, **kwargs):
        super().__init__(model_name, api_key)
        self.endpoint_url = endpoint_url
        self.extra_config = kwargs
        self.conversation_history = []

    def _get_default_api_key(self) -> str:
        return os.environ.get('LLM_API_KEY', '')

    async def send_message(self, message: str, tools: List[Dict] = None) -> Any:
        """Send message to custom endpoint"""
        import requests

        headers = {
            'cf-aig-authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }

        # Build the prompt
        full_prompt = message
        if tools:
            tools_desc = "\n\nAvailable tools:\n"
            for tool in tools:
                tools_desc += f"- {tool['name']}: {tool['description']}\n"
            full_prompt += tools_desc

        data = {
            'model': self.model_name,
            'input': [{'role': 'user', 'content': full_prompt}],
            'max_output_tokens': 1000,
            **self.extra_config
        }

        response = requests.post(self.endpoint_url, headers=headers, json=data)
        response.raise_for_status()
        result = response.json()

        self.conversation_history.append({
            'request': data,
            'response': result
        })

        return result

    async def send_function_response(self, function_name: str, response_content: str) -> Any:
        """Send function response to custom endpoint"""
        import requests

        headers = {
            'cf-aig-authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }

        prompt = f"Tool {function_name} returned:\n{response_content}\n\nRespond to the user."

        data = {
            'model': self.model_name,
            'input': [{'role': 'user', 'content': prompt}],
            'max_output_tokens': 1000,
            **self.extra_config
        }

        response = requests.post(self.endpoint_url, headers=headers, json=data)
        response.raise_for_status()
        result = response.json()

        self.conversation_history.append({
            'request': data,
            'response': result
        })

        return result

    def extract_function_call(self, response: Any) -> Dict:
        """Extract function call from custom endpoint response"""
        # Custom endpoints might not support native function calling
        # Try to parse from text
        if 'output' in response:
            for output in response['output']:
                if output.get('type') == 'message':
                    text = output.get('content', [{}])[0].get('text', '')
                    # Look for function call patterns
                    import re
                    match = re.search(r'CALL_TOOL:\s*(\w+)\s*\((.*?)\)', text)
                    if match:
                        tool_name = match.group(1)
                        args_str = match.group(2)
                        # Very basic parsing - would need improvement
                        return {
                            'name': tool_name,
                            'arguments': {'raw': args_str}
                        }
        return None

    def extract_text_response(self, response: Any) -> str:
        """Extract text from custom endpoint response"""
        if 'output' in response:
            for output in response['output']:
                if output.get('type') == 'message':
                    content = output.get('content', [])
                    if content and 'text' in content[0]:
                        return content[0]['text']
        return "[No response from custom endpoint]"


# Model registry
MODEL_REGISTRY = {
    'gemini-2.5-flash': lambda: GeminiAdapter('gemini-2.5-flash'),
    'gemini-2.5-pro': lambda: GeminiAdapter('gemini-2.5-pro'),
    'gemini-2.5-flash-lite': lambda: GeminiAdapter('gemini-2.5-flash-lite'),
    'gpt-4o': lambda: OpenAIAdapter('gpt-4o'),
    'gpt-4o-mini': lambda: OpenAIAdapter('gpt-4o-mini'),
    'gpt-4-turbo': lambda: OpenAIAdapter('gpt-4-turbo-preview'),
    'gpt-5.1': lambda: OpenAIAdapter('gpt-5.1'),
    'gpt-5.1-mini': lambda: OpenAIAdapter('gpt-5.1-mini'),
    'gpt-5.1-codex-mini': lambda: OpenAIAdapter('gpt-5.1-codex-mini'),
    'gpt-5.1-chat-latest': lambda: OpenAIAdapter('gpt-5.1-chat-latest'),
}


def get_model_adapter(model_identifier: str, **kwargs) -> ModelAdapter:
    """
    Get a model adapter by identifier.

    Args:
        model_identifier: Model name or 'custom:endpoint_url'
        **kwargs: Additional arguments for custom endpoints

    Returns:
        ModelAdapter instance
    """
    if model_identifier.startswith('custom:'):
        endpoint_url = model_identifier.split(':', 1)[1]
        model_name = kwargs.pop('model_name', 'custom-model')
        api_key = kwargs.pop('api_key', None)
        return CustomEndpointAdapter(model_name, endpoint_url, api_key, **kwargs)

    if model_identifier in MODEL_REGISTRY:
        return MODEL_REGISTRY[model_identifier]()

    # Fallback: treat unknown IDs that look like OpenAI-style models as OpenAIAdapter
    if model_identifier.startswith(("gpt-", "o", "chatgpt", "gpt-4", "gpt-5")):
        return OpenAIAdapter(model_identifier)

    raise ValueError(f"Unknown model: {model_identifier}")
