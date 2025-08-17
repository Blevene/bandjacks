"""LiteLLM client wrapper for OpenAI-compatible LLM access."""

import os
import json
from typing import List, Dict, Any, Optional
import httpx
from litellm import completion


class LLMClient:
    """Client for interacting with LLMs via LiteLLM."""
    
    def __init__(self):
        """Initialize LLM client with environment configuration."""
        # Check for direct API keys first
        self.openai_api_key = os.getenv("OPENAI_API_KEY", "")
        self.google_api_key = os.getenv("GOOGLE_API_KEY", "")
        
        # LiteLLM configuration (fallback or proxy)
        self.base_url = os.getenv("LITELLM_BASE_URL", "http://localhost:4000")
        self.api_key = os.getenv("LITELLM_API_KEY", "")
        self.model = os.getenv("LITELLM_MODEL", "gpt-4o-mini")
        self.timeout = int(os.getenv("LITELLM_TIMEOUT_MS", "30000")) / 1000
        self.temperature = float(os.getenv("LITELLM_TEMPERATURE", "0.2"))
        self.max_tokens = int(os.getenv("LITELLM_MAX_TOKENS", "800"))
        
        # Configure for direct OpenAI if key available
        if self.openai_api_key:
            os.environ["OPENAI_API_KEY"] = self.openai_api_key
            # Use GPT-5 as specified
            self.model = os.getenv("OPENAI_MODEL", "gpt-5")
        # Configure for Google if key available and no OpenAI
        elif self.google_api_key:
            os.environ["GEMINI_API_KEY"] = self.google_api_key
            self.model = os.getenv("GOOGLE_MODEL", "gemini-2.5-flash")
        # Configure LiteLLM proxy as fallback
        elif self.base_url and self.api_key:
            os.environ["OPENAI_API_BASE"] = self.base_url
            os.environ["OPENAI_API_KEY"] = self.api_key
    
    def call(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict[str, Any]]] = None,
        tool_choice: Optional[str] = "auto"
    ) -> Dict[str, Any]:
        """
        Call the LLM with messages and optional tools.
        
        Args:
            messages: List of message dicts with 'role' and 'content'
            tools: Optional list of tool definitions
            tool_choice: How to handle tool selection ("auto", "none", or specific tool)
            
        Returns:
            Response from LLM including content and/or tool calls
        """
        try:
            # Build request parameters
            params = {
                "model": self.model,
                "messages": messages,
                "temperature": self.temperature,
                "max_tokens": self.max_tokens,
                "timeout": self.timeout
            }
            
            if tools:
                params["tools"] = tools
                params["tool_choice"] = tool_choice
            
            # Call via LiteLLM
            response = completion(**params)
            
            # Extract response data
            choice = response.choices[0]
            result = {
                "content": choice.message.content,
                "tool_calls": []
            }
            
            # Extract tool calls if present
            if hasattr(choice.message, 'tool_calls') and choice.message.tool_calls:
                for tool_call in choice.message.tool_calls:
                    result["tool_calls"].append({
                        "id": tool_call.id,
                        "type": "function",
                        "function": {
                            "name": tool_call.function.name,
                            "arguments": tool_call.function.arguments
                        }
                    })
            
            return result
            
        except Exception as e:
            raise RuntimeError(f"LLM call failed: {str(e)}")


def call_llm(
    messages: List[Dict[str, str]],
    tools: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Convenience function to call LLM.
    
    Args:
        messages: List of message dicts
        tools: Optional tool definitions
        
    Returns:
        LLM response with content and/or tool calls
    """
    client = LLMClient()
    return client.call(messages, tools)


def execute_tool_loop(
    messages: List[Dict[str, str]],
    tools: List[Dict[str, Any]],
    tool_functions: Dict[str, callable],
    max_iterations: int = 10
) -> str:
    """
    Execute a tool-calling loop with the LLM.
    
    Args:
        messages: Initial messages (system + user)
        tools: Tool definitions for the LLM
        tool_functions: Dict mapping tool names to Python functions
        max_iterations: Maximum tool-calling iterations
        
    Returns:
        Final JSON response from the LLM
    """
    client = LLMClient()
    current_messages = messages.copy()
    
    for i in range(max_iterations):
        # Call LLM
        response = client.call(current_messages, tools)
        
        # If no tool calls, we have our final answer
        if not response["tool_calls"]:
            return response["content"]
        
        # Execute tool calls
        for tool_call in response["tool_calls"]:
            function_name = tool_call["function"]["name"]
            function_args = json.loads(tool_call["function"]["arguments"])
            
            if function_name not in tool_functions:
                tool_result = {"error": f"Unknown tool: {function_name}"}
            else:
                try:
                    # Execute the tool
                    tool_result = tool_functions[function_name](**function_args)
                except Exception as e:
                    tool_result = {"error": str(e)}
            
            # Add tool response to messages
            current_messages.append({
                "role": "assistant",
                "content": None,
                "tool_calls": [tool_call]
            })
            current_messages.append({
                "role": "tool",
                "tool_call_id": tool_call["id"],
                "name": function_name,
                "content": json.dumps(tool_result)
            })
    
    raise RuntimeError(f"Tool loop exceeded max iterations ({max_iterations})")


def validate_json_response(response: str, schema: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate and parse JSON response from LLM.
    
    Args:
        response: Raw text response from LLM
        schema: JSON schema to validate against
        
    Returns:
        Parsed and validated JSON object
        
    Raises:
        ValueError: If response is not valid JSON or doesn't match schema
    """
    import jsonschema
    
    try:
        # Parse JSON
        data = json.loads(response)
    except json.JSONDecodeError as e:
        # Try to extract JSON from markdown code block
        import re
        json_match = re.search(r'```(?:json)?\s*\n(.*?)\n```', response, re.DOTALL)
        if json_match:
            try:
                data = json.loads(json_match.group(1))
            except json.JSONDecodeError:
                raise ValueError(f"Invalid JSON in response: {e}")
        else:
            raise ValueError(f"Response is not valid JSON: {e}")
    
    # Validate against schema
    try:
        jsonschema.validate(data, schema)
    except jsonschema.ValidationError as e:
        raise ValueError(f"Response doesn't match schema: {e}")
    
    return data