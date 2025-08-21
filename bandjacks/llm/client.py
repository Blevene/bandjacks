"""LiteLLM client wrapper for OpenAI-compatible LLM access."""

import os
import json
from typing import List, Dict, Any, Optional
import httpx
from litellm import completion
from bandjacks.llm.cache import get_cache


class LLMClient:
    """Client for interacting with LLMs via LiteLLM."""
    
    def __init__(self):
        """Initialize LLM client with environment configuration."""
        # Check for direct API keys first
        self.openai_api_key = os.getenv("OPENAI_API_KEY", "")
        self.google_api_key = os.getenv("GOOGLE_API_KEY", "")
        self.primary_llm = os.getenv("PRIMARY_LLM", "gemini")  # Default to Gemini
        
        # LiteLLM configuration (fallback or proxy)
        self.base_url = os.getenv("LITELLM_BASE_URL", "http://localhost:4000")
        self.api_key = os.getenv("LITELLM_API_KEY", "")
        self.model = os.getenv("LITELLM_MODEL", "gpt-4o-mini")
        self.timeout = int(os.getenv("LITELLM_TIMEOUT_MS", "60000")) / 1000
        self.temperature = float(os.getenv("LITELLM_TEMPERATURE", "0.3"))  # Lower for more consistent output
        self.max_tokens = int(os.getenv("LITELLM_MAX_TOKENS", "8000"))  # Increased for comprehensive extraction
        
        # Prioritize Gemini as primary model
        if self.google_api_key and self.primary_llm == "gemini":
            os.environ["GEMINI_API_KEY"] = self.google_api_key
            # Use gemini/ prefix to ensure LiteLLM uses Gemini API instead of Vertex
            self.model = "gemini/" + os.getenv("GOOGLE_MODEL", "gemini-2.5-flash")
            print(f"[DEBUG] Using Google Gemini as primary with model: {self.model}")
        # Use OpenAI as backup or if explicitly set as primary
        elif self.openai_api_key and (self.primary_llm == "openai" or not self.google_api_key):
            os.environ["OPENAI_API_KEY"] = self.openai_api_key
            self.model = os.getenv("OPENAI_MODEL", "gpt-5")
            print(f"[DEBUG] Using OpenAI with model: {self.model}")
        # Configure LiteLLM proxy as fallback
        elif self.base_url and self.api_key:
            os.environ["OPENAI_API_BASE"] = self.base_url
            os.environ["OPENAI_API_KEY"] = self.api_key
            print(f"[DEBUG] Using LiteLLM proxy with model: {self.model}")
        else:
            print(f"[DEBUG] No API keys configured, using fallback model: {self.model}")
    
    def call(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict[str, Any]]] = None,
        tool_choice: Optional[str] = "auto",
        use_cache: bool = True
    ) -> Dict[str, Any]:
        """
        Call the LLM with messages and optional tools.
        
        Args:
            messages: List of message dicts with 'role' and 'content'
            tools: Optional list of tool definitions
            tool_choice: How to handle tool selection ("auto", "none", or specific tool)
            use_cache: Whether to use cached responses (default: True)
            
        Returns:
            Response from LLM including content and/or tool calls
        """
        # Check cache first if enabled
        if use_cache:
            cache = get_cache()
            cached_response = cache.get(messages, tools=tools, tool_choice=tool_choice)
            if cached_response:
                print("[DEBUG] Cache hit - returning cached LLM response")
                return cached_response
        
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
            content = choice.message.content
            
            # DEBUG: Print what we actually get from GPT-5
            print(f"[DEBUG] Raw choice.message.content: {repr(content)}")
            print(f"[DEBUG] Choice message type: {type(choice.message)}")
            
            # Check if there's content in other places
            if hasattr(choice.message, 'to_dict'):
                message_dict = choice.message.to_dict()
                print(f"[DEBUG] Full message dict: {message_dict}")
            
            # Check if content is in a different field for GPT-5
            if hasattr(choice.message, 'model_dump'):
                message_dump = choice.message.model_dump()
                print(f"[DEBUG] Message model_dump: {message_dump}")
            
            result = {
                "content": content,
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
            
            # Cache the response if enabled
            if use_cache:
                cache = get_cache()
                cache.set(messages, result, tools=tools, tool_choice=tool_choice)
            
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
    max_iterations: int = 2,  # Reduced for performance optimization
    model: Optional[str] = None  # Allow model override
) -> str:
    """
    Execute a tool-calling loop with the LLM.
    
    Args:
        messages: Initial messages (system + user)
        tools: Tool definitions for the LLM
        tool_functions: Dict mapping tool names to Python functions
        max_iterations: Maximum tool-calling iterations
        model: Optional model override (e.g., "gemini/gemini-2.5-flash")
        
    Returns:
        Final JSON response from the LLM
    """
    client = LLMClient()
    if model:
        client.model = model  # Override model if specified
    current_messages = messages.copy()
    
    for i in range(max_iterations):
        # DEBUG: Print the messages being sent
        if i == 0:  # Only print on first iteration to avoid spam
            print(f"[DEBUG] Sending {len(current_messages)} messages to LLM")
            for j, msg in enumerate(current_messages):
                print(f"[DEBUG] Message {j}: role={msg['role']}, content_length={len(msg.get('content', '') or '')}")
                if j == len(current_messages) - 1:  # Print last message content
                    print(f"[DEBUG] Last message content: {msg.get('content', '')[:300]}...")
        
        # Force final response on last iteration
        tools_to_use = tools if i < max_iterations - 1 else None
        if tools_to_use is None:
            print(f"[DEBUG] Final iteration - forcing response without tools")
            # Add explicit JSON instruction for final iteration
            current_messages.append({
                "role": "system",
                "content": "You must now provide your final extraction in valid JSON format. Do not make any more tool calls. Return only the JSON response as specified in the original instructions."
            })
        
        # Call LLM
        print(f"[DEBUG] Iteration {i}: Calling LLM with {len(tools_to_use or [])} tools...")
        try:
            response = client.call(current_messages, tools_to_use)
            print(f"[DEBUG] LLM responded with {len(response.get('tool_calls', []))} tool calls")
        except Exception as e:
            print(f"[DEBUG] LLM call failed: {e}")
            raise
        
        # If no tool calls, we have our final answer
        if not response["tool_calls"]:
            content = response["content"]
            
            # If content is empty, try to force a JSON response
            if not content or content.strip() == "":
                print(f"[DEBUG] Empty response detected, forcing JSON generation...")
                
                # Add explicit JSON instruction and retry once
                json_messages = current_messages.copy()
                json_messages.append({
                    "role": "user", 
                    "content": "Based on the search results, provide your final analysis as JSON. Include the chunk_id and claims with evidence. The JSON must include: chunk_id, claims array with type, span, line_refs, mappings, evidence fields. Output ONLY valid JSON, no markdown."
                })
                
                try:
                    json_response = client.call(json_messages, None)  # No tools
                    content = json_response.get("content", "")
                    print(f"[DEBUG] Forced JSON response: {repr(content[:200])}")
                    return content if content else '{"chunk_id": "", "claims": []}'
                except Exception as e:
                    print(f"[DEBUG] JSON retry failed: {e}")
                    return '{"chunk_id": "", "claims": []}'
            
            return content
        
        # Execute tool calls
        for tool_call in response["tool_calls"]:
            function_name = tool_call["function"]["name"]
            function_args = json.loads(tool_call["function"]["arguments"])
            print(f"[DEBUG] Tool call: {function_name}({function_args})")
            
            if function_name not in tool_functions:
                tool_result = {"error": f"Unknown tool: {function_name}"}
            else:
                try:
                    # Execute the tool
                    tool_result = tool_functions[function_name](**function_args)
                    print(f"[DEBUG] Tool result: {str(tool_result)[:200]}...")
                except Exception as e:
                    tool_result = {"error": str(e)}
                    print(f"[DEBUG] Tool error: {e}")
            
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


def repair_truncated_json(json_text: str) -> str:
    """
    Attempt to repair truncated or malformed JSON.
    
    Args:
        json_text: Potentially truncated JSON string
        
    Returns:
        Repaired JSON string
    """
    if not json_text or not json_text.strip():
        return '{"chunk_id": "", "claims": []}'
    
    text = json_text.strip()
    
    # If it doesn't start with {, try to find the JSON object
    if not text.startswith('{'):
        start_idx = text.find('{')
        if start_idx >= 0:
            text = text[start_idx:]
        else:
            return '{"chunk_id": "", "claims": []}'
    
    # Count brackets to see what needs to be closed
    open_braces = 0
    open_brackets = 0
    in_string = False
    escape_next = False
    
    for char in text:
        if escape_next:
            escape_next = False
            continue
            
        if char == '\\':
            escape_next = True
            continue
            
        if char == '"' and not escape_next:
            in_string = not in_string
            continue
            
        if in_string:
            continue
            
        if char == '{':
            open_braces += 1
        elif char == '}':
            open_braces -= 1
            if open_braces == 0:
                # Found complete JSON object
                return text[:text.index(char)+1]
        elif char == '[':
            open_brackets += 1
        elif char == ']':
            open_brackets -= 1
    
    # If we have unclosed strings, try to close them
    if in_string:
        text += '"'
    
    # Close any open arrays
    while open_brackets > 0:
        text += ']'
        open_brackets -= 1
    
    # Close any open objects  
    while open_braces > 0:
        text += '}'
        open_braces -= 1
    
    return text


def validate_json_response(response: str, schema: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate and parse JSON response from LLM with repair capabilities.
    
    Args:
        response: Raw text response from LLM
        schema: JSON schema to validate against
        
    Returns:
        Parsed and validated JSON object
        
    Raises:
        ValueError: If response is not valid JSON or doesn't match schema
    """
    import jsonschema
    import re
    
    # DEBUG: Print the raw response to understand what we're getting
    print(f"[DEBUG] Raw LLM response (first 500 chars): {response[:500]}")
    print(f"[DEBUG] Response length: {len(response)}")
    
    # First attempt: Try to parse as-is
    try:
        data = json.loads(response)
    except json.JSONDecodeError as e:
        print(f"[DEBUG] Initial JSON decode failed: {e}")
        
        # Second attempt: Extract from markdown code block
        # Also handle incomplete code blocks
        json_match = re.search(r'```(?:json)?\s*\n(.*?)(?:\n```|$)', response, re.DOTALL)
        if json_match:
            print(f"[DEBUG] Found JSON in code block")
            try:
                data = json.loads(json_match.group(1))
            except json.JSONDecodeError:
                # Third attempt: Try to repair the JSON from code block
                print(f"[DEBUG] Attempting JSON repair on code block content")
                repaired = repair_truncated_json(json_match.group(1))
                try:
                    data = json.loads(repaired)
                    print(f"[DEBUG] JSON repair successful")
                except json.JSONDecodeError:
                    raise ValueError(f"Could not parse JSON even after repair: {e}")
        else:
            # Fourth attempt: Try to repair the raw response
            print(f"[DEBUG] No code block found, attempting direct repair")
            repaired = repair_truncated_json(response)
            try:
                data = json.loads(repaired)
                print(f"[DEBUG] Direct JSON repair successful")
            except json.JSONDecodeError:
                raise ValueError(f"Response is not valid JSON and could not be repaired: {e}")
    
    # Validate against schema
    try:
        jsonschema.validate(data, schema)
    except jsonschema.ValidationError as e:
        # Try to fix common schema issues
        print(f"[DEBUG] Schema validation failed: {e}")
        
        # Add missing required fields with defaults
        if "chunk_id" not in data:
            data["chunk_id"] = ""
        if "claims" not in data:
            data["claims"] = []
            
        # Retry validation
        try:
            jsonschema.validate(data, schema)
            print(f"[DEBUG] Schema validation successful after fixing")
        except jsonschema.ValidationError:
            raise ValueError(f"Response doesn't match schema: {e}")
    
    return data