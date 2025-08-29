"""LiteLLM client wrapper for OpenAI-compatible LLM access with resilience."""

import os
import json
import time
import logging
from typing import List, Dict, Any, Optional
import httpx
from litellm import completion
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log,
)
from bandjacks.llm.cache import get_cache
from bandjacks.llm.rate_limiter import get_rate_limiter, get_circuit_breaker

logger = logging.getLogger(__name__)


class LLMClient:
    """Client for interacting with LLMs via LiteLLM with retry and fallback."""
    
    def __init__(self):
        """Initialize LLM client with environment configuration."""
        # Retry configuration
        self.max_retries = int(os.getenv("LLM_MAX_RETRIES", "5"))
        self.retry_min_wait = int(os.getenv("LLM_RETRY_MIN_WAIT", "1"))
        self.retry_max_wait = int(os.getenv("LLM_RETRY_MAX_WAIT", "60"))
        self.retry_multiplier = float(os.getenv("LLM_RETRY_MULTIPLIER", "2"))
        
        # Check for direct API keys first
        self.openai_api_key = os.getenv("OPENAI_API_KEY", "")
        self.google_api_key = os.getenv("GOOGLE_API_KEY", "")
        self.primary_llm = os.getenv("PRIMARY_LLM", "gemini")  # Default to Gemini
        
        # Fallback models list
        self.fallback_models = []
        
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
            # Add OpenAI as fallback if available
            if self.openai_api_key:
                self.fallback_models.append(os.getenv("OPENAI_MODEL", "gpt-4o-mini"))
        # Use OpenAI as primary or if explicitly set
        elif self.openai_api_key and (self.primary_llm == "openai" or not self.google_api_key):
            os.environ["OPENAI_API_KEY"] = self.openai_api_key
            self.model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
            print(f"[DEBUG] Using OpenAI with model: {self.model}")
            # Add Gemini as fallback if available
            if self.google_api_key:
                self.fallback_models.append("gemini/" + os.getenv("GOOGLE_MODEL", "gemini-2.5-flash"))
        # Configure LiteLLM proxy as fallback
        elif self.base_url and self.api_key:
            os.environ["OPENAI_API_BASE"] = self.base_url
            os.environ["OPENAI_API_KEY"] = self.api_key
            print(f"[DEBUG] Using LiteLLM proxy with model: {self.model}")
        else:
            print(f"[DEBUG] No API keys configured, using fallback model: {self.model}")
        
        logger.info(f"Initialized LLM client with model: {self.model}, fallbacks: {self.fallback_models}")
    
    def _should_retry(self, exception):
        """Determine if we should retry based on the exception."""
        # Check for specific error codes
        error_str = str(exception)
        retryable_errors = [
            "503",  # Service Unavailable
            "429",  # Too Many Requests
            "500",  # Internal Server Error
            "overloaded",  # Model overloaded
            "rate_limit",  # Rate limit
            "timeout",  # Timeout
            "connection",  # Connection error
        ]
        return any(err in error_str.lower() for err in retryable_errors)
    
    def call(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict[str, Any]]] = None,
        tool_choice: Optional[str] = "auto",
        use_cache: bool = True,
        retry_count: int = 0,
        response_format: Optional[Dict[str, Any]] = None,
        max_tokens: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Call the LLM with messages and optional tools.
        
        Args:
            messages: List of message dicts with 'role' and 'content'
            tools: Optional list of tool definitions
            tool_choice: How to handle tool selection ("auto", "none", or specific tool)
            use_cache: Whether to use cached responses (default: True)
            response_format: Optional response format (e.g., {"type": "json_object"})
            max_tokens: Optional max tokens override (default: uses self.max_tokens)
            
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
                "max_tokens": max_tokens if max_tokens is not None else self.max_tokens,
                "timeout": self.timeout
            }
            
            if tools:
                params["tools"] = tools
                params["tool_choice"] = tool_choice
            
            # Add response_format if provided
            if response_format:
                # Check if we're using Gemini which needs special handling
                if "gemini" in self.model.lower():
                    # For Gemini, we need to enable JSON schema validation
                    # and ensure the system message mentions JSON output
                    import litellm
                    litellm.enable_json_schema_validation = True
                    
                    # Ensure there's a system message mentioning JSON
                    has_json_instruction = any(
                        "json" in msg.get("content", "").lower() 
                        for msg in messages 
                        if msg.get("role") == "system"
                    )
                    if not has_json_instruction:
                        # Prepend a system message about JSON output
                        messages = [
                            {"role": "system", "content": "You must output valid JSON."},
                            *messages
                        ]
                        params["messages"] = messages
                
                # Add response_format to params
                params["response_format"] = response_format
            
            # Check circuit breaker
            circuit_breaker = get_circuit_breaker()
            if circuit_breaker.is_open(self.model):
                raise RuntimeError(f"Circuit breaker open for {self.model} due to repeated failures")
            
            # Apply rate limiting
            rate_limiter = get_rate_limiter()
            rate_limiter.wait_if_needed(self.model)
            
            # Retry decorator for the actual LLM call
            @retry(
                stop=stop_after_attempt(self.max_retries),
                wait=wait_exponential(
                    multiplier=self.retry_multiplier,
                    min=self.retry_min_wait,
                    max=self.retry_max_wait
                ),
                retry=retry_if_exception_type(Exception),
                before_sleep=before_sleep_log(logger, logging.WARNING)
            )
            def _make_llm_call():
                return completion(**params)
            
            # Call via LiteLLM with retry
            response = _make_llm_call()
            
            # Record success with circuit breaker
            circuit_breaker.record_success(self.model)
            
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
            error_msg = str(e)
            logger.warning(f"LLM call failed with {self.model}: {error_msg}")
            
            # Record failure with circuit breaker
            circuit_breaker = get_circuit_breaker()
            circuit_breaker.record_failure(self.model)
            
            # Check if we should retry with a fallback model
            if self._should_retry(e) and retry_count < len(self.fallback_models):
                fallback_model = self.fallback_models[retry_count]
                logger.info(f"Retrying with fallback model: {fallback_model}")
                
                # Temporarily switch to fallback model
                original_model = self.model
                self.model = fallback_model
                
                try:
                    # Recursive call with incremented retry count
                    result = self.call(
                        messages=messages,
                        tools=tools,
                        tool_choice=tool_choice,
                        use_cache=False,  # Don't use cache for retries
                        retry_count=retry_count + 1,
                        response_format=response_format,
                        max_tokens=max_tokens
                    )
                    # Restore original model on success
                    self.model = original_model
                    return result
                except Exception as fallback_error:
                    # Restore original model
                    self.model = original_model
                    logger.error(f"Fallback model {fallback_model} also failed: {fallback_error}")
            
            # If all retries exhausted, raise the error
            raise RuntimeError(f"LLM call failed after {retry_count + 1} attempts: {error_msg}")


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
    model: Optional[str] = None,  # Allow model override
    response_format: Optional[Dict[str, Any]] = None  # Optional response format
) -> str:
    """
    Execute a tool-calling loop with the LLM.
    
    Args:
        messages: Initial messages (system + user)
        tools: Tool definitions for the LLM
        tool_functions: Dict mapping tool names to Python functions
        max_iterations: Maximum tool-calling iterations
        model: Optional model override (e.g., "gemini/gemini-2.5-flash")
        response_format: Optional response format (e.g., {"type": "json_object"})
        
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
            # On final iteration without tools, use response_format if provided
            if tools_to_use is None and response_format:
                response = client.call(current_messages, tools_to_use, response_format=response_format)
            else:
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
                    # Use response_format to force JSON output
                    json_response = client.call(
                        json_messages, 
                        None,  # No tools
                        response_format=response_format or {"type": "json_object"}
                    )
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