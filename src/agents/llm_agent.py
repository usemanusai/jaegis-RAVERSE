"""
LLM Agent Module for RAVERSE
Date: October 25, 2025

This module provides LLM-powered code analysis using OpenRouter API
with LangChain integration. Uses FREE models only by default.
"""

import os
import time
import hashlib
from typing import Dict, List, Optional, Any
from langchain_openai import ChatOpenAI
from langchain.prompts import ChatPromptTemplate, SystemMessagePromptTemplate, HumanMessagePromptTemplate
from langchain.schema import HumanMessage, SystemMessage
from utils.cache import CacheManager
from utils.metrics import metrics_collector
import json


class LLMAgent:
    """
    LLM-powered agent for binary code analysis.
    Uses OpenRouter API with free models by default.
    """
    
    # Free models available on OpenRouter (as of October 2025)
    FREE_MODELS = [
        "meta-llama/llama-3.2-3b-instruct:free",
        "meta-llama/llama-3.1-8b-instruct:free",
        "google/gemma-2-9b-it:free",
        "microsoft/phi-3-mini-128k-instruct:free",
        "qwen/qwen-2-7b-instruct:free"
    ]
    
    DEFAULT_MODEL = "meta-llama/llama-3.2-3b-instruct:free"
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        cache_manager: Optional[CacheManager] = None,
        temperature: float = 0.1,
        max_tokens: int = 2048
    ):
        """
        Initialize LLM agent.
        
        Args:
            api_key: OpenRouter API key (defaults to env var)
            model: Model to use (defaults to free model)
            cache_manager: Optional cache manager
            temperature: Temperature for generation (0-1)
            max_tokens: Maximum tokens in response
        """
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        if not self.api_key:
            raise ValueError("OPENROUTER_API_KEY not set")
        
        self.model = model or self.DEFAULT_MODEL
        self.cache_manager = cache_manager
        self.temperature = temperature
        self.max_tokens = max_tokens
        
        # Initialize LangChain ChatOpenAI with OpenRouter
        self.llm = ChatOpenAI(
            model=self.model,
            openai_api_key=self.api_key,
            openai_api_base="https://openrouter.ai/api/v1",
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            model_kwargs={
                "headers": {
                    "HTTP-Referer": "https://github.com/raverse",
                    "X-Title": "RAVERSE Binary Patcher"
                }
            }
        )
    
    def _get_cache_key(self, prompt: str) -> str:
        """Generate cache key for prompt."""
        prompt_hash = hashlib.sha256(f"{self.model}:{prompt}".encode()).hexdigest()
        return f"llm:{self.model}:{prompt_hash}"
    
    def _call_llm(self, messages: List[Dict[str, str]]) -> str:
        """
        Call LLM with caching and metrics.
        
        Args:
            messages: List of message dicts with 'role' and 'content'
            
        Returns:
            LLM response text
        """
        # Create cache key from messages
        prompt_text = json.dumps(messages)
        cache_key = self._get_cache_key(prompt_text)
        
        # Check cache
        if self.cache_manager:
            cached = self.cache_manager.get(cache_key)
            if cached:
                metrics_collector.record_cache_hit('llm')
                return cached.decode('utf-8')
            metrics_collector.record_cache_miss('llm')
        
        # Convert to LangChain messages
        lc_messages = []
        for msg in messages:
            if msg['role'] == 'system':
                lc_messages.append(SystemMessage(content=msg['content']))
            else:
                lc_messages.append(HumanMessage(content=msg['content']))
        
        # Call LLM
        start_time = time.time()
        try:
            response = self.llm.invoke(lc_messages)
            response_text = response.content
            duration = time.time() - start_time
            
            # Record metrics
            metrics_collector.record_api_call(
                provider="openrouter",
                model=self.model,
                status="success",
                duration=duration
            )
            
            # Cache response
            if self.cache_manager:
                self.cache_manager.set(
                    cache_key,
                    response_text.encode('utf-8'),
                    ttl=604800  # 7 days
                )
            
            return response_text
            
        except Exception as e:
            duration = time.time() - start_time
            metrics_collector.record_api_call(
                provider="openrouter",
                model=self.model,
                status="error",
                duration=duration
            )
            raise
    
    def analyze_assembly(self, code: str) -> Dict[str, Any]:
        """
        Analyze assembly code and identify key patterns.
        
        Args:
            code: Assembly code snippet
            
        Returns:
            Analysis results dict
        """
        system_prompt = """You are an expert reverse engineer analyzing assembly code.
Your task is to analyze the provided assembly code and identify:
1. The purpose of the code
2. Key operations and logic flow
3. Any conditional checks or comparisons
4. Potential security-relevant operations

Provide your analysis in JSON format with keys: purpose, operations, conditionals, security_notes."""
        
        user_prompt = f"""Analyze this assembly code:

```assembly
{code}
```

Provide detailed analysis in JSON format."""
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
        
        response = self._call_llm(messages)
        
        try:
            # Try to parse JSON response
            return json.loads(response)
        except json.JSONDecodeError:
            # Return raw response if not JSON
            return {"raw_analysis": response}
    
    def identify_password_check(self, code: str) -> Dict[str, Any]:
        """
        Identify password check routines in assembly code.
        
        Args:
            code: Assembly code snippet
            
        Returns:
            Password check identification results
        """
        system_prompt = """You are an expert at identifying password verification routines in assembly code.
Analyze the code and determine:
1. Is this likely a password check routine? (yes/no)
2. What type of check is it? (string comparison, hash comparison, etc.)
3. Where is the comparison happening? (instruction addresses)
4. What would be the best way to bypass it?

Provide your analysis in JSON format with keys: is_password_check, check_type, comparison_location, bypass_strategy."""
        
        user_prompt = f"""Analyze this assembly code for password checking:

```assembly
{code}
```

Provide analysis in JSON format."""
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
        
        response = self._call_llm(messages)
        
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return {"raw_analysis": response}
    
    def suggest_patch_location(self, code: str, analysis: Dict) -> Dict[str, Any]:
        """
        Suggest optimal patch location based on code analysis.
        
        Args:
            code: Assembly code snippet
            analysis: Previous analysis results
            
        Returns:
            Patch location suggestions
        """
        system_prompt = """You are an expert at binary patching.
Based on the assembly code and analysis, suggest:
1. The best instruction(s) to patch
2. What to patch them with (NOP, JMP, etc.)
3. Why this location is optimal
4. Potential risks or side effects

Provide suggestions in JSON format with keys: target_instructions, patch_type, rationale, risks."""
        
        analysis_text = json.dumps(analysis, indent=2)
        user_prompt = f"""Based on this analysis:

{analysis_text}

And this assembly code:

```assembly
{code}
```

Suggest the best patch location and strategy in JSON format."""
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
        
        response = self._call_llm(messages)
        
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return {"raw_suggestions": response}
    
    def explain_code(self, code: str) -> str:
        """
        Explain assembly code in natural language.
        
        Args:
            code: Assembly code snippet
            
        Returns:
            Natural language explanation
        """
        system_prompt = """You are an expert at explaining assembly code to humans.
Provide a clear, concise explanation of what the code does in plain English.
Focus on the high-level logic and purpose, not just instruction-by-instruction translation."""
        
        user_prompt = f"""Explain what this assembly code does:

```assembly
{code}
```"""
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
        
        return self._call_llm(messages)
    
    def generate_patch_strategies(self, code: str, target: str) -> List[Dict[str, Any]]:
        """
        Generate multiple patch strategies for a target.
        
        Args:
            code: Assembly code snippet
            target: Target to achieve (e.g., "bypass password check")
            
        Returns:
            List of patch strategies
        """
        system_prompt = """You are an expert binary patcher.
Generate 3-5 different strategies to achieve the specified target.
For each strategy, provide:
1. Strategy name
2. Instructions to modify
3. New bytes/instructions
4. Pros and cons
5. Success likelihood (0-100%)

Provide strategies in JSON array format."""
        
        user_prompt = f"""Generate patch strategies to: {target}

Assembly code:

```assembly
{code}
```

Provide 3-5 strategies in JSON array format."""
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
        
        response = self._call_llm(messages)
        
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return [{"raw_strategies": response}]


# Global LLM agent instance
_llm_agent: Optional[LLMAgent] = None


def get_llm_agent(
    model: Optional[str] = None,
    cache_manager: Optional[CacheManager] = None
) -> LLMAgent:
    """
    Get or create global LLM agent instance.
    
    Args:
        model: Model to use (defaults to free model)
        cache_manager: Optional cache manager
        
    Returns:
        LLMAgent instance
    """
    global _llm_agent
    if _llm_agent is None:
        _llm_agent = LLMAgent(model=model, cache_manager=cache_manager)
    return _llm_agent

