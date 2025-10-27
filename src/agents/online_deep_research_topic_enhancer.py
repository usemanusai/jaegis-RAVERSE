"""
Deep Research Topic Enhancer Agent
Expands and enhances user topics for better research results.
"""

import os
import json
import requests
import time
from typing import Dict, Any, Optional
from datetime import datetime
from .base_memory_agent import BaseMemoryAgent


class DeepResearchTopicEnhancerAgent(BaseMemoryAgent):
    """
    Topic Enhancer Agent - Query optimization expert.
    Expands and enhances user topics based on context for better research results.

    Optional Memory Support:
        memory_strategy: Optional memory strategy (e.g., "memory_augmented")
        memory_config: Optional memory configuration dictionary
    """

    def __init__(
        self,
        orchestrator=None,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        memory_strategy: Optional[str] = None,
        memory_config: Optional[Dict[str, Any]] = None
    ):
        """Initialize Topic Enhancer Agent."""
        super().__init__(
            name="Deep Research Topic Enhancer",
            agent_type="DEEP_RESEARCH_TOPIC_ENHANCER",
            orchestrator=orchestrator,
            memory_strategy=memory_strategy,
            memory_config=memory_config
        )
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        self.model = model or "anthropic/claude-3.5-sonnet:free"
        self.base_url = "https://openrouter.ai/api/v1"
        self.temperature = 0.5
        self.max_tokens = 1000

    def _execute_impl(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute topic enhancement."""
        topic = task.get("topic", "")
        context = task.get("context", "")

        # Get memory context if available
        memory_context = self.get_memory_context(topic)

        self.logger.info(f"Enhancing topic: {topic}")

        if not topic:
            raise ValueError("Topic is required")

        # Prepare prompt
        prompt = self._prepare_prompt(topic, context)

        # Call LLM
        enhanced_topic = self._call_llm(prompt)

        # Extract enhancements
        enhancements = self._parse_enhancements(enhanced_topic)

        self.set_metric("topic_length_original", len(topic))
        self.set_metric("topic_length_enhanced", len(enhanced_topic))

        result = {
            "original_topic": topic,
            "enhanced_topic": enhanced_topic,
            "enhancements": enhancements,
            "timestamp": datetime.now().isoformat()
        }

        # Store in memory if enabled
        if result:
            self.add_to_memory(topic, json.dumps(result, default=str))

        return result

    def _prepare_prompt(self, topic: str, context: str = "") -> str:
        """Prepare LLM prompt for topic enhancement."""
        prompt = f"""You are a query optimization expert. Your task is to expand and enhance the original user topic based on the provided context to create a more detailed and comprehensive query that is likely to yield better search results.

Original Topic: {topic}

{f'Context: {context}' if context else ''}

Please enhance this topic by:
1. Adding relevant keywords and synonyms
2. Clarifying the scope and intent
3. Suggesting related angles or perspectives
4. Identifying key entities and relationships
5. Proposing search strategies

Provide the enhanced topic as a clear, comprehensive query that maintains the original intent while being more specific and searchable."""
        
        return prompt

    def _call_llm(self, prompt: str, max_retries: int = 3) -> str:
        """Call LLM via OpenRouter with exponential backoff retry logic."""
        for attempt in range(max_retries):
            try:
                headers = {
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                }
                
                payload = {
                    "model": self.model,
                    "messages": [
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    "temperature": self.temperature,
                    "max_tokens": self.max_tokens,
                    "stream": False
                }
                
                response = requests.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=30
                )
                
                if response.status_code == 200:
                    result = response.json()
                    return result['choices'][0]['message']['content']
                elif response.status_code in [429, 500, 502, 503, 504]:
                    if attempt < max_retries - 1:
                        wait_time = 2 ** attempt
                        self.logger.warning(f"LLM call failed with {response.status_code}, retrying in {wait_time}s")
                        time.sleep(wait_time)
                        continue
                    else:
                        raise Exception(f"LLM call failed after {max_retries} retries: {response.status_code}")
                else:
                    raise Exception(f"LLM call failed: {response.status_code} - {response.text}")
                    
            except requests.exceptions.Timeout:
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt
                    self.logger.warning(f"LLM call timeout, retrying in {wait_time}s")
                    time.sleep(wait_time)
                    continue
                else:
                    raise Exception(f"LLM call timeout after {max_retries} retries")
            except requests.exceptions.ConnectionError as e:
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt
                    self.logger.warning(f"Connection error, retrying in {wait_time}s: {e}")
                    time.sleep(wait_time)
                    continue
                else:
                    raise Exception(f"Connection error after {max_retries} retries: {e}")
        
        raise Exception("LLM call failed after all retries")

    def _parse_enhancements(self, enhanced_topic: str) -> Dict[str, Any]:
        """Parse enhancements from LLM response."""
        return {
            "enhanced_query": enhanced_topic,
            "keywords": self._extract_keywords(enhanced_topic),
            "entities": self._extract_entities(enhanced_topic)
        }

    def _extract_keywords(self, text: str) -> list:
        """Extract keywords from enhanced topic."""
        # Simple keyword extraction (can be enhanced with NLP)
        words = text.lower().split()
        # Filter out common words
        common_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'is', 'are'}
        keywords = [w for w in words if w not in common_words and len(w) > 3]
        return list(set(keywords))[:10]  # Return top 10 unique keywords

    def _extract_entities(self, text: str) -> list:
        """Extract entities from enhanced topic."""
        # Simple entity extraction (can be enhanced with NER)
        entities = []
        # Look for capitalized words (potential entities)
        words = text.split()
        for word in words:
            if word and word[0].isupper() and len(word) > 2:
                entities.append(word.rstrip('.,;:'))
        return list(set(entities))[:5]  # Return top 5 unique entities

    def validate_inputs(self, task: Dict[str, Any]) -> bool:
        """Validate task inputs."""
        return "topic" in task and isinstance(task["topic"], str) and len(task["topic"]) > 0

    def _format_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Format result for output."""
        return {
            "status": "success",
            "result": result,
            "artifacts": self.artifacts,
            "metrics": self.metrics
        }

    def _format_error(self, error: Exception) -> Dict[str, Any]:
        """Format error for output."""
        return {
            "status": "error",
            "error": str(error),
            "artifacts": self.artifacts,
            "metrics": self.metrics
        }

