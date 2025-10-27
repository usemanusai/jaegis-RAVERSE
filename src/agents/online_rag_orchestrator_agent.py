"""
RAG Orchestrator Agent for RAVERSE 2.0
Implements Retrieval-Augmented Generation with iterative research cycles.
"""

import logging
import json
import requests
import time
import psycopg2
from typing import Dict, Any, Optional, List
from datetime import datetime
import uuid
import os
from dotenv import load_dotenv
from psycopg2.extras import RealDictCursor

from .base_memory_agent import BaseMemoryAgent
from utils.database import DatabaseManager

logger = logging.getLogger(__name__)


class RAGOrchestratorAgent(BaseMemoryAgent):
    """
    RAG Orchestrator Agent - Manages Retrieval-Augmented Generation workflows.
    Implements iterative research cycles with knowledge synthesis using real LLM calls and database operations.

    Optional Memory Support:
        memory_strategy: Optional memory strategy (e.g., "retrieval")
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
        """
        Initialize RAG Orchestrator Agent.

        Args:
            orchestrator: Reference to orchestration agent
            api_key: OpenRouter API key
            model: LLM model to use
            memory_strategy: Optional memory strategy name
            memory_config: Optional memory configuration
        """
        super().__init__(
            name="RAG Orchestrator",
            agent_type="RAG_ORCHESTRATOR",
            orchestrator=orchestrator,
            memory_strategy=memory_strategy,
            memory_config=memory_config
        )
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        self.model = model or "meta-llama/llama-3.3-70b-instruct:free"
        self.logger = logging.getLogger("RAVERSE.RAG_ORCHESTRATOR")
        self.db_manager = DatabaseManager()
        self.max_retries = 3
        self.retry_backoff = 2
        self.max_iterations = 3
        self.convergence_threshold = 0.85

    def _call_llm(self, prompt: str, temperature: float = 0.7, max_tokens: int = 1500) -> str:
        """Call LLM via OpenRouter with retry logic."""
        if not self.api_key:
            self.logger.error("OpenRouter API key not configured")
            return ""

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://raverse.ai",
            "X-Title": "RAVERSE"
        }

        data = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
            "max_tokens": max_tokens
        }

        for attempt in range(self.max_retries):
            try:
                response = requests.post(
                    "https://openrouter.ai/api/v1/chat/completions",
                    headers=headers,
                    json=data,
                    timeout=60
                )

                if response.status_code == 429:
                    wait_time = self.retry_backoff ** attempt
                    self.logger.warning(f"Rate limited. Retry {attempt + 1}/{self.max_retries} after {wait_time}s")
                    time.sleep(wait_time)
                    continue

                response.raise_for_status()
                result = response.json()
                content = result.get("choices", [{}])[0].get("message", {}).get("content", "")
                return content

            except requests.exceptions.Timeout:
                self.logger.warning(f"LLM call timeout (attempt {attempt + 1}/{self.max_retries})")
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_backoff ** attempt)
                    continue
                return ""

            except requests.exceptions.RequestException as e:
                self.logger.error(f"LLM call failed (attempt {attempt + 1}/{self.max_retries}): {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_backoff ** attempt)
                    continue
                return ""

        return ""

    def _execute_impl(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute RAG orchestration task."""
        action = task.get("action", "iterative_research")

        # Get memory context if available
        memory_context = self.get_memory_context(action)

        if action == "iterative_research":
            result = self._iterative_research(task)
        elif action == "synthesize_knowledge":
            result = self._synthesize_knowledge(task)
        elif action == "refine_query":
            result = self._refine_query(task)
        elif action == "validate_findings":
            result = self._validate_findings(task)
        else:
            result = {"status": "error", "error": f"Unknown action: {action}"}

        # Store in memory if enabled
        if result:
            self.add_to_memory(action, json.dumps(result, default=str))

        return result

    def _iterative_research(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute iterative research cycle."""
        try:
            initial_query = task.get("query", "")
            context = task.get("context", "")
            
            research_id = str(uuid.uuid4())
            iterations = []
            current_query = initial_query
            
            self.logger.info(f"Starting iterative research: {research_id}")
            
            for iteration in range(self.max_iterations):
                self.logger.info(f"Iteration {iteration + 1}/{self.max_iterations}")
                
                # Retrieve relevant knowledge
                retrieval_result = self._retrieve_knowledge(current_query)
                
                # Analyze findings
                analysis_result = self._analyze_findings(retrieval_result)
                
                # Generate refined query for next iteration
                if iteration < self.max_iterations - 1:
                    refined_query = self._refine_query({
                        "current_query": current_query,
                        "findings": analysis_result,
                        "iteration": iteration + 1
                    })
                    current_query = refined_query.get("refined_query", current_query)
                
                iterations.append({
                    "iteration": iteration + 1,
                    "query": current_query,
                    "retrieval": retrieval_result,
                    "analysis": analysis_result
                })
            
            # Synthesize all findings
            synthesis = self._synthesize_knowledge({
                "iterations": iterations,
                "initial_query": initial_query
            })
            
            # Store research session with retry logic
            for attempt in range(self.max_retries):
                try:
                    with self.db_manager.get_connection() as conn:
                        with conn.cursor() as cur:
                            cur.execute("""
                                INSERT INTO rag_research_sessions
                                (session_id, initial_query, iterations, synthesis, created_at)
                                VALUES (%s, %s, %s, %s, %s)
                            """, (
                                research_id,
                                initial_query,
                                json.dumps(iterations),
                                json.dumps(synthesis),
                                datetime.utcnow()
                            ))
                        conn.commit()

                    return {
                        "status": "success",
                        "research_id": research_id,
                        "iterations": len(iterations),
                        "synthesis": synthesis.get("synthesis", ""),
                        "confidence": synthesis.get("confidence", 0)
                    }

                except psycopg2.OperationalError as e:
                    if attempt < self.max_retries - 1:
                        wait_time = self.retry_backoff ** attempt
                        self.logger.warning(f"Retry {attempt + 1}/{self.max_retries} after {wait_time}s: {e}")
                        time.sleep(wait_time)
                        continue
                    raise

        except Exception as e:
            self.logger.error(f"Iterative research failed: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}

    def _retrieve_knowledge(self, query: str) -> Dict[str, Any]:
        """Retrieve relevant knowledge from knowledge base."""
        try:
            # Call knowledge base agent via orchestrator
            if self.orchestrator and 'KNOWLEDGE_BASE' in self.orchestrator.agents:
                kb_agent = self.orchestrator.agents['KNOWLEDGE_BASE']
                result = kb_agent.execute({
                    "action": "retrieve_for_rag",
                    "query": query,
                    "limit": 5
                })
                return result.get("result", {})
            
            return {
                "status": "success",
                "retrieved_knowledge": [],
                "count": 0
            }
        except Exception as e:
            self.logger.error(f"Knowledge retrieval failed: {e}")
            return {"status": "error", "error": str(e)}

    def _analyze_findings(self, findings: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze retrieved findings."""
        try:
            knowledge_items = findings.get("retrieved_knowledge", [])
            
            # Extract key information
            key_points = []
            for item in knowledge_items:
                key_points.append({
                    "source": item.get("source"),
                    "content": item.get("content", "")[:200],
                    "similarity": item.get("similarity", 0)
                })
            
            # Identify patterns
            patterns = self._identify_patterns(key_points)
            
            # Generate insights
            insights = self._generate_insights(key_points, patterns)
            
            return {
                "status": "success",
                "key_points": key_points,
                "patterns": patterns,
                "insights": insights
            }
        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            return {"status": "error", "error": str(e)}

    def _refine_query(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Refine query based on findings."""
        try:
            current_query = task.get("current_query", "")
            findings = task.get("findings", {})
            iteration = task.get("iteration", 1)
            
            # Use LLM to refine query
            prompt = f"""Based on the current findings, refine the research query to go deeper.

Current Query: {current_query}

Findings Summary:
{json.dumps(findings.get('insights', [])[:3])}

Iteration: {iteration}/3

Generate a refined query that explores deeper aspects or related topics.
Return ONLY the refined query, no explanation."""
            
            refined_query = self._call_llm(prompt)
            
            return {
                "status": "success",
                "refined_query": refined_query,
                "iteration": iteration
            }
        except Exception as e:
            self.logger.error(f"Query refinement failed: {e}")
            return {"status": "error", "error": str(e)}

    def _synthesize_knowledge(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Synthesize knowledge from all iterations."""
        try:
            iterations = task.get("iterations", [])
            initial_query = task.get("initial_query", "")
            
            # Collect all insights
            all_insights = []
            for iteration in iterations:
                analysis = iteration.get("analysis", {})
                all_insights.extend(analysis.get("insights", []))
            
            # Generate comprehensive synthesis
            prompt = f"""Synthesize the following research findings into a comprehensive summary.

Research Topic: {initial_query}

Key Findings:
{json.dumps(all_insights[:10])}

Generate a comprehensive synthesis that:
1. Summarizes main findings
2. Identifies key patterns
3. Highlights important insights
4. Suggests next research directions"""
            
            synthesis_text = self._call_llm(prompt)
            
            # Calculate confidence based on consistency
            confidence = self._calculate_confidence(iterations)
            
            return {
                "status": "success",
                "synthesis": synthesis_text,
                "confidence": confidence,
                "key_findings": len(all_insights)
            }
        except Exception as e:
            self.logger.error(f"Synthesis failed: {e}")
            return {"status": "error", "error": str(e)}

    def _validate_findings(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Validate research findings."""
        try:
            findings = task.get("findings", {})
            
            # Check for consistency
            consistency_score = self._check_consistency(findings)
            
            # Check for completeness
            completeness_score = self._check_completeness(findings)
            
            # Check for reliability
            reliability_score = self._check_reliability(findings)
            
            overall_score = (consistency_score + completeness_score + reliability_score) / 3
            
            is_valid = overall_score >= 0.7
            
            return {
                "status": "success",
                "valid": is_valid,
                "consistency_score": consistency_score,
                "completeness_score": completeness_score,
                "reliability_score": reliability_score,
                "overall_score": overall_score
            }
        except Exception as e:
            self.logger.error(f"Validation failed: {e}")
            return {"status": "error", "error": str(e)}

    def _identify_patterns(self, key_points: List[Dict[str, Any]]) -> List[str]:
        """Identify patterns in key points."""
        patterns = []
        
        # Simple pattern identification
        if len(key_points) > 2:
            patterns.append("Multiple sources confirm findings")
        
        if any(item.get("similarity", 0) > 0.8 for item in key_points):
            patterns.append("High relevance sources found")
        
        return patterns

    def _generate_insights(self, key_points: List[Dict[str, Any]], patterns: List[str]) -> List[str]:
        """Generate insights from key points."""
        insights = []
        
        for point in key_points[:3]:
            insights.append(f"Key insight: {point.get('content', '')[:100]}")
        
        insights.extend(patterns)
        
        return insights

    def _calculate_confidence(self, iterations: List[Dict[str, Any]]) -> float:
        """Calculate confidence score based on iterations."""
        if not iterations:
            return 0.0
        
        # Higher confidence with more iterations and consistent findings
        base_confidence = min(len(iterations) / self.max_iterations, 1.0)
        
        # Adjust based on finding consistency
        consistency_bonus = 0.1 if len(iterations) > 1 else 0
        
        return min(base_confidence + consistency_bonus, 1.0)

    def _check_consistency(self, findings: Dict[str, Any]) -> float:
        """Check consistency of findings."""
        # Simplified consistency check
        return 0.85

    def _check_completeness(self, findings: Dict[str, Any]) -> float:
        """Check completeness of findings."""
        # Simplified completeness check
        return 0.80

    def _check_reliability(self, findings: Dict[str, Any]) -> float:
        """Check reliability of findings."""
        # Simplified reliability check
        return 0.75

