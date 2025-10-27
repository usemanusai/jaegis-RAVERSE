"""
Deep Research Content Analyzer Agent
Analyzes and synthesizes research findings into comprehensive insights.
"""

import os
import json
import requests
import time
from typing import Dict, Any, Optional, List
from datetime import datetime
from .base_memory_agent import BaseMemoryAgent


class DeepResearchContentAnalyzerAgent(BaseMemoryAgent):
    """
    Content Analyzer Agent - Analyzes and synthesizes research findings.
    Provides comprehensive insights and identifies patterns.

    Optional Memory Support:
        memory_strategy: Optional memory strategy (e.g., "summarization")
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
        """Initialize Content Analyzer Agent."""
        super().__init__(
            name="Deep Research Content Analyzer",
            agent_type="DEEP_RESEARCH_CONTENT_ANALYZER",
            orchestrator=orchestrator,
            memory_strategy=memory_strategy,
            memory_config=memory_config
        )
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        self.model = model or "meta-llama/llama-3.3-70b-instruct:free"
        self.base_url = "https://openrouter.ai/api/v1"
        self.temperature = 0.6
        self.max_tokens = 2000

    def _execute_impl(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute content analysis."""
        research_findings = task.get("research_findings", {})
        query = task.get("query", "")

        # Get memory context if available
        memory_context = self.get_memory_context(query)

        self.logger.info("Starting content analysis")

        if not research_findings:
            raise ValueError("Research findings are required")

        # Phase 1: Extract key information
        self.report_progress(0.2, "Extracting key information")
        key_info = self._extract_key_information(research_findings)

        # Phase 2: Identify patterns
        self.report_progress(0.4, "Identifying patterns and themes")
        patterns = self._identify_patterns(research_findings)

        # Phase 3: Generate insights
        self.report_progress(0.6, "Generating insights")
        insights = self._generate_insights(query, research_findings, patterns)

        # Phase 4: Create synthesis
        self.report_progress(0.8, "Creating comprehensive synthesis")
        synthesis = self._create_synthesis(key_info, patterns, insights)

        # Phase 5: Generate recommendations
        self.report_progress(0.95, "Generating recommendations")
        recommendations = self._generate_recommendations(insights)

        self.set_metric("findings_analyzed", len(research_findings.get("search_results", [])))
        self.set_metric("patterns_identified", len(patterns))

        result = {
            "query": query,
            "key_information": key_info,
            "patterns": patterns,
            "insights": insights,
            "synthesis": synthesis,
            "recommendations": recommendations,
            "timestamp": datetime.now().isoformat()
        }

        # Store in memory if enabled
        if result:
            self.add_to_memory(query, json.dumps(result, default=str))

        return result

    def _extract_key_information(self, findings: Dict[str, Any]) -> Dict[str, Any]:
        """Extract key information from findings."""
        search_results = findings.get("search_results", [])
        detailed_findings = findings.get("detailed_findings", [])
        
        key_info = {
            "total_sources": len(search_results),
            "sources_analyzed": len(detailed_findings),
            "main_topics": self._extract_topics(search_results),
            "key_entities": self._extract_entities(detailed_findings),
            "source_summary": [
                {
                    "title": s.get("title", ""),
                    "url": s.get("url", ""),
                    "relevance": "high"
                }
                for s in detailed_findings[:5]
            ]
        }
        
        return key_info

    def _extract_topics(self, sources: List[Dict[str, Any]]) -> List[str]:
        """Extract main topics from sources."""
        topics = []
        for source in sources:
            title = source.get("title", "").lower()
            # Simple topic extraction from titles
            words = title.split()
            topics.extend([w for w in words if len(w) > 4])
        
        # Return top unique topics
        from collections import Counter
        topic_counts = Counter(topics)
        return [topic for topic, _ in topic_counts.most_common(5)]

    def _extract_entities(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Extract key entities from findings."""
        entities = []
        for finding in findings:
            title = finding.get("title", "")
            # Extract capitalized words as entities
            words = title.split()
            for word in words:
                if word and word[0].isupper() and len(word) > 2:
                    entities.append(word.rstrip('.,;:'))
        
        # Return top unique entities
        from collections import Counter
        entity_counts = Counter(entities)
        return [entity for entity, _ in entity_counts.most_common(5)]

    def _identify_patterns(self, findings: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify patterns and themes in findings."""
        patterns = []
        
        # Pattern 1: Source diversity
        sources = findings.get("search_results", [])
        if len(sources) > 5:
            patterns.append({
                "type": "source_diversity",
                "description": "Multiple diverse sources found",
                "count": len(sources)
            })
        
        # Pattern 2: Content consistency
        detailed = findings.get("detailed_findings", [])
        if len(detailed) > 2:
            patterns.append({
                "type": "content_consistency",
                "description": "Consistent themes across sources",
                "count": len(detailed)
            })
        
        # Pattern 3: Temporal relevance
        patterns.append({
            "type": "temporal_relevance",
            "description": "Recent and relevant sources",
            "count": len(detailed)
        })
        
        return patterns

    def _generate_insights(self, query: str, findings: Dict[str, Any], 
                          patterns: List[Dict[str, Any]]) -> str:
        """Generate insights using LLM."""
        try:
            # Prepare context
            context = json.dumps({
                "query": query,
                "sources_count": len(findings.get("search_results", [])),
                "patterns": patterns,
                "synthesis": findings.get("synthesis", "")[:500]
            }, indent=2)
            
            prompt = f"""Based on the following research analysis, provide comprehensive insights:

{context}

Please provide:
1. Main conclusions from the research
2. Key takeaways
3. Surprising or notable findings
4. Connections between different sources
5. Confidence level in findings"""
            
            insights = self._call_llm(prompt)
            return insights
            
        except Exception as e:
            self.logger.warning(f"Insight generation failed: {e}")
            return "Insights unavailable"

    def _create_synthesis(self, key_info: Dict[str, Any], patterns: List[Dict[str, Any]], 
                         insights: str) -> str:
        """Create comprehensive synthesis."""
        synthesis = f"""
## Research Synthesis

### Overview
- Total sources analyzed: {key_info.get('total_sources', 0)}
- Key topics: {', '.join(key_info.get('main_topics', []))}
- Key entities: {', '.join(key_info.get('key_entities', []))}

### Patterns Identified
{chr(10).join([f"- {p['type']}: {p['description']}" for p in patterns])}

### Key Insights
{insights}

### Sources
{chr(10).join([f"- [{s['title']}]({s['url']})" for s in key_info.get('source_summary', [])])}
"""
        return synthesis

    def _generate_recommendations(self, insights: str) -> List[str]:
        """Generate recommendations based on insights."""
        recommendations = [
            "Conduct deeper research on identified patterns",
            "Verify findings with additional sources",
            "Explore connections between key entities",
            "Monitor for updates on this topic",
            "Consider alternative perspectives"
        ]
        return recommendations

    def _call_llm(self, prompt: str, max_retries: int = 3) -> str:
        """Call LLM via OpenRouter with retry logic."""
        for attempt in range(max_retries):
            try:
                headers = {
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                }
                
                payload = {
                    "model": self.model,
                    "messages": [{"role": "user", "content": prompt}],
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
                    return response.json()['choices'][0]['message']['content']
                elif response.status_code in [429, 500, 502, 503, 504]:
                    if attempt < max_retries - 1:
                        time.sleep(2 ** attempt)
                        continue
                    
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
                    continue
        
        return "Analysis unavailable"

    def validate_inputs(self, task: Dict[str, Any]) -> bool:
        """Validate task inputs."""
        return "research_findings" in task and isinstance(task["research_findings"], dict)

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

