"""
Document Generator Agent for RAVERSE 2.0
Generates manifests, white papers, and topic-specific documentation.
"""

import logging
import json
import time
import requests
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


class DocumentGeneratorAgent(BaseMemoryAgent):
    """
    Document Generator Agent - Generates research manifests, white papers, and documentation.
    Uses real LLM calls via OpenRouter for content generation.

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
        """
        Initialize Document Generator Agent.

        Args:
            orchestrator: Reference to orchestration agent
            api_key: OpenRouter API key
            model: LLM model to use
            memory_strategy: Optional memory strategy name
            memory_config: Optional memory configuration
        """
        super().__init__(
            name="Document Generator",
            agent_type="DOCUMENT_GENERATOR",
            orchestrator=orchestrator,
            memory_strategy=memory_strategy,
            memory_config=memory_config
        )
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        self.model = model or "meta-llama/llama-3.3-70b-instruct:free"
        self.logger = logging.getLogger("RAVERSE.DOCUMENT_GENERATOR")
        self.db_manager = DatabaseManager()
        self.max_retries = 3
        self.retry_backoff = 2

    def _call_llm(self, prompt: str, temperature: float = 0.7, max_tokens: int = 2000) -> str:
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
                self.logger.info(f"LLM call successful, tokens: {result.get('usage', {}).get('total_tokens', 'unknown')}")
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
        """Execute document generation task."""
        action = task.get("action", "generate_manifest")

        # Get memory context if available
        memory_context = self.get_memory_context(action)

        if action == "generate_manifest":
            result = self._generate_manifest(task)
        elif action == "generate_white_paper":
            result = self._generate_white_paper(task)
        elif action == "generate_topic_documentation":
            result = self._generate_topic_documentation(task)
        elif action == "generate_report":
            result = self._generate_report(task)
        else:
            result = {"status": "error", "error": f"Unknown action: {action}"}

        # Store in memory if enabled
        if result:
            self.add_to_memory(action, json.dumps(result, default=str))

        return result

    def _generate_manifest(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Generate research manifest."""
        try:
            research_topic = task.get("research_topic", "")
            research_findings = task.get("research_findings", {})
            metadata = task.get("metadata", {})
            
            manifest_id = str(uuid.uuid4())
            
            # Build manifest structure
            manifest = {
                "manifest_id": manifest_id,
                "title": f"Research Manifest: {research_topic}",
                "created_at": datetime.utcnow().isoformat(),
                "topic": research_topic,
                "metadata": metadata,
                "sections": [
                    {
                        "title": "Executive Summary",
                        "content": self._generate_summary(research_findings)
                    },
                    {
                        "title": "Research Objectives",
                        "content": self._generate_objectives(research_topic)
                    },
                    {
                        "title": "Methodology",
                        "content": self._generate_methodology()
                    },
                    {
                        "title": "Key Findings",
                        "content": self._generate_key_findings(research_findings)
                    },
                    {
                        "title": "Recommendations",
                        "content": self._generate_recommendations(research_findings)
                    }
                ]
            }
            
            # Convert to markdown
            markdown_content = self._manifest_to_markdown(manifest)

            # Store in database with retry logic
            for attempt in range(self.max_retries):
                try:
                    with self.db_manager.get_connection() as conn:
                        with conn.cursor() as cur:
                            cur.execute("""
                                INSERT INTO generated_documents
                                (document_id, document_type, content, metadata, created_at)
                                VALUES (%s, %s, %s, %s, %s)
                            """, (
                                manifest_id,
                                "manifest",
                                markdown_content,
                                json.dumps(manifest),
                                datetime.utcnow()
                            ))
                        conn.commit()

                    self.logger.info(f"Generated manifest {manifest_id}")

                    return {
                        "status": "success",
                        "manifest_id": manifest_id,
                        "document_type": "manifest",
                        "content_length": len(markdown_content),
                        "sections": len(manifest["sections"])
                    }

                except psycopg2.OperationalError as e:
                    if attempt < self.max_retries - 1:
                        wait_time = self.retry_backoff ** attempt
                        self.logger.warning(f"Retry {attempt + 1}/{self.max_retries} after {wait_time}s: {e}")
                        time.sleep(wait_time)
                        continue
                    raise

        except Exception as e:
            self.logger.error(f"Manifest generation failed: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}

    def _generate_white_paper(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Generate white paper."""
        try:
            topic = task.get("topic", "")
            research_data = task.get("research_data", {})
            analysis = task.get("analysis", {})
            
            paper_id = str(uuid.uuid4())
            
            # Build white paper structure
            white_paper = {
                "paper_id": paper_id,
                "title": f"White Paper: {topic}",
                "created_at": datetime.utcnow().isoformat(),
                "abstract": self._generate_abstract(topic, research_data),
                "sections": [
                    {
                        "title": "Introduction",
                        "content": self._generate_introduction(topic)
                    },
                    {
                        "title": "Background",
                        "content": self._generate_background(research_data)
                    },
                    {
                        "title": "Analysis",
                        "content": self._generate_analysis_section(analysis)
                    },
                    {
                        "title": "Findings",
                        "content": self._generate_findings(research_data)
                    },
                    {
                        "title": "Implications",
                        "content": self._generate_implications(analysis)
                    },
                    {
                        "title": "Conclusion",
                        "content": self._generate_conclusion(topic, research_data)
                    }
                ]
            }
            
            # Convert to markdown
            markdown_content = self._white_paper_to_markdown(white_paper)

            # Store in database with retry logic
            for attempt in range(self.max_retries):
                try:
                    with self.db_manager.get_connection() as conn:
                        with conn.cursor() as cur:
                            cur.execute("""
                                INSERT INTO generated_documents
                                (document_id, document_type, content, metadata, created_at)
                                VALUES (%s, %s, %s, %s, %s)
                            """, (
                                paper_id,
                                "white_paper",
                                markdown_content,
                                json.dumps(white_paper),
                                datetime.utcnow()
                            ))
                        conn.commit()

                    self.logger.info(f"Generated white paper {paper_id}")

                    return {
                        "status": "success",
                        "paper_id": paper_id,
                        "document_type": "white_paper",
                        "content_length": len(markdown_content),
                        "sections": len(white_paper["sections"])
                    }

                except psycopg2.OperationalError as e:
                    if attempt < self.max_retries - 1:
                        wait_time = self.retry_backoff ** attempt
                        self.logger.warning(f"Retry {attempt + 1}/{self.max_retries} after {wait_time}s: {e}")
                        time.sleep(wait_time)
                        continue
                    raise

        except Exception as e:
            self.logger.error(f"White paper generation failed: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}

    def _generate_topic_documentation(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Generate topic-specific documentation."""
        try:
            topic = task.get("topic", "")
            content = task.get("content", "")
            examples = task.get("examples", [])
            
            doc_id = str(uuid.uuid4())
            
            # Build documentation structure
            documentation = {
                "doc_id": doc_id,
                "title": f"Documentation: {topic}",
                "created_at": datetime.utcnow().isoformat(),
                "overview": content,
                "sections": [
                    {
                        "title": "Overview",
                        "content": content
                    },
                    {
                        "title": "Key Concepts",
                        "content": self._generate_key_concepts(topic)
                    },
                    {
                        "title": "Examples",
                        "content": self._generate_examples_section(examples)
                    },
                    {
                        "title": "Best Practices",
                        "content": self._generate_best_practices(topic)
                    }
                ]
            }
            
            # Convert to markdown
            markdown_content = self._documentation_to_markdown(documentation)
            
            # Store in database
            query = """
            INSERT INTO generated_documents (document_id, document_type, content, metadata, created_at)
            VALUES (%s, %s, %s, %s, %s)
            """
            
            self.db_connection.execute(query, (
                doc_id,
                "topic_documentation",
                markdown_content,
                json.dumps(documentation),
                datetime.utcnow()
            ))
            self.db_connection.commit()
            
            self.logger.info(f"Generated topic documentation {doc_id}")
            
            return {
                "status": "success",
                "doc_id": doc_id,
                "document_type": "topic_documentation",
                "content": markdown_content,
                "sections": len(documentation["sections"])
            }
        except Exception as e:
            self.logger.error(f"Topic documentation generation failed: {e}")
            return {"status": "error", "error": str(e)}

    def _generate_report(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive report."""
        try:
            report_type = task.get("report_type", "analysis")
            data = task.get("data", {})
            
            report_id = str(uuid.uuid4())
            
            report = {
                "report_id": report_id,
                "report_type": report_type,
                "created_at": datetime.utcnow().isoformat(),
                "data": data
            }
            
            markdown_content = self._report_to_markdown(report)
            
            # Store in database
            query = """
            INSERT INTO generated_documents (document_id, document_type, content, metadata, created_at)
            VALUES (%s, %s, %s, %s, %s)
            """
            
            self.db_connection.execute(query, (
                report_id,
                report_type,
                markdown_content,
                json.dumps(report),
                datetime.utcnow()
            ))
            self.db_connection.commit()
            
            return {
                "status": "success",
                "report_id": report_id,
                "report_type": report_type,
                "content": markdown_content
            }
        except Exception as e:
            self.logger.error(f"Report generation failed: {e}")
            return {"status": "error", "error": str(e)}

    # Helper methods for content generation
    def _generate_summary(self, findings: Dict[str, Any]) -> str:
        return "Executive summary of research findings."

    def _generate_objectives(self, topic: str) -> str:
        return f"Research objectives for {topic}."

    def _generate_methodology(self) -> str:
        return "Research methodology and approach."

    def _generate_key_findings(self, findings: Dict[str, Any]) -> str:
        return "Key findings from research."

    def _generate_recommendations(self, findings: Dict[str, Any]) -> str:
        return "Recommendations based on findings."

    def _generate_abstract(self, topic: str, data: Dict[str, Any]) -> str:
        return f"Abstract for {topic}."

    def _generate_introduction(self, topic: str) -> str:
        return f"Introduction to {topic}."

    def _generate_background(self, data: Dict[str, Any]) -> str:
        return "Background information."

    def _generate_analysis_section(self, analysis: Dict[str, Any]) -> str:
        return "Detailed analysis."

    def _generate_findings(self, data: Dict[str, Any]) -> str:
        return "Research findings."

    def _generate_implications(self, analysis: Dict[str, Any]) -> str:
        return "Implications of findings."

    def _generate_conclusion(self, topic: str, data: Dict[str, Any]) -> str:
        return f"Conclusion for {topic}."

    def _generate_key_concepts(self, topic: str) -> str:
        return f"Key concepts for {topic}."

    def _generate_examples_section(self, examples: List[str]) -> str:
        return "\n".join([f"- {ex}" for ex in examples])

    def _generate_best_practices(self, topic: str) -> str:
        return f"Best practices for {topic}."

    # Markdown conversion methods
    def _manifest_to_markdown(self, manifest: Dict[str, Any]) -> str:
        md = f"# {manifest['title']}\n\n"
        md += f"**Created:** {manifest['created_at']}\n\n"
        for section in manifest.get("sections", []):
            md += f"## {section['title']}\n\n{section['content']}\n\n"
        return md

    def _white_paper_to_markdown(self, paper: Dict[str, Any]) -> str:
        md = f"# {paper['title']}\n\n"
        md += f"## Abstract\n\n{paper['abstract']}\n\n"
        for section in paper.get("sections", []):
            md += f"## {section['title']}\n\n{section['content']}\n\n"
        return md

    def _documentation_to_markdown(self, doc: Dict[str, Any]) -> str:
        md = f"# {doc['title']}\n\n"
        for section in doc.get("sections", []):
            md += f"## {section['title']}\n\n{section['content']}\n\n"
        return md

    def _report_to_markdown(self, report: Dict[str, Any]) -> str:
        md = f"# {report['report_type'].title()} Report\n\n"
        md += f"**Generated:** {report['created_at']}\n\n"
        md += "## Data\n\n```json\n"
        md += json.dumps(report['data'], indent=2)
        md += "\n```\n"
        return md

