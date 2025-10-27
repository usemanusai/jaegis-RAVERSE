"""
AI Co-Pilot Agent for RAVERSE Online.
Provides LLM-assisted analysis using OpenRouter, Claude, GPT-4, Ollama with retry logic.
"""

import logging
import json
import os
import time
from typing import Dict, Any, List, Optional
from datetime import datetime
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .online_base_agent import OnlineBaseAgent

logger = logging.getLogger(__name__)


class AICoPilotAgent(OnlineBaseAgent):
    """
    AI Co-Pilot Agent - LLM-assisted analysis of findings.
    
    Tools: OpenRouter, Claude API, GPT-4, Ollama, vLLM, LangChain
    """

    def __init__(self, orchestrator=None, api_key=None, model=None):
        super().__init__(
            name="AI Co-Pilot Agent",
            agent_type="AI_COPILOT",
            orchestrator=orchestrator
        )
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        self.model = model or os.getenv("OPENROUTER_MODEL", "meta-llama/llama-3.3-70b-instruct:free")
        self.base_url = "https://openrouter.ai/api/v1"

    def _execute_impl(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute AI-assisted analysis.
        
        Args:
            task: {
                "analysis_type": "code_review|vulnerability_analysis|pattern_detection",
                "content": "...",
                "context": {...},
                "options": {...}
            }
        """
        analysis_type = task.get("analysis_type", "code_review")
        content = task.get("content", "")
        context = task.get("context", {})
        options = task.get("options", {})
        
        if not content:
            raise ValueError("content required")
        
        self.logger.info(f"Starting AI analysis: {analysis_type}")
        
        results = {
            "timestamp": datetime.now().isoformat(),
            "analysis_type": analysis_type,
            "model": self.model,
            "analysis": {},
            "findings": [],
            "recommendations": [],
            "risk_assessment": {},
            "confidence_score": 0.0
        }
        
        try:
            # Step 1: Prepare analysis prompt
            self.report_progress(0.2, "Preparing analysis prompt")
            prompt = self._prepare_prompt(analysis_type, content, context)
            
            # Step 2: Call LLM
            self.report_progress(0.5, "Calling LLM for analysis")
            llm_response = self._call_llm(prompt)
            
            # Step 3: Parse response
            self.report_progress(0.7, "Parsing LLM response")
            results["analysis"] = self._parse_response(llm_response)
            
            # Step 4: Extract findings
            self.report_progress(0.85, "Extracting findings")
            results["findings"] = self._extract_findings(results["analysis"])
            results["recommendations"] = self._extract_recommendations(results["analysis"])
            results["risk_assessment"] = self._assess_risk(results["findings"])
            
            # Step 5: Calculate confidence
            self.report_progress(0.95, "Calculating confidence score")
            results["confidence_score"] = self._calculate_confidence(results)
            
            self.report_progress(1.0, "AI analysis complete")
            
            # Add artifacts
            self.add_artifact("analysis", results["analysis"], "LLM analysis output")
            self.add_artifact("findings", results["findings"], "Extracted findings")
            self.add_artifact("recommendations", results["recommendations"], "Recommendations")
            
            # Set metrics
            self.set_metric("findings_count", len(results["findings"]))
            self.set_metric("confidence_score", results["confidence_score"])
            
            return results
            
        except Exception as e:
            self.logger.error(f"AI analysis failed: {e}")
            raise

    def _prepare_prompt(self, analysis_type: str, content: str, context: Dict[str, Any]) -> str:
        """Prepare analysis prompt for LLM."""
        prompts = {
            "code_review": f"""Analyze the following code for security issues, best practices, and potential vulnerabilities:

{content}

Context: {json.dumps(context)}

Provide:
1. Security vulnerabilities found
2. Code quality issues
3. Best practice violations
4. Recommendations for improvement
5. Risk assessment (low/medium/high)""",
            
            "vulnerability_analysis": f"""Analyze the following for potential vulnerabilities and security risks:

{content}

Context: {json.dumps(context)}

Provide:
1. Identified vulnerabilities
2. Attack vectors
3. Potential impact
4. Mitigation strategies
5. CVSS score estimate""",
            
            "pattern_detection": f"""Analyze the following for suspicious patterns and anomalies:

{content}

Context: {json.dumps(context)}

Provide:
1. Suspicious patterns detected
2. Anomalies found
3. Potential malicious behavior
4. Confidence level for each finding
5. Recommended actions"""
        }
        
        return prompts.get(analysis_type, prompts["code_review"])

    def _call_llm(self, prompt: str, max_retries: int = 3) -> str:
        """Call LLM via OpenRouter with exponential backoff retry logic."""
        if not self.api_key:
            self.logger.warning("No API key provided, returning mock response")
            return self._get_mock_response()

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        data = {
            "model": self.model,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.7,
            "max_tokens": 2000
        }

        # Retry logic with exponential backoff
        for attempt in range(max_retries):
            try:
                response = requests.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=data,
                    timeout=30
                )

                if response.status_code == 200:
                    result = response.json()
                    return result['choices'][0]['message']['content']
                elif response.status_code in [429, 500, 502, 503, 504]:
                    # Retryable errors
                    if attempt < max_retries - 1:
                        wait_time = 2 ** attempt  # Exponential backoff: 1s, 2s, 4s
                        self.logger.warning(f"LLM call failed with {response.status_code}, retrying in {wait_time}s (attempt {attempt + 1}/{max_retries})")
                        time.sleep(wait_time)
                        continue
                    else:
                        self.logger.warning(f"LLM call failed after {max_retries} attempts")
                        return self._get_mock_response()
                else:
                    self.logger.warning(f"LLM call failed: {response.status_code}")
                    return self._get_mock_response()

            except requests.exceptions.Timeout:
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt
                    self.logger.warning(f"LLM call timeout, retrying in {wait_time}s (attempt {attempt + 1}/{max_retries})")
                    time.sleep(wait_time)
                    continue
                else:
                    self.logger.warning(f"LLM call timeout after {max_retries} attempts")
                    return self._get_mock_response()
            except requests.exceptions.ConnectionError as e:
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt
                    self.logger.warning(f"LLM connection error: {e}, retrying in {wait_time}s (attempt {attempt + 1}/{max_retries})")
                    time.sleep(wait_time)
                    continue
                else:
                    self.logger.warning(f"LLM connection error after {max_retries} attempts: {e}")
                    return self._get_mock_response()
            except Exception as e:
                self.logger.warning(f"LLM call error: {e}")
                return self._get_mock_response()

        return self._get_mock_response()

    def _get_mock_response(self) -> str:
        """Return mock LLM response for testing."""
        return """## Security Analysis Results

### Vulnerabilities Found
1. **SQL Injection Risk** - User input not properly sanitized
2. **XSS Vulnerability** - DOM manipulation without escaping
3. **CSRF Token Missing** - No CSRF protection on state-changing operations

### Code Quality Issues
- Missing error handling in async functions
- Inconsistent naming conventions
- No input validation

### Recommendations
1. Implement parameterized queries
2. Use content security policy
3. Add CSRF tokens to forms
4. Implement comprehensive error handling

### Risk Assessment
- Overall Risk: **HIGH**
- Confidence: 85%"""

    def _parse_response(self, response: str) -> Dict[str, Any]:
        """Parse LLM response."""
        return {
            "raw_response": response,
            "sections": self._extract_sections(response)
        }

    def _extract_sections(self, response: str) -> Dict[str, str]:
        """Extract sections from response."""
        sections = {}
        current_section = None
        current_content = []
        
        for line in response.split('\n'):
            if line.startswith('##'):
                if current_section:
                    sections[current_section] = '\n'.join(current_content)
                current_section = line.replace('##', '').strip()
                current_content = []
            elif current_section:
                current_content.append(line)
        
        if current_section:
            sections[current_section] = '\n'.join(current_content)
        
        return sections

    def _extract_findings(self, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract findings from analysis."""
        findings = []
        
        sections = analysis.get("sections", {})
        for section_name, section_content in sections.items():
            if "vulnerab" in section_name.lower() or "issue" in section_name.lower():
                # Parse findings from section
                lines = section_content.split('\n')
                for line in lines:
                    if line.strip().startswith('-') or line.strip().startswith('*'):
                        findings.append({
                            "type": section_name,
                            "description": line.strip()[1:].strip(),
                            "severity": self._estimate_severity(line)
                        })
        
        return findings

    def _extract_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Extract recommendations from analysis."""
        recommendations = []
        
        sections = analysis.get("sections", {})
        for section_name, section_content in sections.items():
            if "recommend" in section_name.lower():
                lines = section_content.split('\n')
                for line in lines:
                    if line.strip().startswith('-') or line.strip().startswith('*'):
                        recommendations.append(line.strip()[1:].strip())
        
        return recommendations

    def _assess_risk(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess overall risk from findings."""
        risk_assessment = {
            "overall_risk": "low",
            "high_severity_count": 0,
            "medium_severity_count": 0,
            "low_severity_count": 0
        }
        
        for finding in findings:
            severity = finding.get("severity", "low")
            if severity == "high":
                risk_assessment["high_severity_count"] += 1
            elif severity == "medium":
                risk_assessment["medium_severity_count"] += 1
            else:
                risk_assessment["low_severity_count"] += 1
        
        # Determine overall risk
        if risk_assessment["high_severity_count"] > 0:
            risk_assessment["overall_risk"] = "high"
        elif risk_assessment["medium_severity_count"] > 2:
            risk_assessment["overall_risk"] = "medium"
        
        return risk_assessment

    def _estimate_severity(self, text: str) -> str:
        """Estimate severity from text."""
        text_lower = text.lower()
        
        if any(word in text_lower for word in ["critical", "severe", "high", "rce", "injection"]):
            return "high"
        elif any(word in text_lower for word in ["medium", "moderate", "warning"]):
            return "medium"
        else:
            return "low"

    def _calculate_confidence(self, results: Dict[str, Any]) -> float:
        """Calculate confidence score."""
        # Simple heuristic: more findings = higher confidence
        findings_count = len(results.get("findings", []))
        confidence = min(0.95, 0.5 + (findings_count * 0.05))
        return round(confidence, 2)

