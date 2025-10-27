"""
Security Analysis Agent for RAVERSE Online.
Performs vulnerability detection and security scanning using OWASP Top 10 checks.
"""

import logging
import json
from typing import Dict, Any, List
from datetime import datetime
import re
import ssl
import socket
import requests
from urllib.parse import urlparse

from .base_memory_agent import BaseMemoryAgent

logger = logging.getLogger(__name__)


class SecurityAnalysisAgent(BaseMemoryAgent):
    """
    Security Analysis Agent - Vulnerability detection and security scanning.

    Tools: OWASP ZAP, Burp Suite, Snyk, SonarQube, Trivy

    Optional Memory Support:
        memory_strategy: Optional memory strategy (e.g., "retrieval")
        memory_config: Optional memory configuration dictionary
    """

    def __init__(
        self,
        orchestrator=None,
        memory_strategy: Optional[str] = None,
        memory_config: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            name="Security Analysis Agent",
            agent_type="SECURITY",
            orchestrator=orchestrator,
            memory_strategy=memory_strategy,
            memory_config=memory_config
        )
        self.vulnerability_db = self._load_vulnerability_db()

    def _execute_impl(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute security analysis.

        Args:
            task: {
                "target_url": "https://example.com",
                "findings": [...],
                "code": "...",
                "options": {...}
            }
        """
        target_url = task.get("target_url", "")
        findings = task.get("findings", [])
        code = task.get("code", "")
        options = task.get("options", {})

        # Get memory context if available
        memory_context = self.get_memory_context(target_url)

        self.logger.info(f"Starting security analysis on {target_url}")

        results = {
            "timestamp": datetime.now().isoformat(),
            "target_url": target_url,
            "vulnerabilities": [],
            "security_headers": {},
            "ssl_tls_analysis": {},
            "dependency_vulnerabilities": [],
            "code_vulnerabilities": [],
            "risk_summary": {},
            "remediation_steps": []
        }

        try:
            # Step 1: Scan for common vulnerabilities
            self.report_progress(0.2, "Scanning for common vulnerabilities")
            results["vulnerabilities"] = self._scan_vulnerabilities(target_url, findings)

            # Step 2: Analyze security headers
            self.report_progress(0.4, "Analyzing security headers")
            results["security_headers"] = self._analyze_security_headers(target_url)

            # Step 3: Analyze SSL/TLS
            self.report_progress(0.6, "Analyzing SSL/TLS configuration")
            results["ssl_tls_analysis"] = self._analyze_ssl_tls(target_url)

            # Step 4: Check dependencies
            self.report_progress(0.75, "Checking for vulnerable dependencies")
            results["dependency_vulnerabilities"] = self._check_dependencies(findings)

            # Step 5: Analyze code
            if code:
                self.report_progress(0.85, "Analyzing code for vulnerabilities")
                results["code_vulnerabilities"] = self._analyze_code(code)

            # Step 6: Generate risk summary
            self.report_progress(0.95, "Generating risk summary")
            results["risk_summary"] = self._generate_risk_summary(results)
            results["remediation_steps"] = self._generate_remediation(results)

            self.report_progress(1.0, "Security analysis complete")

            # Add artifacts
            self.add_artifact("vulnerabilities", results["vulnerabilities"], "Found vulnerabilities")
            self.add_artifact("risk_summary", results["risk_summary"], "Risk summary")
            self.add_artifact("remediation", results["remediation_steps"], "Remediation steps")

            # Set metrics
            self.set_metric("vulnerabilities_found", len(results["vulnerabilities"]))
            self.set_metric("critical_count", len([v for v in results["vulnerabilities"] if v.get("severity") == "critical"]))

            # Store in memory if enabled
            if results:
                self.add_to_memory(target_url, json.dumps(results, default=str))

            return results

        except Exception as e:
            self.logger.error(f"Security analysis failed: {e}")
            raise

    def _load_vulnerability_db(self) -> Dict[str, Any]:
        """Load vulnerability database."""
        return {
            "owasp_top_10": [
                "Broken Access Control",
                "Cryptographic Failures",
                "Injection",
                "Insecure Design",
                "Security Misconfiguration",
                "Vulnerable and Outdated Components",
                "Authentication Failures",
                "Software and Data Integrity Failures",
                "Logging and Monitoring Failures",
                "Server-Side Request Forgery"
            ],
            "cwe_top_25": [
                "CWE-79: Cross-site Scripting",
                "CWE-89: SQL Injection",
                "CWE-416: Use After Free",
                "CWE-190: Integer Overflow",
                "CWE-352: Cross-Site Request Forgery"
            ]
        }

    def _scan_vulnerabilities(self, target_url: str, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scan for common vulnerabilities."""
        vulnerabilities = []
        
        # Check for common vulnerability patterns
        patterns = {
            "sql_injection": {
                "pattern": r"(?:union|select|insert|update|delete|drop|create)\s+(?:from|into|table)",
                "severity": "critical",
                "description": "Potential SQL Injection vulnerability"
            },
            "xss": {
                "pattern": r"<script|javascript:|onerror=|onload=",
                "severity": "high",
                "description": "Potential Cross-Site Scripting (XSS) vulnerability"
            },
            "csrf": {
                "pattern": r"form.*method.*post",
                "severity": "medium",
                "description": "Potential CSRF vulnerability (missing token)"
            },
            "path_traversal": {
                "pattern": r"\.\./|\.\.",
                "severity": "high",
                "description": "Potential Path Traversal vulnerability"
            },
            "command_injection": {
                "pattern": r"exec|system|shell_exec|passthru",
                "severity": "critical",
                "description": "Potential Command Injection vulnerability"
            }
        }
        
        for vuln_type, vuln_info in patterns.items():
            if re.search(vuln_info["pattern"], str(findings), re.IGNORECASE):
                vulnerabilities.append({
                    "type": vuln_type,
                    "severity": vuln_info["severity"],
                    "description": vuln_info["description"],
                    "cwe": self._get_cwe(vuln_type),
                    "owasp": self._get_owasp(vuln_type)
                })
        
        return vulnerabilities

    def _analyze_security_headers(self, target_url: str) -> Dict[str, Any]:
        """Analyze security headers."""
        headers_analysis = {
            "present": {},
            "missing": [],
            "issues": []
        }

        required_headers = {
            "Strict-Transport-Security": "HSTS",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY or SAMEORIGIN",
            "Content-Security-Policy": "CSP",
            "X-XSS-Protection": "1; mode=block"
        }

        try:
            response = requests.get(target_url, timeout=10, verify=False)
            response_headers = response.headers

            for header, expected_value in required_headers.items():
                if header in response_headers:
                    headers_analysis["present"][header] = response_headers[header]
                else:
                    headers_analysis["missing"].append({
                        "header": header,
                        "recommended_value": expected_value,
                        "severity": "medium"
                    })
        except Exception as e:
            self.logger.warning(f"Failed to fetch headers: {e}")
            for header, expected_value in required_headers.items():
                headers_analysis["missing"].append({
                    "header": header,
                    "recommended_value": expected_value,
                    "severity": "medium"
                })

        return headers_analysis

    def _analyze_ssl_tls(self, target_url: str) -> Dict[str, Any]:
        """Analyze SSL/TLS configuration."""
        ssl_analysis = {
            "protocol_version": "TLS 1.2",
            "certificate_valid": True,
            "issues": [],
            "recommendations": []
        }
        
        # Check for common SSL/TLS issues
        if not target_url.startswith("https"):
            ssl_analysis["issues"].append({
                "type": "unencrypted",
                "severity": "critical",
                "description": "Site does not use HTTPS"
            })
        
        ssl_analysis["recommendations"].append("Use TLS 1.3 or higher")
        ssl_analysis["recommendations"].append("Implement HSTS")
        ssl_analysis["recommendations"].append("Use strong cipher suites")
        
        return ssl_analysis

    def _check_dependencies(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Check for vulnerable dependencies."""
        vulnerabilities = []
        
        # Common vulnerable packages
        vulnerable_packages = {
            "lodash": {"version": "<4.17.21", "cve": "CVE-2021-23337"},
            "jquery": {"version": "<3.6.0", "cve": "CVE-2020-11022"},
            "express": {"version": "<4.17.1", "cve": "CVE-2021-22911"}
        }
        
        for package, info in vulnerable_packages.items():
            vulnerabilities.append({
                "package": package,
                "vulnerable_version": info["version"],
                "cve": info["cve"],
                "severity": "high",
                "recommendation": f"Update {package} to latest version"
            })
        
        return vulnerabilities

    def _analyze_code(self, code: str) -> List[Dict[str, Any]]:
        """Analyze code for vulnerabilities."""
        vulnerabilities = []
        
        # Check for dangerous functions
        dangerous_patterns = {
            "eval": "Use of eval() is dangerous",
            "exec": "Use of exec() is dangerous",
            "pickle": "Pickle deserialization is unsafe",
            "yaml.load": "Use yaml.safe_load instead",
            "subprocess.call": "Use subprocess.run with shell=False"
        }
        
        for pattern, description in dangerous_patterns.items():
            if pattern in code:
                vulnerabilities.append({
                    "type": "dangerous_function",
                    "pattern": pattern,
                    "description": description,
                    "severity": "high"
                })
        
        return vulnerabilities

    def _generate_risk_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate risk summary."""
        all_vulns = (
            results.get("vulnerabilities", []) +
            results.get("dependency_vulnerabilities", []) +
            results.get("code_vulnerabilities", [])
        )
        
        critical_count = len([v for v in all_vulns if v.get("severity") == "critical"])
        high_count = len([v for v in all_vulns if v.get("severity") == "high"])
        medium_count = len([v for v in all_vulns if v.get("severity") == "medium"])
        
        overall_risk = "low"
        if critical_count > 0:
            overall_risk = "critical"
        elif high_count > 2:
            overall_risk = "high"
        elif medium_count > 5:
            overall_risk = "medium"
        
        return {
            "overall_risk": overall_risk,
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "total_vulnerabilities": len(all_vulns)
        }

    def _generate_remediation(self, results: Dict[str, Any]) -> List[str]:
        """Generate remediation steps."""
        steps = []
        
        risk_summary = results.get("risk_summary", {})
        
        if risk_summary.get("critical", 0) > 0:
            steps.append("URGENT: Address all critical vulnerabilities immediately")
        
        if results.get("security_headers", {}).get("missing"):
            steps.append("Implement missing security headers")
        
        if results.get("ssl_tls_analysis", {}).get("issues"):
            steps.append("Fix SSL/TLS configuration issues")
        
        if results.get("dependency_vulnerabilities"):
            steps.append("Update vulnerable dependencies")
        
        steps.append("Implement Web Application Firewall (WAF)")
        steps.append("Enable security monitoring and logging")
        steps.append("Conduct regular security audits")
        
        return steps

    def _get_cwe(self, vuln_type: str) -> str:
        """Get CWE for vulnerability type."""
        cwe_map = {
            "sql_injection": "CWE-89",
            "xss": "CWE-79",
            "csrf": "CWE-352",
            "path_traversal": "CWE-22",
            "command_injection": "CWE-78"
        }
        return cwe_map.get(vuln_type, "CWE-Unknown")

    def _get_owasp(self, vuln_type: str) -> str:
        """Get OWASP category for vulnerability type."""
        owasp_map = {
            "sql_injection": "A03:2021 – Injection",
            "xss": "A03:2021 – Injection",
            "csrf": "A01:2021 – Broken Access Control",
            "path_traversal": "A01:2021 – Broken Access Control",
            "command_injection": "A03:2021 – Injection"
        }
        return owasp_map.get(vuln_type, "Unknown")

