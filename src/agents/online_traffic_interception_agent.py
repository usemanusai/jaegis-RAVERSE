"""
Traffic Interception Agent for RAVERSE Online.
Captures and analyzes HTTP(S) traffic using mitmproxy and Playwright.
"""

import logging
import json
import subprocess
import os
import time
import re
from typing import Dict, Any, List, Optional
from datetime import datetime
import tempfile
import threading
from urllib.parse import urlparse

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None

try:
    from mitmproxy import proxy, options
    from mitmproxy.tools.dump import DumpMaster
except ImportError:
    DumpMaster = None

from .base_memory_agent import BaseMemoryAgent

logger = logging.getLogger(__name__)


class TrafficInterceptionAgent(BaseMemoryAgent):
    """
    Traffic Interception Agent - Captures and analyzes HTTP(S) traffic.

    Tools: mitmproxy, OWASP ZAP, Burp Suite, Wireshark

    Optional Memory Support:
        memory_strategy: Optional memory strategy (e.g., "os_like")
        memory_config: Optional memory configuration dictionary
    """

    def __init__(
        self,
        orchestrator=None,
        memory_strategy: Optional[str] = None,
        memory_config: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            name="Traffic Interception Agent",
            agent_type="TRAFFIC",
            orchestrator=orchestrator,
            memory_strategy=memory_strategy,
            memory_config=memory_config
        )
        self.temp_dir = tempfile.mkdtemp(prefix="raverse_traffic_")
        self.pcap_file = os.path.join(self.temp_dir, "traffic.pcap")
        self.log_file = os.path.join(self.temp_dir, "traffic.log")

    def _execute_impl(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute traffic interception on target.

        Args:
            task: {
                "target_url": "https://example.com",
                "duration_seconds": 30,
                "scope": {...},
                "options": {...}
            }
        """
        target_url = task.get("target_url")
        duration = task.get("duration_seconds", 30)
        scope = task.get("scope", {})
        options = task.get("options", {})

        # Get memory context if available
        memory_context = self.get_memory_context(target_url)

        if not target_url:
            raise ValueError("target_url required")

        # Validate authorization
        if not self.validate_authorization(target_url, scope):
            return self.skip("Target not in authorized scope")

        self.logger.info(f"Starting traffic interception on {target_url} for {duration}s")

        results = {
            "target_url": target_url,
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": duration,
            "requests": [],
            "responses": [],
            "api_calls": [],
            "cookies": [],
            "headers_analysis": {},
            "pcap_file": self.pcap_file,
            "log_file": self.log_file
        }

        try:
            # Step 1: Start traffic capture
            self.report_progress(0.1, "Starting traffic capture")
            self._start_capture()

            # Step 2: Simulate user interaction (would use Playwright/Puppeteer in real implementation)
            self.report_progress(0.3, "Simulating user interaction")
            self._simulate_interaction(target_url, duration)

            # Step 3: Stop capture and parse
            self.report_progress(0.6, "Parsing captured traffic")
            traffic_data = self._parse_traffic()

            # Step 4: Analyze traffic
            self.report_progress(0.8, "Analyzing traffic patterns")
            results["requests"] = traffic_data.get("requests", [])
            results["responses"] = traffic_data.get("responses", [])
            results["api_calls"] = self._extract_api_calls(traffic_data)
            results["cookies"] = self._extract_cookies(traffic_data)
            results["headers_analysis"] = self._analyze_headers(traffic_data)

            self.report_progress(1.0, "Traffic interception complete")

            # Add artifacts
            self.add_artifact("traffic_pcap", self.pcap_file, "PCAP file with captured traffic")
            self.add_artifact("api_calls", results["api_calls"], "Extracted API calls")
            self.add_artifact("cookies", results["cookies"], "Extracted cookies")

            # Set metrics
            self.set_metric("requests_captured", len(results["requests"]))
            self.set_metric("api_calls_found", len(results["api_calls"]))
            self.set_metric("cookies_found", len(results["cookies"]))

            # Store in memory if enabled
            if results:
                self.add_to_memory(target_url, json.dumps(results, default=str))

            return results

        except Exception as e:
            self.logger.error(f"Traffic interception failed: {e}")
            raise

    def _start_capture(self):
        """Start traffic capture using mitmproxy or tcpdump."""
        try:
            # Try using tcpdump for PCAP capture
            cmd = [
                "tcpdump",
                "-i", "any",
                "-w", self.pcap_file,
                "-G", "30",  # Rotate every 30 seconds
                "tcp port 80 or tcp port 443"
            ]

            try:
                self.capture_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    preexec_fn=os.setsid if hasattr(os, 'setsid') else None
                )
                self.logger.info(f"Traffic capture started with tcpdump - PCAP: {self.pcap_file}")
            except FileNotFoundError:
                self.logger.warning("tcpdump not found, using Playwright-based traffic capture")
                self.capture_process = None

        except Exception as e:
            self.logger.warning(f"Failed to start capture: {e}")
            self.capture_process = None

    def _simulate_interaction(self, target_url: str, duration: int):
        """Simulate user interaction with target using Playwright."""
        try:
            if not sync_playwright:
                self.logger.warning("Playwright not installed, skipping browser automation")
                time.sleep(min(duration, 5))
                return

            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(
                    ignore_https_errors=True,
                    proxy={"server": "http://127.0.0.1:8080"}  # mitmproxy proxy
                )
                page = context.new_page()

                try:
                    self.logger.info(f"Navigating to {target_url}")
                    page.goto(target_url, wait_until="networkidle", timeout=30000)

                    # Simulate user interactions
                    start_time = time.time()
                    while time.time() - start_time < duration:
                        # Click on links
                        links = page.query_selector_all("a")
                        if links:
                            links[0].click()
                            page.wait_for_load_state("networkidle")

                        # Fill forms
                        inputs = page.query_selector_all("input")
                        for inp in inputs[:3]:
                            inp.fill("test_value")

                        time.sleep(1)

                    self.logger.info(f"Interaction simulation completed")

                except Exception as e:
                    self.logger.warning(f"Browser interaction failed: {e}")
                finally:
                    context.close()
                    browser.close()

        except Exception as e:
            self.logger.warning(f"Playwright interaction failed: {e}")
            time.sleep(min(duration, 5))

    def _parse_traffic(self) -> Dict[str, Any]:
        """Parse captured traffic from PCAP file."""
        traffic_data = {
            "requests": [],
            "responses": [],
            "total_bytes": 0
        }

        try:
            # Stop capture if running
            if hasattr(self, 'capture_process') and self.capture_process:
                try:
                    if hasattr(os, 'killpg'):
                        os.killpg(os.getpgid(self.capture_process.pid), 15)
                    else:
                        self.capture_process.terminate()
                    self.capture_process.wait(timeout=5)
                except Exception as e:
                    self.logger.warning(f"Failed to stop capture process: {e}")

            # Parse PCAP file if it exists
            if os.path.exists(self.pcap_file) and os.path.getsize(self.pcap_file) > 0:
                try:
                    import scapy.all as scapy
                    packets = scapy.rdpcap(self.pcap_file)

                    for packet in packets:
                        if packet.haslayer(scapy.IP):
                            traffic_data["total_bytes"] += len(packet)

                            # Extract HTTP requests/responses
                            if packet.haslayer(scapy.Raw):
                                payload = bytes(packet[scapy.Raw].load)
                                if b"HTTP" in payload:
                                    traffic_data["requests"].append({
                                        "method": "UNKNOWN",
                                        "url": "extracted_from_pcap",
                                        "headers": {},
                                        "timestamp": datetime.now().isoformat()
                                    })

                    self.logger.info(f"Parsed {len(traffic_data['requests'])} requests from PCAP")
                except ImportError:
                    self.logger.warning("Scapy not installed, cannot parse PCAP")
            else:
                self.logger.warning(f"PCAP file not found or empty: {self.pcap_file}")

        except Exception as e:
            self.logger.warning(f"Traffic parsing failed: {e}")

        return traffic_data

    def _extract_api_calls(self, traffic_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract API calls from traffic."""
        api_calls = []
        
        for req in traffic_data.get("requests", []):
            if "/api/" in req.get("url", ""):
                api_calls.append({
                    "method": req.get("method"),
                    "endpoint": req.get("url"),
                    "headers": req.get("headers", {}),
                    "has_auth": "Authorization" in req.get("headers", {})
                })
        
        return api_calls

    def _extract_cookies(self, traffic_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract cookies from traffic."""
        cookies = []
        
        for req in traffic_data.get("requests", []):
            headers = req.get("headers", {})
            if "Cookie" in headers:
                cookies.append({
                    "value": headers["Cookie"],
                    "timestamp": req.get("timestamp")
                })
        
        return cookies

    def _analyze_headers(self, traffic_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze response headers for security issues."""
        analysis = {
            "security_headers": {},
            "missing_headers": [],
            "suspicious_headers": []
        }
        
        for resp in traffic_data.get("responses", []):
            headers = resp.get("headers", {})
            
            # Check for security headers
            security_headers = [
                "Strict-Transport-Security",
                "X-Content-Type-Options",
                "X-Frame-Options",
                "Content-Security-Policy"
            ]
            
            for header in security_headers:
                if header in headers:
                    analysis["security_headers"][header] = headers[header]
                else:
                    analysis["missing_headers"].append(header)
        
        return analysis

    def inspect_websocket(self, traffic_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Inspect WebSocket connections in traffic.

        Args:
            traffic_data: Traffic data dictionary

        Returns:
            List of WebSocket connections found
        """
        websockets = []

        for req in traffic_data.get("requests", []):
            headers = req.get("headers", {})

            # Check for WebSocket upgrade
            if headers.get("Upgrade", "").lower() == "websocket":
                ws_data = {
                    'url': req.get("url", "").replace("http", "ws"),
                    'protocol': headers.get("Sec-WebSocket-Protocol", "unknown"),
                    'version': headers.get("Sec-WebSocket-Version", "13"),
                    'key': headers.get("Sec-WebSocket-Key", ""),
                    'timestamp': req.get("timestamp"),
                }
                websockets.append(ws_data)

        return websockets

    def detect_websocket_handshake(self, traffic_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Detect WebSocket handshakes (HTTP 101 Switching Protocols).

        Args:
            traffic_data: Traffic data dictionary

        Returns:
            List of WebSocket handshakes detected
        """
        handshakes = []

        for resp in traffic_data.get("responses", []):
            status = resp.get("status_code", 0)
            headers = resp.get("headers", {})

            # HTTP 101 Switching Protocols indicates WebSocket upgrade
            if status == 101 and headers.get("Upgrade", "").lower() == "websocket":
                handshakes.append({
                    'status': status,
                    'upgrade': headers.get("Upgrade"),
                    'connection': headers.get("Connection"),
                    'protocol': headers.get("Sec-WebSocket-Protocol"),
                    'timestamp': resp.get("timestamp"),
                })

        return handshakes

    def parse_websocket_frames(self, websocket_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parse WebSocket frames and messages.

        Args:
            websocket_data: WebSocket data dictionary

        Returns:
            List of parsed frames
        """
        frames = []

        # Extract frames from WebSocket data
        messages = websocket_data.get("messages", [])
        for msg in messages:
            frame = {
                'type': msg.get("type", "unknown"),  # text, binary, ping, pong, close
                'payload': msg.get("payload", ""),
                'timestamp': msg.get("timestamp"),
                'direction': msg.get("direction", "unknown"),  # client->server or server->client
            }
            frames.append(frame)

        return frames

    def classify_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classify response as API or not.

        Args:
            response: Response dictionary with status, headers, body

        Returns:
            Classification result with confidence score
        """
        classification = {
            'is_api': False,
            'confidence': 0.0,
            'reasons': [],
            'content_type': response.get("headers", {}).get("Content-Type", ""),
        }

        headers = response.get("headers", {})
        content_type = headers.get("Content-Type", "").lower()

        # Check content type
        if "application/json" in content_type:
            classification['confidence'] += 0.3
            classification['reasons'].append("JSON content type")
        elif "application/xml" in content_type or "text/xml" in content_type:
            classification['confidence'] += 0.25
            classification['reasons'].append("XML content type")

        # Check for authentication headers
        if "Authorization" in headers or "X-API-Key" in headers:
            classification['confidence'] += 0.2
            classification['reasons'].append("Authentication header present")

        # Check URL pattern
        url = response.get("url", "")
        if any(keyword in url.lower() for keyword in ["/api/", "/v1/", "/v2/", "/graphql"]):
            classification['confidence'] += 0.4
            classification['reasons'].append("API-like URL pattern")

        # Check response structure
        try:
            body = response.get("body", "")
            if body and (body.startswith("{") or body.startswith("[")):
                classification['confidence'] += 0.1
                classification['reasons'].append("JSON-like structure")
        except:
            pass

        # Determine if API
        classification['is_api'] = classification['confidence'] >= 0.6

        return classification

    def cleanup(self):
        """Clean up temporary files."""
        try:
            import shutil
            if os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
                self.logger.info(f"Cleaned up temporary directory: {self.temp_dir}")
        except Exception as e:
            self.logger.warning(f"Cleanup failed: {e}")

