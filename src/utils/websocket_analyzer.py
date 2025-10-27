"""
WebSocket Analyzer for DeepCrawler - Real-time Communication Analysis
Analyzes WebSocket connections and extracts API endpoints
Date: October 26, 2025
"""

import logging
import json
import re
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class WebSocketAnalyzer:
    """
    Analyzes WebSocket connections to extract API endpoints and protocols.
    """
    
    # Protocol patterns
    PROTOCOL_PATTERNS = {
        'socket_io': r'socket\.io',
        'sockjs': r'sockjs',
        'raw_websocket': r'ws(?:s)?://',
    }
    
    def __init__(self):
        """Initialize WebSocket analyzer."""
        self.websockets = []
        self.protocols = {}
    
    def detect_handshake(self, headers: Dict[str, str]) -> bool:
        """
        Detect WebSocket handshake (HTTP 101 Switching Protocols).
        
        Args:
            headers: HTTP response headers
            
        Returns:
            True if WebSocket handshake detected, False otherwise
        """
        upgrade = headers.get("Upgrade", "").lower()
        connection = headers.get("Connection", "").lower()
        
        # Check for WebSocket upgrade
        if upgrade == "websocket" and "upgrade" in connection:
            logger.debug("WebSocket handshake detected")
            return True
        
        return False
    
    def parse_frames(self, frames: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Parse WebSocket frames.
        
        Args:
            frames: List of WebSocket frames
            
        Returns:
            List of parsed frames with extracted data
        """
        parsed_frames = []
        
        for frame in frames:
            parsed_frame = {
                'type': frame.get('type', 'unknown'),
                'payload': frame.get('payload', ''),
                'timestamp': frame.get('timestamp'),
                'direction': frame.get('direction', 'unknown'),
                'is_json': False,
                'parsed_data': None,
            }
            
            # Try to parse payload as JSON
            try:
                payload = frame.get('payload', '')
                if payload and (payload.startswith('{') or payload.startswith('[')):
                    parsed_frame['parsed_data'] = json.loads(payload)
                    parsed_frame['is_json'] = True
            except (json.JSONDecodeError, ValueError):
                pass
            
            parsed_frames.append(parsed_frame)
        
        return parsed_frames
    
    def extract_messages(self, frames: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Extract messages from WebSocket frames.
        
        Args:
            frames: List of WebSocket frames
            
        Returns:
            List of extracted messages
        """
        messages = []
        
        for frame in frames:
            if frame.get('type') == 'text':
                message = {
                    'payload': frame.get('payload', ''),
                    'timestamp': frame.get('timestamp'),
                    'direction': frame.get('direction'),
                    'is_json': False,
                    'data': None,
                }
                
                # Try to parse as JSON
                try:
                    payload = frame.get('payload', '')
                    if payload:
                        message['data'] = json.loads(payload)
                        message['is_json'] = True
                except:
                    pass
                
                messages.append(message)
        
        return messages
    
    def analyze_protocol(self, url: str, headers: Dict[str, str]) -> Dict[str, Any]:
        """
        Analyze WebSocket protocol type.
        
        Args:
            url: WebSocket URL
            headers: Connection headers
            
        Returns:
            Protocol analysis dictionary
        """
        analysis = {
            'protocol': 'unknown',
            'url': url,
            'version': None,
            'subprotocol': None,
            'extensions': [],
        }
        
        # Check for Socket.IO
        if 'socket.io' in url.lower():
            analysis['protocol'] = 'socket.io'
            # Extract version from URL
            version_match = re.search(r'socket\.io/\?EIO=(\d+)', url)
            if version_match:
                analysis['version'] = version_match.group(1)
        
        # Check for SockJS
        elif 'sockjs' in url.lower():
            analysis['protocol'] = 'sockjs'
        
        # Check for raw WebSocket
        elif url.lower().startswith(('ws://', 'wss://')):
            analysis['protocol'] = 'raw_websocket'
        
        # Extract subprotocol
        subprotocol = headers.get('Sec-WebSocket-Protocol')
        if subprotocol:
            analysis['subprotocol'] = subprotocol
        
        # Extract extensions
        extensions = headers.get('Sec-WebSocket-Extensions', '')
        if extensions:
            analysis['extensions'] = [ext.strip() for ext in extensions.split(',')]
        
        return analysis
    
    def extract_endpoints(self, messages: List[Dict[str, Any]]) -> List[str]:
        """
        Extract API endpoints from WebSocket messages.
        
        Args:
            messages: List of WebSocket messages
            
        Returns:
            List of discovered endpoints
        """
        endpoints = []
        
        for message in messages:
            data = message.get('data')
            
            if isinstance(data, dict):
                # Look for common endpoint patterns in message data
                for key, value in data.items():
                    if isinstance(value, str):
                        # Check if value looks like an endpoint
                        if any(keyword in value.lower() for keyword in ['api', 'endpoint', 'url']):
                            if value not in endpoints:
                                endpoints.append(value)
            
            elif isinstance(data, list):
                # Check list items
                for item in data:
                    if isinstance(item, str):
                        if any(keyword in item.lower() for keyword in ['api', 'endpoint', 'url']):
                            if item not in endpoints:
                                endpoints.append(item)
            
            # Also check raw payload for URLs
            payload = message.get('payload', '')
            url_pattern = r'(?:https?://)?(?:[a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/[a-zA-Z0-9/_-]*)?'
            for match in re.finditer(url_pattern, payload):
                url = match.group(0)
                if url not in endpoints and len(url) > 10:
                    endpoints.append(url)
        
        return endpoints
    
    def get_message_patterns(self, messages: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze message patterns in WebSocket communication.
        
        Args:
            messages: List of WebSocket messages
            
        Returns:
            Message pattern analysis
        """
        patterns = {
            'total_messages': len(messages),
            'json_messages': 0,
            'text_messages': 0,
            'binary_messages': 0,
            'client_to_server': 0,
            'server_to_client': 0,
            'common_keys': {},
            'message_types': [],
        }
        
        for message in messages:
            # Count message types
            if message.get('is_json'):
                patterns['json_messages'] += 1
            else:
                patterns['text_messages'] += 1
            
            # Count directions
            if message.get('direction') == 'client->server':
                patterns['client_to_server'] += 1
            elif message.get('direction') == 'server->client':
                patterns['server_to_client'] += 1
            
            # Extract common keys from JSON messages
            data = message.get('data')
            if isinstance(data, dict):
                for key in data.keys():
                    patterns['common_keys'][key] = patterns['common_keys'].get(key, 0) + 1
                
                # Extract message type
                if 'type' in data:
                    msg_type = data['type']
                    if msg_type not in patterns['message_types']:
                        patterns['message_types'].append(msg_type)
        
        return patterns
    
    def detect_api_calls(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Detect API calls in WebSocket messages.
        
        Args:
            messages: List of WebSocket messages
            
        Returns:
            List of detected API calls
        """
        api_calls = []
        
        for message in messages:
            data = message.get('data')
            
            if isinstance(data, dict):
                # Look for action/method patterns
                if 'action' in data or 'method' in data or 'type' in data:
                    api_call = {
                        'action': data.get('action') or data.get('method') or data.get('type'),
                        'payload': data,
                        'direction': message.get('direction'),
                        'timestamp': message.get('timestamp'),
                    }
                    api_calls.append(api_call)
        
        return api_calls

