"""
DeepCrawler Configuration Management
Handles configuration loading, validation, and environment overrides
Date: October 26, 2025
"""

import os
import logging
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, List

logger = logging.getLogger(__name__)


@dataclass
class DeepCrawlerConfig:
    """
    Configuration for DeepCrawler system.
    Supports environment variable overrides.
    """
    
    # Crawling parameters
    max_depth: int = 3
    max_urls: int = 10000
    max_concurrent: int = 5
    timeout: int = 30
    rate_limit: float = 20.0  # requests per minute
    
    # Browser settings
    headless: bool = True
    browser_type: str = 'chromium'
    user_agent: Optional[str] = None
    
    # Proxy settings
    use_proxy: bool = False
    proxy_url: Optional[str] = None
    proxy_username: Optional[str] = None
    proxy_password: Optional[str] = None
    
    # Authentication settings
    auth_type: Optional[str] = None  # basic, bearer, cookie
    auth_token: Optional[str] = None
    auth_username: Optional[str] = None
    auth_password: Optional[str] = None
    
    # API discovery settings
    detect_rest_apis: bool = True
    detect_graphql: bool = True
    detect_websockets: bool = True
    min_confidence_score: float = 0.6
    
    # Database settings
    db_host: str = 'localhost'
    db_port: int = 5432
    db_user: str = 'raverse'
    db_password: str = os.getenv('DB_PASSWORD', 'raverse_password')
    db_name: str = 'raverse'
    
    # Redis settings
    redis_host: str = 'localhost'
    redis_port: int = 6379
    redis_db: int = 0
    
    # Memory settings
    memory_preset: str = 'medium'  # none, light, medium, heavy
    
    # Logging settings
    log_level: str = 'INFO'
    log_file: Optional[str] = None
    
    # Retry settings
    max_retries: int = 3
    retry_backoff_base: int = 2
    
    # Output settings
    output_format: str = 'openapi'  # openapi, json, yaml
    output_dir: str = './crawl_results'
    
    def __post_init__(self):
        """Validate configuration after initialization."""
        self.validate()
    
    @classmethod
    def load_from_env(cls) -> 'DeepCrawlerConfig':
        """
        Load configuration from environment variables.
        
        Environment variables:
        - DEEPCRAWLER_MAX_DEPTH
        - DEEPCRAWLER_MAX_URLS
        - DEEPCRAWLER_MAX_CONCURRENT
        - DEEPCRAWLER_TIMEOUT
        - DEEPCRAWLER_RATE_LIMIT
        - DEEPCRAWLER_HEADLESS
        - DEEPCRAWLER_BROWSER_TYPE
        - DEEPCRAWLER_USER_AGENT
        - DEEPCRAWLER_USE_PROXY
        - DEEPCRAWLER_PROXY_URL
        - DEEPCRAWLER_AUTH_TYPE
        - DEEPCRAWLER_AUTH_TOKEN
        - DEEPCRAWLER_DB_HOST
        - DEEPCRAWLER_DB_PORT
        - DEEPCRAWLER_DB_USER
        - DEEPCRAWLER_DB_PASSWORD
        - DEEPCRAWLER_DB_NAME
        - DEEPCRAWLER_REDIS_HOST
        - DEEPCRAWLER_REDIS_PORT
        - DEEPCRAWLER_MEMORY_PRESET
        - DEEPCRAWLER_LOG_LEVEL
        - DEEPCRAWLER_OUTPUT_FORMAT
        - DEEPCRAWLER_OUTPUT_DIR
        
        Returns:
            DeepCrawlerConfig instance
        """
        config = cls()
        
        # Crawling parameters
        if os.getenv('DEEPCRAWLER_MAX_DEPTH'):
            config.max_depth = int(os.getenv('DEEPCRAWLER_MAX_DEPTH'))
        if os.getenv('DEEPCRAWLER_MAX_URLS'):
            config.max_urls = int(os.getenv('DEEPCRAWLER_MAX_URLS'))
        if os.getenv('DEEPCRAWLER_MAX_CONCURRENT'):
            config.max_concurrent = int(os.getenv('DEEPCRAWLER_MAX_CONCURRENT'))
        if os.getenv('DEEPCRAWLER_TIMEOUT'):
            config.timeout = int(os.getenv('DEEPCRAWLER_TIMEOUT'))
        if os.getenv('DEEPCRAWLER_RATE_LIMIT'):
            config.rate_limit = float(os.getenv('DEEPCRAWLER_RATE_LIMIT'))
        
        # Browser settings
        if os.getenv('DEEPCRAWLER_HEADLESS'):
            config.headless = os.getenv('DEEPCRAWLER_HEADLESS').lower() == 'true'
        if os.getenv('DEEPCRAWLER_BROWSER_TYPE'):
            config.browser_type = os.getenv('DEEPCRAWLER_BROWSER_TYPE')
        if os.getenv('DEEPCRAWLER_USER_AGENT'):
            config.user_agent = os.getenv('DEEPCRAWLER_USER_AGENT')
        
        # Proxy settings
        if os.getenv('DEEPCRAWLER_USE_PROXY'):
            config.use_proxy = os.getenv('DEEPCRAWLER_USE_PROXY').lower() == 'true'
        if os.getenv('DEEPCRAWLER_PROXY_URL'):
            config.proxy_url = os.getenv('DEEPCRAWLER_PROXY_URL')
        if os.getenv('DEEPCRAWLER_PROXY_USERNAME'):
            config.proxy_username = os.getenv('DEEPCRAWLER_PROXY_USERNAME')
        if os.getenv('DEEPCRAWLER_PROXY_PASSWORD'):
            config.proxy_password = os.getenv('DEEPCRAWLER_PROXY_PASSWORD')
        
        # Authentication settings
        if os.getenv('DEEPCRAWLER_AUTH_TYPE'):
            config.auth_type = os.getenv('DEEPCRAWLER_AUTH_TYPE')
        if os.getenv('DEEPCRAWLER_AUTH_TOKEN'):
            config.auth_token = os.getenv('DEEPCRAWLER_AUTH_TOKEN')
        if os.getenv('DEEPCRAWLER_AUTH_USERNAME'):
            config.auth_username = os.getenv('DEEPCRAWLER_AUTH_USERNAME')
        if os.getenv('DEEPCRAWLER_AUTH_PASSWORD'):
            config.auth_password = os.getenv('DEEPCRAWLER_AUTH_PASSWORD')
        
        # API discovery settings
        if os.getenv('DEEPCRAWLER_DETECT_REST_APIS'):
            config.detect_rest_apis = os.getenv('DEEPCRAWLER_DETECT_REST_APIS').lower() == 'true'
        if os.getenv('DEEPCRAWLER_DETECT_GRAPHQL'):
            config.detect_graphql = os.getenv('DEEPCRAWLER_DETECT_GRAPHQL').lower() == 'true'
        if os.getenv('DEEPCRAWLER_DETECT_WEBSOCKETS'):
            config.detect_websockets = os.getenv('DEEPCRAWLER_DETECT_WEBSOCKETS').lower() == 'true'
        if os.getenv('DEEPCRAWLER_MIN_CONFIDENCE_SCORE'):
            config.min_confidence_score = float(os.getenv('DEEPCRAWLER_MIN_CONFIDENCE_SCORE'))
        
        # Database settings
        if os.getenv('DEEPCRAWLER_DB_HOST'):
            config.db_host = os.getenv('DEEPCRAWLER_DB_HOST')
        if os.getenv('DEEPCRAWLER_DB_PORT'):
            config.db_port = int(os.getenv('DEEPCRAWLER_DB_PORT'))
        if os.getenv('DEEPCRAWLER_DB_USER'):
            config.db_user = os.getenv('DEEPCRAWLER_DB_USER')
        if os.getenv('DEEPCRAWLER_DB_PASSWORD'):
            config.db_password = os.getenv('DEEPCRAWLER_DB_PASSWORD')
        if os.getenv('DEEPCRAWLER_DB_NAME'):
            config.db_name = os.getenv('DEEPCRAWLER_DB_NAME')
        
        # Redis settings
        if os.getenv('DEEPCRAWLER_REDIS_HOST'):
            config.redis_host = os.getenv('DEEPCRAWLER_REDIS_HOST')
        if os.getenv('DEEPCRAWLER_REDIS_PORT'):
            config.redis_port = int(os.getenv('DEEPCRAWLER_REDIS_PORT'))
        if os.getenv('DEEPCRAWLER_REDIS_DB'):
            config.redis_db = int(os.getenv('DEEPCRAWLER_REDIS_DB'))
        
        # Memory settings
        if os.getenv('DEEPCRAWLER_MEMORY_PRESET'):
            config.memory_preset = os.getenv('DEEPCRAWLER_MEMORY_PRESET')
        
        # Logging settings
        if os.getenv('DEEPCRAWLER_LOG_LEVEL'):
            config.log_level = os.getenv('DEEPCRAWLER_LOG_LEVEL')
        if os.getenv('DEEPCRAWLER_LOG_FILE'):
            config.log_file = os.getenv('DEEPCRAWLER_LOG_FILE')
        
        # Output settings
        if os.getenv('DEEPCRAWLER_OUTPUT_FORMAT'):
            config.output_format = os.getenv('DEEPCRAWLER_OUTPUT_FORMAT')
        if os.getenv('DEEPCRAWLER_OUTPUT_DIR'):
            config.output_dir = os.getenv('DEEPCRAWLER_OUTPUT_DIR')
        
        logger.info("DeepCrawler configuration loaded from environment")
        return config
    
    def validate(self):
        """
        Validate configuration values.
        
        Raises:
            ValueError: If configuration is invalid
        """
        if self.max_depth <= 0:
            raise ValueError("max_depth must be > 0")
        if self.max_urls <= 0:
            raise ValueError("max_urls must be > 0")
        if self.max_concurrent <= 0:
            raise ValueError("max_concurrent must be > 0")
        if self.timeout <= 0:
            raise ValueError("timeout must be > 0")
        if self.rate_limit <= 0:
            raise ValueError("rate_limit must be > 0")
        if not (0.0 <= self.min_confidence_score <= 1.0):
            raise ValueError("min_confidence_score must be between 0.0 and 1.0")
        if self.memory_preset not in ['none', 'light', 'medium', 'heavy']:
            raise ValueError("memory_preset must be one of: none, light, medium, heavy")
        if self.output_format not in ['openapi', 'json', 'yaml']:
            raise ValueError("output_format must be one of: openapi, json, yaml")
        
        logger.info("DeepCrawler configuration validated successfully")
    
    def to_dict(self) -> Dict:
        """
        Convert configuration to dictionary.
        
        Returns:
            Configuration as dictionary
        """
        return asdict(self)
    
    def __repr__(self) -> str:
        """String representation of configuration."""
        return f"DeepCrawlerConfig(max_depth={self.max_depth}, max_urls={self.max_urls}, " \
               f"max_concurrent={self.max_concurrent}, timeout={self.timeout}, " \
               f"rate_limit={self.rate_limit})"

