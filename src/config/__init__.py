"""
RAVERSE 2.0 Configuration Module
Centralized configuration management for all agents and components
"""

import os
import logging
from typing import Dict, Any

# Import existing settings
from .settings import Settings

# Import new component-specific configurations
try:
    from .knowledge_base_settings import get_config as get_kb_config, validate_config as validate_kb_config
except ImportError:
    get_kb_config = None
    validate_kb_config = None

try:
    from .quality_gate_settings import get_config as get_qg_config, validate_config as validate_qg_config
except ImportError:
    get_qg_config = None
    validate_qg_config = None

try:
    from .governance_settings import get_config as get_gov_config, validate_config as validate_gov_config
except ImportError:
    get_gov_config = None
    validate_gov_config = None

try:
    from .binary_analysis_settings import get_config as get_ba_config, validate_config as validate_ba_config
except ImportError:
    get_ba_config = None
    validate_ba_config = None

logger = logging.getLogger(__name__)

class ConfigurationManager:
    """Master configuration manager for RAVERSE 2.0."""

    def __init__(self):
        """Initialize configuration manager."""
        self.settings = Settings()
        self.configs = {}
        self.validated = False

    def load_all_configs(self) -> Dict[str, Any]:
        """Load all component configurations."""
        try:
            self.configs = {
                "global": {
                    "environment": os.getenv("ENVIRONMENT", "development"),
                    "debug": os.getenv("DEBUG", "false").lower() == "true",
                    "version": "2.0.0"
                }
            }

            if get_kb_config:
                self.configs["knowledge_base"] = get_kb_config()
            if get_qg_config:
                self.configs["quality_gate"] = get_qg_config()
            if get_gov_config:
                self.configs["governance"] = get_gov_config()
            if get_ba_config:
                self.configs["binary_analysis"] = get_ba_config()

            logger.info("All configurations loaded successfully")
            return self.configs
        except Exception as e:
            logger.error(f"Failed to load configurations: {e}")
            raise

    def validate_all_configs(self) -> bool:
        """Validate all component configurations."""
        try:
            if validate_kb_config:
                validate_kb_config()
                logger.info("✓ Knowledge Base configuration validated")

            if validate_qg_config:
                validate_qg_config()
                logger.info("✓ Quality Gate configuration validated")

            if validate_gov_config:
                validate_gov_config()
                logger.info("✓ Governance configuration validated")

            if validate_ba_config:
                validate_ba_config()
                logger.info("✓ Binary Analysis configuration validated")

            self.validated = True
            logger.info("All configurations validated successfully")
            return True
        except Exception as e:
            logger.error(f"Configuration validation failed: {e}")
            raise

    def get_config(self, component: str) -> Dict[str, Any]:
        """Get configuration for specific component."""
        if component not in self.configs:
            raise ValueError(f"Unknown component: {component}")
        return self.configs[component]

    def get_all_configs(self) -> Dict[str, Any]:
        """Get all configurations."""
        return self.configs

# Global configuration manager instance
_config_manager = None

def get_config_manager() -> ConfigurationManager:
    """Get or create global configuration manager."""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigurationManager()
        _config_manager.load_all_configs()
        _config_manager.validate_all_configs()
    return _config_manager

__all__ = ['Settings', 'ConfigurationManager', 'get_config_manager']

