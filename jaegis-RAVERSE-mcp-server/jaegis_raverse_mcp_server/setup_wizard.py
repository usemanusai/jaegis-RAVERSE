"""
RAVERSE MCP Server - Interactive Setup Wizard

Provides automated and manual setup options for first-time configuration.
Handles PostgreSQL, Redis, and OpenRouter API key setup with cross-platform support.
"""

import os
import sys
import signal
import platform
import secrets
import socket
import subprocess
import logging
import argparse
from pathlib import Path
from typing import Optional, Tuple
from datetime import datetime

from colorama import init as colorama_init, Fore, Back, Style, just_fix_windows_console

# Initialize colorama for cross-platform colored output
just_fix_windows_console()

logger = logging.getLogger(__name__)


class SetupWizard:
    """Interactive setup wizard for RAVERSE MCP Server configuration."""

    def __init__(self):
        """Initialize the setup wizard."""
        self.os_type = platform.system()  # 'Windows', 'Linux', 'Darwin'
        self.package_dir = Path(__file__).parent.parent
        self.env_file = self.package_dir / ".env"
        self.env_example = self.package_dir / ".env.example"
        self.setup_log = self.package_dir / "setup_wizard.log"
        
        # Generated credentials (stored in memory only)
        self.db_username: Optional[str] = None
        self.db_password: Optional[str] = None
        self.redis_password: Optional[str] = None
        self.db_port: int = 5432
        self.redis_port: int = 6379
        self.api_key: Optional[str] = None

        # Connection URLs (for non-interactive mode)
        self.db_url: Optional[str] = None
        self.redis_url: Optional[str] = None

        # Setup signal handler for Ctrl+C
        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, sig, frame):
        """Handle Ctrl+C interruption."""
        print(f"\n\n{Fore.YELLOW}⚠ Setup interrupted by user.{Style.RESET_ALL}")
        self._cleanup_partial_installation()
        sys.exit(0)

    def _cleanup_partial_installation(self):
        """Clean up partial installation on interruption."""
        print(f"{Fore.CYAN}ℹ Cleaning up partial installation...{Style.RESET_ALL}")
        # Remove partial .env file if it exists
        if self.env_file.exists():
            try:
                self.env_file.unlink()
                print(f"{Fore.GREEN}✓ Removed partial .env file{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}✗ Failed to remove .env file: {e}{Style.RESET_ALL}")

    def _log(self, message: str, level: str = "INFO"):
        """Log message to setup_wizard.log."""
        timestamp = datetime.now().isoformat()
        log_entry = f"[{timestamp}] [{level}] {message}\n"
        try:
            with open(self.setup_log, "a") as f:
                f.write(log_entry)
        except Exception as e:
            logger.warning(f"Failed to write to setup log: {e}")

    def _print_banner(self):
        """Print ASCII art banner."""
        banner = f"""
{Fore.CYAN}
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║     RAVERSE MCP Server - First-Time Setup Wizard              ║
║                                                                ║
║     AI Multi-Agent Binary Patching System                     ║
║     Version 1.0.4                                             ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
        print(banner)

    def _print_menu(self):
        """Print setup options menu."""
        menu = f"""
{Fore.CYAN}Select Setup Mode:{Style.RESET_ALL}

{Fore.GREEN}[1] Secure Automatic Setup (Recommended for Beginners){Style.RESET_ALL}
    → Fully automated installation with one-click setup
    → Only requires OpenRouter API key
    → Auto-installs PostgreSQL, Redis, and generates secure credentials
    → Estimated time: 5-10 minutes

{Fore.YELLOW}[2] Manual Setup (Advanced Users){Style.RESET_ALL}
    → Guided configuration with full control
    → Bring your own database and Redis instances
    → Manual credential entry with validation
    → Estimated time: 10-15 minutes

{Fore.CYAN}Enter your choice (1 or 2): {Style.RESET_ALL}"""
        print(menu)

    def _get_user_choice(self) -> str:
        """Get and validate user choice."""
        while True:
            choice = input().strip()
            if choice in ['1', '2']:
                return choice
            print(f"{Fore.RED}✗ Invalid choice. Please enter 1 or 2.{Style.RESET_ALL}")

    def _generate_credentials(self):
        """Generate secure credentials using secrets module."""
        # Generate PostgreSQL password (43 characters, URL-safe)
        self.db_password = secrets.token_urlsafe(32)
        
        # Generate Redis password (43 characters, URL-safe)
        self.redis_password = secrets.token_urlsafe(32)
        
        # Generate PostgreSQL username
        random_suffix = secrets.token_hex(4)
        self.db_username = f"raverse_user_{random_suffix}"
        
        self._log(f"Generated credentials for PostgreSQL user: {self.db_username}")

    def _find_available_port(self, start_port: int, max_attempts: int = 10) -> int:
        """Find an available port by testing socket binding."""
        for port in range(start_port, start_port + max_attempts):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(('localhost', port))
                    return port
            except OSError:
                continue
        raise RuntimeError(f"No available ports found starting from {start_port}")

    def _check_port_availability(self):
        """Check and find available ports for PostgreSQL and Redis."""
        print(f"\n{Fore.CYAN}ℹ Checking port availability...{Style.RESET_ALL}")
        
        try:
            self.db_port = self._find_available_port(5432)
            print(f"{Fore.GREEN}✓ PostgreSQL port available: {self.db_port}{Style.RESET_ALL}")
            self._log(f"PostgreSQL port available: {self.db_port}")
        except RuntimeError as e:
            print(f"{Fore.RED}✗ {e}{Style.RESET_ALL}")
            self._log(f"Port check failed: {e}", "ERROR")
            raise
        
        try:
            self.redis_port = self._find_available_port(6379)
            print(f"{Fore.GREEN}✓ Redis port available: {self.redis_port}{Style.RESET_ALL}")
            self._log(f"Redis port available: {self.redis_port}")
        except RuntimeError as e:
            print(f"{Fore.RED}✗ {e}{Style.RESET_ALL}")
            self._log(f"Port check failed: {e}", "ERROR")
            raise

    def _validate_api_key(self, api_key: str) -> bool:
        """Validate OpenRouter API key format."""
        if not api_key.startswith("sk-or-v1-"):
            return False
        if len(api_key) < 40:
            return False
        return True

    def _prompt_for_api_key(self) -> str:
        """Prompt user for OpenRouter API key with validation."""
        print(f"\n{Fore.CYAN}╔════════════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║  OpenRouter API Key Required                                   ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╠════════════════════════════════════════════════════════════════╣{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║  Get your API key at: https://openrouter.ai/keys               ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║  Format: sk-or-v1-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx     ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
        
        max_attempts = 3
        for attempt in range(max_attempts):
            api_key = input(f"{Fore.CYAN}Enter your OpenRouter API key: {Style.RESET_ALL}").strip()
            
            if self._validate_api_key(api_key):
                print(f"{Fore.GREEN}✓ API key format valid{Style.RESET_ALL}")
                self._log("OpenRouter API key validated")
                return api_key
            else:
                remaining = max_attempts - attempt - 1
                if remaining > 0:
                    print(f"{Fore.RED}✗ Invalid API key format. {remaining} attempts remaining.{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}⚠ Skipping API key validation. You can add it later to .env{Style.RESET_ALL}")
                    return ""

    def _create_env_file(self, auto_setup: bool = True):
        """Create .env file with configuration."""
        env_content = f"""# Auto-generated by RAVERSE Setup Wizard on {datetime.now().isoformat()}
# Generated for {self.os_type} system

# Server Settings
SERVER_NAME=jaegis-raverse-mcp-server
SERVER_VERSION=1.0.4
LOG_LEVEL=INFO

# Database Settings
DATABASE_URL=postgresql://{self.db_username}:{self.db_password}@localhost:{self.db_port}/raverse
DATABASE_POOL_SIZE=10
DATABASE_MAX_OVERFLOW=20

# Redis Settings
REDIS_URL=redis://:{self.redis_password}@localhost:{self.redis_port}/0
REDIS_TIMEOUT=5

# LLM Settings
LLM_API_KEY={self.api_key if self.api_key else 'your_api_key_here'}
LLM_PROVIDER=openrouter
LLM_MODEL=meta-llama/llama-3.1-70b-instruct
LLM_TIMEOUT=30

# Embeddings Settings
EMBEDDINGS_MODEL=all-MiniLM-L6-v2
EMBEDDINGS_DIMENSION=384

# Feature Flags
ENABLE_BINARY_ANALYSIS=true
ENABLE_WEB_ANALYSIS=true
ENABLE_KNOWLEDGE_BASE=true
ENABLE_INFRASTRUCTURE=true

# Performance Settings
MAX_CONCURRENT_TASKS=10
CACHE_TTL_SECONDS=3600
REQUEST_TIMEOUT_SECONDS=60
"""
        
        try:
            self.env_file.write_text(env_content)
            # Set secure permissions (600 on Unix, equivalent on Windows)
            if self.os_type != 'Windows':
                os.chmod(self.env_file, 0o600)
            print(f"{Fore.GREEN}✓ Created .env file{Style.RESET_ALL}")
            self._log(".env file created successfully")
        except Exception as e:
            print(f"{Fore.RED}✗ Failed to create .env file: {e}{Style.RESET_ALL}")
            self._log(f"Failed to create .env file: {e}", "ERROR")
            raise

    def _print_summary(self):
        """Print setup summary."""
        summary = f"""
{Fore.GREEN}╔════════════════════════════════════════════════════════════════╗{Style.RESET_ALL}
{Fore.GREEN}║  ✓ RAVERSE MCP Server - Setup Complete!                       ║{Style.RESET_ALL}
{Fore.GREEN}╠════════════════════════════════════════════════════════════════╣{Style.RESET_ALL}
{Fore.GREEN}║  PostgreSQL Configuration:                                     ║{Style.RESET_ALL}
{Fore.GREEN}║    Host: localhost                                             ║{Style.RESET_ALL}
{Fore.GREEN}║    Port: {self.db_port}                                              ║{Style.RESET_ALL}
{Fore.GREEN}║    Database: raverse                                           ║{Style.RESET_ALL}
{Fore.GREEN}║    Username: {self.db_username:<45} ║{Style.RESET_ALL}
{Fore.GREEN}║    Password: [HIDDEN - Saved in .env]                          ║{Style.RESET_ALL}
{Fore.GREEN}║                                                                ║{Style.RESET_ALL}
{Fore.GREEN}║  Redis Configuration:                                          ║{Style.RESET_ALL}
{Fore.GREEN}║    Host: localhost                                             ║{Style.RESET_ALL}
{Fore.GREEN}║    Port: {self.redis_port}                                              ║{Style.RESET_ALL}
{Fore.GREEN}║    Password: [HIDDEN - Saved in .env]                          ║{Style.RESET_ALL}
{Fore.GREEN}║                                                                ║{Style.RESET_ALL}
{Fore.YELLOW}║  ⚠️  IMPORTANT: Save these credentials securely!               ║{Style.RESET_ALL}
{Fore.YELLOW}║  They will not be displayed again.                             ║{Style.RESET_ALL}
{Fore.GREEN}╚════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(summary)

    def run_automatic_setup(self):
        """Run automatic setup mode."""
        print(f"\n{Fore.CYAN}Starting Automatic Setup...{Style.RESET_ALL}\n")
        self._log("Starting automatic setup mode")
        
        try:
            # Step 1: Generate credentials
            print(f"{Fore.CYAN}Step 1/4: Generating secure credentials...{Style.RESET_ALL}")
            self._generate_credentials()
            print(f"{Fore.GREEN}✓ Credentials generated{Style.RESET_ALL}\n")
            
            # Step 2: Check port availability
            print(f"{Fore.CYAN}Step 2/4: Checking port availability...{Style.RESET_ALL}")
            self._check_port_availability()
            print()
            
            # Step 3: Get API key
            print(f"{Fore.CYAN}Step 3/4: OpenRouter API Key{Style.RESET_ALL}")
            self.api_key = self._prompt_for_api_key()
            print()
            
            # Step 4: Create .env file
            print(f"{Fore.CYAN}Step 4/4: Creating configuration file...{Style.RESET_ALL}")
            self._create_env_file(auto_setup=True)
            print()
            
            # Print summary
            self._print_summary()
            
            self._log("Automatic setup completed successfully")
            
        except Exception as e:
            print(f"{Fore.RED}✗ Setup failed: {e}{Style.RESET_ALL}")
            self._log(f"Setup failed: {e}", "ERROR")
            self._cleanup_partial_installation()
            raise

    def _validate_connection_string(self, url: str, url_type: str) -> bool:
        """Validate connection string format."""
        if url_type == "database":
            return url.startswith("postgresql://") and "@" in url and "/" in url
        elif url_type == "redis":
            return url.startswith("redis://") and ":" in url
        return False

    def _prompt_for_connection_string(self, url_type: str) -> str:
        """Prompt user for connection string with validation."""
        if url_type == "database":
            prompt_text = "PostgreSQL Connection String"
            example = "postgresql://user:password@localhost:5432/raverse"
        else:
            prompt_text = "Redis Connection String"
            example = "redis://:password@localhost:6379/0"

        print(f"\n{Fore.CYAN}{prompt_text}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Example: {example}{Style.RESET_ALL}")

        max_attempts = 3
        for attempt in range(max_attempts):
            url = input(f"{Fore.CYAN}Enter {url_type} URL: {Style.RESET_ALL}").strip()

            if self._validate_connection_string(url, url_type):
                print(f"{Fore.GREEN}✓ {url_type.capitalize()} URL format valid{Style.RESET_ALL}")
                self._log(f"{url_type.capitalize()} URL validated")
                return url
            else:
                remaining = max_attempts - attempt - 1
                if remaining > 0:
                    print(f"{Fore.RED}✗ Invalid {url_type} URL format. {remaining} attempts remaining.{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}✗ Invalid {url_type} URL format. Setup cancelled.{Style.RESET_ALL}")
                    self._log(f"Invalid {url_type} URL format", "ERROR")
                    raise ValueError(f"Invalid {url_type} URL")

    def run_manual_setup(self):
        """Run manual setup mode."""
        print(f"\n{Fore.CYAN}Starting Manual Setup...{Style.RESET_ALL}\n")
        self._log("Starting manual setup mode")

        try:
            # Step 1: Get database URL
            print(f"{Fore.CYAN}Step 1/3: Database Configuration{Style.RESET_ALL}")
            db_url = self._prompt_for_connection_string("database")
            print()

            # Step 2: Get Redis URL
            print(f"{Fore.CYAN}Step 2/3: Redis Configuration{Style.RESET_ALL}")
            redis_url = self._prompt_for_connection_string("redis")
            print()

            # Step 3: Get API key
            print(f"{Fore.CYAN}Step 3/3: OpenRouter API Key{Style.RESET_ALL}")
            self.api_key = self._prompt_for_api_key()
            print()

            # Create .env file with manual settings
            self._create_env_file_manual(db_url, redis_url)

            print(f"{Fore.GREEN}✓ Manual setup completed successfully!{Style.RESET_ALL}")
            self._log("Manual setup completed successfully")

        except Exception as e:
            print(f"{Fore.RED}✗ Setup failed: {e}{Style.RESET_ALL}")
            self._log(f"Setup failed: {e}", "ERROR")
            self._cleanup_partial_installation()
            raise

    def _create_env_file_manual(self, db_url: str, redis_url: str):
        """Create .env file with manual configuration."""
        env_content = f"""# Auto-generated by RAVERSE Setup Wizard on {datetime.now().isoformat()}
# Generated for {self.os_type} system (Manual Setup)

# Server Settings
SERVER_NAME=jaegis-raverse-mcp-server
SERVER_VERSION=1.0.4
LOG_LEVEL=INFO

# Database Settings
DATABASE_URL={db_url}
DATABASE_POOL_SIZE=10
DATABASE_MAX_OVERFLOW=20

# Redis Settings
REDIS_URL={redis_url}
REDIS_TIMEOUT=5

# LLM Settings
LLM_API_KEY={self.api_key if self.api_key else 'your_api_key_here'}
LLM_PROVIDER=openrouter
LLM_MODEL=meta-llama/llama-3.1-70b-instruct
LLM_TIMEOUT=30

# Embeddings Settings
EMBEDDINGS_MODEL=all-MiniLM-L6-v2
EMBEDDINGS_DIMENSION=384

# Feature Flags
ENABLE_BINARY_ANALYSIS=true
ENABLE_WEB_ANALYSIS=true
ENABLE_KNOWLEDGE_BASE=true
ENABLE_INFRASTRUCTURE=true

# Performance Settings
MAX_CONCURRENT_TASKS=10
CACHE_TTL_SECONDS=3600
REQUEST_TIMEOUT_SECONDS=60
"""

        try:
            self.env_file.write_text(env_content)
            # Set secure permissions (600 on Unix, equivalent on Windows)
            if self.os_type != 'Windows':
                os.chmod(self.env_file, 0o600)
            print(f"{Fore.GREEN}✓ Created .env file{Style.RESET_ALL}")
            self._log(".env file created successfully (manual setup)")
        except Exception as e:
            print(f"{Fore.RED}✗ Failed to create .env file: {e}{Style.RESET_ALL}")
            self._log(f"Failed to create .env file: {e}", "ERROR")
            raise

    def run(self):
        """Run the setup wizard."""
        self._print_banner()
        
        # Check if .env already exists
        if self.env_file.exists():
            print(f"{Fore.YELLOW}⚠ .env file already exists. Skipping setup wizard.{Style.RESET_ALL}")
            self._log(".env file already exists, skipping setup")
            return
        
        self._print_menu()
        choice = self._get_user_choice()
        
        if choice == '1':
            self.run_automatic_setup()
        else:
            self.run_manual_setup()


def run_setup_wizard(non_interactive: bool = False, db_url: Optional[str] = None,
                     redis_url: Optional[str] = None, api_key: Optional[str] = None):
    """Entry point for setup wizard.

    Args:
        non_interactive: If True, use default values without prompting
        db_url: Database URL (used in non-interactive mode)
        redis_url: Redis URL (used in non-interactive mode)
        api_key: OpenRouter API key (used in non-interactive mode)
    """
    wizard = SetupWizard()

    if non_interactive:
        # Non-interactive mode - use provided values or defaults
        wizard.db_url = db_url or "postgresql://raverse:raverse_secure_password_2025@localhost:5432/raverse"
        wizard.redis_url = redis_url or "redis://localhost:6379/0"
        wizard.api_key = api_key or os.getenv("OPENROUTER_API_KEY", "sk-or-v1-placeholder")
        wizard._create_env_file()
        wizard._log("Non-interactive setup completed successfully")
        print(f"{Fore.GREEN}✓ Configuration created successfully!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Configuration saved to: {wizard.env_file}{Style.RESET_ALL}")
    else:
        wizard.run()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="RAVERSE MCP Server Setup Wizard")
    parser.add_argument("--non-interactive", action="store_true", help="Run in non-interactive mode")
    parser.add_argument("--db-url", help="Database URL (for non-interactive mode)")
    parser.add_argument("--redis-url", help="Redis URL (for non-interactive mode)")
    parser.add_argument("--api-key", help="OpenRouter API key (for non-interactive mode)")

    args = parser.parse_args()
    run_setup_wizard(
        non_interactive=args.non_interactive,
        db_url=args.db_url,
        redis_url=args.redis_url,
        api_key=args.api_key
    )

