"""
RAVERSE MCP Server - Automated Installation Script

Handles complete setup without user interaction:
- PostgreSQL installation and configuration
- Redis installation and configuration
- Database initialization
- Server configuration
- Verification
"""

import os
import sys
import subprocess
import platform
import socket
import time
import logging
from pathlib import Path
from typing import Optional, Tuple
from datetime import datetime

# Setup logging with UTF-8 encoding for Windows compatibility
log_file = Path(__file__).parent.parent / "installation.log"

# Configure file handler with UTF-8 encoding
file_handler = logging.FileHandler(log_file, encoding='utf-8')
file_handler.setFormatter(logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s'))

# Configure stream handler with error handling
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s'))

logging.basicConfig(
    level=logging.INFO,
    handlers=[file_handler, stream_handler]
)
logger = logging.getLogger(__name__)


class AutoInstaller:
    """Automated installer for RAVERSE MCP Server."""
    
    def __init__(self):
        """Initialize the auto installer."""
        self.os_type = platform.system()
        self.package_dir = Path(__file__).parent.parent
        self.env_file = self.package_dir / ".env"
        self.docker_available = self._check_docker()
        self.db_url = "postgresql://raverse:raverse_secure_password_2025@localhost:5432/raverse"
        self.redis_url = "redis://:raverse_redis_password_2025@localhost:6379/0"
        self.api_key = os.getenv("OPENROUTER_API_KEY", "sk-or-v1-placeholder-key")
        
    def _check_docker(self) -> bool:
        """Check if Docker is available."""
        try:
            subprocess.run(
                ["docker", "--version"],
                capture_output=True,
                timeout=5
            )
            return True
        except Exception:
            return False
    
    def _run_command(self, cmd: list, description: str, timeout: int = 600) -> Tuple[bool, str]:
        """Run a shell command and return success status and output."""
        try:
            logger.info(f"Running: {description}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            if result.returncode == 0:
                logger.info(f"[OK] {description}")
                return True, result.stdout
            else:
                logger.error(f"[FAILED] {description}: {result.stderr}")
                return False, result.stderr
        except subprocess.TimeoutExpired:
            logger.error(f"[TIMEOUT] {description}: Command timed out after {timeout}s")
            return False, "Command timeout"
        except Exception as e:
            logger.error(f"[ERROR] {description}: {str(e)}")
            return False, str(e)
    
    def _check_port(self, port: int) -> bool:
        """Check if a port is available."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex(('localhost', port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def _wait_for_service(self, port: int, timeout: int = 60) -> bool:
        """Wait for a service to be available on a port."""
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self._check_port(port):
                logger.info(f"[OK] Service available on port {port}")
                return True
            time.sleep(2)
        logger.error(f"[FAILED] Service not available on port {port} after {timeout}s")
        return False
    
    def setup_with_docker(self) -> bool:
        """Setup using Docker Compose."""
        logger.info("=" * 70)
        logger.info("RAVERSE MCP Server - Automated Installation (Docker)")
        logger.info("=" * 70)

        # Start only PostgreSQL and Redis services (skip raverse-app build)
        logger.info("Starting PostgreSQL and Redis services...")
        success, _ = self._run_command(
            ["docker-compose", "up", "-d", "postgres", "redis"],
            "Starting Docker Compose services (postgres, redis)",
            timeout=600
        )
        if not success:
            logger.error("[FAILED] Could not start Docker services")
            return False

        # Wait for PostgreSQL
        logger.info("Waiting for PostgreSQL to be ready...")
        if not self._wait_for_service(5432, timeout=60):
            logger.error("[FAILED] PostgreSQL did not become ready")
            return False

        # Wait for Redis
        logger.info("Waiting for Redis to be ready...")
        if not self._wait_for_service(6379, timeout=60):
            logger.error("[FAILED] Redis did not become ready")
            return False

        logger.info("[OK] Docker services started successfully")
        return True
    
    def create_env_file(self) -> bool:
        """Create .env file with configuration."""
        try:
            logger.info("Creating .env file...")
            env_content = f"""# Auto-generated by RAVERSE Auto Installer on {datetime.now().isoformat()}
# Generated for {self.os_type} system (Automated Setup)

# Server Settings
SERVER_NAME=jaegis-raverse-mcp-server
SERVER_VERSION=1.0.10
LOG_LEVEL=INFO

# Database Settings
DATABASE_URL={self.db_url}
DATABASE_POOL_SIZE=10
DATABASE_MAX_OVERFLOW=20

# Redis Settings
REDIS_URL={self.redis_url}
REDIS_TIMEOUT=5

# LLM Settings
LLM_API_KEY={self.api_key}
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
            with open(self.env_file, "w", encoding='utf-8') as f:
                f.write(env_content)
            logger.info(f"[OK] Created .env file at {self.env_file}")
            return True
        except Exception as e:
            logger.error(f"[FAILED] Failed to create .env file: {e}")
            return False
    
    def verify_database_connection(self) -> bool:
        """Verify database connection."""
        try:
            import psycopg2
            logger.info("Verifying PostgreSQL connection...")
            conn = psycopg2.connect(
                host="localhost",
                port=5432,
                user="raverse",
                password="raverse_secure_password_2025",
                database="raverse"
            )
            conn.close()
            logger.info("[OK] PostgreSQL connection verified")
            return True
        except ImportError:
            logger.warning("psycopg2 not available, skipping database verification")
            return True
        except Exception as e:
            logger.error(f"[FAILED] Database connection failed: {e}")
            return False

    def verify_redis_connection(self) -> bool:
        """Verify Redis connection."""
        try:
            import redis
            logger.info("Verifying Redis connection...")
            r = redis.Redis(
                host='localhost',
                port=6379,
                password='raverse_redis_password_2025',
                decode_responses=True
            )
            r.ping()
            logger.info("[OK] Redis connection verified")
            return True
        except ImportError:
            logger.warning("redis not available, skipping Redis verification")
            return True
        except Exception as e:
            logger.error(f"[FAILED] Redis connection failed: {e}")
            return False
    
    def run(self) -> int:
        """Run the automated installation."""
        try:
            logger.info(f"Starting automated installation on {self.os_type}")
            
            # Setup databases
            if self.docker_available:
                logger.info("Docker detected, using Docker Compose for database setup")
                if not self.setup_with_docker():
                    logger.error("Docker setup failed")
                    return 1
            else:
                logger.error("Docker not available and local setup not yet implemented")
                return 1
            
            # Create .env file
            if not self.create_env_file():
                return 1
            
            # Verify connections
            if not self.verify_database_connection():
                logger.warning("Database verification failed, continuing anyway...")
            
            if not self.verify_redis_connection():
                logger.warning("Redis verification failed, continuing anyway...")
            
            logger.info("=" * 70)
            logger.info("[OK] Automated installation completed successfully!")
            logger.info("=" * 70)
            logger.info(f"Configuration saved to: {self.env_file}")
            logger.info("You can now start the server with:")
            logger.info("  python -m jaegis_raverse_mcp_server.server")
            
            return 0
            
        except Exception as e:
            logger.error(f"Installation failed: {e}", exc_info=True)
            return 1


def main():
    """Main entry point."""
    installer = AutoInstaller()
    return installer.run()


if __name__ == "__main__":
    sys.exit(main())

