import os
import time
import hashlib
import requests
from dotenv import load_dotenv
from urllib3.util import Retry
from requests.adapters import HTTPAdapter
import logging

from .disassembly_analysis import DisassemblyAnalysisAgent
from .logic_identification import LogicIdentificationMappingAgent
from .patching_execution import PatchingExecutionAgent
from .verification import VerificationAgent

# Import new infrastructure components
try:
    from ..utils.database import DatabaseManager
    from ..utils.cache import CacheManager
    from ..utils.binary_utils import BinaryAnalyzer
    from ..config.settings import Settings
    DB_AVAILABLE = True
except ImportError:
    DB_AVAILABLE = False
    logging.warning("Database/Cache utilities not available. Running in standalone mode.")

logger = logging.getLogger(__name__)


class OrchestratingAgent:
    """
    Main controller that coordinates all agents and provides OpenRouter access.
    Enhanced with PostgreSQL and Redis integration for production deployment.
    """

    def __init__(self, openrouter_api_key=None, model=None, use_database=True):
        """
        Initialize the Orchestrating Agent with OpenRouter API key and model selection.

        :param openrouter_api_key: Your OpenRouter API key (optional; falls back to env OPENROUTER_API_KEY).
        :param model: The model to use for AI-powered actions (optional; falls back to env OPENROUTER_MODEL or default).
        :param use_database: Whether to use PostgreSQL/Redis (default True if available).
        """
        load_dotenv()
        self.openrouter_api_key = openrouter_api_key or os.getenv("OPENROUTER_API_KEY")
        if not self.openrouter_api_key:
            raise ValueError("OPENROUTER_API_KEY not found. Set it as an environment variable or pass it explicitly.")
        self.model = model or os.getenv("OPENROUTER_MODEL", "meta-llama/llama-3.2-3b-instruct:free")

        # MCP-guided: Initialize persistent session with connection pooling
        # Context7 (/psf/requests): Sessions reuse TCP connections, reducing latency
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {self.openrouter_api_key}",
            "Content-Type": "application/json"
        })

        # Configure automatic retry strategy with exponential backoff
        # Retry on rate limits (429) and server errors (500, 502, 503, 504)
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,  # Wait 1s, 2s, 4s between retries
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["POST"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)

        # Initialize database and cache managers if available
        self.use_database = use_database and DB_AVAILABLE
        if self.use_database:
            try:
                self.db = DatabaseManager()
                self.cache_manager = CacheManager()
                logger.info("Database and cache managers initialized successfully")
            except Exception as e:
                logger.warning(f"Failed to initialize database/cache: {e}. Running in standalone mode.")
                self.use_database = False
                self.db = None
                self.cache_manager = None
        else:
            self.db = None
            self.cache_manager = None
            logger.info("Running in standalone mode (no database/cache)")

        # Initialize agents
        self.agents = {
            'DAA': DisassemblyAnalysisAgent(self),
            'LIMA': LogicIdentificationMappingAgent(self),
            'PEA': PatchingExecutionAgent(self),
            'VA': VerificationAgent(self)
        }

        # Fallback in-memory cache for standalone mode
        self.memory_cache = {}

    def _get_binary_hash(self, binary_path: str) -> str:
        """Calculate SHA-256 hash of binary file"""
        with open(binary_path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()

    def run(self, binary_path):
        """
        Run the entire binary patching process.
        Enhanced with database tracking and caching.

        :param binary_path: Path to the target binary file.
        :return: Result of the verification process.
        """
        binary_id = None
        start_time = time.time()

        try:
            # Extract binary metadata
            metadata = BinaryAnalyzer.extract_metadata(binary_path)
            binary_hash = metadata['file_hash']

            logger.info(f"Processing binary: {metadata['file_name']} ({metadata['file_type']}/{metadata['architecture']})")

            # Create binary record in database if available
            if self.use_database and self.db:
                try:
                    binary_id = self.db.create_binary_record(
                        file_name=metadata['file_name'],
                        file_path=metadata['file_path'],
                        file_hash=binary_hash,
                        file_size=metadata['file_size'],
                        file_type=metadata['file_type'],
                        architecture=metadata['architecture'],
                        metadata=metadata
                    )
                    self.db.update_binary_status(binary_id, 'processing')
                except Exception as e:
                    logger.warning(f"Database record creation failed: {e}")

            # Check cache (Redis or memory)
            cached_result = None
            if self.use_database and self.cache_manager:
                cached_result = self.cache_manager.get_cached_analysis(binary_hash, 'full_analysis')
            elif binary_hash in self.memory_cache:
                cached_result = self.memory_cache.get(binary_hash)

            if cached_result:
                logger.info("Using cached analysis for binary")
                if binary_id:
                    self.db.update_binary_status(binary_id, 'completed_cached')
                return cached_result

            # Run analysis pipeline
            logger.info("Starting DAA.disassemble")
            self.daa_output = self.agents['DAA'].disassemble(binary_path)

            logger.info("Starting LIMA.identify_logic")
            self.lima_output = self.agents['LIMA'].identify_logic(self.daa_output)

            logger.info("Starting PEA.patch_binary")
            self.pea_output = self.agents['PEA'].patch_binary(self.lima_output, binary_path)

            logger.info("Starting VA.verify_patch")
            self.va_output = self.agents['VA'].verify_patch(self.pea_output, binary_path)

            # Cache the result
            if self.use_database and self.cache_manager:
                self.cache_manager.cache_analysis(binary_hash, 'full_analysis', self.va_output)
            else:
                self.memory_cache[binary_hash] = self.va_output

            # Update database status
            if binary_id:
                status = 'completed_success' if self.va_output.get('success') else 'completed_failed'
                self.db.update_binary_status(binary_id, status)

            execution_time = int((time.time() - start_time) * 1000)
            logger.info(f"Analysis completed in {execution_time}ms")

            return self.va_output

        except Exception as e:
            logger.error(f"Error during orchestration: {e}")
            if binary_id and self.use_database:
                try:
                    self.db.update_binary_status(binary_id, 'error')
                except Exception as db_error:
                    logger.warning(f"Failed to update binary status in database: {db_error}")
            return None

    def call_openrouter(self, prompt, max_retries=3, retry_delay=1, max_tokens=500):
        """
        Call the OpenRouter API with retry logic (exponential backoff) and connection pooling.
        Enhanced with LLM response caching to reduce API calls and costs.

        MCP-guided improvements:
        - Uses persistent Session for connection reuse (Context7: /psf/requests)
        - Separate connect/read timeouts (10s, 30s) to avoid hanging
        - Configurable max_tokens for token optimization (default 500 for structured JSON)
        - PostgreSQL/Redis caching for LLM responses

        :param prompt: The prompt to send to the OpenRouter model.
        :param max_retries: Maximum number of retries for API calls.
        :param retry_delay: Base delay (seconds) before retry; grows exponentially.
        :param max_tokens: Maximum tokens in response (default 500 for JSON, use 2000 for complex analysis).
        :return: JSON response from the OpenRouter API.
        """
        # Check cache first (PostgreSQL or Redis)
        if self.use_database:
            cached_response = None

            # Try Redis cache first (faster)
            if self.cache_manager:
                cached_response = self.cache_manager.get_cached_llm_response(prompt, self.model)

            # Try PostgreSQL cache if Redis miss
            if not cached_response and self.db:
                prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()
                cached_data = self.db.get_llm_cache(prompt_hash)
                if cached_data:
                    cached_response = cached_data['response_text']
                    logger.info(f"LLM cache hit (PostgreSQL): {prompt_hash[:16]}...")

            if cached_response:
                logger.info("Using cached LLM response")
                return {'choices': [{'message': {'content': cached_response}}]}

        url = "https://openrouter.ai/api/v1/chat/completions"
        data = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens
        }

        for attempt in range(max_retries):
            try:
                # Context7-guided: set separate connect/read timeouts to avoid hanging
                # Session automatically includes headers set in __init__
                response = self.session.post(url, json=data, timeout=(10, 30))
                response.raise_for_status()
                resp_json = response.json()

                # Log token usage and response time for optimization tracking
                tokens_used = None
                if 'usage' in resp_json:
                    tokens_used = resp_json['usage'].get('total_tokens')
                    logger.info(f"Token usage: {resp_json['usage']}")
                logger.debug(f"API response time: {response.elapsed.total_seconds():.2f}s")

                # Cache the response
                if self.use_database and 'choices' in resp_json and len(resp_json['choices']) > 0:
                    response_text = resp_json['choices'][0]['message']['content']

                    # Cache in Redis (fast access)
                    if self.cache_manager:
                        self.cache_manager.cache_llm_response(prompt, response_text, self.model)

                    # Cache in PostgreSQL (persistent)
                    if self.db:
                        self.db.save_llm_cache(prompt, response_text, self.model, tokens_used)

                return resp_json

            except requests.exceptions.Timeout as e:
                logger.error(f"Request timeout after 30s: {e}")
                wait_time = retry_delay * (2 ** attempt)
                if attempt < max_retries - 1:
                    logger.warning(f"Retrying in {wait_time}s...")
                    time.sleep(wait_time)
            except requests.exceptions.HTTPError as e:
                if response.status_code == 429:
                    logger.warning("Rate limit exceeded. Implementing backoff...")
                elif response.status_code == 503:
                    logger.warning("Service unavailable. Model may be overloaded...")
                else:
                    logger.error(f"HTTP error {response.status_code}: {e}")
                wait_time = retry_delay * (2 ** attempt)
                if attempt < max_retries - 1:
                    logger.warning(f"Retrying in {wait_time}s...")
                    time.sleep(wait_time)
            except requests.exceptions.RequestException as e:
                wait_time = retry_delay * (2 ** attempt)
                logger.warning(
                    f"API call failed (attempt {attempt+1}/{max_retries}): {e}. Retrying in {wait_time}s..."
                )
                if attempt < max_retries - 1:
                    time.sleep(wait_time)
        raise Exception("Max retries exceeded for API call.")

    def __del__(self):
        """Ensure session and database connections are closed when agent is destroyed."""
        if hasattr(self, 'session'):
            self.session.close()
        if hasattr(self, 'db') and self.db:
            self.db.close()
        if hasattr(self, 'cache_manager') and self.cache_manager:
            self.cache_manager.close()

