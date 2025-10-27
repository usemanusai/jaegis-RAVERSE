"""
Enhanced Orchestrator for RAVERSE 2.0
Date: October 25, 2025

This module coordinates all AI-powered agents for comprehensive
binary analysis and patching.
"""

import os
import time
import hashlib
import logging
from typing import Dict, List, Optional, Any
from dotenv import load_dotenv

# Import infrastructure
from utils.database import DatabaseManager
from utils.cache import CacheManager
from utils.binary_utils import BinaryAnalyzer
from utils.embeddings_v2 import get_embedding_generator
from utils.semantic_search import get_search_engine
from utils.metrics import metrics_collector

# Import agents
from agents.disassembly_agent import DisassemblyAgent
from agents.pattern_agent import PatternAgent
from agents.llm_agent import get_llm_agent
from agents.patch_generator import PatchGenerator
from agents.validation_agent import ValidationAgent

logger = logging.getLogger(__name__)


class EnhancedOrchestrator:
    """
    Enhanced orchestrator that coordinates all AI-powered agents
    for comprehensive binary analysis and patching.
    """
    
    def __init__(
        self,
        binary_path: str,
        use_database: bool = True,
        use_llm: bool = True
    ):
        """
        Initialize enhanced orchestrator.
        
        Args:
            binary_path: Path to binary file to analyze
            use_database: Whether to use PostgreSQL/Redis
            use_llm: Whether to use LLM for analysis
        """
        load_dotenv()
        
        self.binary_path = binary_path
        self.use_database = use_database
        self.use_llm = use_llm
        
        # Initialize infrastructure
        self._init_infrastructure()
        
        # Initialize binary analyzer
        self.binary_analyzer = BinaryAnalyzer(binary_path)
        
        # Initialize agents
        self._init_agents()
        
        # Analysis state
        self.analysis_state = {
            "binary_hash": self._get_binary_hash(),
            "binary_id": None,
            "disassembly": None,
            "patterns": None,
            "llm_analysis": None,
            "patch_strategies": None,
            "validation": None
        }
        
        logger.info(f"Enhanced orchestrator initialized for {binary_path}")
    
    def _init_infrastructure(self):
        """Initialize database and cache infrastructure."""
        if self.use_database:
            try:
                self.db = DatabaseManager()
                self.cache = CacheManager()
                logger.info("Database and cache initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize database/cache: {e}")
                self.use_database = False
                self.db = None
                self.cache = None
        else:
            self.db = None
            self.cache = None
    
    def _init_agents(self):
        """Initialize all specialized agents."""
        # Disassembly agent
        self.disasm_agent = DisassemblyAgent(
            self.binary_analyzer,
            self.db
        )
        
        # LLM agent (if enabled)
        if self.use_llm:
            try:
                self.llm_agent = get_llm_agent(cache_manager=self.cache)
                logger.info("LLM agent initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize LLM agent: {e}")
                self.llm_agent = None
                self.use_llm = False
        else:
            self.llm_agent = None
        
        # Semantic search (if database available)
        if self.use_database:
            try:
                self.embedding_gen = get_embedding_generator(cache_manager=self.cache)
                self.semantic_search = get_search_engine(
                    self.db,
                    cache_manager=self.cache
                )
                logger.info("Semantic search initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize semantic search: {e}")
                self.semantic_search = None
                self.embedding_gen = None
        else:
            self.semantic_search = None
            self.embedding_gen = None
        
        # Pattern agent
        self.pattern_agent = PatternAgent(
            self.disasm_agent,
            self.semantic_search,
            self.llm_agent
        )
        
        # Patch generator
        self.patch_generator = PatchGenerator(
            self.binary_analyzer,
            self.db
        )
        
        # Validation agent
        self.validation_agent = ValidationAgent(
            self.binary_analyzer,
            self.disasm_agent
        )
        
        logger.info("All agents initialized")
    
    def _get_binary_hash(self) -> str:
        """Calculate SHA-256 hash of binary."""
        with open(self.binary_path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    
    def _store_binary_metadata(self):
        """Store binary metadata in database."""
        if not self.db:
            return
        
        import os
        
        query = """
            INSERT INTO raverse.binaries
            (file_name, file_path, file_hash, file_size, file_type, architecture, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (file_hash) DO UPDATE
            SET updated_at = CURRENT_TIMESTAMP
            RETURNING id
        """
        
        result = self.db.execute_query(
            query,
            (
                os.path.basename(self.binary_path),
                self.binary_path,
                self.analysis_state["binary_hash"],
                os.path.getsize(self.binary_path),
                self.binary_analyzer.file_type,
                self.binary_analyzer.arch,
                "analyzing"
            )
        )
        
        if result:
            self.analysis_state["binary_id"] = result[0]['id']
            logger.info(f"Binary metadata stored with ID: {self.analysis_state['binary_id']}")
    
    def analyze_binary(
        self,
        entry_point: Optional[int] = None,
        num_instructions: int = 100
    ) -> Dict[str, Any]:
        """
        Perform comprehensive binary analysis.
        
        Args:
            entry_point: Optional entry point address
            num_instructions: Number of instructions to analyze
            
        Returns:
            Comprehensive analysis results
        """
        logger.info("Starting comprehensive binary analysis")
        metrics_collector.set_active_patches(1)
        
        start_time = time.time()
        
        # Store binary metadata
        self._store_binary_metadata()
        
        # Step 1: Disassembly
        logger.info("Step 1: Disassembling binary")
        if entry_point is None:
            entry_point = self.binary_analyzer.entry_point
        
        disassembly = self.disasm_agent.disassemble_function(
            entry_point,
            max_instructions=num_instructions
        )
        self.analysis_state["disassembly"] = disassembly
        
        # Step 2: Pattern recognition
        logger.info("Step 2: Recognizing patterns")
        pattern_analysis = self.pattern_agent.analyze_function_for_patterns(
            entry_point
        )
        self.analysis_state["patterns"] = pattern_analysis
        
        # Step 3: LLM analysis (if enabled)
        if self.use_llm and self.llm_agent:
            logger.info("Step 3: LLM-powered analysis")
            disasm_text = self.disasm_agent.get_disassembly_text(
                disassembly["instructions"]
            )
            
            llm_analysis = {
                "code_explanation": self.llm_agent.explain_code(disasm_text),
                "password_check": self.llm_agent.identify_password_check(disasm_text),
                "assembly_analysis": self.llm_agent.analyze_assembly(disasm_text)
            }
            self.analysis_state["llm_analysis"] = llm_analysis
        
        # Step 4: Store embeddings (if available)
        if self.semantic_search and self.analysis_state["binary_id"]:
            logger.info("Step 4: Storing code embeddings")
            code_snippets = [
                instr["full"]
                for instr in disassembly["instructions"]
            ]
            
            self.semantic_search.store_code_embeddings_batch(
                self.analysis_state["binary_hash"],
                code_snippets,
                [{"address": instr["address"]} for instr in disassembly["instructions"]]
            )
        
        duration = time.time() - start_time
        logger.info(f"Analysis completed in {duration:.2f}s")
        
        metrics_collector.set_active_patches(0)
        
        return {
            "binary_hash": self.analysis_state["binary_hash"],
            "disassembly": disassembly,
            "patterns": pattern_analysis,
            "llm_analysis": self.analysis_state.get("llm_analysis"),
            "duration": duration
        }
    
    def generate_patches(
        self,
        analysis: Optional[Dict] = None
    ) -> List[Dict]:
        """
        Generate patch strategies based on analysis.
        
        Args:
            analysis: Optional analysis results (uses stored state if None)
            
        Returns:
            List of patch strategies
        """
        if analysis is None:
            analysis = self.analysis_state.get("patterns", {})
        
        logger.info("Generating patch strategies")
        
        # Get target addresses from pattern analysis
        target_addresses = self.pattern_agent.identify_target_addresses(analysis)
        
        # Generate strategies
        strategies = []
        
        # Use LLM to generate strategies if available
        if self.use_llm and self.llm_agent and self.analysis_state.get("disassembly"):
            disasm_text = self.disasm_agent.get_disassembly_text(
                self.analysis_state["disassembly"]["instructions"]
            )
            
            llm_strategies = self.llm_agent.generate_patch_strategies(
                disasm_text,
                "bypass password check"
            )
            
            # Convert LLM strategies to PatchStrategy objects
            for llm_strat in llm_strategies:
                if isinstance(llm_strat, dict) and "target_instructions" in llm_strat:
                    # Generate actual patches for LLM suggestions
                    for addr in target_addresses[:3]:  # Limit to top 3
                        strategies.extend(
                            self.patch_generator.generate_patch_strategies(
                                {"comparison_location": addr}
                            )
                        )
        else:
            # Generate strategies without LLM
            for addr in target_addresses[:5]:  # Limit to top 5
                strategies.extend(
                    self.patch_generator.generate_patch_strategies(
                        {"comparison_location": addr}
                    )
                )
        
        self.analysis_state["patch_strategies"] = strategies
        logger.info(f"Generated {len(strategies)} patch strategies")
        
        return strategies
    
    def apply_and_validate_patch(
        self,
        strategy_index: int = 0,
        output_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Apply patch strategy and validate result.
        
        Args:
            strategy_index: Index of strategy to apply
            output_path: Optional output path for patched binary
            
        Returns:
            Patch application and validation results
        """
        strategies = self.analysis_state.get("patch_strategies", [])
        if not strategies or strategy_index >= len(strategies):
            return {"error": "No strategies available or invalid index"}
        
        strategy = strategies[strategy_index]
        logger.info(f"Applying patch strategy: {strategy.name}")
        
        # Read original binary
        with open(self.binary_path, 'rb') as f:
            original_data = f.read()
        
        # Apply patch
        patched_data = self.patch_generator.apply_patch(original_data, strategy)
        
        # Validate patch
        validation = self.validation_agent.comprehensive_validation(
            original_data,
            patched_data,
            strategy.target_address,
            len(strategy.patched_bytes),
            output_path
        )
        
        # Store results
        if self.db and self.analysis_state.get("binary_id"):
            self.patch_generator.store_strategy(
                strategy,
                validation.get("overall_valid", False)
            )
        
        # Write patched binary if output path provided
        if output_path and validation.get("overall_valid"):
            with open(output_path, 'wb') as f:
                f.write(patched_data)
            logger.info(f"Patched binary written to {output_path}")
        
        # Record metrics
        metrics_collector.record_patch_attempt(
            self.binary_analyzer.file_type,
            "success" if validation.get("overall_valid") else "failed"
        )
        
        return {
            "strategy": {
                "name": strategy.name,
                "type": strategy.patch_type.value,
                "address": f"0x{strategy.target_address:x}",
                "description": strategy.description
            },
            "validation": validation,
            "output_path": output_path if validation.get("overall_valid") else None
        }
    
    def get_analysis_report(self) -> str:
        """
        Generate comprehensive analysis report.
        
        Returns:
            Formatted analysis report
        """
        lines = []
        lines.append("=" * 80)
        lines.append("RAVERSE 2.0 - COMPREHENSIVE ANALYSIS REPORT")
        lines.append("=" * 80)
        lines.append("")
        
        lines.append(f"Binary: {os.path.basename(self.binary_path)}")
        lines.append(f"Hash: {self.analysis_state['binary_hash']}")
        lines.append(f"Type: {self.binary_analyzer.file_type}")
        lines.append(f"Architecture: {self.binary_analyzer.arch}")
        lines.append("")
        
        # Pattern analysis
        if self.analysis_state.get("patterns"):
            lines.append(self.pattern_agent.generate_pattern_report(
                self.analysis_state["patterns"]
            ))
        
        # LLM analysis
        if self.analysis_state.get("llm_analysis"):
            lines.append("\nLLM ANALYSIS:")
            lines.append("-" * 80)
            llm = self.analysis_state["llm_analysis"]
            if "code_explanation" in llm:
                lines.append(f"\nExplanation:\n{llm['code_explanation']}")
        
        # Patch strategies
        if self.analysis_state.get("patch_strategies"):
            lines.append("\nPATCH STRATEGIES:")
            lines.append("-" * 80)
            for i, strat in enumerate(self.analysis_state["patch_strategies"], 1):
                lines.append(f"\n{i}. {strat.name}")
                lines.append(f"   Type: {strat.patch_type.value}")
                lines.append(f"   Address: 0x{strat.target_address:x}")
                lines.append(f"   Confidence: {strat.confidence:.2%}")
                lines.append(f"   Description: {strat.description}")
        
        lines.append("\n" + "=" * 80)
        
        return "\n".join(lines)

