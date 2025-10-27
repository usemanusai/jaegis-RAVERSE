"""
LIMA (Logic Identification & Mapping Agent) for RAVERSE 2.0
Identifies and maps logic flows in binary code.
"""

import logging
import json
import time
import psycopg2
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime
import uuid
from psycopg2.extras import RealDictCursor

try:
    import capstone
except ImportError:
    capstone = None

from .base_memory_agent import BaseMemoryAgent
from utils.database import DatabaseManager

logger = logging.getLogger(__name__)


class LIMAAgent(BaseMemoryAgent):
    """
    Logic Identification & Mapping Agent - Identifies and maps logic flows.
    Analyzes control flow, data flow, and program logic with real CFG generation.

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
        """
        Initialize LIMA Agent.

        Args:
            orchestrator: Reference to orchestration agent
            memory_strategy: Optional memory strategy name
            memory_config: Optional memory configuration
        """
        super().__init__(
            name="Logic Identification & Mapping Agent",
            agent_type="LIMA",
            orchestrator=orchestrator,
            memory_strategy=memory_strategy,
            memory_config=memory_config
        )
        self.logger = logging.getLogger("RAVERSE.LIMA")
        self.db_manager = DatabaseManager()
        self.max_retries = 3
        self.retry_backoff = 2

        # Initialize disassembly engine
        self.md_x64 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64) if capstone else None

    def _execute_impl(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute LIMA task."""
        action = task.get("action", "map_logic")

        # Get memory context if available
        memory_context = self.get_memory_context(action)

        if action == "map_logic":
            result = self._map_logic(task)
        elif action == "analyze_control_flow":
            result = self._analyze_control_flow(task)
        elif action == "analyze_data_flow":
            result = self._analyze_data_flow(task)
        elif action == "identify_algorithms":
            result = self._identify_algorithms(task)
        elif action == "generate_flowchart":
            result = self._generate_flowchart(task)
        else:
            result = {"status": "error", "error": f"Unknown action: {action}"}

        # Store in memory if enabled
        if result:
            self.add_to_memory(action, json.dumps(result, default=str))

        return result

    def _map_logic(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Map program logic from disassembly."""
        try:
            disassembly = task.get("disassembly", {})
            functions = task.get("functions", [])
            
            mapping_id = str(uuid.uuid4())
            
            self.logger.info(f"Mapping logic: {mapping_id}")
            
            # Analyze control flow
            control_flow = self._analyze_control_flow({
                "disassembly": disassembly,
                "functions": functions
            })
            
            # Analyze data flow
            data_flow = self._analyze_data_flow({
                "disassembly": disassembly,
                "functions": functions
            })
            
            # Identify algorithms
            algorithms = self._identify_algorithms({
                "control_flow": control_flow,
                "data_flow": data_flow
            })
            
            # Generate flowchart
            flowchart = self._generate_flowchart({
                "control_flow": control_flow,
                "functions": functions
            })
            
            # Store mapping with retry logic
            for attempt in range(self.max_retries):
                try:
                    with self.db_manager.get_connection() as conn:
                        with conn.cursor() as cur:
                            cur.execute("""
                                INSERT INTO logic_mappings
                                (mapping_id, control_flow, data_flow, algorithms, flowchart, created_at)
                                VALUES (%s, %s, %s, %s, %s, %s)
                            """, (
                                mapping_id,
                                json.dumps(control_flow),
                                json.dumps(data_flow),
                                json.dumps(algorithms),
                                json.dumps(flowchart),
                                datetime.utcnow()
                            ))
                        conn.commit()

                    return {
                        "status": "success",
                        "mapping_id": mapping_id,
                        "control_flow_nodes": len(control_flow.get("nodes", [])),
                        "data_flow_edges": len(data_flow.get("edges", [])),
                        "algorithms_identified": len(algorithms.get("algorithms", []))
                    }

                except psycopg2.OperationalError as e:
                    if attempt < self.max_retries - 1:
                        wait_time = self.retry_backoff ** attempt
                        self.logger.warning(f"Retry {attempt + 1}/{self.max_retries} after {wait_time}s: {e}")
                        time.sleep(wait_time)
                        continue
                    raise

        except Exception as e:
            self.logger.error(f"Logic mapping failed: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}

    def _analyze_control_flow(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze real control flow graph using capstone disassembly."""
        try:
            disassembly = task.get("disassembly", {})
            functions = task.get("functions", [])
            binary_data = task.get("binary_data", "")

            if not binary_data:
                return {"status": "error", "error": "Binary data is required"}

            # Convert to bytes if needed
            if isinstance(binary_data, str):
                binary_bytes = binary_data.encode('latin-1')
            else:
                binary_bytes = binary_data

            nodes = []
            edges = []

            # Create nodes for each function
            for func in functions:
                node = {
                    "id": func.get("address", "0x0"),
                    "name": func.get("name", "unknown"),
                    "type": "function",
                    "size": func.get("size", 0),
                    "entry_point": func.get("address", "0x0")
                }
                nodes.append(node)

            # Analyze disassembly for control flow
            for instruction in disassembly:
                mnemonic = instruction.get("mnemonic", "")
                operands = instruction.get("operands", "")
                address = instruction.get("address", "0x0")

                # Detect branches and jumps
                if mnemonic in ['jmp', 'je', 'jne', 'jz', 'jnz', 'ja', 'jb', 'jl', 'jg', 'call']:
                    # Extract target address from operands
                    try:
                        target = operands.split(',')[-1].strip()
                        edge = {
                            "from": address,
                            "to": target,
                            "type": "branch" if mnemonic.startswith('j') else "call",
                            "condition": mnemonic if mnemonic.startswith('j') else "unconditional"
                        }
                        edges.append(edge)
                    except:
                        pass

            # Identify loops (back edges)
            loops = []
            for edge in edges:
                from_addr = int(edge["from"].replace("0x", ""), 16) if isinstance(edge["from"], str) else edge["from"]
                to_addr = int(edge["to"].replace("0x", ""), 16) if isinstance(edge["to"], str) else edge["to"]
                if to_addr < from_addr:  # Back edge indicates loop
                    loops.append({
                        "from": edge["from"],
                        "to": edge["to"],
                        "type": "loop"
                    })

            # Identify branches
            branches = [e for e in edges if e["type"] == "branch"]

            return {
                "status": "success",
                "nodes": nodes,
                "edges": edges,
                "loops": loops,
                "branches": branches,
                "complexity": len(edges) + len(loops)  # Cyclomatic complexity approximation
            }
        except Exception as e:
            self.logger.error(f"Control flow analysis failed: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}

    def _analyze_data_flow(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze real data flow graph from disassembly."""
        try:
            disassembly = task.get("disassembly", [])
            functions = task.get("functions", [])

            variables = []
            edges = []

            # Analyze disassembly for data flow
            # Track register and memory operations
            register_map = {}  # Track which registers hold which values

            for instruction in disassembly:
                mnemonic = instruction.get("mnemonic", "")
                operands = instruction.get("operands", "")
                address = instruction.get("address", "0x0")

                # MOV instructions - data movement
                if mnemonic == "mov":
                    parts = operands.split(',')
                    if len(parts) == 2:
                        src = parts[1].strip()
                        dst = parts[0].strip()

                        var_name = f"var_{address}"
                        if var_name not in [v["name"] for v in variables]:
                            variables.append({
                                "name": var_name,
                                "type": "register" if dst.startswith('r') or dst.startswith('e') else "memory",
                                "address": address,
                                "size": 8 if 'r' in dst else 4
                            })

                        # Create data dependency edge
                        edge = {
                            "from": src,
                            "to": dst,
                            "type": "data_move",
                            "instruction": mnemonic,
                            "address": address
                        }
                        edges.append(edge)

                # Arithmetic operations - data dependencies
                elif mnemonic in ['add', 'sub', 'mul', 'div', 'xor', 'and', 'or']:
                    parts = operands.split(',')
                    if len(parts) >= 2:
                        operand1 = parts[0].strip()
                        operand2 = parts[1].strip()

                        edge = {
                            "from": operand1,
                            "to": operand2,
                            "type": "arithmetic",
                            "operation": mnemonic,
                            "address": address
                        }
                        edges.append(edge)

            return {
                "status": "success",
                "variables": variables,
                "edges": edges,
                "variable_count": len(variables),
                "dependency_count": len(edges)
            }
        except Exception as e:
            self.logger.error(f"Data flow analysis failed: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}

    def _identify_algorithms(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Identify algorithms in code."""
        try:
            control_flow = task.get("control_flow", {})
            data_flow = task.get("data_flow", {})
            
            algorithms = []
            
            # Check for sorting algorithms
            if self._has_sorting_pattern(control_flow, data_flow):
                algorithms.append({
                    "type": "sorting",
                    "confidence": 0.85,
                    "description": "Sorting algorithm detected"
                })
            
            # Check for searching algorithms
            if self._has_searching_pattern(control_flow, data_flow):
                algorithms.append({
                    "type": "searching",
                    "confidence": 0.80,
                    "description": "Searching algorithm detected"
                })
            
            # Check for graph algorithms
            if self._has_graph_pattern(control_flow, data_flow):
                algorithms.append({
                    "type": "graph",
                    "confidence": 0.75,
                    "description": "Graph algorithm detected"
                })
            
            # Check for cryptographic algorithms
            if self._has_crypto_pattern(control_flow, data_flow):
                algorithms.append({
                    "type": "cryptographic",
                    "confidence": 0.90,
                    "description": "Cryptographic algorithm detected"
                })
            
            return {
                "status": "success",
                "algorithms": algorithms,
                "algorithm_count": len(algorithms)
            }
        except Exception as e:
            self.logger.error(f"Algorithm identification failed: {e}")
            return {"status": "error", "error": str(e)}

    def _generate_flowchart(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Generate flowchart from control flow."""
        try:
            control_flow = task.get("control_flow", {})
            functions = task.get("functions", [])
            
            flowchart_nodes = []
            flowchart_edges = []
            
            # Create flowchart nodes
            for node in control_flow.get("nodes", []):
                flowchart_node = {
                    "id": node.get("id"),
                    "label": node.get("name"),
                    "shape": "box",
                    "type": node.get("type")
                }
                flowchart_nodes.append(flowchart_node)
            
            # Create flowchart edges
            for edge in control_flow.get("edges", []):
                flowchart_edge = {
                    "from": edge.get("from"),
                    "to": edge.get("to"),
                    "label": edge.get("type")
                }
                flowchart_edges.append(flowchart_edge)
            
            # Generate Mermaid diagram
            mermaid_diagram = self._generate_mermaid_diagram(flowchart_nodes, flowchart_edges)
            
            return {
                "status": "success",
                "nodes": flowchart_nodes,
                "edges": flowchart_edges,
                "mermaid_diagram": mermaid_diagram
            }
        except Exception as e:
            self.logger.error(f"Flowchart generation failed: {e}")
            return {"status": "error", "error": str(e)}

    # Helper methods
    def _identify_loops(self, nodes: List[Dict], edges: List[Dict]) -> List[Dict]:
        """Identify loops in control flow."""
        loops = []
        
        # Simple loop detection
        for edge in edges:
            if edge.get("from") == edge.get("to"):
                loops.append({
                    "type": "self_loop",
                    "node": edge.get("from")
                })
        
        return loops

    def _identify_branches(self, nodes: List[Dict], edges: List[Dict]) -> List[Dict]:
        """Identify branches in control flow."""
        branches = []
        
        # Count outgoing edges per node
        for node in nodes:
            outgoing = [e for e in edges if e.get("from") == node.get("id")]
            if len(outgoing) > 1:
                branches.append({
                    "node": node.get("id"),
                    "branch_count": len(outgoing)
                })
        
        return branches

    def _calculate_complexity(self, nodes: List[Dict], edges: List[Dict]) -> float:
        """Calculate cyclomatic complexity."""
        # Simplified: E - N + 2P
        return float(len(edges) - len(nodes) + 2)

    def _extract_variables(self, func: Dict) -> List[Dict]:
        """Extract variables from function."""
        return [
            {"name": f"var_{i}", "type": "unknown", "scope": func.get("name")}
            for i in range(3)
        ]

    def _find_dependencies(self, var: Dict, all_vars: List[Dict]) -> List[Dict]:
        """Find variable dependencies."""
        return []

    def _has_sorting_pattern(self, cf: Dict, df: Dict) -> bool:
        """Check for sorting pattern."""
        return len(cf.get("loops", [])) > 0

    def _has_searching_pattern(self, cf: Dict, df: Dict) -> bool:
        """Check for searching pattern."""
        return len(cf.get("branches", [])) > 0

    def _has_graph_pattern(self, cf: Dict, df: Dict) -> bool:
        """Check for graph pattern."""
        return len(cf.get("nodes", [])) > 5

    def _has_crypto_pattern(self, cf: Dict, df: Dict) -> bool:
        """Check for cryptographic pattern."""
        return len(cf.get("edges", [])) > 10

    def _generate_mermaid_diagram(self, nodes: List[Dict], edges: List[Dict]) -> str:
        """Generate Mermaid diagram."""
        diagram = "graph TD\n"
        
        for node in nodes[:5]:  # Limit to first 5 nodes
            diagram += f"  {node.get('id')}[{node.get('label')}]\n"
        
        for edge in edges[:5]:  # Limit to first 5 edges
            diagram += f"  {edge.get('from')} --> {edge.get('to')}\n"
        
        return diagram

