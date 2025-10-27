"""
RAVERSE 2.0 - 9 Memory Optimization Strategies
Based on: FareedKhan-dev/optimize-ai-agent-memory
"""

from abc import ABC, abstractmethod
from collections import deque
from typing import List, Dict, Tuple, Optional
import re
import logging

# Lazy imports for optional dependencies
# numpy, faiss, and networkx are imported only when needed


class BaseMemoryStrategy(ABC):
    """Abstract base class for all memory strategies."""
    
    @abstractmethod
    def add_message(self, user_input: str, ai_response: str) -> None:
        """Add a user-AI interaction to memory."""
        pass
    
    @abstractmethod
    def get_context(self, query: str) -> str:
        """Retrieve context for the given query."""
        pass
    
    @abstractmethod
    def clear(self) -> None:
        """Clear all memory."""
        pass


# Strategy 1: Sequential Memory
class SequentialMemory(BaseMemoryStrategy):
    """Stores entire conversation history. Simple but expensive."""
    
    def __init__(self):
        self.history = []
    
    def add_message(self, user_input: str, ai_response: str) -> None:
        self.history.append({"role": "user", "content": user_input})
        self.history.append({"role": "assistant", "content": ai_response})
    
    def get_context(self, query: str) -> str:
        return "\n".join([f"{turn['role'].capitalize()}: {turn['content']}" for turn in self.history])
    
    def clear(self) -> None:
        self.history = []


# Strategy 2: Sliding Window Memory
class SlidingWindowMemory(BaseMemoryStrategy):
    """Keeps only N most recent turns. Scalable but may lose context."""
    
    def __init__(self, window_size: int = 4):
        self.history = deque(maxlen=window_size)
    
    def add_message(self, user_input: str, ai_response: str) -> None:
        self.history.append([
            {"role": "user", "content": user_input},
            {"role": "assistant", "content": ai_response}
        ])
    
    def get_context(self, query: str) -> str:
        context_list = []
        for turn in self.history:
            for message in turn:
                context_list.append(f"{message['role'].capitalize()}: {message['content']}")
        return "\n".join(context_list)
    
    def clear(self) -> None:
        self.history.clear()


# Strategy 3: Summarization Memory
class SummarizationMemory(BaseMemoryStrategy):
    """Periodically summarizes buffer. Reduces tokens, preserves key info."""
    
    def __init__(self, summary_threshold: int = 4):
        self.running_summary = ""
        self.buffer = []
        self.summary_threshold = summary_threshold
    
    def add_message(self, user_input: str, ai_response: str) -> None:
        self.buffer.append({"role": "user", "content": user_input})
        self.buffer.append({"role": "assistant", "content": ai_response})
        
        if len(self.buffer) >= self.summary_threshold:
            self._consolidate_memory()
    
    def _consolidate_memory(self) -> None:
        """Consolidate buffer into summary."""
        buffer_text = "\n".join([f"{msg['role'].capitalize()}: {msg['content']}" for msg in self.buffer])
        # In production, call LLM to summarize
        self.running_summary = f"Summary: {buffer_text[:200]}..."
        self.buffer = []
    
    def get_context(self, query: str) -> str:
        buffer_text = "\n".join([f"{msg['role'].capitalize()}: {msg['content']}" for msg in self.buffer])
        return f"### Summary:\n{self.running_summary}\n\n### Recent:\n{buffer_text}"
    
    def clear(self) -> None:
        self.running_summary = ""
        self.buffer = []


# Strategy 4: Retrieval-Based Memory (RAG)
class RetrievalMemory(BaseMemoryStrategy):
    """Vector embeddings + semantic search. Industry standard for RAG."""

    def __init__(self, k: int = 2, embedding_dim: int = 384):
        self.k = k
        self.embedding_dim = embedding_dim
        self.documents = []
        self.index = None
        self._faiss_available = False
        self._initialize_faiss()

    def _initialize_faiss(self):
        """Lazy load FAISS only when needed."""
        try:
            import faiss
            self.index = faiss.IndexFlatL2(self.embedding_dim)
            self._faiss_available = True
        except ImportError:
            import logging
            logging.warning(
                "FAISS not installed. Install with: pip install faiss-cpu\n"
                "For GPU support: pip install faiss-gpu"
            )
            self._faiss_available = False

    def add_message(self, user_input: str, ai_response: str) -> None:
        docs = [f"User: {user_input}", f"AI: {ai_response}"]
        for doc in docs:
            self.documents.append(doc)
            if self.index and self._faiss_available:
                try:
                    import numpy as np
                    # In production, generate real embeddings
                    embedding = np.random.rand(self.embedding_dim).astype('float32')
                    self.index.add(np.array([embedding], dtype='float32'))
                except ImportError:
                    logging.warning("NumPy not available for embeddings")
    
    def get_context(self, query: str) -> str:
        if not self.documents:
            return "No information in memory."

        if self.index and self._faiss_available and self.index.ntotal > 0:
            try:
                import numpy as np
                # In production, generate real query embedding
                query_embedding = np.random.rand(self.embedding_dim).astype('float32')
                distances, indices = self.index.search(np.array([query_embedding], dtype='float32'), min(self.k, len(self.documents)))
                retrieved = [self.documents[i] for i in indices[0] if i != -1]
                return "### Retrieved:\n" + "\n---\n".join(retrieved)
            except ImportError:
                logging.warning("NumPy not available for retrieval")

        return "\n".join(self.documents[-self.k:])
    
    def clear(self) -> None:
        self.documents = []
        if self.index and self._faiss_available:
            try:
                import faiss
                self.index = faiss.IndexFlatL2(self.embedding_dim)
            except Exception as e:
                logging.warning(f"Failed to clear FAISS index: {e}")


# Strategy 5: Memory-Augmented Memory
class MemoryAugmentedMemory(BaseMemoryStrategy):
    """Sliding window + fact extraction. Retains critical facts."""
    
    def __init__(self, window_size: int = 2):
        self.recent_memory = SlidingWindowMemory(window_size)
        self.memory_tokens = []
    
    def add_message(self, user_input: str, ai_response: str) -> None:
        self.recent_memory.add_message(user_input, ai_response)
        
        # Extract important facts
        keywords = ["remember", "rule", "preference", "always", "never", "allergic"]
        if any(kw in user_input.lower() for kw in keywords):
            self.memory_tokens.append(f"FACT: {user_input}")
    
    def get_context(self, query: str) -> str:
        recent = self.recent_memory.get_context(query)
        tokens = "\n".join([f"- {token}" for token in self.memory_tokens])
        return f"### Key Facts:\n{tokens}\n\n### Recent:\n{recent}"
    
    def clear(self) -> None:
        self.recent_memory.clear()
        self.memory_tokens = []


# Strategy 6: Hierarchical Memory
class HierarchicalMemory(BaseMemoryStrategy):
    """Working memory + long-term memory. Multi-level importance."""
    
    def __init__(self, window_size: int = 2, k: int = 2):
        self.working_memory = SlidingWindowMemory(window_size)
        self.long_term_memory = RetrievalMemory(k=k)
        self.promotion_keywords = ["remember", "rule", "preference", "always", "never"]
    
    def add_message(self, user_input: str, ai_response: str) -> None:
        self.working_memory.add_message(user_input, ai_response)
        
        if any(kw in user_input.lower() for kw in self.promotion_keywords):
            self.long_term_memory.add_message(user_input, ai_response)
    
    def get_context(self, query: str) -> str:
        long_term = self.long_term_memory.get_context(query)
        working = self.working_memory.get_context(query)
        return f"### Long-Term:\n{long_term}\n\n### Working:\n{working}"
    
    def clear(self) -> None:
        self.working_memory.clear()
        self.long_term_memory.clear()


# Strategy 7: Graph-Based Memory
class GraphMemory(BaseMemoryStrategy):
    """Knowledge graph with relationships. Excellent for reasoning."""

    def __init__(self):
        self.graph = None
        self._networkx_available = False
        self._initialize_networkx()

    def _initialize_networkx(self):
        """Lazy load NetworkX only when needed."""
        try:
            import networkx as nx
            self.graph = nx.DiGraph()
            self._networkx_available = True
        except ImportError:
            import logging
            logging.warning(
                "NetworkX not installed. Install with: pip install networkx"
            )
            self._networkx_available = False
    
    def add_message(self, user_input: str, ai_response: str) -> None:
        if not self._networkx_available or not self.graph:
            return

        text = f"User: {user_input}\nAI: {ai_response}"
        triples = self._extract_triples(text)
        for subject, relation, obj in triples:
            self.graph.add_edge(subject.strip(), obj.strip(), relation=relation.strip())

    def _extract_triples(self, text: str) -> List[Tuple[str, str, str]]:
        """Extract Subject-Relation-Object triples from text."""
        # Simple pattern matching (in production, use LLM)
        triples = []
        patterns = [
            r"(\w+)\s+works\s+for\s+(\w+)",
            r"(\w+)\s+manages\s+(\w+)",
            r"(\w+)\s+is\s+(\w+)",
        ]
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                triples.append((match[0], "related_to", match[1]))
        return triples

    def get_context(self, query: str) -> str:
        if not self._networkx_available or not self.graph or not self.graph.nodes:
            return "Knowledge graph is empty."

        context = []
        for node in self.graph.nodes:
            if node.lower() in query.lower():
                for u, v, data in self.graph.out_edges(node, data=True):
                    context.append(f"{u} --[{data.get('relation', 'related')}]--> {v}")

        return "### Knowledge Graph:\n" + "\n".join(context) if context else "No relevant facts found."

    def clear(self) -> None:
        if self._networkx_available and self.graph:
            self.graph.clear()


# Strategy 8: Compression & Consolidation Memory
class CompressionMemory(BaseMemoryStrategy):
    """Compress each turn to essential facts. Extreme token reduction."""
    
    def __init__(self):
        self.compressed_facts = []
    
    def add_message(self, user_input: str, ai_response: str) -> None:
        # In production, use LLM to compress
        compressed = f"User: {user_input[:50]}... AI: {ai_response[:50]}..."
        self.compressed_facts.append(compressed)
    
    def get_context(self, query: str) -> str:
        return "### Compressed Facts:\n- " + "\n- ".join(self.compressed_facts)
    
    def clear(self) -> None:
        self.compressed_facts = []


# Strategy 9: OS-Like Memory Management
class OSMemory(BaseMemoryStrategy):
    """Active (RAM) + Passive (Disk) memory. Virtual memory system."""
    
    def __init__(self, ram_size: int = 2):
        self.ram_size = ram_size
        self.active_memory = deque()
        self.passive_memory = {}
        self.turn_count = 0
    
    def add_message(self, user_input: str, ai_response: str) -> None:
        turn_id = self.turn_count
        turn_data = f"User: {user_input}\nAI: {ai_response}"
        
        if len(self.active_memory) >= self.ram_size:
            lru_id, lru_data = self.active_memory.popleft()
            self.passive_memory[lru_id] = lru_data
        
        self.active_memory.append((turn_id, turn_data))
        self.turn_count += 1
    
    def get_context(self, query: str) -> str:
        active = "\n".join([data for _, data in self.active_memory])
        
        # Page in relevant data
        paged_in = ""
        for turn_id, data in self.passive_memory.items():
            if any(word in data.lower() for word in query.lower().split() if len(word) > 3):
                paged_in += f"\n(Paged in Turn {turn_id}): {data}"
        
        return f"### Active:\n{active}\n\n### Paged In:\n{paged_in}"
    
    def clear(self) -> None:
        self.active_memory.clear()
        self.passive_memory = {}
        self.turn_count = 0


# Memory Strategy Factory
MEMORY_STRATEGIES = {
    "sequential": SequentialMemory,
    "sliding_window": SlidingWindowMemory,
    "summarization": SummarizationMemory,
    "retrieval": RetrievalMemory,
    "memory_augmented": MemoryAugmentedMemory,
    "hierarchical": HierarchicalMemory,
    "graph": GraphMemory,
    "compression": CompressionMemory,
    "os_like": OSMemory,
}


def get_memory_strategy(strategy_name: str, **kwargs) -> BaseMemoryStrategy:
    """Factory function to get memory strategy by name."""
    if strategy_name not in MEMORY_STRATEGIES:
        raise ValueError(f"Unknown strategy: {strategy_name}")
    return MEMORY_STRATEGIES[strategy_name](**kwargs)

