"""
Pipeline Error Handling & Recovery - Comprehensive error management and recovery strategies.
Handles failures, retries, fallbacks, and error propagation.
"""

import logging
from typing import Any, Dict, Optional, Callable, List
from enum import Enum
from dataclasses import dataclass
from datetime import datetime, timedelta
import traceback

logger = logging.getLogger("RAVERSE.ERROR_HANDLING")


class ErrorSeverity(Enum):
    """Error severity levels"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class ErrorRecoveryStrategy(Enum):
    """Error recovery strategies"""
    RETRY = "retry"
    FALLBACK = "fallback"
    SKIP = "skip"
    ABORT = "abort"
    CUSTOM = "custom"


@dataclass
class PipelineError:
    """Represents a pipeline error"""
    error_id: str
    error_type: str
    message: str
    severity: ErrorSeverity
    source_agent: str
    source_task: str
    timestamp: datetime
    traceback: Optional[str] = None
    context: Dict[str, Any] = None
    recovery_attempted: bool = False
    recovery_strategy: Optional[ErrorRecoveryStrategy] = None
    recovery_result: Optional[str] = None
    
    def __post_init__(self):
        if self.context is None:
            self.context = {}


class RetryPolicy:
    """Defines retry behavior"""
    
    def __init__(
        self,
        max_retries: int = 3,
        initial_delay: float = 1.0,
        max_delay: float = 60.0,
        backoff_multiplier: float = 2.0,
        jitter: bool = True
    ):
        self.max_retries = max_retries
        self.initial_delay = initial_delay
        self.max_delay = max_delay
        self.backoff_multiplier = backoff_multiplier
        self.jitter = jitter
    
    def get_delay(self, attempt: int) -> float:
        """Calculate delay for retry attempt"""
        delay = min(
            self.initial_delay * (self.backoff_multiplier ** attempt),
            self.max_delay
        )
        
        if self.jitter:
            import random
            delay *= (0.5 + random.random())
        
        return delay


class FallbackHandler:
    """Manages fallback strategies"""
    
    def __init__(self):
        self.fallbacks: Dict[str, Callable] = {}
    
    def register_fallback(self, error_type: str, handler: Callable):
        """Register fallback handler for error type"""
        self.fallbacks[error_type] = handler
        logger.info(f"Registered fallback for {error_type}")
    
    def handle_fallback(self, error: PipelineError) -> Optional[Any]:
        """Execute fallback handler"""
        handler = self.fallbacks.get(error.error_type)
        if handler:
            try:
                logger.info(f"Executing fallback for {error.error_type}")
                result = handler(error)
                error.recovery_attempted = True
                error.recovery_strategy = ErrorRecoveryStrategy.FALLBACK
                error.recovery_result = "success"
                return result
            except Exception as e:
                logger.error(f"Fallback handler failed: {e}")
                error.recovery_result = "failed"
                return None
        return None


class ErrorHandler:
    """Central error handling system"""
    
    def __init__(self):
        self.errors: List[PipelineError] = []
        self.retry_policy = RetryPolicy()
        self.fallback_handler = FallbackHandler()
        self.error_callbacks: List[Callable] = []
    
    def register_error_callback(self, callback: Callable):
        """Register callback for error events"""
        self.error_callbacks.append(callback)
    
    def handle_error(
        self,
        error_type: str,
        message: str,
        source_agent: str,
        source_task: str,
        severity: ErrorSeverity = ErrorSeverity.ERROR,
        context: Dict[str, Any] = None,
        exc: Optional[Exception] = None
    ) -> PipelineError:
        """Handle an error"""
        import uuid
        
        error = PipelineError(
            error_id=str(uuid.uuid4()),
            error_type=error_type,
            message=message,
            severity=severity,
            source_agent=source_agent,
            source_task=source_task,
            timestamp=datetime.now(),
            traceback=traceback.format_exc() if exc else None,
            context=context or {}
        )
        
        self.errors.append(error)
        logger.log(
            logging.ERROR if severity == ErrorSeverity.ERROR else logging.WARNING,
            f"[{error_type}] {message} (Agent: {source_agent}, Task: {source_task})"
        )
        
        # Trigger callbacks
        for callback in self.error_callbacks:
            try:
                callback(error)
            except Exception as e:
                logger.error(f"Error callback failed: {e}")
        
        return error
    
    def should_retry(self, error: PipelineError, attempt: int) -> bool:
        """Determine if error should be retried"""
        if attempt >= self.retry_policy.max_retries:
            return False
        
        # Retry on transient errors
        transient_errors = ["TIMEOUT", "CONNECTION_ERROR", "TEMPORARY_FAILURE"]
        return error.error_type in transient_errors
    
    def get_retry_delay(self, attempt: int) -> float:
        """Get delay before retry"""
        return self.retry_policy.get_delay(attempt)
    
    def get_errors(self, severity: Optional[ErrorSeverity] = None) -> List[PipelineError]:
        """Get errors, optionally filtered by severity"""
        if severity:
            return [e for e in self.errors if e.severity == severity]
        return self.errors
    
    def get_error_stats(self) -> Dict[str, Any]:
        """Get error statistics"""
        total = len(self.errors)
        by_severity = {}
        by_type = {}
        
        for error in self.errors:
            severity_name = error.severity.value
            by_severity[severity_name] = by_severity.get(severity_name, 0) + 1
            by_type[error.error_type] = by_type.get(error.error_type, 0) + 1
        
        return {
            "total_errors": total,
            "by_severity": by_severity,
            "by_type": by_type,
            "recovery_attempted": sum(1 for e in self.errors if e.recovery_attempted),
            "recovery_successful": sum(1 for e in self.errors if e.recovery_result == "success")
        }
    
    def clear_errors(self):
        """Clear error history"""
        self.errors.clear()


class CircuitBreaker:
    """Circuit breaker pattern for fault tolerance"""
    
    def __init__(self, failure_threshold: int = 5, timeout_seconds: int = 60):
        self.failure_threshold = failure_threshold
        self.timeout_seconds = timeout_seconds
        self.failure_count = 0
        self.last_failure_time: Optional[datetime] = None
        self.state = "closed"  # closed, open, half-open
    
    def record_success(self):
        """Record successful operation"""
        self.failure_count = 0
        self.state = "closed"
    
    def record_failure(self):
        """Record failed operation"""
        self.failure_count += 1
        self.last_failure_time = datetime.now()
        
        if self.failure_count >= self.failure_threshold:
            self.state = "open"
            logger.warning(f"Circuit breaker opened after {self.failure_count} failures")
    
    def can_execute(self) -> bool:
        """Check if operation can be executed"""
        if self.state == "closed":
            return True
        
        if self.state == "open":
            # Check if timeout has passed
            if self.last_failure_time:
                elapsed = (datetime.now() - self.last_failure_time).total_seconds()
                if elapsed > self.timeout_seconds:
                    self.state = "half-open"
                    logger.info("Circuit breaker half-open, attempting recovery")
                    return True
            return False
        
        # half-open state
        return True
    
    def get_state(self) -> str:
        """Get circuit breaker state"""
        return self.state


class ErrorRecoveryManager:
    """Manages error recovery strategies"""
    
    def __init__(self, error_handler: ErrorHandler):
        self.error_handler = error_handler
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
    
    def get_circuit_breaker(self, agent_type: str) -> CircuitBreaker:
        """Get or create circuit breaker for agent"""
        if agent_type not in self.circuit_breakers:
            self.circuit_breakers[agent_type] = CircuitBreaker()
        return self.circuit_breakers[agent_type]
    
    async def execute_with_recovery(
        self,
        agent_type: str,
        task_func: Callable,
        error_context: Dict[str, Any]
    ) -> Optional[Any]:
        """Execute task with error recovery"""
        circuit_breaker = self.get_circuit_breaker(agent_type)
        
        if not circuit_breaker.can_execute():
            return {
                "success": False,
                "error": "Circuit breaker is open",
                "error_code": "CIRCUIT_OPEN"
            }
        
        attempt = 0
        while attempt <= self.error_handler.retry_policy.max_retries:
            try:
                result = await task_func() if hasattr(task_func, '__await__') else task_func()
                circuit_breaker.record_success()
                return result
            except Exception as e:
                attempt += 1
                error = self.error_handler.handle_error(
                    error_type=type(e).__name__,
                    message=str(e),
                    source_agent=agent_type,
                    source_task=error_context.get("task_id", "unknown"),
                    severity=ErrorSeverity.ERROR,
                    context=error_context,
                    exc=e
                )
                
                circuit_breaker.record_failure()
                
                if self.error_handler.should_retry(error, attempt):
                    delay = self.error_handler.get_retry_delay(attempt)
                    logger.info(f"Retrying after {delay}s (attempt {attempt})")
                    import asyncio
                    await asyncio.sleep(delay)
                else:
                    break
        
        return None

