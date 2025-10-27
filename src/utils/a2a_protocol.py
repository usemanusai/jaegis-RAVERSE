"""
Agent-to-Agent (A2A) Protocol Implementation for RAVERSE 2.0.
Provides JSON-based message format and validation for inter-agent communication.
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from enum import Enum
from dataclasses import dataclass, asdict
from pydantic import BaseModel, Field, validator

logger = logging.getLogger(__name__)


class MessageType(str, Enum):
    """A2A message types."""
    REQUEST = "request"
    RESPONSE = "response"
    NOTIFICATION = "notification"
    ERROR = "error"


class MessageAction(str, Enum):
    """A2A message actions."""
    ANALYZE = "analyze"
    EXECUTE = "execute"
    REPORT = "report"
    VALIDATE = "validate"
    QUERY = "query"
    UPDATE = "update"


class MessagePriority(str, Enum):
    """A2A message priority levels."""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"


class MessageStatus(str, Enum):
    """A2A message status."""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class A2AMessage(BaseModel):
    """
    Agent-to-Agent message schema.
    Defines the structure for all inter-agent communication.
    """

    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    sender: str
    receiver: str
    message_type: MessageType
    action: MessageAction
    payload: Dict[str, Any] = Field(default_factory=dict)
    correlation_id: Optional[str] = Field(default_factory=lambda: str(uuid.uuid4()))
    priority: MessagePriority = MessagePriority.NORMAL
    timeout_seconds: int = 300
    retry_count: int = 0
    status: MessageStatus = MessageStatus.PENDING

    @validator("sender", "receiver")
    def validate_agent_names(cls, v: str) -> str:
        """Validate agent names are non-empty."""
        if not v or not isinstance(v, str):
            raise ValueError("Agent name must be non-empty string")
        return v

    @validator("timeout_seconds")
    def validate_timeout(cls, v: int) -> int:
        """Validate timeout is positive."""
        if v <= 0:
            raise ValueError("Timeout must be positive")
        return v

    def to_json(self) -> str:
        """Serialize message to JSON."""
        return self.model_dump_json()

    def to_dict(self) -> Dict[str, Any]:
        """Convert message to dictionary."""
        return self.model_dump()

    @classmethod
    def from_json(cls, json_str: str) -> "A2AMessage":
        """Deserialize message from JSON."""
        return cls(**json.loads(json_str))

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "A2AMessage":
        """Create message from dictionary."""
        return cls(**data)


class A2AProtocol:
    """
    Agent-to-Agent Protocol Handler.
    Manages message creation, validation, and serialization.
    """

    def __init__(self):
        """Initialize A2A protocol handler."""
        self.logger = logging.getLogger(f"RAVERSE.A2AProtocol")

    def create_request(
        self,
        sender: str,
        receiver: str,
        action: MessageAction,
        payload: Dict[str, Any],
        priority: MessagePriority = MessagePriority.NORMAL,
        timeout_seconds: int = 300,
    ) -> A2AMessage:
        """
        Create a request message.

        Args:
            sender: Sending agent name
            receiver: Receiving agent name
            action: Action to perform
            payload: Message payload
            priority: Message priority
            timeout_seconds: Request timeout

        Returns:
            A2AMessage request
        """
        return A2AMessage(
            sender=sender,
            receiver=receiver,
            message_type=MessageType.REQUEST,
            action=action,
            payload=payload,
            priority=priority,
            timeout_seconds=timeout_seconds,
            status=MessageStatus.PENDING,
        )

    def create_response(
        self,
        sender: str,
        receiver: str,
        payload: Dict[str, Any],
        correlation_id: str,
        status: MessageStatus = MessageStatus.COMPLETED,
    ) -> A2AMessage:
        """
        Create a response message.

        Args:
            sender: Sending agent name
            receiver: Receiving agent name
            payload: Response payload
            correlation_id: Correlation ID from request
            status: Response status

        Returns:
            A2AMessage response
        """
        return A2AMessage(
            sender=sender,
            receiver=receiver,
            message_type=MessageType.RESPONSE,
            action=MessageAction.QUERY,
            payload=payload,
            correlation_id=correlation_id,
            status=status,
        )

    def create_notification(
        self,
        sender: str,
        action: MessageAction,
        payload: Dict[str, Any],
        priority: MessagePriority = MessagePriority.NORMAL,
    ) -> A2AMessage:
        """
        Create a broadcast notification.

        Args:
            sender: Sending agent name
            action: Action/event type
            payload: Notification payload
            priority: Message priority

        Returns:
            A2AMessage notification
        """
        return A2AMessage(
            sender=sender,
            receiver="broadcast",
            message_type=MessageType.NOTIFICATION,
            action=action,
            payload=payload,
            priority=priority,
            status=MessageStatus.COMPLETED,
        )

    def create_error(
        self,
        sender: str,
        receiver: str,
        error_message: str,
        error_code: str,
        correlation_id: Optional[str] = None,
    ) -> A2AMessage:
        """
        Create an error message.

        Args:
            sender: Sending agent name
            receiver: Receiving agent name
            error_message: Error description
            error_code: Error code
            correlation_id: Correlation ID from original message

        Returns:
            A2AMessage error
        """
        return A2AMessage(
            sender=sender,
            receiver=receiver,
            message_type=MessageType.ERROR,
            action=MessageAction.QUERY,
            payload={
                "error_message": error_message,
                "error_code": error_code,
            },
            correlation_id=correlation_id,
            status=MessageStatus.FAILED,
        )

    def validate_message(self, message: A2AMessage) -> bool:
        """
        Validate message structure and content.

        Args:
            message: Message to validate

        Returns:
            True if valid, raises exception otherwise
        """
        try:
            # Validate required fields
            assert message.sender, "Sender required"
            assert message.receiver, "Receiver required"
            assert message.message_type, "Message type required"
            assert message.action, "Action required"

            # Validate message type
            assert message.message_type in MessageType, "Invalid message type"

            # Validate action
            assert message.action in MessageAction, "Invalid action"

            # Validate priority
            assert message.priority in MessagePriority, "Invalid priority"

            # Validate status
            assert message.status in MessageStatus, "Invalid status"

            self.logger.debug(f"Message {message.message_id} validated successfully")
            return True

        except AssertionError as e:
            self.logger.error(f"Message validation failed: {e}")
            raise

    def serialize_message(self, message: A2AMessage) -> str:
        """
        Serialize message to JSON string.

        Args:
            message: Message to serialize

        Returns:
            JSON string
        """
        return message.to_json()

    def deserialize_message(self, json_str: str) -> A2AMessage:
        """
        Deserialize message from JSON string.

        Args:
            json_str: JSON string

        Returns:
            A2AMessage object
        """
        return A2AMessage.from_json(json_str)


# Convenience functions
def create_a2a_request(
    sender: str,
    receiver: str,
    action: str,
    payload: Dict[str, Any],
) -> A2AMessage:
    """Create A2A request message."""
    protocol = A2AProtocol()
    return protocol.create_request(
        sender=sender,
        receiver=receiver,
        action=MessageAction(action),
        payload=payload,
    )


def create_a2a_response(
    sender: str,
    receiver: str,
    payload: Dict[str, Any],
    correlation_id: str,
) -> A2AMessage:
    """Create A2A response message."""
    protocol = A2AProtocol()
    return protocol.create_response(
        sender=sender,
        receiver=receiver,
        payload=payload,
        correlation_id=correlation_id,
    )

