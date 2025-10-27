"""
A2A Communication Mixin for RAVERSE Agents.
Adds inter-agent communication capabilities to agents.
"""

import logging
import asyncio
from typing import Dict, Any, Optional, Callable, List
from utils.a2a_protocol import (
    A2AMessage,
    A2AProtocol,
    MessageType,
    MessageAction,
    MessagePriority,
    MessageStatus,
)
from utils.message_broker import MessageBroker

logger = logging.getLogger(__name__)


class A2AMixin:
    """
    Mixin class to add A2A communication to agents.
    Provides send/receive message capabilities.
    """

    def __init__(self, agent_id: str, message_broker: Optional[MessageBroker] = None):
        """
        Initialize A2A mixin.

        Args:
            agent_id: Unique agent identifier
            message_broker: Message broker instance
        """
        self.agent_id = agent_id
        self.message_broker = message_broker or MessageBroker()
        self.a2a_protocol = A2AProtocol()
        self.logger = logging.getLogger(f"RAVERSE.{agent_id}.A2A")
        self.message_handlers: Dict[str, Callable] = {}
        self.pending_responses: Dict[str, A2AMessage] = {}

    def send_message(
        self,
        receiver: str,
        action: MessageAction,
        payload: Dict[str, Any],
        priority: MessagePriority = MessagePriority.NORMAL,
        timeout_seconds: int = 300,
    ) -> A2AMessage:
        """
        Send message to another agent.

        Args:
            receiver: Receiving agent ID
            action: Action to perform
            payload: Message payload
            priority: Message priority
            timeout_seconds: Request timeout

        Returns:
            A2AMessage sent
        """
        try:
            # Create message
            message = self.a2a_protocol.create_request(
                sender=self.agent_id,
                receiver=receiver,
                action=action,
                payload=payload,
                priority=priority,
                timeout_seconds=timeout_seconds,
            )

            # Publish message
            self.message_broker.publish_message(message)
            self.logger.info(
                f"Sent message {message.message_id} to {receiver} "
                f"(action: {action.value})"
            )

            return message

        except Exception as e:
            self.logger.error(f"Failed to send message: {e}")
            raise

    def send_response(
        self,
        receiver: str,
        payload: Dict[str, Any],
        correlation_id: str,
        status: MessageStatus = MessageStatus.COMPLETED,
    ) -> A2AMessage:
        """
        Send response message to another agent.

        Args:
            receiver: Receiving agent ID
            payload: Response payload
            correlation_id: Correlation ID from request
            status: Response status

        Returns:
            A2AMessage response
        """
        try:
            message = self.a2a_protocol.create_response(
                sender=self.agent_id,
                receiver=receiver,
                payload=payload,
                correlation_id=correlation_id,
                status=status,
            )

            self.message_broker.publish_message(message)
            self.logger.info(
                f"Sent response {message.message_id} to {receiver} "
                f"(correlation: {correlation_id})"
            )

            return message

        except Exception as e:
            self.logger.error(f"Failed to send response: {e}")
            raise

    def broadcast_notification(
        self,
        action: MessageAction,
        payload: Dict[str, Any],
        priority: MessagePriority = MessagePriority.NORMAL,
    ) -> A2AMessage:
        """
        Broadcast notification to all agents.

        Args:
            action: Action/event type
            payload: Notification payload
            priority: Message priority

        Returns:
            A2AMessage notification
        """
        try:
            message = self.a2a_protocol.create_notification(
                sender=self.agent_id,
                action=action,
                payload=payload,
                priority=priority,
            )

            self.message_broker.publish_message(message)
            self.logger.info(
                f"Broadcast notification {message.message_id} "
                f"(action: {action.value})"
            )

            return message

        except Exception as e:
            self.logger.error(f"Failed to broadcast notification: {e}")
            raise

    def send_error(
        self,
        receiver: str,
        error_message: str,
        error_code: str,
        correlation_id: Optional[str] = None,
    ) -> A2AMessage:
        """
        Send error message to another agent.

        Args:
            receiver: Receiving agent ID
            error_message: Error description
            error_code: Error code
            correlation_id: Correlation ID from original message

        Returns:
            A2AMessage error
        """
        try:
            message = self.a2a_protocol.create_error(
                sender=self.agent_id,
                receiver=receiver,
                error_message=error_message,
                error_code=error_code,
                correlation_id=correlation_id,
            )

            self.message_broker.publish_message(message)
            self.logger.warning(
                f"Sent error {message.message_id} to {receiver} "
                f"(code: {error_code})"
            )

            return message

        except Exception as e:
            self.logger.error(f"Failed to send error: {e}")
            raise

    def register_message_handler(
        self,
        action: MessageAction,
        handler: Callable[[A2AMessage], None],
    ) -> None:
        """
        Register handler for specific message action.

        Args:
            action: Message action to handle
            handler: Handler function
        """
        self.message_handlers[action.value] = handler
        self.logger.debug(f"Registered handler for action: {action.value}")

    def handle_message(self, message: A2AMessage) -> None:
        """
        Handle received message.

        Args:
            message: Received A2AMessage
        """
        try:
            # Validate message
            self.a2a_protocol.validate_message(message)

            # Route to appropriate handler
            if message.message_type == MessageType.REQUEST:
                handler = self.message_handlers.get(message.action.value)
                if handler:
                    handler(message)
                else:
                    self.logger.warning(
                        f"No handler for action: {message.action.value}"
                    )

            elif message.message_type == MessageType.RESPONSE:
                # Store response for correlation
                self.pending_responses[message.correlation_id] = message
                self.logger.debug(
                    f"Received response {message.message_id} "
                    f"(correlation: {message.correlation_id})"
                )

            elif message.message_type == MessageType.NOTIFICATION:
                handler = self.message_handlers.get(message.action.value)
                if handler:
                    handler(message)

            elif message.message_type == MessageType.ERROR:
                self.logger.error(
                    f"Received error from {message.sender}: "
                    f"{message.payload.get('error_message')}"
                )

        except Exception as e:
            self.logger.error(f"Failed to handle message: {e}")

    def get_response(
        self,
        correlation_id: str,
        timeout_seconds: int = 30,
    ) -> Optional[A2AMessage]:
        """
        Wait for response with correlation ID.

        Args:
            correlation_id: Correlation ID to wait for
            timeout_seconds: Timeout in seconds

        Returns:
            Response message or None if timeout
        """
        start_time = asyncio.get_event_loop().time()

        while True:
            if correlation_id in self.pending_responses:
                return self.pending_responses.pop(correlation_id)

            elapsed = asyncio.get_event_loop().time() - start_time
            if elapsed > timeout_seconds:
                self.logger.warning(
                    f"Timeout waiting for response {correlation_id}"
                )
                return None

            asyncio.sleep(0.1)

    def publish_state_update(self, state: Dict[str, Any]) -> None:
        """
        Publish agent state update.

        Args:
            state: State dictionary
        """
        try:
            self.message_broker.publish_state_update(self.agent_id, state)
            self.logger.debug("Published state update")
        except Exception as e:
            self.logger.error(f"Failed to publish state update: {e}")

    def publish_metric(
        self,
        metric_name: str,
        value: float,
        tags: Optional[Dict] = None,
    ) -> None:
        """
        Publish performance metric.

        Args:
            metric_name: Metric name
            value: Metric value
            tags: Optional tags
        """
        try:
            self.message_broker.publish_metric(metric_name, value, tags)
        except Exception as e:
            self.logger.error(f"Failed to publish metric: {e}")

