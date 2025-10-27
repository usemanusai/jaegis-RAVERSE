"""
Message Broker for A2A Protocol.
Manages Redis pub/sub channels for inter-agent communication.
"""

import logging
import asyncio
from typing import Callable, Dict, List, Optional, Any
from redis import Redis
from redis.asyncio import Redis as AsyncRedis
from utils.a2a_protocol import A2AMessage, MessageType

logger = logging.getLogger(__name__)


class MessageBroker:
    """
    Redis-based message broker for A2A communication.
    Handles pub/sub messaging between agents.
    """

    # Redis channel prefixes
    AGENT_CHANNEL_PREFIX = "raverse:a2a:messages"
    BROADCAST_CHANNEL = "raverse:a2a:broadcast"
    ERROR_CHANNEL = "raverse:a2a:errors"
    METRICS_CHANNEL = "raverse:a2a:metrics"
    STATE_CHANNEL_PREFIX = "raverse:a2a:state"

    def __init__(self, redis_client: Optional[Redis] = None):
        """
        Initialize message broker.

        Args:
            redis_client: Redis client instance (creates new if None)
        """
        self.redis = redis_client or Redis(
            host="localhost",
            port=6379,
            db=0,
            decode_responses=True,
        )
        self.logger = logging.getLogger(f"RAVERSE.MessageBroker")
        self.subscriptions: Dict[str, Callable] = {}

    def get_agent_channel(self, agent_id: str) -> str:
        """Get Redis channel name for agent."""
        return f"{self.AGENT_CHANNEL_PREFIX}:{agent_id}"

    def get_state_channel(self, agent_id: str) -> str:
        """Get Redis channel name for agent state."""
        return f"{self.STATE_CHANNEL_PREFIX}:{agent_id}"

    def publish_message(self, message: A2AMessage) -> int:
        """
        Publish message to appropriate channel.

        Args:
            message: A2AMessage to publish

        Returns:
            Number of subscribers that received the message
        """
        try:
            if message.message_type == MessageType.NOTIFICATION:
                # Broadcast to all agents
                channel = self.BROADCAST_CHANNEL
            elif message.message_type == MessageType.ERROR:
                # Send to error channel
                channel = self.ERROR_CHANNEL
            else:
                # Send to specific agent
                channel = self.get_agent_channel(message.receiver)

            # Publish message
            count = self.redis.publish(channel, message.to_json())
            self.logger.debug(f"Published message {message.message_id} to {channel} ({count} subscribers)")
            return count

        except Exception as e:
            self.logger.error(f"Failed to publish message: {e}")
            raise

    def subscribe_to_agent_channel(
        self,
        agent_id: str,
        callback: Callable[[A2AMessage], None],
    ) -> None:
        """
        Subscribe to agent's message channel.

        Args:
            agent_id: Agent ID to subscribe to
            callback: Callback function for received messages
        """
        channel = self.get_agent_channel(agent_id)
        self.subscriptions[channel] = callback
        self.logger.info(f"Subscribed to channel: {channel}")

    def subscribe_to_broadcast(
        self,
        callback: Callable[[A2AMessage], None],
    ) -> None:
        """
        Subscribe to broadcast channel.

        Args:
            callback: Callback function for received messages
        """
        self.subscriptions[self.BROADCAST_CHANNEL] = callback
        self.logger.info(f"Subscribed to broadcast channel")

    def unsubscribe(self, channel: str) -> None:
        """
        Unsubscribe from channel.

        Args:
            channel: Channel to unsubscribe from
        """
        if channel in self.subscriptions:
            del self.subscriptions[channel]
            self.logger.info(f"Unsubscribed from channel: {channel}")

    def publish_state_update(self, agent_id: str, state: Dict[str, Any]) -> int:
        """
        Publish agent state update.

        Args:
            agent_id: Agent ID
            state: State dictionary

        Returns:
            Number of subscribers
        """
        channel = self.get_state_channel(agent_id)
        import json
        count = self.redis.publish(channel, json.dumps(state))
        self.logger.debug(f"Published state update for {agent_id}")
        return count

    def publish_metric(self, metric_name: str, value: float, tags: Optional[Dict] = None) -> int:
        """
        Publish performance metric.

        Args:
            metric_name: Metric name
            value: Metric value
            tags: Optional tags

        Returns:
            Number of subscribers
        """
        import json
        metric_data = {
            "metric": metric_name,
            "value": value,
            "tags": tags or {},
        }
        count = self.redis.publish(self.METRICS_CHANNEL, json.dumps(metric_data))
        return count

    def get_pending_messages(self, agent_id: str) -> List[A2AMessage]:
        """
        Get pending messages for agent (from Redis list).

        Args:
            agent_id: Agent ID

        Returns:
            List of pending messages
        """
        queue_key = f"raverse:a2a:queue:{agent_id}"
        messages = []

        try:
            # Get all messages from queue
            while True:
                msg_json = self.redis.lpop(queue_key)
                if not msg_json:
                    break
                messages.append(A2AMessage.from_json(msg_json))

            self.logger.debug(f"Retrieved {len(messages)} pending messages for {agent_id}")
            return messages

        except Exception as e:
            self.logger.error(f"Failed to get pending messages: {e}")
            return []

    def queue_message(self, agent_id: str, message: A2AMessage) -> None:
        """
        Queue message for agent (persistent storage).

        Args:
            agent_id: Agent ID
            message: Message to queue
        """
        queue_key = f"raverse:a2a:queue:{agent_id}"

        try:
            # Push to queue
            self.redis.rpush(queue_key, message.to_json())
            # Set expiration (24 hours)
            self.redis.expire(queue_key, 86400)
            self.logger.debug(f"Queued message {message.message_id} for {agent_id}")

        except Exception as e:
            self.logger.error(f"Failed to queue message: {e}")
            raise

    def clear_agent_queue(self, agent_id: str) -> int:
        """
        Clear message queue for agent.

        Args:
            agent_id: Agent ID

        Returns:
            Number of messages cleared
        """
        queue_key = f"raverse:a2a:queue:{agent_id}"
        count = self.redis.delete(queue_key)
        self.logger.info(f"Cleared {count} messages from queue for {agent_id}")
        return count

    def health_check(self) -> bool:
        """
        Check broker health.

        Returns:
            True if broker is healthy
        """
        try:
            self.redis.ping()
            return True
        except Exception as e:
            self.logger.error(f"Broker health check failed: {e}")
            return False

    def close(self) -> None:
        """Close broker connection."""
        try:
            self.redis.close()
            self.logger.info("Message broker closed")
        except Exception as e:
            self.logger.error(f"Error closing broker: {e}")


class AsyncMessageBroker:
    """
    Async version of message broker for async agents.
    """

    def __init__(self, redis_client: Optional[AsyncRedis] = None):
        """
        Initialize async message broker.

        Args:
            redis_client: Async Redis client instance
        """
        self.redis = redis_client
        self.logger = logging.getLogger(f"RAVERSE.AsyncMessageBroker")
        self.pubsub = None

    async def connect(self) -> None:
        """Connect to Redis."""
        if not self.redis:
            self.redis = await AsyncRedis(
                host="localhost",
                port=6379,
                db=0,
                decode_responses=True,
            )
        self.pubsub = self.redis.pubsub()
        self.logger.info("Async message broker connected")

    async def publish_message(self, message: A2AMessage) -> int:
        """Publish message asynchronously."""
        channel = f"raverse:a2a:messages:{message.receiver}"
        count = await self.redis.publish(channel, message.to_json())
        return count

    async def close(self) -> None:
        """Close async broker connection."""
        if self.pubsub:
            await self.pubsub.close()
        if self.redis:
            await self.redis.close()
        self.logger.info("Async message broker closed")

