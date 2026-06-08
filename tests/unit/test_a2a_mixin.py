import pytest
import asyncio
from unittest.mock import MagicMock, patch
from typing import Dict, Any

from agents.a2a_mixin import A2AMixin
from utils.message_broker import MessageBroker
from utils.a2a_protocol import (
    A2AMessage,
    MessageAction,
    MessagePriority,
    MessageStatus,
    MessageType,
)

class DummyAgent(A2AMixin):
    """Dummy agent for testing A2AMixin."""
    def __init__(self, agent_id: str, message_broker: MessageBroker):
        super().__init__(agent_id=agent_id, message_broker=message_broker)

@pytest.fixture
def mock_message_broker():
    """Mock MessageBroker to avoid Redis connections."""
    broker = MagicMock(spec=MessageBroker)
    broker.publish_message.return_value = 1
    broker.publish_state_update.return_value = 1
    broker.publish_metric.return_value = 1
    return broker

@pytest.fixture
def dummy_agent(mock_message_broker):
    """Fixture providing a DummyAgent instance."""
    return DummyAgent(agent_id="test_agent", message_broker=mock_message_broker)


def test_initialization(dummy_agent, mock_message_broker):
    """Test A2AMixin initialization."""
    assert dummy_agent.agent_id == "test_agent"
    assert dummy_agent.message_broker == mock_message_broker
    assert dummy_agent.a2a_protocol is not None
    assert dummy_agent.message_handlers == {}
    assert dummy_agent.pending_responses == {}

def test_send_message(dummy_agent, mock_message_broker):
    """Test send_message functionality."""
    payload = {"task": "analyze_data"}
    message = dummy_agent.send_message(
        receiver="target_agent",
        action=MessageAction.ANALYZE,
        payload=payload,
        priority=MessagePriority.HIGH,
        timeout_seconds=60
    )

    assert isinstance(message, A2AMessage)
    assert message.sender == "test_agent"
    assert message.receiver == "target_agent"
    assert message.action == MessageAction.ANALYZE
    assert message.payload == payload
    assert message.priority == MessagePriority.HIGH
    assert message.timeout_seconds == 60

    mock_message_broker.publish_message.assert_called_once_with(message)

def test_send_message_error(dummy_agent, mock_message_broker):
    """Test send_message when broker raises exception."""
    mock_message_broker.publish_message.side_effect = Exception("Broker error")
    with pytest.raises(Exception, match="Broker error"):
        dummy_agent.send_message(
            receiver="target_agent",
            action=MessageAction.ANALYZE,
            payload={}
        )

def test_send_response(dummy_agent, mock_message_broker):
    """Test send_response functionality."""
    payload = {"result": "success"}
    correlation_id = "test-corr-id"
    message = dummy_agent.send_response(
        receiver="target_agent",
        payload=payload,
        correlation_id=correlation_id,
        status=MessageStatus.COMPLETED
    )

    assert isinstance(message, A2AMessage)
    assert message.sender == "test_agent"
    assert message.receiver == "target_agent"
    assert message.message_type == MessageType.RESPONSE
    assert message.payload == payload
    assert message.correlation_id == correlation_id
    assert message.status == MessageStatus.COMPLETED

    mock_message_broker.publish_message.assert_called_once_with(message)

def test_send_response_error(dummy_agent, mock_message_broker):
    """Test send_response when broker raises exception."""
    mock_message_broker.publish_message.side_effect = Exception("Broker error")
    with pytest.raises(Exception, match="Broker error"):
        dummy_agent.send_response(
            receiver="target_agent",
            payload={},
            correlation_id="test-corr-id"
        )

def test_broadcast_notification(dummy_agent, mock_message_broker):
    """Test broadcast_notification functionality."""
    payload = {"event": "startup"}
    message = dummy_agent.broadcast_notification(
        action=MessageAction.UPDATE,
        payload=payload,
        priority=MessagePriority.LOW
    )

    assert isinstance(message, A2AMessage)
    assert message.sender == "test_agent"
    assert message.receiver == "broadcast"
    assert message.message_type == MessageType.NOTIFICATION
    assert message.action == MessageAction.UPDATE
    assert message.payload == payload
    assert message.priority == MessagePriority.LOW

    mock_message_broker.publish_message.assert_called_once_with(message)

def test_broadcast_notification_error(dummy_agent, mock_message_broker):
    """Test broadcast_notification when broker raises exception."""
    mock_message_broker.publish_message.side_effect = Exception("Broker error")
    with pytest.raises(Exception, match="Broker error"):
        dummy_agent.broadcast_notification(
            action=MessageAction.UPDATE,
            payload={}
        )

def test_send_error(dummy_agent, mock_message_broker):
    """Test send_error functionality."""
    correlation_id = "error-corr-id"
    message = dummy_agent.send_error(
        receiver="target_agent",
        error_message="Something went wrong",
        error_code="ERR500",
        correlation_id=correlation_id
    )

    assert isinstance(message, A2AMessage)
    assert message.sender == "test_agent"
    assert message.receiver == "target_agent"
    assert message.message_type == MessageType.ERROR
    assert message.payload == {
        "error_message": "Something went wrong",
        "error_code": "ERR500"
    }
    assert message.correlation_id == correlation_id

    mock_message_broker.publish_message.assert_called_once_with(message)

def test_send_error_error(dummy_agent, mock_message_broker):
    """Test send_error when broker raises exception."""
    mock_message_broker.publish_message.side_effect = Exception("Broker error")
    with pytest.raises(Exception, match="Broker error"):
        dummy_agent.send_error(
            receiver="target_agent",
            error_message="Something went wrong",
            error_code="ERR500"
        )

def test_register_message_handler(dummy_agent):
    """Test registering a message handler."""
    def sample_handler(msg):
        pass

    dummy_agent.register_message_handler(MessageAction.ANALYZE, sample_handler)
    assert dummy_agent.message_handlers[MessageAction.ANALYZE.value] == sample_handler

def test_handle_message_request(dummy_agent):
    """Test handling a REQUEST message."""
    mock_handler = MagicMock()
    dummy_agent.register_message_handler(MessageAction.EXECUTE, mock_handler)

    msg = A2AMessage(
        sender="other_agent",
        receiver="test_agent",
        message_type=MessageType.REQUEST,
        action=MessageAction.EXECUTE,
        payload={"cmd": "run"}
    )
    dummy_agent.handle_message(msg)

    mock_handler.assert_called_once_with(msg)

def test_handle_message_request_no_handler(dummy_agent, caplog):
    """Test handling a REQUEST message with no registered handler."""
    msg = A2AMessage(
        sender="other_agent",
        receiver="test_agent",
        message_type=MessageType.REQUEST,
        action=MessageAction.EXECUTE,
        payload={"cmd": "run"}
    )
    # Shouldn't raise, just log warning
    dummy_agent.handle_message(msg)

    # Can verify log if needed, structlog testing makes it possible via log_output
    assert "No handler for action: execute" in caplog.text

def test_handle_message_response(dummy_agent):
    """Test handling a RESPONSE message."""
    correlation_id = "test-corr-id"
    msg = A2AMessage(
        sender="other_agent",
        receiver="test_agent",
        message_type=MessageType.RESPONSE,
        action=MessageAction.QUERY,  # Action is required by validator
        correlation_id=correlation_id,
        payload={"result": "ok"}
    )

    dummy_agent.handle_message(msg)
    assert correlation_id in dummy_agent.pending_responses
    assert dummy_agent.pending_responses[correlation_id] == msg

def test_handle_message_notification(dummy_agent):
    """Test handling a NOTIFICATION message."""
    mock_handler = MagicMock()
    dummy_agent.register_message_handler(MessageAction.UPDATE, mock_handler)

    msg = A2AMessage(
        sender="other_agent",
        receiver="broadcast",
        message_type=MessageType.NOTIFICATION,
        action=MessageAction.UPDATE,
        payload={"status": "running"}
    )

    dummy_agent.handle_message(msg)
    mock_handler.assert_called_once_with(msg)

def test_handle_message_error(dummy_agent, caplog):
    """Test handling an ERROR message."""
    msg = A2AMessage(
        sender="other_agent",
        receiver="test_agent",
        message_type=MessageType.ERROR,
        action=MessageAction.QUERY,
        payload={"error_message": "Failed task"}
    )

    dummy_agent.handle_message(msg)
    assert "Received error from other_agent: Failed task" in caplog.text

def test_handle_message_validation_failure(dummy_agent, caplog):
    """Test handling a message that fails validation."""
    # A manually constructed dict that we force-feed to avoid Pydantic failing on creation
    # or we can mock validation. Let's just mock validate_message to raise an error
    with patch.object(dummy_agent.a2a_protocol, 'validate_message', side_effect=AssertionError("Invalid")):
        msg = MagicMock(spec=A2AMessage)
        dummy_agent.handle_message(msg)
        assert "Failed to handle message: Invalid" in caplog.text

def test_publish_state_update(dummy_agent, mock_message_broker):
    """Test publish_state_update functionality."""
    state = {"status": "idle"}
    dummy_agent.publish_state_update(state)
    mock_message_broker.publish_state_update.assert_called_once_with("test_agent", state)

def test_publish_state_update_error(dummy_agent, mock_message_broker):
    """Test publish_state_update when broker raises an error."""
    mock_message_broker.publish_state_update.side_effect = Exception("Broker error")
    # Should log error, not raise
    dummy_agent.publish_state_update({"status": "idle"})
    # Since we catch the exception and log, we ensure no exception propagates

def test_publish_metric(dummy_agent, mock_message_broker):
    """Test publish_metric functionality."""
    dummy_agent.publish_metric("cpu_usage", 45.5, {"host": "server1"})
    mock_message_broker.publish_metric.assert_called_once_with("cpu_usage", 45.5, {"host": "server1"})

def test_publish_metric_error(dummy_agent, mock_message_broker):
    """Test publish_metric when broker raises an error."""
    mock_message_broker.publish_metric.side_effect = Exception("Broker error")
    # Should catch error and not propagate
    dummy_agent.publish_metric("cpu_usage", 45.5, {"host": "server1"})




@patch('asyncio.get_event_loop')
def test_get_response_immediate(mock_get_loop, dummy_agent):
    """Test get_response when response is already pending."""
    mock_loop = MagicMock()
    mock_loop.time.return_value = 0.0
    mock_get_loop.return_value = mock_loop

    correlation_id = "test-corr-id"
    msg = A2AMessage(
        sender="other_agent",
        receiver="test_agent",
        message_type=MessageType.RESPONSE,
        action=MessageAction.QUERY,
        correlation_id=correlation_id,
        payload={"result": "ok"}
    )
    dummy_agent.pending_responses[correlation_id] = msg

    response = dummy_agent.get_response(correlation_id)
    assert response == msg
    # Ensure it was removed
    assert correlation_id not in dummy_agent.pending_responses

@patch('asyncio.sleep', new_callable=MagicMock) # Mocked as MagicMock to bypass missing await in sync method
@patch('asyncio.get_event_loop')
def test_get_response_timeout(mock_get_loop, mock_sleep, dummy_agent, caplog):
    """Test get_response timeout."""
    mock_loop = MagicMock()
    import itertools
    mock_loop.time.side_effect = itertools.count(start=0.0, step=15.0)
    mock_get_loop.return_value = mock_loop

    response = dummy_agent.get_response("missing-corr-id", timeout_seconds=30)

    assert response is None
    assert "Timeout waiting for response missing-corr-id" in caplog.text


@patch('asyncio.sleep', new_callable=MagicMock) # Mocked as MagicMock to bypass missing await in sync method
@patch('asyncio.get_event_loop')
def test_get_response_delayed(mock_get_loop, mock_sleep, dummy_agent):
    """Test get_response when response arrives after some delay."""
    correlation_id = "test-corr-id"
    msg = A2AMessage(
        sender="other_agent",
        receiver="test_agent",
        message_type=MessageType.RESPONSE,
        action=MessageAction.QUERY,
        correlation_id=correlation_id,
        payload={"result": "ok"}
    )

    mock_loop = MagicMock()
    import itertools
    mock_loop.time.side_effect = itertools.count(start=0.0, step=1.0) # Simulate time passing
    mock_get_loop.return_value = mock_loop

    # We can inject the response during sleep using side_effect
    def inject_response(*args):
        dummy_agent.pending_responses[correlation_id] = msg
        return None

    mock_sleep.side_effect = inject_response

    response = dummy_agent.get_response(correlation_id, timeout_seconds=30)
    assert response == msg
    assert correlation_id not in dummy_agent.pending_responses
