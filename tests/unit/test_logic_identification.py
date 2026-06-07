import pytest
from unittest.mock import MagicMock, patch
from src.agents.logic_identification import LogicIdentificationMappingAgent

class TestLogicIdentificationMappingAgent:

    def test_init_with_none(self):
        agent = LogicIdentificationMappingAgent(None)
        assert hasattr(agent.openrouter_agent, "call_openrouter")
        # Test stub functionality
        response = agent.openrouter_agent.call_openrouter("test prompt")
        assert "choices" in response
        assert response["choices"][0]["message"]["content"] == ""

    def test_init_without_call_openrouter(self):
        class DummyAgent:
            pass

        dummy = DummyAgent()
        agent = LogicIdentificationMappingAgent(dummy)
        assert hasattr(agent.openrouter_agent, "call_openrouter")
        response = agent.openrouter_agent.call_openrouter("test prompt")
        assert "choices" in response

    def test_init_with_valid_agent(self):
        mock_agent = MagicMock()
        mock_agent.call_openrouter.return_value = {"valid": "response"}
        agent = LogicIdentificationMappingAgent(mock_agent)

        assert agent.openrouter_agent is mock_agent
        assert agent.openrouter_agent.call_openrouter("prompt") == {"valid": "response"}

    @pytest.mark.parametrize("addr, expected", [
        ("0x401234", True),
        ("0x1", True),
        ("0xabcdef", True),
        ("0xABCDEF", True),
        ("401234", False),  # Missing 0x
        ("0xGHI", False),   # Invalid hex chars
        ("", False),
        (None, False)
    ])
    def test_validate_hex_addr(self, addr, expected):
        agent = LogicIdentificationMappingAgent(None)
        assert agent._validate_hex_addr(addr) is expected

    @pytest.mark.parametrize("opcode, expected", [
        ("74", True),
        ("0F", True),
        ("a1", True),
        ("745", False),     # Too long
        ("7", False),       # Too short
        ("0x74", False),    # Starts with 0x
        ("ZZ", False),      # Invalid hex
        ("", False),
        (None, False)
    ])
    def test_validate_opcode_byte(self, opcode, expected):
        agent = LogicIdentificationMappingAgent(None)
        assert agent._validate_opcode_byte(opcode) is expected

    def test_parse_response_valid(self):
        agent = LogicIdentificationMappingAgent(None)
        content = "compare_addr: 0x401234\njump_addr: 0x401240\nopcode: 74"
        compare_addr, jump_addr, opcode = agent.parse_response(content)

        assert compare_addr == "0x401234"
        assert jump_addr == "0x401240"
        assert opcode == "74"

    def test_parse_response_invalid_formats_fallback(self):
        agent = LogicIdentificationMappingAgent(None)
        # If regex doesn't match, it uses "0x0000", which is valid, skipping warning.
        # We need regex to match an INVALID string, but regex already filters out non-hex.
        # Let's mock re.search to return something that fails validation.
        with patch('src.agents.logic_identification.re.search') as mock_search:
            # We'll make it return a match object whose group(1) returns bad formats
            mock_match = MagicMock()
            mock_match.group.side_effect = ["0x", "0x123Z", "745"]
            mock_search.return_value = mock_match

            with patch('src.agents.logic_identification.logger') as mock_logger:
                compare_addr, jump_addr, opcode = agent.parse_response("dummy")

                assert mock_logger.warning.call_count == 3
                assert compare_addr == "0x0000"
                assert jump_addr == "0x0000"
                assert opcode == "00"

    def test_parse_response_missing_fields(self):
        agent = LogicIdentificationMappingAgent(None)
        content = "Just some random text without addresses"

        with patch('src.agents.logic_identification.logger') as mock_logger:
            compare_addr, jump_addr, opcode = agent.parse_response(content)

            assert compare_addr == "0x0000"
            assert jump_addr == "0x0000"
            assert opcode == "00"

    def test_identify_logic_valid_json(self):
        mock_agent = MagicMock()
        valid_json_response = {
            "choices": [{
                "message": {
                    "content": "Some text\n{\n\"compare_addr\": \"0x1000\",\n\"jump_addr\": \"0x1008\",\n\"opcode\": \"75\"\n}\nMore text"
                }
            }]
        }
        mock_agent.call_openrouter.return_value = valid_json_response
        agent = LogicIdentificationMappingAgent(mock_agent)

        result = agent.identify_logic("disassembly")

        assert result == {
            "compare_addr": "0x1000",
            "jump_addr": "0x1008",
            "opcode": "75"
        }

    def test_identify_logic_invalid_json_fallback(self):
        mock_agent = MagicMock()
        # Missing closing brace, invalid JSON
        invalid_json_response = {
            "choices": [{
                "message": {
                    "content": "{\n\"compare_addr\": \"0x1000\",\ncompare_addr: 0x2000\njump_addr: 0x2008\nopcode: 74\n}"
                }
            }]
        }
        mock_agent.call_openrouter.return_value = invalid_json_response
        agent = LogicIdentificationMappingAgent(mock_agent)

        with patch('src.agents.logic_identification.logger') as mock_logger:
            result = agent.identify_logic("disassembly")

            # Should have warned about JSON failure
            mock_logger.warning.assert_any_call("Failed to parse JSON response, falling back to regex")

            assert result == {
                "compare_addr": "0x2000",
                "jump_addr": "0x2008",
                "opcode": "74"
            }

    def test_identify_logic_exception(self):
        mock_agent = MagicMock()
        mock_agent.call_openrouter.side_effect = Exception("API Error")
        agent = LogicIdentificationMappingAgent(mock_agent)

        with patch('src.agents.logic_identification.logger') as mock_logger:
            result = agent.identify_logic("disassembly")

            assert result is None
            mock_logger.error.assert_called_once()
            assert "Error during logic identification: API Error" in mock_logger.error.call_args[0][0]
