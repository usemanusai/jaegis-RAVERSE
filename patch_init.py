import re

with open("tests/unit/test_a2a_mixin.py", "r") as f:
    content = f.read()

content = content.replace(
    'super().__init__(agent_id=agent_id, message_broker=message_broker)',
    'super().__init__(agent_id=agent_id, message_broker=message_broker)'
)

with open("tests/unit/test_a2a_mixin.py", "w") as f:
    f.write(content)
