## Expected AI Response Formats

This project uses free-tier LLMs via OpenRouter. To improve reliability, prompts request structured JSON. Agents should expect and parse the following shapes.

### Disassembly/Analysis (DAA)
- Prompt requests JSON like:
````json
{
  "compare_addr": "0x401234",
  "jump_addr": "0x401240",
  "opcode": "74",
  "analysis": "brief explanation"
}
````
- Only `compare_addr`, `jump_addr`, and `opcode` are consumed downstream.

### Logic Identification (LIMA)
- Prompt requests EXACT JSON:
````json
{
  "compare_addr": "0x401234",
  "jump_addr": "0x401240",
  "opcode": "74"
}
````
- LIMA first attempts strict JSON parsing, then falls back to regex extraction.
- Validation rules:
  - `compare_addr` and `jump_addr`: hex string with `0x` prefix
  - `opcode`: exactly two hex digits (byte)
  - Invalid/missing values fall back to defaults: `0x0000`, `00`

### Notes
- Agents log token usage (if provided by the API) and key parsing warnings.
- If the model emits extra prose, JSON is extracted from the first `{...}` block.

