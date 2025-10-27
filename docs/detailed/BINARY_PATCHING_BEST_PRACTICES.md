# Binary Patching Best Practices

## Overview

This document provides best practices for safely modifying executable binary files, with a focus on PE (Portable Executable) and ELF (Executable and Linkable Format) formats. These guidelines are derived from authoritative sources including Microsoft's PE/COFF specification and industry reverse engineering practices.

---

## 1. Virtual Address to File Offset Conversion

### PE Format (Windows Executables)

**Formula:**
```
FileOffset = VirtualAddress - SectionVirtualAddress + SectionPointerToRawData
```

**Process:**
1. Locate the section containing the target Virtual Address (VA)
2. Find the section's `VirtualAddress` field (RVA where section loads in memory)
3. Find the section's `PointerToRawData` field (file offset of section data)
4. Apply the formula above

**Example:**
```
Target VA: 0x00401234
Section .text:
  VirtualAddress: 0x00001000
  PointerToRawData: 0x00000400

FileOffset = 0x00401234 - 0x00401000 + 0x00000400 = 0x00000634
```

**Important Notes:**
- RVA (Relative Virtual Address) = VA - ImageBase
- ImageBase is typically 0x00400000 for Windows executables
- Section alignment in memory differs from file alignment
- Always validate that VA falls within section boundaries

### ELF Format (Linux Executables)

**Formula:**
```
FileOffset = VirtualAddress - SegmentVirtualAddress + SegmentFileOffset
```

**Process:**
1. Parse ELF program headers to find the segment containing the target VA
2. Use the segment's `p_vaddr` (virtual address) and `p_offset` (file offset)
3. Apply the formula above

**Example:**
```
Target VA: 0x08048400
Segment LOAD:
  p_vaddr: 0x08048000
  p_offset: 0x00000000

FileOffset = 0x08048400 - 0x08048000 + 0x00000000 = 0x00000400
```

---

## 2. Conditional Jump Opcodes Reference

### Common x86 Conditional Jumps

| Mnemonic | Opcode (Short) | Opcode (Near) | Condition | Description |
|----------|----------------|---------------|-----------|-------------|
| **JE/JZ** | `0x74` | `0x0F 0x84` | ZF=1 | Jump if Equal / Jump if Zero |
| **JNE/JNZ** | `0x75` | `0x0F 0x85` | ZF=0 | Jump if Not Equal / Jump if Not Zero |
| **JA/JNBE** | `0x77` | `0x0F 0x87` | CF=0 AND ZF=0 | Jump if Above (unsigned) |
| **JAE/JNB** | `0x73` | `0x0F 0x83` | CF=0 | Jump if Above or Equal (unsigned) |
| **JB/JNAE** | `0x72` | `0x0F 0x82` | CF=1 | Jump if Below (unsigned) |
| **JBE/JNA** | `0x76` | `0x0F 0x86` | CF=1 OR ZF=1 | Jump if Below or Equal (unsigned) |
| **JG/JNLE** | `0x7F` | `0x0F 0x8F` | ZF=0 AND SF=OF | Jump if Greater (signed) |
| **JGE/JNL** | `0x7D` | `0x0F 0x8D` | SF=OF | Jump if Greater or Equal (signed) |
| **JL/JNGE** | `0x7C` | `0x0F 0x8C` | SF≠OF | Jump if Less (signed) |
| **JLE/JNG** | `0x7E` | `0x0F 0x8E` | ZF=1 OR SF≠OF | Jump if Less or Equal (signed) |

### Short vs Near Jumps

**Short Jump (2 bytes):**
- Format: `[Opcode] [Signed 8-bit offset]`
- Range: -128 to +127 bytes from end of instruction
- Example: `74 05` = JE +5 bytes

**Near Jump (5-6 bytes):**
- Format: `[0x0F] [Opcode] [Signed 32-bit offset]`
- Range: ±2GB from end of instruction
- Example: `0F 84 00 01 00 00` = JE +256 bytes

**Patching Considerations:**
- Replacing short jump with near jump changes instruction size
- May require NOP padding or code relocation
- RAVERSE focuses on opcode-only patching (same instruction size)

---

## 3. Common Patching Techniques

### Technique 1: Conditional Jump Inversion
**Purpose:** Bypass authentication checks

**Example:**
```assembly
; Original code
CMP password_input, correct_password
JE  access_granted        ; 0x74 XX - Jump if passwords match
JMP access_denied

; Patched code
CMP password_input, correct_password
JNE access_granted        ; 0x75 XX - Jump if passwords DON'T match
JMP access_denied
```

**Opcode Change:** `0x74` → `0x75` (JE → JNE)

### Technique 2: Unconditional Jump Replacement
**Purpose:** Force execution path

**Example:**
```assembly
; Original
JE  target_address        ; 0x74 XX

; Patched
JMP target_address        ; 0xEB XX (short) or 0xE9 XX XX XX XX (near)
```

### Technique 3: NOP Sled
**Purpose:** Disable functionality

**Example:**
```assembly
; Original
CALL check_license        ; E8 XX XX XX XX

; Patched
NOP                       ; 90 90 90 90 90
```

---

## 4. Safety Checklist

### Pre-Patching Validation
- [ ] **Create backup** of original binary
- [ ] **Verify file format** (PE/ELF) using header magic bytes
- [ ] **Check file permissions** (read/write access)
- [ ] **Validate target address** exists within executable sections
- [ ] **Confirm instruction boundaries** (don't patch mid-instruction)
- [ ] **Document original opcodes** for rollback capability

### Address Validation
- [ ] **Hex format check:** Address matches `0x[0-9a-fA-F]+` pattern
- [ ] **Range check:** Address falls within valid section bounds
- [ ] **Alignment check:** Address aligns with instruction boundaries
- [ ] **Section permissions:** Target section is executable (PE: IMAGE_SCN_MEM_EXECUTE)

### Opcode Validation
- [ ] **Format check:** Opcode is valid 2-digit hex (e.g., `74`, `75`)
- [ ] **Instruction size:** Replacement opcode has same byte length
- [ ] **Semantic validity:** Opcode is a valid x86 instruction
- [ ] **Context appropriateness:** Opcode makes sense in context (e.g., conditional jump)

### Post-Patching Verification
- [ ] **File integrity:** Patched file size unchanged
- [ ] **Checksum update:** Recalculate PE CheckSum if required
- [ ] **Execution test:** Run patched binary with test inputs
- [ ] **Behavior validation:** Verify intended bypass works
- [ ] **Side effects check:** Ensure no unintended crashes or errors

---

## 5. Common Pitfalls and Mitigations

### Pitfall 1: Incorrect VA-to-Offset Conversion
**Problem:** Patching wrong file location due to calculation error

**Mitigation:**
- Use disassembler (e.g., IDA Pro, Ghidra) to verify file offsets
- Cross-reference with multiple tools
- Implement validation in patching code

### Pitfall 2: Patching Mid-Instruction
**Problem:** Corrupting multi-byte instructions

**Mitigation:**
- Always disassemble target region first
- Identify instruction boundaries
- Only patch at instruction start addresses

### Pitfall 3: Ignoring Code Signing
**Problem:** Modified binary fails signature verification

**Mitigation:**
- Remove or invalidate Authenticode signatures
- Document that patching breaks code signing
- Consider re-signing with test certificate

### Pitfall 4: Hardcoded Offsets
**Problem:** Patches fail on different binary versions

**Mitigation:**
- Use pattern matching to find target code
- Implement version detection
- Provide multiple patch sets for different versions

### Pitfall 5: Insufficient Testing
**Problem:** Patch works in one scenario but fails in others

**Mitigation:**
- Test with multiple input combinations
- Verify edge cases (empty input, max length, special characters)
- Use debugger to trace execution flow

---

## 6. Tools and Resources

### Recommended Tools
- **Disassemblers:** IDA Pro, Ghidra, Binary Ninja, radare2
- **Hex Editors:** HxD, 010 Editor, ImHex
- **Debuggers:** x64dbg, WinDbg, GDB
- **PE Analyzers:** CFF Explorer, PE-bear, pestudio

### Authoritative References
- [Microsoft PE/COFF Specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Intel x86 Instruction Set Reference](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
- [ELF Specification](https://refspecs.linuxfoundation.org/elf/elf.pdf)
- [x86 Instruction Listings (Wikipedia)](https://en.wikipedia.org/wiki/X86_instruction_listings)

---

## 7. Legal and Ethical Considerations

**WARNING:** Binary patching may violate:
- Software license agreements (EULA)
- Digital Millennium Copyright Act (DMCA) anti-circumvention provisions
- Computer Fraud and Abuse Act (CFAA)
- Local laws regarding reverse engineering

**Legitimate Use Cases:**
- Security research (responsible disclosure)
- Malware analysis (isolated environment)
- Legacy software maintenance (with proper authorization)
- Educational purposes (on self-created or authorized binaries)

**Best Practices:**
- Only patch binaries you own or have explicit permission to modify
- Use isolated test environments
- Document all modifications
- Follow responsible disclosure for security vulnerabilities

---

## Conclusion

Binary patching is a powerful technique that requires careful attention to file formats, instruction sets, and safety procedures. Always create backups, validate inputs, and test thoroughly. The RAVERSE system implements these best practices through automated validation and structured agent workflows.

For RAVERSE-specific implementation details, see:
- `agents/logic_identification.py` - Address and opcode validation
- `agents/patching_execution.py` - Safe file modification with backups
- `tests/` - Comprehensive test coverage for patching operations

