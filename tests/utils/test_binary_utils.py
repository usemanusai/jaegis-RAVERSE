import os
import pytest
import tempfile
import hashlib
import struct
from src.utils.binary_utils import BinaryAnalyzer

@pytest.fixture
def temp_file():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"Hello World")
        path = f.name
    yield path
    if os.path.exists(path):
        os.remove(path)

def test_calculate_file_hash(temp_file):
    expected_hash = hashlib.sha256(b"Hello World").hexdigest()
    assert BinaryAnalyzer.calculate_file_hash(temp_file) == expected_hash

def test_get_file_size(temp_file):
    assert BinaryAnalyzer.get_file_size(temp_file) == 11

def test_read_bytes_at_offset(temp_file):
    assert BinaryAnalyzer.read_bytes_at_offset(temp_file, 0, 5) == b"Hello"
    assert BinaryAnalyzer.read_bytes_at_offset(temp_file, 6, 5) == b"World"

def test_write_bytes_at_offset(temp_file):
    assert BinaryAnalyzer.write_bytes_at_offset(temp_file, 6, b"Earth") is True
    assert BinaryAnalyzer.read_bytes_at_offset(temp_file, 0, 11) == b"Hello Earth"

def test_create_backup(temp_file):
    backup_path = BinaryAnalyzer.create_backup(temp_file)
    assert os.path.exists(backup_path)
    assert BinaryAnalyzer.read_bytes_at_offset(backup_path, 0, 11) == b"Hello World"
    os.remove(backup_path)

def test_detect_file_type_pe(tmp_path):
    pe_file = tmp_path / "test.exe"
    # MZ signature (0x4D 0x5A) + basic structure
    pe_data = bytearray(64)
    pe_data[0:2] = b'MZ'
    pe_data[0x3C:0x40] = struct.pack('<I', 0x40) # PE offset
    pe_file.write_bytes(pe_data)

    # We need a bit more data for the PE header
    pe_header = bytearray(32)
    pe_header[0:4] = b'PE\0\0' # PE Signature
    # Machine type 0x014c (i386)
    pe_header[4:6] = struct.pack('<H', 0x014c)

    with open(pe_file, "ab") as f:
        f.write(pe_header)

    file_type, arch = BinaryAnalyzer.detect_file_type(str(pe_file))
    assert file_type == 'PE'
    assert arch == 'i386'

def test_detect_file_type_elf(tmp_path):
    elf_file = tmp_path / "test.elf"
    # ELF signature + basic structure
    elf_data = bytearray(64)
    elf_data[0:4] = b'\x7fELF'
    # Machine type 0x3e (x86_64) at offset 0x12
    elf_data[0x12:0x14] = struct.pack('<H', 0x3e)
    elf_file.write_bytes(elf_data)

    file_type, arch = BinaryAnalyzer.detect_file_type(str(elf_file))
    assert file_type == 'ELF'
    assert arch == 'x86_64'

def test_detect_file_type_unknown(tmp_path):
    unknown_file = tmp_path / "test.bin"
    unknown_file.write_bytes(b"Just some random text file, not a binary")

    file_type, arch = BinaryAnalyzer.detect_file_type(str(unknown_file))
    assert file_type == 'UNKNOWN'
    assert arch == 'UNKNOWN'

def test_extract_metadata(tmp_path):
    test_file = tmp_path / "meta_test.bin"
    test_file.write_bytes(b"Dummy data for metadata test")

    metadata = BinaryAnalyzer.extract_metadata(str(test_file))

    assert metadata['file_name'] == "meta_test.bin"
    assert metadata['file_size'] == 28
    assert metadata['exists'] is True
    assert 'file_hash' in metadata
    assert 'architecture' in metadata

def test_va_to_file_offset_pe():
    # Simple RVA without sections
    assert BinaryAnalyzer.va_to_file_offset_pe(0x401000) == 0x1000

    # With section headers
    sections = [
        {'VirtualAddress': 0x1000, 'VirtualSize': 0x200, 'PointerToRawData': 0x400},
        {'VirtualAddress': 0x2000, 'VirtualSize': 0x400, 'PointerToRawData': 0x600}
    ]

    # Match in first section: RVA = 0x1100 -> Offset = 0x1100 - 0x1000 + 0x400 = 0x500
    assert BinaryAnalyzer.va_to_file_offset_pe(0x401100, 0x400000, sections) == 0x500

    # Match in second section: RVA = 0x2200 -> Offset = 0x2200 - 0x2000 + 0x600 = 0x800
    assert BinaryAnalyzer.va_to_file_offset_pe(0x402200, 0x400000, sections) == 0x800

    # No match
    assert BinaryAnalyzer.va_to_file_offset_pe(0x403000, 0x400000, sections) is None

def test_va_to_file_offset_elf():
    # Without program headers
    assert BinaryAnalyzer.va_to_file_offset_elf(0x8048000) is None

    # With program headers
    segments = [
        {'p_vaddr': 0x8048000, 'p_memsz': 0x1000, 'p_offset': 0x0},
        {'p_vaddr': 0x8049000, 'p_memsz': 0x500, 'p_offset': 0x1000}
    ]

    # Match in first segment
    assert BinaryAnalyzer.va_to_file_offset_elf(0x8048100, segments) == 0x100

    # Match in second segment
    assert BinaryAnalyzer.va_to_file_offset_elf(0x8049200, segments) == 0x1200

    # No match
    assert BinaryAnalyzer.va_to_file_offset_elf(0x8050000, segments) is None


def test_calculate_file_hash_error(tmp_path):
    with pytest.raises(Exception):
        BinaryAnalyzer.calculate_file_hash(str(tmp_path / "non_existent_file.bin"))

def test_get_file_size_error(tmp_path):
    with pytest.raises(Exception):
        BinaryAnalyzer.get_file_size(str(tmp_path / "non_existent_file.bin"))

def test_detect_file_type_error(tmp_path):
    non_existent = tmp_path / "does_not_exist.bin"
    file_type, arch = BinaryAnalyzer.detect_file_type(str(non_existent))
    assert file_type == 'UNKNOWN'
    assert arch == 'UNKNOWN'

def test_extract_metadata_error(tmp_path):
    with pytest.raises(Exception):
        BinaryAnalyzer.extract_metadata(str(tmp_path / "non_existent_file.bin"))

def test_create_backup_error(tmp_path):
    with pytest.raises(Exception):
        BinaryAnalyzer.create_backup(str(tmp_path / "non_existent_file.bin"))

def test_read_bytes_at_offset_error(tmp_path):
    with pytest.raises(Exception):
        BinaryAnalyzer.read_bytes_at_offset(str(tmp_path / "non_existent_file.bin"), 0, 10)

def test_write_bytes_at_offset_error(tmp_path):
    assert BinaryAnalyzer.write_bytes_at_offset(str(tmp_path / "non_existent_file.bin"), 0, b"data") is False


def test_init_and_load_binary_pe(tmp_path):
    pe_file = tmp_path / "test_init.exe"
    pe_data = bytearray(64)
    pe_data[0:2] = b'MZ'
    pe_data[0x3C:0x40] = struct.pack('<I', 0x40)
    pe_file.write_bytes(pe_data)

    pe_header = bytearray(32)
    pe_header[0:4] = b'PE\0\0'
    pe_header[4:6] = struct.pack('<H', 0x014c) # i386

    with open(pe_file, "ab") as f:
        f.write(pe_header)

    # The pefile module is not installed by default in this environment,
    # so we test the fallback or error handling logic.
    analyzer = BinaryAnalyzer(str(pe_file))
    assert analyzer.binary_path == str(pe_file)
    assert analyzer.file_type == 'PE'
    assert analyzer.arch == 'x86' # Notice the mapped arch
    assert analyzer.binary_data is not None

def test_init_and_load_binary_elf(tmp_path):
    elf_file = tmp_path / "test_init.elf"
    elf_data = bytearray(64)
    elf_data[0:4] = b'\x7fELF'
    elf_data[0x12:0x14] = struct.pack('<H', 0x3e) # x86_64
    elf_file.write_bytes(elf_data)

    analyzer = BinaryAnalyzer(str(elf_file))
    assert analyzer.binary_path == str(elf_file)
    assert analyzer.file_type == 'ELF'
    assert analyzer.arch == 'x64' # Mapped from x86_64
    assert analyzer.binary_data is not None

def test_va_to_offset_instance(tmp_path):
    bin_file = tmp_path / "test.bin"
    bin_file.write_bytes(b"dummy")
    analyzer = BinaryAnalyzer(str(bin_file))
    # Test fallback branch when pe/elf headers aren't parsed
    assert analyzer.va_to_offset(0x1000) is None

def test_offset_to_va_instance(tmp_path):
    bin_file = tmp_path / "test.bin"
    bin_file.write_bytes(b"dummy")
    analyzer = BinaryAnalyzer(str(bin_file))
    # Test fallback branch when pe/elf headers aren't parsed
    assert analyzer.offset_to_va(0) is None

import sys

def test_pe_parsing_with_mock(tmp_path, monkeypatch):
    class MockPE:
        def __init__(self, data=None):
            self.OPTIONAL_HEADER = type('obj', (object,), {'AddressOfEntryPoint': 0x1000, 'ImageBase': 0x400000})()

        def get_offset_from_rva(self, rva):
            if rva == 0x1000:
                return 0x400
            raise Exception("Invalid RVA")

        def get_rva_from_offset(self, offset):
            if offset == 0x400:
                return 0x1000
            raise Exception("Invalid Offset")

    import sys
    import types
    mock_pefile = types.ModuleType('pefile')
    mock_pefile.PE = MockPE
    monkeypatch.setitem(sys.modules, 'pefile', mock_pefile)

    pe_file = tmp_path / "test_pe_mock.exe"
    pe_data = bytearray(64)
    pe_data[0:2] = b'MZ'
    pe_data[0x3C:0x40] = struct.pack('<I', 0x40)
    pe_file.write_bytes(pe_data)

    pe_header = bytearray(32)
    pe_header[0:4] = b'PE\0\0'
    pe_header[4:6] = struct.pack('<H', 0x014c)

    with open(pe_file, "ab") as f:
        f.write(pe_header)

    analyzer = BinaryAnalyzer(str(pe_file))

    assert analyzer.entry_point == 0x401000
    assert analyzer.va_to_offset(0x401000) == 0x400
    assert analyzer.va_to_offset(0x402000) is None # test exception

    assert analyzer.offset_to_va(0x400) == 0x401000
    assert analyzer.offset_to_va(0x500) is None # test exception

def test_elf_parsing_with_mock(tmp_path, monkeypatch):
    class MockELFFile:
        def __init__(self, stream):
            self.header = {'e_entry': 0x8048000}

        def iter_segments(self):
            return [
                {'p_type': 'PT_LOAD', 'p_vaddr': 0x8048000, 'p_memsz': 0x1000, 'p_offset': 0x0, 'p_filesz': 0x1000},
                {'p_type': 'PT_DYNAMIC', 'p_vaddr': 0x8049000, 'p_memsz': 0x100, 'p_offset': 0x1000, 'p_filesz': 0x100}
            ]

    import sys
    import types
    mock_elftools = types.ModuleType('elftools')
    mock_elf = types.ModuleType('elftools.elf')
    mock_elffile = types.ModuleType('elftools.elf.elffile')
    mock_elffile.ELFFile = MockELFFile

    mock_elf.elffile = mock_elffile
    mock_elftools.elf = mock_elf

    monkeypatch.setitem(sys.modules, 'elftools', mock_elftools)
    monkeypatch.setitem(sys.modules, 'elftools.elf', mock_elf)
    monkeypatch.setitem(sys.modules, 'elftools.elf.elffile', mock_elffile)

    elf_file = tmp_path / "test_elf_mock.elf"
    elf_data = bytearray(64)
    elf_data[0:4] = b'\x7fELF'
    elf_data[0x12:0x14] = struct.pack('<H', 0x3e)
    elf_file.write_bytes(elf_data)

    analyzer = BinaryAnalyzer(str(elf_file))

    assert analyzer.entry_point == 0x8048000
    assert analyzer.va_to_offset(0x8048100) == 0x100
    assert analyzer.va_to_offset(0x8050000) is None # outside PT_LOAD

    assert analyzer.offset_to_va(0x100) == 0x8048100
    assert analyzer.offset_to_va(0x2000) is None # outside PT_LOAD

def test_pe_parsing_exception(tmp_path, monkeypatch):
    class MockPEError:
        def __init__(self, data=None):
            raise Exception("PE Init Error")

    import sys
    import types
    mock_pefile = types.ModuleType('pefile')
    mock_pefile.PE = MockPEError
    monkeypatch.setitem(sys.modules, 'pefile', mock_pefile)

    pe_file = tmp_path / "test_pe_err.exe"
    pe_data = bytearray(64)
    pe_data[0:2] = b'MZ'
    pe_data[0x3C:0x40] = struct.pack('<I', 0x40)
    pe_file.write_bytes(pe_data)

    pe_header = bytearray(32)
    pe_header[0:4] = b'PE\0\0'
    pe_header[4:6] = struct.pack('<H', 0x014c)

    with open(pe_file, "ab") as f:
        f.write(pe_header)

    analyzer = BinaryAnalyzer(str(pe_file))
    assert analyzer.pe is None

def test_elf_parsing_exception(tmp_path, monkeypatch):
    class MockELFFileError:
        def __init__(self, stream):
            raise Exception("ELF Init Error")

    import sys
    import types
    mock_elftools = types.ModuleType('elftools')
    mock_elf = types.ModuleType('elftools.elf')
    mock_elffile = types.ModuleType('elftools.elf.elffile')
    mock_elffile.ELFFile = MockELFFileError

    mock_elf.elffile = mock_elffile
    mock_elftools.elf = mock_elf

    monkeypatch.setitem(sys.modules, 'elftools', mock_elftools)
    monkeypatch.setitem(sys.modules, 'elftools.elf', mock_elf)
    monkeypatch.setitem(sys.modules, 'elftools.elf.elffile', mock_elffile)

    elf_file = tmp_path / "test_elf_err.elf"
    elf_data = bytearray(64)
    elf_data[0:4] = b'\x7fELF'
    elf_data[0x12:0x14] = struct.pack('<H', 0x3e)
    elf_file.write_bytes(elf_data)

    analyzer = BinaryAnalyzer(str(elf_file))
    assert analyzer.elf is None
