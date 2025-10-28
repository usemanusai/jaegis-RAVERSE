#!/usr/bin/env python
"""Test script for setup wizard"""

import sys
from pathlib import Path

# Add package to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    print("Testing setup wizard import...")
    from jaegis_raverse_mcp_server.setup_wizard import SetupWizard
    print("✓ Import successful")
    
    print("\nTesting SetupWizard instantiation...")
    wizard = SetupWizard()
    print("✓ SetupWizard created")
    
    print("\nTesting banner print...")
    wizard._print_banner()
    print("✓ Banner printed")
    
    print("\nTesting menu print...")
    wizard._print_menu()
    print("✓ Menu printed")
    
    print("\nTesting credential generation...")
    wizard._generate_credentials()
    print(f"✓ Credentials generated")
    print(f"  - DB Username: {wizard.db_username}")
    print(f"  - DB Password length: {len(wizard.db_password)}")
    print(f"  - Redis Password length: {len(wizard.redis_password)}")
    
    print("\nTesting port availability check...")
    wizard._check_port_availability()
    print(f"✓ Ports available")
    print(f"  - PostgreSQL port: {wizard.db_port}")
    print(f"  - Redis port: {wizard.redis_port}")
    
    print("\n✓ All tests passed!")
    
except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

