#!/usr/bin/env python3
"""KaliAgent v3 - Payload Encoding Demo"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from weaponization.encoder import PayloadEncoder
from pathlib import Path
from datetime import datetime
import tempfile

print("="*70)
print("  KaliAgent v3 - Payload Encoding & Obfuscation")
print("  Advanced Evasion Techniques")
print("="*70)
print()

# Create test payload
test_dir = Path(tempfile.mkdtemp(prefix='kali_demo_'))
test_file = test_dir / 'payload.exe'
test_file.write_bytes(b'MZ' + b'\x90' * 1000)  # Fake EXE

print("📦 Original Payload:")
print(f"   File: {test_file.name}")
print(f"   Size: {test_file.stat().st_size} bytes")
print()

enc = PayloadEncoder(output_dir=test_dir / 'encoded')

print("🔧 Encoding Tests:")
print()

encoders = ['base64', 'hex', 'xor', 'xor_dynamic']
for encoder_name in encoders:
    result = enc.encode(test_file, encoder_name)
    if result.success:
        print(f"   ✓ {encoder_name:15s} - {result.encoded_size} bytes ({result.expansion_ratio:.2f}x)")
    else:
        print(f"   ✗ {encoder_name:15s} - Failed: {result.error}")
print()

print("🎭 Obfuscation Tests:")
print()

obfuscation_tests = [
    ('string_encryption', 'String Encryption'),
    ('dead_code_insertion', 'Dead Code Insertion')
]

for tech_name, tech_desc in obfuscation_tests:
    success, msg = enc.add_obfuscation(test_file, [tech_name])
    status = '✅' if success else '❌'
    print(f"   {status} {tech_desc:25s} - {msg}")
print()

print("🛡️  AMSI/ETW Patching:")
ps_file = test_dir / 'script.ps1'
ps_file.write_text('Write-Host "Test"')

success, msg = enc.patch_amsi(ps_file)
print(f"   {'✅' if success else '❌'} AMSI Patch - {msg}")

success, msg = enc.patch_etw(ps_file)
print(f"   {'✅' if success else '❌'} ETW Patch  - {msg}")
print()

print("="*70)
print(f"  Demo completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"  Output directory: {test_dir}")
print("="*70)
