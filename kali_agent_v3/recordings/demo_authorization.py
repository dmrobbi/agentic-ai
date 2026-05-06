#!/usr/bin/env python3
"""KaliAgent v3 - Authorization System Demo"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.authorization import AuthorizationManager, AuthorizationLevel
from datetime import datetime

print("="*70)
print("  KaliAgent v3 - Authorization System")
print("  Multi-Level Safety Gates")
print("="*70)
print()

auth = AuthorizationManager()

print("🔐 Authorization Levels:")
for level in [AuthorizationLevel.NONE, AuthorizationLevel.BASIC, AuthorizationLevel.ADVANCED, AuthorizationLevel.CRITICAL]:
    print(f"   • {level.name:12s} - Level {level.value}")
print()

print("📝 Requesting Authorizations:")
print()

# BASIC authorization
print("   Request 1: nmap_scan (BASIC)")
success, msg, token = auth.request_authorization('nmap_scan', reason='Network reconnaissance')
print(f"      Status: {'✅ APPROVED' if success else '⏳ PENDING'}")
if token:
    print(f"      Token:  {token.token_id}")
print()

# ADVANCED authorization
print("   Request 2: sql_injection (ADVANCED)")
success, msg, token = auth.request_authorization('sql_injection', reason='Web app testing')
print(f"      Status: {'✅ APPROVED' if success else '⏳ PENDING'}")
print(f"      Message: {msg}")
print()

# CRITICAL authorization
print("   Request 3: kernel_exploit (CRITICAL)")
success, msg, token = auth.request_authorization('kernel_exploit', reason='Privilege escalation testing')
print(f"      Status: {'✅ APPROVED' if success else '🔒 REQUIRES PIN'}")
print(f"      Message: {msg}")
print()

print("📋 Pending Authorizations:")
pending = auth.list_pending_authorizations()
print(f"   {len(pending)} authorization(s) pending approval")
print()

print("="*70)
print(f"  Demo completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("="*70)
