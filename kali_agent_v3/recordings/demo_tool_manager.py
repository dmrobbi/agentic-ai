#!/usr/bin/env python3
"""KaliAgent v3 - Tool Manager Demo"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.tool_manager import ToolManager
from datetime import datetime

print("="*70)
print("  KaliAgent v3 - Tool Database Management")
print("  Production Security Automation Framework")
print("="*70)
print()

manager = ToolManager()
stats = manager.get_database_stats()

print("📊 Database Statistics")
print(f"   Total Tools:     {stats['total_tools']}")
print(f"   Installed:       {stats['installed_tools']}")
print(f"   Coverage:        {stats['coverage_pct']:.2f}%")
print(f"   Total Size:      {stats['total_size_gb']:.2f} GB")
print()

print("📁 Tool Categories:")
for i, (cat, data) in enumerate(stats['categories'].items()):
    bar = '█' * min(data['total'], 50)
    print(f"   {cat:25s} {bar} {data['total']:3d} tools")
    if i >= 6:
        print(f"   ... and {len(stats['categories']) - 7} more categories")
        break
print()

print("🔍 Search Demo: 'nmap'")
results = manager.search_tools('nmap')
for tool in results:
    print(f"   ✓ {tool.name:15s} - {tool.description[:50]}")
print()

print("🎯 Top Tools:")
top = manager.get_top_tools()
for i, tool in enumerate(top[:5], 1):
    print(f"   {i}. {tool.name:15s} (Priority: {tool.priority}/10)")
print()

print("="*70)
print(f"  Demo completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("="*70)
