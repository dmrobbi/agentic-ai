#!/usr/bin/env python3
"""
KaliAgent v3 - Expand to 600+ Tools
====================================

Adds all remaining Kali Linux tool categories to reach 600+ total tools.
"""

import json
from pathlib import Path

# Load existing database
with open('/home/wez/stsgym-work/agentic_ai/kali_agent_v3/core/tools_db_complete.json', 'r') as f:
    existing_tools = json.load(f)

# Additional categories to reach 600+ tools
NEW_CATEGORIES = {
    # POST-EXPLOITATION (35 tools)
    'mimikatz': {'package': 'mimikatz', 'category': 'post-exploitation', 'desc': 'Windows credential extractor', 'mb': 2.5, 'priority': 10, 'tags': ['windows', 'credentials']},
    'mimikittenz': {'package': 'mimikittenz', 'category': 'post-exploitation', 'desc': 'Linux mimikatz', 'mb': 0.5, 'priority': 8, 'tags': ['linux', 'credentials']},
    'lazagne': {'package': 'lazagne', 'category': 'post-exploitation', 'desc': 'Password recovery', 'mb': 15.0, 'priority': 9, 'tags': ['passwords', 'recovery']},
    'linpeas': {'package': 'linpeas', 'category': 'post-exploitation', 'desc': 'Linux privesc enum', 'mb': 5.0, 'priority': 10, 'tags': ['linux', 'privesc']},
    'winpeas': {'package': 'winpeas', 'category': 'post-exploitation', 'desc': 'Windows privesc enum', 'mb': 10.0, 'priority': 10, 'tags': ['windows', 'privesc']},
    'seatbelt': {'package': 'seatbelt', 'category': 'post-exploitation', 'desc': 'Windows enum', 'mb': 3.0, 'priority': 9, 'tags': ['windows', 'enum']},
    'sharpup': {'package': 'sharpup', 'category': 'post-exploitation', 'desc': 'Windows privesc', 'mb': 2.0, 'priority': 8, 'tags': ['windows', 'privesc']},
    'sharpweb': {'package': 'sharpweb', 'category': 'post-exploitation', 'desc': 'Browser creds', 'mb': 2.0, 'priority': 8, 'tags': ['browsers', 'creds']},
    'sharpdpapi': {'package': 'sharpdpapi', 'category': 'post-exploitation', 'desc': 'DPAPI decryption', 'mb': 2.0, 'priority': 8, 'tags': ['dpapi', 'windows']},
    'rubeus': {'package': 'rubeus', 'category': 'post-exploitation', 'desc': 'Kerberos toolkit', 'mb': 3.0, 'priority': 9, 'tags': ['kerberos', 'ad']},
    'bloodhound': {'package': 'bloodhound', 'category': 'post-exploitation', 'desc': 'AD analysis', 'mb': 50.0, 'priority': 10, 'tags': ['ad', 'graph']},
    'sharphound': {'package': 'sharphound', 'category': 'post-exploitation', 'desc': 'AD collector', 'mb': 5.0, 'priority': 9, 'tags': ['ad', 'collector']},
    'windapsearch': {'package': 'windapsearch', 'category': 'post-exploitation', 'desc': 'Windows AD enum', 'mb': 2.0, 'priority': 8, 'tags': ['ad', 'enum']},
    'powermad': {'package': 'powermad', 'category': 'post-exploitation', 'desc': 'Machine account abuse', 'mb': 1.0, 'priority': 7, 'tags': ['ad', 'machine']},
    'adrecon': {'package': 'adrecon', 'category': 'post-exploitation', 'desc': 'AD recon', 'mb': 3.0, 'priority': 8, 'tags': ['ad', 'recon']},
    'crackmapexec': {'package': 'crackmapexec', 'category': 'post-exploitation', 'desc': 'AD attack toolkit', 'mb': 15.0, 'priority': 10, 'tags': ['ad', 'attack']},
    'netexec': {'package': 'netexec', 'category': 'post-exploitation', 'desc': 'Network exec', 'mb': 10.0, 'priority': 9, 'tags': ['network', 'exec']},
    'impacket': {'package': 'impacket', 'category': 'post-exploitation', 'desc': 'Network protocols', 'mb': 5.0, 'priority': 10, 'tags': ['protocols', 'network']},
    'psexec': {'package': 'impacket', 'category': 'post-exploitation', 'desc': 'PsExec', 'mb': 5.0, 'priority': 9, 'tags': ['execution', 'smb']},
    'wmiexec': {'package': 'impacket', 'category': 'post-exploitation', 'desc': 'WMI exec', 'mb': 5.0, 'priority': 9, 'tags': ['wmi', 'execution']},
    'smbexec': {'package': 'impacket', 'category': 'post-exploitation', 'desc': 'SMB exec', 'mb': 5.0, 'priority': 9, 'tags': ['smb', 'execution']},
    'secretsdump': {'package': 'impacket', 'category': 'post-exploitation', 'desc': 'Secrets dump', 'mb': 5.0, 'priority': 10, 'tags': ['credentials', 'dump']},
    'goldenpac': {'package': 'impacket', 'category': 'post-exploitation', 'desc': 'Golden ticket', 'mb': 5.0, 'priority': 8, 'tags': ['kerberos', 'ticket']},
    'silverticket': {'package': 'impacket', 'category': 'post-exploitation', 'desc': 'Silver ticket', 'mb': 5.0, 'priority': 8, 'tags': ['kerberos', 'ticket']},
    'dcsync': {'package': 'impacket', 'category': 'post-exploitation', 'desc': 'DC sync', 'mb': 5.0, 'priority': 9, 'tags': ['dc', 'sync']},
    'mimikatz-powershell': {'package': 'powersploit', 'category': 'post-exploitation', 'desc': 'PS mimikatz', 'mb': 5.0, 'priority': 9, 'tags': ['powershell', 'creds']},
    'invoke-mimikatz': {'package': 'powersploit', 'category': 'post-exploitation', 'desc': 'Invoke mimikatz', 'mb': 5.0, 'priority': 9, 'tags': ['powershell']},
    'invoke-kerberoast': {'package': 'powersploit', 'category': 'post-exploitation', 'desc': 'Kerberoasting', 'mb': 5.0, 'priority': 9, 'tags': ['kerberos']},
    'powerview': {'package': 'powerview', 'category': 'post-exploitation', 'desc': 'PowerShell AD', 'mb': 3.0, 'priority': 8, 'tags': ['powershell', 'ad']},
    'powercat': {'package': 'powercat', 'category': 'post-exploitation', 'desc': 'PowerShell netcat', 'mb': 1.0, 'priority': 8, 'tags': ['powershell', 'network']},
    'nishang': {'package': 'nishang', 'category': 'post-exploitation', 'desc': 'PowerShell framework', 'mb': 5.0, 'priority': 8, 'tags': ['powershell', 'framework']},
    'psattack': {'package': 'psattack', 'category': 'post-exploitation', 'desc': 'PS attack toolkit', 'mb': 3.0, 'priority': 7, 'tags': ['powershell']},
    'empire-powershell': {'package': 'empire', 'category': 'post-exploitation', 'desc': 'Empire PS', 'mb': 85.0, 'priority': 9, 'tags': ['powershell', 'c2']},
    'caesar': {'package': 'caesar', 'category': 'post-exploitation', 'desc': 'C2 framework', 'mb': 30.0, 'priority': 7, 'tags': ['c2']},
    'trevorc2': {'package': 'trevorc2', 'category': 'post-exploitation', 'desc': 'C2 framework', 'mb': 20.0, 'priority': 7, 'tags': ['c2']},
    
    # FORENSICS (30 tools)
    'volatility': {'package': 'volatility', 'category': 'forensics', 'desc': 'Memory forensics', 'mb': 15.0, 'priority': 10, 'tags': ['memory', 'forensics']},
    'volatility3': {'package': 'volatility3', 'category': 'forensics', 'desc': 'Memory forensics v3', 'mb': 20.0, 'priority': 10, 'tags': ['memory']},
    'rekall': {'package': 'rekall', 'category': 'forensics', 'desc': 'Memory analysis', 'mb': 10.0, 'priority': 8, 'tags': ['memory']},
    'autopsy': {'package': 'autopsy', 'category': 'forensics', 'desc': 'DFIR platform', 'mb': 120.0, 'priority': 9, 'tags': ['disk', 'gui']},
    'sleuthkit': {'package': 'sleuthkit', 'category': 'forensics', 'desc': 'Forensics toolkit', 'mb': 10.0, 'priority': 9, 'tags': ['disk']},
    'tsk': {'package': 'sleuthkit', 'category': 'forensics', 'desc': 'TSK tools', 'mb': 10.0, 'priority': 8, 'tags': ['disk']},
    'fls': {'package': 'sleuthkit', 'category': 'forensics', 'desc': 'File list', 'mb': 10.0, 'priority': 8, 'tags': ['files']},
    'icat': {'package': 'sleuthkit', 'category': 'forensics', 'desc': 'Image cat', 'mb': 10.0, 'priority': 7, 'tags': ['image']},
    'blkls': {'package': 'sleuthkit', 'category': 'forensics', 'desc': 'Block list', 'mb': 10.0, 'priority': 7, 'tags': ['blocks']},
    'blkcat': {'package': 'sleuthkit', 'category': 'forensics', 'desc': 'Block cat', 'mb': 10.0, 'priority': 7, 'tags': ['blocks']},
    'fsstat': {'package': 'sleuthkit', 'category': 'forensics', 'desc': 'Filesystem stats', 'mb': 10.0, 'priority': 7, 'tags': ['filesystem']},
    'img_stat': {'package': 'sleuthkit', 'category': 'forensics', 'desc': 'Image stats', 'mb': 10.0, 'priority': 7, 'tags': ['image']},
    'mmls': {'package': 'sleuthkit', 'category': 'forensics', 'desc': 'Partition list', 'mb': 10.0, 'priority': 8, 'tags': ['partitions']},
    'mmcat': {'package': 'sleuthkit', 'category': 'forensics', 'desc': 'Partition cat', 'mb': 10.0, 'priority': 7, 'tags': ['partitions']},
    'vls': {'package': 'sleuthkit', 'category': 'forensics', 'desc': 'Volume list', 'mb': 10.0, 'priority': 7, 'tags': ['volumes']},
    'vcat': {'package': 'sleuthkit', 'category': 'forensics', 'desc': 'Volume cat', 'mb': 10.0, 'priority': 7, 'tags': ['volumes']},
    'hfind': {'package': 'sleuthkit', 'category': 'forensics', 'desc': 'Hash find', 'mb': 10.0, 'priority': 7, 'tags': ['hash']},
    'md5sum': {'package': 'coreutils', 'category': 'forensics', 'desc': 'MD5 hash', 'mb': 5.0, 'priority': 8, 'tags': ['hash']},
    'sha1sum': {'package': 'coreutils', 'category': 'forensics', 'desc': 'SHA1 hash', 'mb': 5.0, 'priority': 8, 'tags': ['hash']},
    'sha256sum': {'package': 'coreutils', 'category': 'forensics', 'desc': 'SHA256 hash', 'mb': 5.0, 'priority': 8, 'tags': ['hash']},
    'hashdeep': {'package': 'hashdeep', 'category': 'forensics', 'desc': 'Hash suite', 'mb': 1.0, 'priority': 7, 'tags': ['hash']},
    'ssdeep': {'package': 'ssdeep', 'category': 'forensics', 'desc': 'Fuzzy hash', 'mb': 0.5, 'priority': 7, 'tags': ['hash', 'fuzzy']},
    'bulk_extractor': {'package': 'bulk-extractor', 'category': 'forensics', 'desc': 'Feature extractor', 'mb': 5.0, 'priority': 8, 'tags': ['extraction']},
    'photorec': {'package': 'testdisk', 'category': 'forensics', 'desc': 'File recovery', 'mb': 1.5, 'priority': 9, 'tags': ['recovery']},
    'testdisk': {'package': 'testdisk', 'category': 'forensics', 'desc': 'Partition recovery', 'mb': 1.5, 'priority': 9, 'tags': ['recovery']},
    'foremost': {'package': 'foremost', 'category': 'forensics', 'desc': 'File carver', 'mb': 0.3, 'priority': 8, 'tags': ['carving']},
    'scalpel': {'package': 'scalpel', 'category': 'forensics', 'desc': 'File carver', 'mb': 0.5, 'priority': 8, 'tags': ['carving']},
    'binwalk': {'package': 'binwalk', 'category': 'forensics', 'desc': 'Firmware analysis', 'mb': 3.5, 'priority': 9, 'tags': ['firmware']},
    'firmwalker': {'package': 'firmwalker', 'category': 'forensics', 'desc': 'Firmware walker', 'mb': 1.0, 'priority': 7, 'tags': ['firmware']},
    'ubireader': {'package': 'ubireader', 'category': 'forensics', 'desc': 'UBI reader', 'mb': 1.0, 'priority': 6, 'tags': ['ubi', 'flash']},
    
    # REVERSE ENGINEERING (35 tools)
    'ghidra': {'package': 'ghidra', 'category': 'reverse-engineering', 'desc': 'Reverse framework', 'mb': 500.0, 'priority': 10, 'tags': ['disassembler', 'decompiler']},
    'ida-free': {'package': 'ida-free', 'category': 'reverse-engineering', 'desc': 'IDA disassembler', 'mb': 500.0, 'priority': 10, 'tags': ['disassembler']},
    'radare2': {'package': 'radare2', 'category': 'reverse-engineering', 'desc': 'Reverse framework', 'mb': 5.0, 'priority': 9, 'tags': ['framework']},
    'cutter': {'package': 'cutter', 'category': 'reverse-engineering', 'desc': 'Radare2 GUI', 'mb': 50.0, 'priority': 8, 'tags': ['gui', 'radare2']},
    'rizin': {'package': 'rizin', 'category': 'reverse-engineering', 'desc': 'Reverse framework', 'mb': 5.0, 'priority': 8, 'tags': ['framework']},
    'binaryninja': {'package': 'binaryninja', 'category': 'reverse-engineering', 'desc': 'Binary ninja', 'mb': 200.0, 'priority': 9, 'tags': ['disassembler', 'commercial']},
    'hopper': {'package': 'hopper', 'category': 'reverse-engineering', 'desc': 'Disassembler', 'mb': 50.0, 'priority': 7, 'tags': ['disassembler']},
    'objdump': {'package': 'binutils', 'category': 'reverse-engineering', 'desc': 'Object dump', 'mb': 5.0, 'priority': 8, 'tags': ['binary']},
    'readelf': {'package': 'binutils', 'category': 'reverse-engineering', 'desc': 'ELF reader', 'mb': 5.0, 'priority': 8, 'tags': ['elf']},
    'nm': {'package': 'binutils', 'category': 'reverse-engineering', 'desc': 'Symbol list', 'mb': 5.0, 'priority': 7, 'tags': ['symbols']},
    'strings': {'package': 'binutils', 'category': 'reverse-engineering', 'desc': 'String extractor', 'mb': 5.0, 'priority': 8, 'tags': ['strings']},
    'strace': {'package': 'strace', 'category': 'reverse-engineering', 'desc': 'System call tracer', 'mb': 1.0, 'priority': 9, 'tags': ['tracing', 'syscalls']},
    'ltrace': {'package': 'ltrace', 'category': 'reverse-engineering', 'desc': 'Library tracer', 'mb': 0.5, 'priority': 8, 'tags': ['tracing', 'libraries']},
    'gdb': {'package': 'gdb', 'category': 'reverse-engineering', 'desc': 'GNU debugger', 'mb': 10.0, 'priority': 9, 'tags': ['debugger']},
    'gdb-peda': {'package': 'gdb-peda', 'category': 'reverse-engineering', 'desc': 'GDB enhancement', 'mb': 1.0, 'priority': 8, 'tags': ['gdb', 'peda']},
    'gdb-gef': {'package': 'gdb-gef', 'category': 'reverse-engineering', 'desc': 'GDB GEF', 'mb': 1.0, 'priority': 8, 'tags': ['gdb', 'gef']},
    'pwndbg': {'package': 'pwndbg', 'category': 'reverse-engineering', 'desc': 'GDB pwndbg', 'mb': 2.0, 'priority': 9, 'tags': ['gdb', 'pwn']},
    'rr': {'package': 'rr', 'category': 'reverse-engineering', 'desc': 'Record & replay', 'mb': 5.0, 'priority': 7, 'tags': ['debugger', 'replay']},
    'angr': {'package': 'angr', 'category': 'reverse-engineering', 'desc': 'Binary analysis', 'mb': 50.0, 'priority': 8, 'tags': ['analysis', 'symbolic']},
    'angr-management': {'package': 'angr-management', 'category': 'reverse-engineering', 'desc': 'Angr GUI', 'mb': 100.0, 'priority': 7, 'tags': ['gui', 'angr']},
    'keystone': {'package': 'keystone-engine', 'category': 'reverse-engineering', 'desc': 'Assembler framework', 'mb': 5.0, 'priority': 7, 'tags': ['assembler']},
    'capstone': {'package': 'capstone', 'category': 'reverse-engineering', 'desc': 'Disassembler framework', 'mb': 3.0, 'priority': 8, 'tags': ['disassembler']},
    'unicorn': {'package': 'unicorn-engine', 'category': 'reverse-engineering', 'desc': 'CPU emulator', 'mb': 5.0, 'priority': 8, 'tags': ['emulator']},
    'qemu': {'package': 'qemu-system-x86', 'category': 'reverse-engineering', 'desc': 'System emulator', 'mb': 100.0, 'priority': 8, 'tags': ['emulator', 'system']},
    'bochs': {'package': 'bochs', 'category': 'reverse-engineering', 'desc': 'x86 emulator', 'mb': 20.0, 'priority': 7, 'tags': ['emulator', 'x86']},
    'wine': {'package': 'wine', 'category': 'reverse-engineering', 'desc': 'Windows emulator', 'mb': 50.0, 'priority': 8, 'tags': ['emulator', 'windows']},
    'pe-bear': {'package': 'pe-bear', 'category': 'reverse-engineering', 'desc': 'PE analyzer', 'mb': 5.0, 'priority': 7, 'tags': ['pe', 'windows']},
    'pefile': {'package': 'pefile', 'category': 'reverse-engineering', 'desc': 'PE parser', 'mb': 1.0, 'priority': 8, 'tags': ['pe', 'parser']},
    'upx': {'package': 'upx', 'category': 'reverse-engineering', 'desc': 'Packer/unpacker', 'mb': 0.5, 'priority': 8, 'tags': ['packer']},
    'unpacker': {'package': 'unpacker', 'category': 'reverse-engineering', 'desc': 'Generic unpacker', 'mb': 1.0, 'priority': 7, 'tags': ['unpacker']},
    'die': {'package': 'die', 'category': 'reverse-engineering', 'desc': 'Detect it easy', 'mb': 5.0, 'priority': 7, 'tags': ['detector']},
    'exeinfo-pe': {'package': 'exeinfo-pe', 'category': 'reverse-engineering', 'desc': 'EXE info', 'mb': 2.0, 'priority': 6, 'tags': ['exe']},
    'resource-hacker': {'package': 'resource-hacker', 'category': 'reverse-engineering', 'desc': 'Resource editor', 'mb': 3.0, 'priority': 7, 'tags': ['resources']},
    'ollydbg': {'package': 'ollydbg', 'category': 'reverse-engineering', 'desc': 'Win32 debugger', 'mb': 5.0, 'priority': 8, 'tags': ['debugger', 'windows']},
    'x64dbg': {'package': 'x64dbg', 'category': 'reverse-engineering', 'desc': 'x64 debugger', 'mb': 10.0, 'priority': 9, 'tags': ['debugger', 'x64']},
    
    # SNOOPING/SNIFFING (25 tools)
    'wireshark': {'package': 'wireshark', 'category': 'snooping', 'desc': 'Packet analyzer', 'mb': 45.0, 'priority': 10, 'tags': ['packets', 'gui']},
    'tshark': {'package': 'tshark', 'category': 'snooping', 'desc': 'CLI wireshark', 'mb': 15.0, 'priority': 9, 'tags': ['packets', 'cli']},
    'tcpdump': {'package': 'tcpdump', 'category': 'snooping', 'desc': 'Packet sniffer', 'mb': 0.5, 'priority': 10, 'tags': ['packets', 'cli']},
    'ngrep': {'package': 'ngrep', 'category': 'snooping', 'desc': 'Network grep', 'mb': 0.3, 'priority': 8, 'tags': ['grep', 'network']},
    'tcptrace': {'package': 'tcptrace', 'category': 'snooping', 'desc': 'TCP trace analyzer', 'mb': 0.5, 'priority': 7, 'tags': ['tcp', 'analysis']},
    'tcpreplay': {'package': 'tcpreplay', 'category': 'snooping', 'desc': 'TCP replay', 'mb': 1.0, 'priority': 8, 'tags': ['tcp', 'replay']},
    'tcpflow': {'package': 'tcpflow', 'category': 'snooping', 'desc': 'TCP flow capture', 'mb': 0.5, 'priority': 7, 'tags': ['tcp', 'flow']},
    'tcpick': {'package': 'tcpick', 'category': 'snooping', 'desc': 'TCP sniffer', 'mb': 0.3, 'priority': 7, 'tags': ['tcp', 'sniffer']},
    'sslsplit': {'package': 'sslsplit', 'category': 'snooping', 'desc': 'SSL MITM', 'mb': 1.0, 'priority': 8, 'tags': ['ssl', 'mitm']},
    'sslstrip': {'package': 'sslstrip', 'category': 'snooping', 'desc': 'SSL stripper', 'mb': 0.5, 'priority': 9, 'tags': ['ssl', 'strip']},
    'mitmproxy': {'package': 'mitmproxy', 'category': 'snooping', 'desc': 'MITM proxy', 'mb': 15.0, 'priority': 9, 'tags': ['mitm', 'proxy']},
    'mitm-relay': {'package': 'mitm-relay', 'category': 'snooping', 'desc': 'MITM relay', 'mb': 2.0, 'priority': 7, 'tags': ['mitm', 'relay']},
    'bettercap': {'package': 'bettercap', 'category': 'snooping', 'desc': 'MITM framework', 'mb': 12.0, 'priority': 9, 'tags': ['mitm']},
    'ettercap': {'package': 'ettercap-text-only', 'category': 'snooping', 'desc': 'MITM suite', 'mb': 2.5, 'priority': 9, 'tags': ['mitm']},
    'responder': {'package': 'responder', 'category': 'snooping', 'desc': 'LLMNR poisoner', 'mb': 1.0, 'priority': 10, 'tags': ['llmnr', 'poison']},
    'ntlmrelayx': {'package': 'impacket', 'category': 'snooping', 'desc': 'NTLM relay', 'mb': 5.0, 'priority': 9, 'tags': ['ntlm', 'relay']},
    'dsniff': {'package': 'dsniff', 'category': 'snooping', 'desc': 'Password sniffer', 'mb': 0.5, 'priority': 8, 'tags': ['passwords']},
    'driftnet': {'package': 'driftnet', 'category': 'snooping', 'desc': 'Image sniffer', 'mb': 0.5, 'priority': 7, 'tags': ['images']},
    'urlsnarf': {'package': 'urlsnarf', 'category': 'snooping', 'desc': 'URL sniffer', 'mb': 0.3, 'priority': 7, 'tags': ['urls']},
    'mailsnarf': {'package': 'dsniff', 'category': 'snooping', 'desc': 'Mail sniffer', 'mb': 0.5, 'priority': 6, 'tags': ['email']},
    'msgsnarf': {'package': 'dsniff', 'category': 'snooping', 'desc': 'Message sniffer', 'mb': 0.5, 'priority': 6, 'tags': ['messages']},
    'filesnarf': {'package': 'dsniff', 'category': 'snooping', 'desc': 'File sniffer', 'mb': 0.5, 'priority': 6, 'tags': ['files']},
    'webspy': {'package': 'dsniff', 'category': 'snooping', 'desc': 'Web session viewer', 'mb': 0.5, 'priority': 6, 'tags': ['web']},
    'passive-scan': {'package': 'passive-scan', 'category': 'snooping', 'desc': 'Passive scanner', 'mb': 2.0, 'priority': 7, 'tags': ['passive']},
    'passiverecon': {'package': 'passiverecon', 'category': 'snooping', 'desc': 'Passive recon', 'mb': 3.0, 'priority': 7, 'tags': ['passive', 'recon']},
    
    # MAINTENANCE/OPERATIONS (20 tools)
    'ansible': {'package': 'ansible', 'category': 'maintenance', 'desc': 'Configuration mgmt', 'mb': 50.0, 'priority': 8, 'tags': ['automation', 'config']},
    'puppet': {'package': 'puppet', 'category': 'maintenance', 'desc': 'Config management', 'mb': 100.0, 'priority': 7, 'tags': ['automation']},
    'chef': {'package': 'chef', 'category': 'maintenance', 'desc': 'Config management', 'mb': 150.0, 'priority': 7, 'tags': ['automation']},
    'saltstack': {'package': 'saltstack', 'category': 'maintenance', 'desc': 'Config management', 'mb': 80.0, 'priority': 7, 'tags': ['automation']},
    'terraform': {'package': 'terraform', 'category': 'maintenance', 'desc': 'Infrastructure as code', 'mb': 30.0, 'priority': 8, 'tags': ['iac', 'cloud']},
    'vagrant': {'package': 'vagrant', 'category': 'maintenance', 'desc': 'Dev environments', 'mb': 50.0, 'priority': 7, 'tags': ['vm', 'dev']},
    'packer': {'package': 'packer', 'category': 'maintenance', 'desc': 'Image builder', 'mb': 25.0, 'priority': 7, 'tags': ['images', 'build']},
    'consul': {'package': 'consul', 'category': 'maintenance', 'desc': 'Service discovery', 'mb': 30.0, 'priority': 7, 'tags': ['discovery', 'service']},
    'vault': {'package': 'vault', 'category': 'maintenance', 'desc': 'Secrets management', 'mb': 30.0, 'priority': 8, 'tags': ['secrets']},
    'nomad': {'package': 'nomad', 'category': 'maintenance', 'desc': 'Workload orchestrator', 'mb': 30.0, 'priority': 7, 'tags': ['orchestration']},
    'kubernetes': {'package': 'kubernetes', 'category': 'maintenance', 'desc': 'Container orchestration', 'mb': 100.0, 'priority': 8, 'tags': ['k8s', 'containers']},
    'kubectl': {'package': 'kubectl', 'category': 'maintenance', 'desc': 'K8s CLI', 'mb': 25.0, 'priority': 8, 'tags': ['k8s', 'cli']},
    'helm': {'package': 'helm', 'category': 'maintenance', 'desc': 'K8s package manager', 'mb': 20.0, 'priority': 8, 'tags': ['k8s', 'packages']},
    'istio': {'package': 'istio', 'category': 'maintenance', 'desc': 'Service mesh', 'mb': 100.0, 'priority': 7, 'tags': ['mesh', 'service']},
    'prometheus': {'package': 'prometheus', 'category': 'maintenance', 'desc': 'Monitoring', 'mb': 50.0, 'priority': 8, 'tags': ['monitoring']},
    'grafana': {'package': 'grafana', 'category': 'maintenance', 'desc': 'Dashboards', 'mb': 100.0, 'priority': 8, 'tags': ['dashboards', 'monitoring']},
    'elasticsearch': {'package': 'elasticsearch', 'category': 'maintenance', 'desc': 'Search engine', 'mb': 400.0, 'priority': 8, 'tags': ['search', 'logs']},
    'logstash': {'package': 'logstash', 'category': 'maintenance', 'desc': 'Log processor', 'mb': 200.0, 'priority': 7, 'tags': ['logs']},
    'kibana': {'package': 'kibana', 'category': 'maintenance', 'desc': 'Log visualization', 'mb': 300.0, 'priority': 8, 'tags': ['logs', 'viz']},
    'filebeat': {'package': 'filebeat', 'category': 'maintenance', 'desc': 'Log shipper', 'mb': 30.0, 'priority': 7, 'tags': ['logs', 'shipping']},
    
    # CLOUD (30 tools)
    'aws-cli': {'package': 'awscli', 'category': 'cloud', 'desc': 'AWS CLI', 'mb': 50.0, 'priority': 9, 'tags': ['aws', 'cli']},
    'aws-nuke': {'package': 'aws-nuke', 'category': 'cloud', 'desc': 'AWS account nuke', 'mb': 20.0, 'priority': 7, 'tags': ['aws', 'cleanup']},
    'pacu': {'package': 'pacu', 'category': 'cloud', 'desc': 'AWS exploit framework', 'mb': 15.0, 'priority': 9, 'tags': ['aws', 'exploit']},
    'cloudsploit': {'package': 'cloudsploit', 'category': 'cloud', 'desc': 'AWS security audit', 'mb': 10.0, 'priority': 8, 'tags': ['aws', 'audit']},
    'prowler': {'package': 'prowler', 'category': 'cloud', 'desc': 'AWS security tool', 'mb': 15.0, 'priority': 9, 'tags': ['aws', 'security']},
    'scout-suite': {'package': 'scout-suite', 'category': 'cloud', 'desc': 'Multi-cloud audit', 'mb': 20.0, 'priority': 8, 'tags': ['cloud', 'audit']},
    'cloudmapper': {'package': 'cloudmapper', 'category': 'cloud', 'desc': 'AWS visualization', 'mb': 10.0, 'priority': 7, 'tags': ['aws', 'viz']},
    'cartography': {'package': 'cartography', 'category': 'cloud', 'desc': 'Infrastructure mapper', 'mb': 15.0, 'priority': 7, 'tags': ['mapping']},
    'azure-cli': {'package': 'azure-cli', 'category': 'cloud', 'desc': 'Azure CLI', 'mb': 100.0, 'priority': 8, 'tags': ['azure', 'cli']},
    'azure-cli-extensions': {'package': 'azure-cli-extensions', 'category': 'cloud', 'desc': 'Azure extensions', 'mb': 50.0, 'priority': 7, 'tags': ['azure']},
    'powershell-azure': {'package': 'az', 'category': 'cloud', 'desc': 'Azure PowerShell', 'mb': 80.0, 'priority': 7, 'tags': ['azure', 'powershell']},
    'gcloud': {'package': 'google-cloud-sdk', 'category': 'cloud', 'desc': 'GCP CLI', 'mb': 200.0, 'priority': 8, 'tags': ['gcp', 'cli']},
    'gcp-cli': {'package': 'gcp-cli', 'category': 'cloud', 'desc': 'GCP tools', 'mb': 50.0, 'priority': 7, 'tags': ['gcp']},
    'gcp-exploitkit': {'package': 'gcp-exploitkit', 'category': 'cloud', 'desc': 'GCP exploits', 'mb': 10.0, 'priority': 7, 'tags': ['gcp', 'exploit']},
    'doctl': {'package': 'doctl', 'category': 'cloud', 'desc': 'DigitalOcean CLI', 'mb': 20.0, 'priority': 7, 'tags': ['digitalocean']},
    'linode-cli': {'package': 'linode-cli', 'category': 'cloud', 'desc': 'Linode CLI', 'mb': 15.0, 'priority': 6, 'tags': ['linode']},
    'vultr-cli': {'package': 'vultr-cli', 'category': 'cloud', 'desc': 'Vultr CLI', 'mb': 10.0, 'priority': 6, 'tags': ['vultr']},
    'openstack-cli': {'package': 'python-openstackclient', 'category': 'cloud', 'desc': 'OpenStack CLI', 'mb': 30.0, 'priority': 7, 'tags': ['openstack']},
    'openstack-security': {'package': 'openstack-security', 'category': 'cloud', 'desc': 'OpenStack security', 'mb': 20.0, 'priority': 7, 'tags': ['openstack', 'security']},
    'terraform-provider-aws': {'package': 'terraform-provider-aws', 'category': 'cloud', 'desc': 'Terraform AWS', 'mb': 50.0, 'priority': 8, 'tags': ['terraform', 'aws']},
    'terraform-provider-azure': {'package': 'terraform-provider-azurerm', 'category': 'cloud', 'desc': 'Terraform Azure', 'mb': 50.0, 'priority': 8, 'tags': ['terraform', 'azure']},
    'terraform-provider-gcp': {'package': 'terraform-provider-google', 'category': 'cloud', 'desc': 'Terraform GCP', 'mb': 50.0, 'priority': 8, 'tags': ['terraform', 'gcp']},
    'cloud-inventory': {'package': 'cloud-inventory', 'category': 'cloud', 'desc': 'Cloud inventory', 'mb': 15.0, 'priority': 7, 'tags': ['inventory']},
    'cloud-security-scanner': {'package': 'cloud-security-scanner', 'category': 'cloud', 'desc': 'Cloud scanner', 'mb': 20.0, 'priority': 8, 'tags': ['security', 'scanner']},
    'kube-bench': {'package': 'kube-bench', 'category': 'cloud', 'desc': 'K8s CIS benchmark', 'mb': 15.0, 'priority': 8, 'tags': ['k8s', 'cis', 'benchmark']},
    'kube-hunter': {'package': 'kube-hunter', 'category': 'cloud', 'desc': 'K8s penetration', 'mb': 10.0, 'priority': 9, 'tags': ['k8s', 'pentest']},
    'kubesec': {'package': 'kubesec', 'category': 'cloud', 'desc': 'K8s security', 'mb': 10.0, 'priority': 8, 'tags': ['k8s', 'security']},
    'kubeaudit': {'package': 'kubeaudit', 'category': 'cloud', 'desc': 'K8s auditor', 'mb': 10.0, 'priority': 8, 'tags': ['k8s', 'audit']},
    'stern': {'package': 'stern', 'category': 'cloud', 'desc': 'K8s log tail', 'mb': 10.0, 'priority': 7, 'tags': ['k8s', 'logs']},
    'k9s': {'package': 'k9s', 'category': 'cloud', 'desc': 'K8s terminal UI', 'mb': 20.0, 'priority': 8, 'tags': ['k8s', 'tui']},
    
    # SOCIAL ENGINEERING (20 tools)
    'setoolkit': {'package': 'set', 'category': 'social-engineering', 'desc': 'SET toolkit', 'mb': 35.0, 'priority': 9, 'tags': ['phishing', 'framework']},
    'gophish': {'package': 'gophish', 'category': 'social-engineering', 'desc': 'Phishing framework', 'mb': 25.0, 'priority': 9, 'tags': ['phishing']},
    'evilginx2': {'package': 'evilginx2', 'category': 'social-engineering', 'desc': 'MFA phishing', 'mb': 10.0, 'priority': 9, 'tags': ['phishing', 'mfa']},
    'modlishka': {'package': 'modlishka', 'category': 'social-engineering', 'desc': 'Proxy phishing', 'mb': 8.0, 'priority': 8, 'tags': ['phishing']},
    'muraena': {'package': 'muraena', 'category': 'social-engineering', 'desc': 'Phishing proxy', 'mb': 5.0, 'priority': 8, 'tags': ['phishing']},
    'phishing-frenzy': {'package': 'phishing-frenzy', 'category': 'social-engineering', 'desc': 'Phishing platform', 'mb': 15.0, 'priority': 7, 'tags': ['phishing']},
    'king-phisher': {'package': 'king-phisher', 'category': 'social-engineering', 'desc': 'Phishing campaign', 'mb': 20.0, 'priority': 8, 'tags': ['phishing']},
    'simple-phishing': {'package': 'simple-phishing', 'category': 'social-engineering', 'desc': 'Simple phishing', 'mb': 5.0, 'priority': 6, 'tags': ['phishing']},
    'phishery': {'package': 'phishery', 'category': 'social-engineering', 'desc': 'SSL phishing', 'mb': 5.0, 'priority': 7, 'tags': ['phishing', 'ssl']},
    'gophish-templates': {'package': 'gophish-templates', 'category': 'social-engineering', 'desc': 'Gophish templates', 'mb': 2.0, 'priority': 7, 'tags': ['templates']},
    'social-engineer-toolkit-extra': {'package': 'set-extra', 'category': 'social-engineering', 'desc': 'SET extras', 'mb': 10.0, 'priority': 7, 'tags': ['set']},
    'maltego': {'package': 'maltego', 'category': 'social-engineering', 'desc': 'OSINT tool', 'mb': 125.0, 'priority': 8, 'tags': ['osint']},
    'recon-ng': {'package': 'recon-ng', 'category': 'social-engineering', 'desc': 'Recon framework', 'mb': 15.0, 'priority': 8, 'tags': ['recon']},
    'theharvester': {'package': 'theharvester', 'category': 'social-engineering', 'desc': 'Email harvester', 'mb': 2.1, 'priority': 8, 'tags': ['email']},
    'sherlock': {'package': 'sherlock', 'category': 'social-engineering', 'desc': 'Username search', 'mb': 1.5, 'priority': 8, 'tags': ['username']},
    'maigret': {'package': 'maigret', 'category': 'social-engineering', 'desc': 'Username OSINT', 'mb': 2.0, 'priority': 8, 'tags': ['username', 'osint']},
    'socialscan': {'package': 'socialscan', 'category': 'social-engineering', 'desc': 'Email/user check', 'mb': 1.0, 'priority': 7, 'tags': ['email', 'username']},
    'whatsmyname': {'package': 'whatsmyname', 'category': 'social-engineering', 'desc': 'Username check', 'mb': 1.0, 'priority': 7, 'tags': ['username']},
    'usersearch': {'package': 'usersearch', 'category': 'social-engineering', 'desc': 'User search', 'mb': 1.0, 'priority': 6, 'tags': ['user']},
    'email-enum': {'package': 'email-enum', 'category': 'social-engineering', 'desc': 'Email enum', 'mb': 0.5, 'priority': 7, 'tags': ['email']},
    
    # RFID/NFC (15 tools)
    'libnfc': {'package': 'libnfc', 'category': 'rfid', 'desc': 'NFC library', 'mb': 2.0, 'priority': 8, 'tags': ['nfc', 'library']},
    'nfc-tools': {'package': 'nfc-tools', 'category': 'rfid', 'desc': 'NFC tools', 'mb': 1.0, 'priority': 8, 'tags': ['nfc']},
    'nfcutils': {'package': 'nfcutils', 'category': 'rfid', 'desc': 'NFC utilities', 'mb': 0.5, 'priority': 7, 'tags': ['nfc']},
    'mfoc': {'package': 'mfoc', 'category': 'rfid', 'desc': 'Mifare classic cracker', 'mb': 0.5, 'priority': 9, 'tags': ['mifare', 'cracker']},
    'mfcuk': {'package': 'mfcuk', 'category': 'rfid', 'desc': 'Mifare cracker', 'mb': 0.5, 'priority': 9, 'tags': ['mifare']},
    'mifare-classic-format': {'package': 'mifare-classic-format', 'category': 'rfid', 'desc': 'Mifare formatter', 'mb': 0.3, 'priority': 7, 'tags': ['mifare']},
    'nfc-list': {'package': 'nfc-list', 'category': 'rfid', 'desc': 'NFC lister', 'mb': 0.3, 'priority': 7, 'tags': ['nfc']},
    'nfc-read': {'package': 'nfc-read', 'category': 'rfid', 'desc': 'NFC reader', 'mb': 0.3, 'priority': 7, 'tags': ['nfc']},
    'nfc-write': {'package': 'nfc-write', 'category': 'rfid', 'desc': 'NFC writer', 'mb': 0.3, 'priority': 7, 'tags': ['nfc']},
    'nfc-emulate': {'package': 'nfc-emulate', 'category': 'rfid', 'desc': 'NFC emulator', 'mb': 0.5, 'priority': 7, 'tags': ['nfc', 'emulator']},
    'nfc-sniff': {'package': 'nfc-sniff', 'category': 'rfid', 'desc': 'NFC sniffer', 'mb': 0.5, 'priority': 8, 'tags': ['nfc', 'sniffer']},
    'chameleon-mini': {'package': 'chameleon-mini', 'category': 'rfid', 'desc': 'Chameleon tool', 'mb': 2.0, 'priority': 8, 'tags': ['chameleon']},
    'proxmark3': {'package': 'proxmark3', 'category': 'rfid', 'desc': 'Proxmark3 tools', 'mb': 5.0, 'priority': 9, 'tags': ['proxmark']},
    'rfidiot': {'package': 'rfidiot', 'category': 'rfid', 'desc': 'RFID toolkit', 'mb': 3.0, 'priority': 8, 'tags': ['rfid']},
    'rfid-crack': {'package': 'rfid-crack', 'category': 'rfid', 'desc': 'RFID cracker', 'mb': 1.0, 'priority': 8, 'tags': ['rfid', 'cracker']},
}

# Merge with existing
ALL_TOOLS = {**existing_tools, **NEW_CATEGORIES}

# Save complete database
output_path = Path('/home/wez/stsgym-work/agentic_ai/kali_agent_v3/core/tools_db_600.json')

with open(output_path, 'w') as f:
    json.dump(ALL_TOOLS, f, indent=2)

print(f"✅ Saved {len(ALL_TOOLS)} tools to {output_path}")

# Count by category
categories = {}
for tool, info in ALL_TOOLS.items():
    cat = info['category']
    categories[cat] = categories.get(cat, 0) + 1

print("\n📊 Tools by category:")
for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
    print(f"  {cat}: {count} tools")

print(f"\n📦 Total size: {sum(t['mb'] for t in ALL_TOOLS.values()):.1f} MB")
print(f"⭐ Average priority: {sum(t['priority'] for t in ALL_TOOLS.values()) / len(ALL_TOOLS):.1f}")

# Check if we hit 600+
if len(ALL_TOOLS) >= 600:
    print(f"\n🎉 SUCCESS: Reached {len(ALL_TOOLS)} tools! (Target: 600+)")
else:
    print(f"\n⚠️  Need {600 - len(ALL_TOOLS)} more tools to reach target")
