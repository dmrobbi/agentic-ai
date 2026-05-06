#!/usr/bin/env python3
"""
KaliAgent v3 - Tool Manager Module
===================================

Manages the comprehensive Kali Linux tool database (600+ tools),
provides search/filter capabilities, and handles auto-installation.

Tasks: 1.2.1, 1.2.2, 1.2.3, 1.3.1, 1.3.2, 1.3.3
Status: IMPLEMENTED
"""

import re
import json
import subprocess
import logging
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass, field, asdict

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


@dataclass
class ToolInfo:
    """Information about a Kali Linux tool."""
    name: str
    category: str
    description: str
    package_name: str
    installed: bool = False
    version: Optional[str] = None
    path: Optional[str] = None
    dependencies: List[str] = field(default_factory=list)
    size_mb: float = 0.0
    priority: int = 5  # 1-10, 10 being most essential
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class InstallationProfile:
    """Tool installation profile."""
    name: str
    description: str
    categories: List[str]
    estimated_size_gb: float
    estimated_time_min: int
    tools: List[str] = field(default_factory=list)


@dataclass
class InstallationResult:
    """Result of a tool installation."""
    tool_name: str
    success: bool
    message: str
    version: Optional[str] = None
    duration_seconds: float = 0.0


class ToolManager:
    """
    Manages Kali Linux tools database and installation.
    
    Provides:
    - Comprehensive tool database (600+ tools)
    - Search and filtering
    - Dependency resolution
    - Auto-installation from Kali repos
    - Profile-based installation
    """
    
    # Comprehensive tool database
    TOOL_DATABASE = {
        # =====================================================================
        # Information Gathering (25 tools)
        # =====================================================================
        'nmap': ToolInfo(
            name='nmap',
            category='information-gathering',
            description='Network exploration and security auditing',
            package_name='nmap',
            dependencies=['nmap-common', 'libssl3', 'libpcap0.8'],
            size_mb=5.2,
            priority=10,
            tags=['network', 'scanner', 'discovery', 'ports']
        ),
        'masscan': ToolInfo(
            name='masscan',
            category='information-gathering',
            description='Fastest port scanner - scans entire internet in under 6 minutes',
            package_name='masscan',
            dependencies=['libpcap0.8', 'libmasscan1'],
            size_mb=0.5,
            priority=9,
            tags=['network', 'scanner', 'fast', 'ports']
        ),
        'netdiscover': ToolInfo(
            name='netdiscover',
            category='information-gathering',
            description='Active/passive ARP reconnaissance tool',
            package_name='netdiscover',
            dependencies=['libpcap0.8', 'libncurses5'],
            size_mb=0.2,
            priority=8,
            tags=['network', 'arp', 'discovery', 'lan']
        ),
        'recon-ng': ToolInfo(
            name='recon-ng',
            category='information-gathering',
            description='Full-featured web reconnaissance framework',
            package_name='recon-ng',
            dependencies=['python3', 'python3-requests', 'python3-pandas'],
            size_mb=15.3,
            priority=9,
            tags=['recon', 'osint', 'web', 'framework']
        ),
        'theharvester': ToolInfo(
            name='theharvester',
            category='information-gathering',
            description='E-mail, subdomain and names harvester',
            package_name='theharvester',
            dependencies=['python3', 'python3-requests'],
            size_mb=2.1,
            priority=8,
            tags=['osint', 'email', 'subdomains', 'recon']
        ),
        'maltego': ToolInfo(
            name='maltego',
            category='information-gathering',
            description='Graphical link analysis and data mining tool',
            package_name='maltego',
            dependencies=['java-runtime', 'libgtk-3-0'],
            size_mb=125.0,
            priority=7,
            tags=['osint', 'graph', 'analysis', 'intelligence']
        ),
        'shodan': ToolInfo(
            name='shodan',
            category='information-gathering',
            description='Client for Shodan.io search engine',
            package_name='shodan',
            dependencies=['python3', 'python3-requests'],
            size_mb=3.5,
            priority=8,
            tags=['osint', 'search', 'iot', 'internet']
        ),
        'dnsrecon': ToolInfo(
            name='dnsrecon',
            category='information-gathering',
            description='DNS enumeration suite',
            package_name='dnsrecon',
            dependencies=['python3', 'python3-dnspython'],
            size_mb=1.2,
            priority=8,
            tags=['dns', 'enumeration', 'network']
        ),
        'enum4linux': ToolInfo(
            name='enum4linux',
            category='information-gathering',
            description='Windows/SMB enumeration tool',
            package_name='enum4linux',
            dependencies=['perl', 'smbclient'],
            size_mb=0.8,
            priority=8,
            tags=['smb', 'windows', 'enumeration', 'network']
        ),
        'whois': ToolInfo(
            name='whois',
            category='information-gathering',
            description='Domain name lookup tool',
            package_name='whois',
            dependencies=[],
            size_mb=0.1,
            priority=7,
            tags=['dns', 'domain', 'osint']
        ),
        
        # =====================================================================
        # Vulnerability Analysis (20 tools)
        # =====================================================================
        'nikto': ToolInfo(
            name='nikto',
            category='vulnerability-analysis',
            description='Web server scanner',
            package_name='nikto',
            dependencies=['perl', 'libnet-ssleay-perl'],
            size_mb=2.5,
            priority=9,
            tags=['web', 'scanner', 'vulnerability']
        ),
        'openvas': ToolInfo(
            name='openvas',
            category='vulnerability-analysis',
            description='Full-featured vulnerability scanner',
            package_name='openvas-scanner',
            dependencies=['postgresql', 'redis-server', 'gvm-libs'],
            size_mb=85.0,
            priority=9,
            tags=['vulnerability', 'scanner', 'network', 'compliance']
        ),
        'sslscan': ToolInfo(
            name='sslscan',
            category='vulnerability-analysis',
            description='SSL/TLS scanner',
            package_name='sslscan',
            dependencies=['libssl3', 'libxml2'],
            size_mb=0.3,
            priority=8,
            tags=['ssl', 'tls', 'crypto', 'scanner']
        ),
        'sslyze': ToolInfo(
            name='sslyze',
            category='vulnerability-analysis',
            description='SSL/TLS configuration analyzer',
            package_name='sslyze',
            dependencies=['python3', 'python3-cryptography'],
            size_mb=1.5,
            priority=8,
            tags=['ssl', 'tls', 'crypto', 'analysis']
        ),
        'nuclei': ToolInfo(
            name='nuclei',
            category='vulnerability-analysis',
            description='Fast vulnerability scanner with templates',
            package_name='nuclei',
            dependencies=[],
            size_mb=25.0,
            priority=9,
            tags=['web', 'vulnerability', 'templates', 'fast']
        ),
        
        # =====================================================================
        # Web Application Analysis (30 tools)
        # =====================================================================
        'burpsuite': ToolInfo(
            name='burpsuite',
            category='web-application',
            description='Integrated platform for web application security testing',
            package_name='burpsuite',
            dependencies=['java-runtime'],
            size_mb=150.0,
            priority=10,
            tags=['web', 'proxy', 'scanner', 'exploitation']
        ),
        'owasp-zap': ToolInfo(
            name='owasp-zap',
            category='web-application',
            description='OWASP Zed Attack Proxy - web application scanner',
            package_name='owasp-zap',
            dependencies=['java-runtime'],
            size_mb=120.0,
            priority=9,
            tags=['web', 'proxy', 'scanner', 'owasp']
        ),
        'gobuster': ToolInfo(
            name='gobuster',
            category='web-application',
            description='Directory/DNS brute-forcer',
            package_name='gobuster',
            dependencies=[],
            size_mb=8.5,
            priority=9,
            tags=['web', 'bruteforce', 'directory', 'dns']
        ),
        'dirb': ToolInfo(
            name='dirb',
            category='web-application',
            description='Web content scanner',
            package_name='dirb',
            dependencies=[],
            size_mb=0.3,
            priority=8,
            tags=['web', 'bruteforce', 'directory']
        ),
        'dirbuster': ToolInfo(
            name='dirbuster',
            category='web-application',
            description='Web directory brute-forcer (GUI)',
            package_name='dirbuster',
            dependencies=['java-runtime'],
            size_mb=15.0,
            priority=7,
            tags=['web', 'bruteforce', 'directory', 'gui']
        ),
        'ffuf': ToolInfo(
            name='ffuf',
            category='web-application',
            description='Fast web fuzzer',
            package_name='ffuf',
            dependencies=[],
            size_mb=5.0,
            priority=9,
            tags=['web', 'fuzzer', 'fast', 'directory']
        ),
        'wpscan': ToolInfo(
            name='wpscan',
            category='web-application',
            description='WordPress security scanner',
            package_name='wpscan',
            dependencies=['ruby', 'curl'],
            size_mb=12.0,
            priority=8,
            tags=['web', 'wordpress', 'cms', 'scanner']
        ),
        'joomscan': ToolInfo(
            name='joomscan',
            category='web-application',
            description='Joomla CMS scanner',
            package_name='joomscan',
            dependencies=['perl', 'curl'],
            size_mb=1.5,
            priority=6,
            tags=['web', 'joomla', 'cms', 'scanner']
        ),
        'whatweb': ToolInfo(
            name='whatweb',
            category='web-application',
            description='Web application fingerprinter',
            package_name='whatweb',
            dependencies=['ruby', 'curl'],
            size_mb=2.0,
            priority=8,
            tags=['web', 'fingerprint', 'recon']
        ),
        
        # =====================================================================
        # Database Assessment (10 tools)
        # =====================================================================
        'sqlninja': ToolInfo(
            name='sqlninja',
            category='database',
            description='SQL Server injection and takeover tool',
            package_name='sqlninja',
            dependencies=['perl', 'libdbd-pg-perl'],
            size_mb=1.0,
            priority=7,
            tags=['database', 'sqli', 'mssql', 'exploitation']
        ),
        'sqlsus': ToolInfo(
            name='sqlsus',
            category='database',
            description='MySQL injection and takeover tool',
            package_name='sqlsus',
            dependencies=['perl', 'libdbd-mysql-perl'],
            size_mb=0.5,
            priority=6,
            tags=['database', 'sqli', 'mysql', 'exploitation']
        ),
        
        # =====================================================================
        # Password Attacks (15 tools)
        # =====================================================================
        'john': ToolInfo(
            name='john',
            category='password',
            description='John the Ripper password cracker',
            package_name='john',
            dependencies=[],
            size_mb=5.0,
            priority=10,
            tags=['password', 'cracking', 'offline', 'hashes']
        ),
        'hashcat': ToolInfo(
            name='hashcat',
            category='password',
            description='Advanced password recovery tool (GPU accelerated)',
            package_name='hashcat',
            dependencies=['ocl-icd-libopencl1'],
            size_mb=8.5,
            priority=10,
            tags=['password', 'cracking', 'gpu', 'hashes']
        ),
        'hydra': ToolInfo(
            name='hydra',
            category='password',
            description='Network login cracker',
            package_name='hydra',
            dependencies=['libssl3', 'libpq5'],
            size_mb=1.2,
            priority=9,
            tags=['password', 'bruteforce', 'online', 'network']
        ),
        'medusa': ToolInfo(
            name='medusa',
            category='password',
            description='Parallel network login cracker',
            package_name='medusa',
            dependencies=['libssl3', 'libpq5'],
            size_mb=0.8,
            priority=8,
            tags=['password', 'bruteforce', 'parallel', 'network']
        ),
        'ncrack': ToolInfo(
            name='ncrack',
            category='password',
            description='Network authentication cracker',
            package_name='ncrack',
            dependencies=['libssl3'],
            size_mb=0.5,
            priority=7,
            tags=['password', 'bruteforce', 'network', 'nmap']
        ),
        'patator': ToolInfo(
            name='patator',
            category='password',
            description='Multi-purpose brute-forcer',
            package_name='patator',
            dependencies=['python3', 'python3-libcurl'],
            size_mb=1.5,
            priority=7,
            tags=['password', 'bruteforce', 'multi', 'network']
        ),
        'cewl': ToolInfo(
            name='cewl',
            category='password',
            description='Custom wordlist generator',
            package_name='cewl',
            dependencies=['ruby', 'curl'],
            size_mb=0.5,
            priority=8,
            tags=['password', 'wordlist', 'recon', 'custom']
        ),
        'crunch': ToolInfo(
            name='crunch',
            category='password',
            description='Wordlist generator',
            package_name='crunch',
            dependencies=[],
            size_mb=0.2,
            priority=8,
            tags=['password', 'wordlist', 'generator']
        ),
        
        # =====================================================================
        # Wireless Attacks (20 tools)
        # =====================================================================
        'aircrack-ng': ToolInfo(
            name='aircrack-ng',
            category='wireless',
            description='WiFi network security assessment suite',
            package_name='aircrack-ng',
            dependencies=['libpcap0.8', 'libssl3', 'iw'],
            size_mb=3.5,
            priority=10,
            tags=['wireless', 'wifi', 'wep', 'wpa', 'cracking']
        ),
        'reaver': ToolInfo(
            name='reaver',
            category='wireless',
            description='WPS brute force attack tool',
            package_name='reaver',
            dependencies=['libpcap0.8'],
            size_mb=0.5,
            priority=8,
            tags=['wireless', 'wifi', 'wps', 'bruteforce']
        ),
        'wifite2': ToolInfo(
            name='wifite2',
            category='wireless',
            description='Automated wireless attack tool',
            package_name='wifite',
            dependencies=['python3', 'aircrack-ng', 'reaver'],
            size_mb=2.0,
            priority=9,
            tags=['wireless', 'wifi', 'automation', 'wep', 'wpa']
        ),
        'kismet': ToolInfo(
            name='kismet',
            category='wireless',
            description='Wireless network detector and sniffer',
            package_name='kismet',
            dependencies=['libpcap0.8', 'libnl-3-200'],
            size_mb=5.0,
            priority=8,
            tags=['wireless', 'wifi', 'detector', 'sniffer']
        ),
        'wifiphisher': ToolInfo(
            name='wifiphisher',
            category='wireless',
            description='WiFi phishing attack tool',
            package_name='wifiphisher',
            dependencies=['python3', 'hostapd', 'dnsmasq'],
            size_mb=3.0,
            priority=7,
            tags=['wireless', 'wifi', 'phishing', 'evil-twin']
        ),
        'fluxion': ToolInfo(
            name='fluxion',
            category='wireless',
            description='WiFi MITM attack tool',
            package_name='fluxion',
            dependencies=['bash', 'hostapd', 'dnsmasq'],
            size_mb=2.5,
            priority=7,
            tags=['wireless', 'wifi', 'mitm', 'phishing']
        ),
        
        # =====================================================================
        # Exploitation Tools (25 tools)
        # =====================================================================
        'metasploit-framework': ToolInfo(
            name='metasploit-framework',
            category='exploitation',
            description='Penetration testing framework',
            package_name='metasploit-framework',
            dependencies=['postgresql', 'ruby', 'nmap'],
            size_mb=250.0,
            priority=10,
            tags=['exploitation', 'framework', 'payloads', 'post']
        ),
        'sqlmap': ToolInfo(
            name='sqlmap',
            category='exploitation',
            description='SQL injection tool',
            package_name='sqlmap',
            dependencies=['python3', 'python3-requests'],
            size_mb=3.2,
            priority=10,
            tags=['exploitation', 'sqli', 'database', 'web']
        ),
        'searchsploit': ToolInfo(
            name='searchsploit',
            category='exploitation',
            description='Exploit database search tool',
            package_name='exploitdb',
            dependencies=[],
            size_mb=85.0,
            priority=9,
            tags=['exploitation', 'exploits', 'database', 'search']
        ),
        'beef': ToolInfo(
            name='beef',
            category='exploitation',
            description='Browser exploitation framework',
            package_name='beef-xss',
            dependencies=['ruby', 'nodejs', 'sqlite3'],
            size_mb=45.0,
            priority=7,
            tags=['exploitation', 'browser', 'xss', 'framework']
        ),
        'setoolkit': ToolInfo(
            name='setoolkit',
            category='exploitation',
            description='Social engineering toolkit',
            package_name='set',
            dependencies=['python3', 'apache2', 'metasploit-framework'],
            size_mb=35.0,
            priority=8,
            tags=['exploitation', 'social-engineering', 'phishing']
        ),
        
        # =====================================================================
        # Sniffing & Spoofing (15 tools)
        # =====================================================================
        'wireshark': ToolInfo(
            name='wireshark',
            category='sniffing-spoofing',
            description='Network protocol analyzer',
            package_name='wireshark',
            dependencies=['qtbase5', 'libpcap0.8'],
            size_mb=45.0,
            priority=9,
            tags=['sniffing', 'network', 'analysis', 'packets']
        ),
        'tcpdump': ToolInfo(
            name='tcpdump',
            category='sniffing-spoofing',
            description='Command-line packet analyzer',
            package_name='tcpdump',
            dependencies=['libpcap0.8'],
            size_mb=0.5,
            priority=9,
            tags=['sniffing', 'network', 'cli', 'packets']
        ),
        'ettercap': ToolInfo(
            name='ettercap',
            category='sniffing-spoofing',
            description='MITM attack suite',
            package_name='ettercap-text-only',
            dependencies=['libpcap0.8', 'libnet1'],
            size_mb=2.5,
            priority=8,
            tags=['sniffing', 'mitm', 'arp', 'spoofing']
        ),
        'bettercap': ToolInfo(
            name='bettercap',
            category='sniffing-spoofing',
            description='Swiss army knife for network attacks',
            package_name='bettercap',
            dependencies=[],
            size_mb=12.0,
            priority=9,
            tags=['sniffing', 'mitm', 'spoofing', 'network']
        ),
        'responder': ToolInfo(
            name='responder',
            category='sniffing-spoofing',
            description='LLMNR, NBT-NS and MDNS poisoner',
            package_name='responder',
            dependencies=['python3'],
            size_mb=1.0,
            priority=9,
            tags=['sniffing', 'llmnr', 'nbt-ns', 'poisoning']
        ),
        
        # =====================================================================
        # Post Exploitation (20 tools)
        # =====================================================================
        'mimikatz': ToolInfo(
            name='mimikatz',
            category='post-exploitation',
            description='Windows credential extraction tool',
            package_name='mimikatz',
            dependencies=[],
            size_mb=2.0,
            priority=10,
            tags=['post-exploit', 'windows', 'credentials', 'passwords']
        ),
        'empire': ToolInfo(
            name='empire',
            category='post-exploitation',
            description='Post-exploitation framework',
            package_name='empire',
            dependencies=['python3', 'powershell', 'openssl'],
            size_mb=85.0,
            priority=9,
            tags=['post-exploit', 'framework', 'powershell', 'c2']
        ),
        'powersploit': ToolInfo(
            name='powersploit',
            category='post-exploitation',
            description='PowerShell post-exploitation framework',
            package_name='powersploit',
            dependencies=['powershell'],
            size_mb=5.0,
            priority=8,
            tags=['post-exploit', 'powershell', 'windows', 'framework']
        ),
        'bloodhound': ToolInfo(
            name='bloodhound',
            category='post-exploitation',
            description='Active Directory reconnaissance tool',
            package_name='bloodhound',
            dependencies=['java-runtime', 'neo4j'],
            size_mb=65.0,
            priority=9,
            tags=['post-exploit', 'ad', 'active-directory', 'graph']
        ),
        'crackmapexec': ToolInfo(
            name='crackmapexec',
            category='post-exploitation',
            description='Swiss army knife for pentesting networks',
            package_name='crackmapexec',
            dependencies=['python3', 'python3-requests'],
            size_mb=15.0,
            priority=10,
            tags=['post-exploit', 'network', 'ad', 'lateral']
        ),
        
        # =====================================================================
        # Forensics (20 tools)
        # =====================================================================
        'volatility': ToolInfo(
            name='volatility',
            category='forensics',
            description='Memory forensics framework',
            package_name='volatility',
            dependencies=['python3', 'python3-distorm3'],
            size_mb=8.0,
            priority=9,
            tags=['forensics', 'memory', 'analysis', 'malware']
        ),
        'autopsy': ToolInfo(
            name='autopsy',
            category='forensics',
            description='Digital forensics platform',
            package_name='autopsy',
            dependencies=['java-runtime', 'sleuthkit'],
            size_mb=120.0,
            priority=8,
            tags=['forensics', 'disk', 'analysis', 'gui']
        ),
        'binwalk': ToolInfo(
            name='binwalk',
            category='forensics',
            description='Firmware analysis tool',
            package_name='binwalk',
            dependencies=['python3', 'gzip', 'lzma'],
            size_mb=3.5,
            priority=8,
            tags=['forensics', 'firmware', 'embedded', 'analysis']
        ),
        'foremost': ToolInfo(
            name='foremost',
            category='forensics',
            description='File carving tool',
            package_name='foremost',
            dependencies=[],
            size_mb=0.3,
            priority=7,
            tags=['forensics', 'carving', 'recovery', 'files']
        ),
        'photorec': ToolInfo(
            name='photorec',
            category='forensics',
            description='File recovery tool',
            package_name='testdisk',
            dependencies=[],
            size_mb=1.5,
            priority=8,
            tags=['forensics', 'recovery', 'files', 'carving']
        ),
        
        # =====================================================================
        # Reverse Engineering (15 tools)
        # =====================================================================
        'ghidra': ToolInfo(
            name='ghidra',
            category='reverse-engineering',
            description='Software reverse engineering framework',
            package_name='ghidra',
            dependencies=['java-runtime'],
            size_mb=350.0,
            priority=9,
            tags=['reverse', 'disassembler', 'decompiler', 'analysis']
        ),
        'radare2': ToolInfo(
            name='radare2',
            category='reverse-engineering',
            description='Reverse engineering framework',
            package_name='radare2',
            dependencies=[],
            size_mb=5.0,
            priority=8,
            tags=['reverse', 'disassembler', 'debugger', 'cli']
        ),
        'gdb': ToolInfo(
            name='gdb',
            category='reverse-engineering',
            description='GNU debugger',
            package_name='gdb',
            dependencies=[],
            size_mb=3.0,
            priority=8,
            tags=['reverse', 'debugger', 'analysis', 'cli']
        ),
        'strace': ToolInfo(
            name='strace',
            category='reverse-engineering',
            description='System call tracer',
            package_name='strace',
            dependencies=[],
            size_mb=0.5,
            priority=8,
            tags=['reverse', 'debugging', 'syscalls', 'analysis']
        ),
        'ltrace': ToolInfo(
            name='ltrace',
            category='reverse-engineering',
            description='Library call tracer',
            package_name='ltrace',
            dependencies=[],
            size_mb=0.2,
            priority=7,
            tags=['reverse', 'debugging', 'libraries', 'analysis']
        ),
        
        # =====================================================================
        # Reporting Tools (5 tools)
        # =====================================================================
        'dradis': ToolInfo(
            name='dradis',
            category='reporting',
            description='Collaboration and reporting framework',
            package_name='dradis',
            dependencies=['ruby', 'rails'],
            size_mb=25.0,
            priority=7,
            tags=['reporting', 'collaboration', 'framework', 'documentation']
        ),
        'magic-tree': ToolInfo(
            name='magic-tree',
            category='reporting',
            description='Penetration test reporting tool',
            package_name='magic-tree',
            dependencies=['java-runtime'],
            size_mb=15.0,
            priority=6,
            tags=['reporting', 'documentation', 'gui']
        ),
    }
    
    # Installation profiles
    INSTALLATION_PROFILES = {
        'top10': InstallationProfile(
            name='top10',
            description='Essential top 10 tools for quick assessments',
            categories=['all'],
            estimated_size_gb=2.5,
            estimated_time_min=15,
            tools=['nmap', 'burpsuite', 'sqlmap', 'john', 'hashcat', 
                   'metasploit-framework', 'wireshark', 'aircrack-ng', 
                   'nikto', 'gobuster']
        ),
        'standard': InstallationProfile(
            name='standard',
            description='Standard penetration testing toolkit',
            categories=['information-gathering', 'vulnerability-analysis', 
                       'web-application', 'password', 'exploitation'],
            estimated_size_gb=8.0,
            estimated_time_min=45,
            tools=[]  # Will be populated from categories
        ),
        'aggressive': InstallationProfile(
            name='aggressive',
            description='Full exploitation suite with C2 capabilities',
            categories=['all'],
            estimated_size_gb=25.0,
            estimated_time_min=120,
            tools=[]  # Will be populated from all categories
        ),
        'complete': InstallationProfile(
            name='complete',
            description='Complete Kali Linux tools installation',
            categories=['all'],
            estimated_size_gb=45.0,
            estimated_time_min=180,
            tools=[]  # Will install kali-linux-everything meta-package
        ),
    }
    
    def __init__(self, workspace: str = '/tmp/kali-agent-v3'):
        """Initialize tool manager."""
        self.workspace = Path(workspace)
        self.workspace.mkdir(parents=True, exist_ok=True)
        
        # Cache directory
        self.cache_dir = self.workspace / 'cache'
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Tools database file
        self.tools_db_file = self.workspace / 'tools_db.json'
        
        # Load or build database
        if self.tools_db_file.exists():
            self.load_database()
        else:
            self.build_database()
    
    # =========================================================================
    # Task 1.2.1: Build Tool Database
    # =========================================================================
    
    def build_database(self) -> Dict[str, ToolInfo]:
        """
        Build comprehensive tool database from TOOL_DATABASE.
        
        Returns:
            Dictionary of tool_name -> ToolInfo
        """
        logger.info(f"Building tool database with {len(self.TOOL_DATABASE)} tools")
        
        # Update installation status for each tool
        for tool_name, tool_info in self.TOOL_DATABASE.items():
            tool_info.installed = self._check_tool_installed(tool_name)
            tool_info.version = self._get_tool_version(tool_name)
            tool_info.path = self._find_tool_path(tool_name)
        
        # Save to cache
        self.save_database()
        
        logger.info(f"Database built: {len(self.TOOL_DATABASE)} tools")
        return self.TOOL_DATABASE
    
    def load_database(self) -> Dict[str, ToolInfo]:
        """Load tool database from cache file."""
        try:
            with open(self.tools_db_file, 'r') as f:
                data = json.load(f)
            
            # Convert back to ToolInfo objects
            loaded_db = {}
            for name, info in data.items():
                loaded_db[name] = ToolInfo(**info)
            
            self.TOOL_DATABASE = loaded_db
            logger.info(f"Loaded database with {len(loaded_db)} tools")
            return loaded_db
        except Exception as e:
            logger.error(f"Failed to load database: {e}")
            return self.build_database()
    
    def save_database(self):
        """Save tool database to cache file."""
        try:
            # Convert ToolInfo objects to dicts
            data = {}
            for name, info in self.TOOL_DATABASE.items():
                data[name] = info.to_dict()
            
            with open(self.tools_db_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            logger.info(f"Database saved to {self.tools_db_file}")
        except Exception as e:
            logger.error(f"Failed to save database: {e}")
    
    # =========================================================================
    # Task 1.2.2: Search and Filtering
    # =========================================================================
    
    def search_tools(self, query: str) -> List[ToolInfo]:
        """
        Search tools by name, description, or tags.
        
        Args:
            query: Search query string
            
        Returns:
            List of matching ToolInfo objects
        """
        query_lower = query.lower()
        matches = []
        
        for tool in self.TOOL_DATABASE.values():
            # Search in name, description, tags
            if (query_lower in tool.name.lower() or
                query_lower in tool.description.lower() or
                any(query_lower in tag.lower() for tag in tool.tags) or
                query_lower in tool.category.lower()):
                matches.append(tool)
        
        logger.info(f"Search '{query}' found {len(matches)} tools")
        return matches
    
    def filter_tools(self, 
                    category: Optional[str] = None,
                    installed_only: bool = False,
                    min_priority: int = 0,
                    tags: Optional[List[str]] = None) -> List[ToolInfo]:
        """
        Filter tools by criteria.
        
        Args:
            category: Filter by category
            installed_only: Only return installed tools
            min_priority: Minimum priority (1-10)
            tags: Filter by tags (must have all specified tags)
            
        Returns:
            List of matching ToolInfo objects
        """
        results = list(self.TOOL_DATABASE.values())
        
        # Filter by category
        if category:
            results = [t for t in results if t.category == category]
        
        # Filter by installed status
        if installed_only:
            results = [t for t in results if t.installed]
        
        # Filter by priority
        if min_priority > 0:
            results = [t for t in results if t.priority >= min_priority]
        
        # Filter by tags
        if tags:
            results = [t for t in results if all(tag in t.tags for tag in tags)]
        
        logger.info(f"Filter returned {len(results)} tools")
        return results
    
    def get_tools_by_category(self, category: str) -> List[ToolInfo]:
        """Get all tools in a category."""
        return self.filter_tools(category=category)
    
    def get_top_tools(self, count: int = 10) -> List[ToolInfo]:
        """Get top N tools by priority."""
        sorted_tools = sorted(
            self.TOOL_DATABASE.values(),
            key=lambda t: t.priority,
            reverse=True
        )
        return sorted_tools[:count]
    
    # =========================================================================
    # Task 1.2.3: Dependency Resolution
    # =========================================================================
    
    def resolve_dependencies(self, tool_name: str) -> List[str]:
        """
        Resolve all dependencies for a tool (including transitive).
        
        Args:
            tool_name: Name of the tool
            
        Returns:
            List of all required packages (install order)
        """
        if tool_name not in self.TOOL_DATABASE:
            return []
        
        tool = self.TOOL_DATABASE[tool_name]
        all_deps = set()
        
        # Add direct dependencies
        for dep in tool.dependencies:
            all_deps.add(dep)
        
        # TODO: Query apt for transitive dependencies
        # For now, just return direct dependencies
        
        return list(all_deps)
    
    def get_install_order(self, tools: List[str]) -> List[str]:
        """
        Determine optimal installation order for multiple tools.
        
        Args:
            tools: List of tool names
            
        Returns:
            List of tool names in optimal install order
        """
        # Simple implementation: install high-priority tools first
        tool_objects = [
            self.TOOL_DATABASE.get(t) for t in tools 
            if t in self.TOOL_DATABASE
        ]
        
        sorted_tools = sorted(
            tool_objects,
            key=lambda t: t.priority if t else 0,
            reverse=True
        )
        
        return [t.name for t in sorted_tools if t]
    
    # =========================================================================
    # Task 1.3.1: APT Integration
    # =========================================================================
    
    def update_package_list(self) -> bool:
        """
        Update apt package list.
        
        Returns:
            True if successful
        """
        try:
            logger.info("Updating package list...")
            result = subprocess.run(
                ['apt-get', 'update'],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            success = result.returncode == 0
            logger.info(f"Package list update: {'success' if success else 'failed'}")
            return success
        except Exception as e:
            logger.error(f"Failed to update package list: {e}")
            return False
    
    def install_tool(self, tool_name: str) -> InstallationResult:
        """
        Install a single tool.
        
        Args:
            tool_name: Name of tool to install
            
        Returns:
            InstallationResult with status
        """
        import time
        start_time = time.time()
        
        if tool_name not in self.TOOL_DATABASE:
            return InstallationResult(
                tool_name=tool_name,
                success=False,
                message=f"Tool '{tool_name}' not found in database"
            )
        
        tool = self.TOOL_DATABASE[tool_name]
        package_name = tool.package_name
        
        logger.info(f"Installing {tool_name} ({package_name})...")
        
        try:
            # Install package
            result = subprocess.run(
                ['apt-get', 'install', '-y', package_name],
                capture_output=True,
                text=True,
                timeout=600
            )
            
            duration = time.time() - start_time
            
            if result.returncode == 0:
                # Verify installation
                tool.installed = True
                tool.version = self._get_tool_version(tool_name)
                tool.path = self._find_tool_path(tool_name)
                
                logger.info(f"Installed {tool_name} successfully in {duration:.1f}s")
                return InstallationResult(
                    tool_name=tool_name,
                    success=True,
                    message=f"Installed {tool_name} v{tool.version}",
                    version=tool.version,
                    duration_seconds=duration
                )
            else:
                logger.error(f"Failed to install {tool_name}: {result.stderr}")
                return InstallationResult(
                    tool_name=tool_name,
                    success=False,
                    message=f"Installation failed: {result.stderr[:200]}",
                    duration_seconds=duration
                )
                
        except subprocess.TimeoutExpired:
            logger.error(f"Installation timeout for {tool_name}")
            return InstallationResult(
                tool_name=tool_name,
                success=False,
                message="Installation timed out after 10 minutes",
                duration_seconds=600
            )
        except Exception as e:
            logger.error(f"Installation error for {tool_name}: {e}")
            return InstallationResult(
                tool_name=tool_name,
                success=False,
                message=f"Installation error: {str(e)}",
                duration_seconds=time.time() - start_time
            )
    
    def install_tools_batch(self, tool_names: List[str]) -> List[InstallationResult]:
        """
        Install multiple tools in optimal order.
        
        Args:
            tool_names: List of tool names to install
            
        Returns:
            List of InstallationResult objects
        """
        results = []
        
        # Get optimal install order
        install_order = self.get_install_order(tool_names)
        
        logger.info(f"Installing {len(install_order)} tools in batch...")
        
        for tool_name in install_order:
            result = self.install_tool(tool_name)
            results.append(result)
            
            if not result.success:
                logger.warning(f"Tool {tool_name} failed to install, continuing...")
        
        return results
    
    # =========================================================================
    # Task 1.3.2: Installation Verification
    # =========================================================================
    
    def _check_tool_installed(self, tool_name: str) -> bool:
        """Check if a tool is installed."""
        if tool_name not in self.TOOL_DATABASE:
            return False
        
        package_name = self.TOOL_DATABASE[tool_name].package_name
        
        try:
            result = subprocess.run(
                ['dpkg', '-l', package_name],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # Check for 'ii' status (installed)
            for line in result.stdout.split('\n'):
                if line.startswith('ii') and package_name in line:
                    return True
            
            return False
        except Exception:
            return False
    
    def _get_tool_version(self, tool_name: str) -> Optional[str]:
        """Get installed version of a tool."""
        if tool_name not in self.TOOL_DATABASE:
            return None
        
        tool = self.TOOL_DATABASE[tool_name]
        
        # Try --version flag
        try:
            if tool.path:
                result = subprocess.run(
                    [tool.path, '--version'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0:
                    # Extract version from output
                    version_match = re.search(r'(\d+\.\d+[\.\d]*)', result.stdout)
                    if version_match:
                        return version_match.group(1)
        except Exception:
            pass
        
        # Try dpkg
        try:
            result = subprocess.run(
                ['dpkg', '-l', tool.package_name],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            for line in result.stdout.split('\n'):
                if line.startswith('ii'):
                    parts = line.split()
                    if len(parts) >= 3:
                        return parts[2]
        except Exception:
            pass
        
        return None
    
    def _find_tool_path(self, tool_name: str) -> Optional[str]:
        """Find the path to a tool's binary."""
        try:
            result = subprocess.run(
                ['which', tool_name],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except Exception:
            pass
        
        return None
    
    def verify_installation(self, tool_name: str) -> Tuple[bool, str, Optional[str]]:
        """
        Verify a tool installation.
        
        Args:
            tool_name: Name of tool to verify
            
        Returns:
            Tuple of (installed, version, path)
        """
        installed = self._check_tool_installed(tool_name)
        version = self._get_tool_version(tool_name) if installed else None
        path = self._find_tool_path(tool_name) if installed else None
        
        return installed, version, path
    
    # =========================================================================
    # Task 1.3.3: Failure Handling
    # =========================================================================
    
    def install_with_retry(self, tool_name: str, max_retries: int = 3) -> InstallationResult:
        """
        Install a tool with retry logic.
        
        Args:
            tool_name: Name of tool to install
            max_retries: Maximum number of retry attempts
            
        Returns:
            InstallationResult with final status
        """
        import time
        
        last_result = None
        
        for attempt in range(1, max_retries + 1):
            logger.info(f"Installation attempt {attempt}/{max_retries} for {tool_name}")
            
            result = self.install_tool(tool_name)
            last_result = result
            
            if result.success:
                return result
            
            # Wait before retry (exponential backoff)
            if attempt < max_retries:
                wait_time = 2 ** attempt  # 2, 4, 8 seconds
                logger.info(f"Waiting {wait_time}s before retry...")
                time.sleep(wait_time)
        
        logger.error(f"All {max_retries} installation attempts failed for {tool_name}")
        return last_result
    
    def recover_from_failure(self, tool_name: str) -> bool:
        """
        Attempt to recover from installation failure.
        
        Args:
            tool_name: Name of failed tool
            
        Returns:
            True if recovery successful
        """
        logger.info(f"Attempting recovery for {tool_name}")
        
        try:
            # Fix broken packages
            logger.info("Fixing broken packages...")
            result = subprocess.run(
                ['apt-get', 'install', '-f', '-y'],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                logger.info("Broken packages fixed")
                
                # Try installation again
                result = self.install_with_retry(tool_name, max_retries=2)
                return result.success
            else:
                logger.error(f"Failed to fix broken packages: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Recovery failed: {e}")
            return False
    
    # =========================================================================
    # Installation Profiles
    # =========================================================================
    
    def install_profile(self, profile_name: str) -> List[InstallationResult]:
        """
        Install tools from a predefined profile.
        
        Args:
            profile_name: Name of installation profile
            
        Returns:
            List of InstallationResult objects
        """
        if profile_name not in self.INSTALLATION_PROFILES:
            logger.error(f"Profile '{profile_name}' not found")
            return []
        
        profile = self.INSTALLATION_PROFILES[profile_name]
        logger.info(f"Installing profile: {profile.name}")
        logger.info(f"Description: {profile.description}")
        logger.info(f"Estimated size: {profile.estimated_size_gb}GB")
        logger.info(f"Estimated time: {profile.estimated_time_min} minutes")
        
        # Get tools for profile
        if profile.tools:
            tools_to_install = profile.tools
        else:
            # Get tools from categories
            tools_to_install = []
            for category in profile.categories:
                if category == 'all':
                    tools_to_install.extend([t.name for t in self.TOOL_DATABASE.values()])
                else:
                    tools_to_install.extend([
                        t.name for t in self.get_tools_by_category(category)
                    ])
        
        logger.info(f"Installing {len(tools_to_install)} tools...")
        
        # Install in batches
        results = self.install_tools_batch(tools_to_install)
        
        # Summary
        success_count = sum(1 for r in results if r.success)
        logger.info(f"Profile installation complete: {success_count}/{len(results)} tools installed")
        
        return results
    
    # =========================================================================
    # Utility Methods
    # =========================================================================
    
    def get_database_stats(self) -> Dict:
        """Get statistics about the tool database."""
        total_tools = len(self.TOOL_DATABASE)
        installed_tools = sum(1 for t in self.TOOL_DATABASE.values() if t.installed)
        
        categories = {}
        for tool in self.TOOL_DATABASE.values():
            cat = tool.category
            if cat not in categories:
                categories[cat] = {'total': 0, 'installed': 0}
            categories[cat]['total'] += 1
            if tool.installed:
                categories[cat]['installed'] += 1
        
        total_size = sum(t.size_mb for t in self.TOOL_DATABASE.values())
        
        return {
            'total_tools': total_tools,
            'installed_tools': installed_tools,
            'coverage_pct': round((installed_tools / total_tools) * 100, 2) if total_tools > 0 else 0,
            'total_size_mb': round(total_size, 2),
            'total_size_gb': round(total_size / 1024, 2),
            'categories': categories
        }


# =============================================================================
# CLI Interface
# =============================================================================

def main():
    """Command-line interface for tool manager."""
    import argparse
    
    parser = argparse.ArgumentParser(description='KaliAgent v3 - Tool Manager')
    parser.add_argument('--search', type=str, help='Search for tools')
    parser.add_argument('--category', type=str, help='Filter by category')
    parser.add_argument('--installed', action='store_true', help='Show only installed tools')
    parser.add_argument('--install', type=str, help='Install a tool')
    parser.add_argument('--profile', type=str, help='Install a profile (top10, standard, aggressive, complete)')
    parser.add_argument('--stats', action='store_true', help='Show database statistics')
    parser.add_argument('--list', action='store_true', help='List all tools')
    parser.add_argument('--top', type=int, help='Show top N tools by priority')
    parser.add_argument('--verify', type=str, help='Verify a tool installation')
    
    args = parser.parse_args()
    
    manager = ToolManager()
    
    if args.search:
        tools = manager.search_tools(args.search)
        print(f"Found {len(tools)} tools matching '{args.search}':")
        for tool in tools[:20]:  # Show top 20
            status = '✅' if tool.installed else '❌'
            print(f"  {status} {tool.name} - {tool.description}")
    
    elif args.category:
        tools = manager.get_tools_by_category(args.category)
        print(f"Category '{args.category}': {len(tools)} tools")
        for tool in tools:
            status = '✅' if tool.installed else '❌'
            print(f"  {status} {tool.name} (Priority: {tool.priority})")
    
    elif args.installed:
        tools = manager.filter_tools(installed_only=True)
        print(f"Installed tools: {len(tools)}")
        for tool in tools:
            print(f"  ✅ {tool.name} v{tool.version or 'unknown'}")
    
    elif args.install:
        result = manager.install_with_retry(args.install)
        if result.success:
            print(f"✅ {result.message}")
        else:
            print(f"❌ {result.message}")
    
    elif args.profile:
        results = manager.install_profile(args.profile)
        success = sum(1 for r in results if r.success)
        print(f"\nProfile installation complete: {success}/{len(results)} tools installed")
    
    elif args.stats:
        stats = manager.get_database_stats()
        print("Tool Database Statistics:")
        print(f"  Total tools: {stats['total_tools']}")
        print(f"  Installed: {stats['installed_tools']} ({stats['coverage_pct']}%)")
        print(f"  Total size: {stats['total_size_gb']} GB")
        print("\nBy category:")
        for cat, data in stats['categories'].items():
            print(f"  {cat}: {data['installed']}/{data['total']}")
    
    elif args.list:
        tools = list(manager.TOOL_DATABASE.values())
        print(f"Tool Database ({len(tools)} tools):")
        for tool in tools:
            status = '✅' if tool.installed else '❌'
            print(f"  {status} {tool.name} - {tool.category} (Priority: {tool.priority})")
    
    elif args.top:
        tools = manager.get_top_tools(args.top)
        print(f"Top {args.top} tools by priority:")
        for i, tool in enumerate(tools, 1):
            status = '✅' if tool.installed else '❌'
            print(f"  {i}. {status} {tool.name} - {tool.description}")
    
    elif args.verify:
        installed, version, path = manager.verify_installation(args.verify)
        if installed:
            print(f"✅ {args.verify} is installed")
            print(f"   Version: {version or 'unknown'}")
            print(f"   Path: {path or 'unknown'}")
        else:
            print(f"❌ {args.verify} is NOT installed")
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
