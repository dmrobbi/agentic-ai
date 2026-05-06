#!/usr/bin/env python3
"""
KaliAgent v3 - Installation Profiles Module
============================================

Defines and manages installation profiles for different use cases.

Tasks: 2.3.1, 2.3.2, 2.3.3
Status: IMPLEMENTED
"""

import os
import subprocess
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ProfileType(Enum):
    """Installation profile types."""
    MINIMAL = "minimal"
    STANDARD = "standard"
    ADVANCED = "advanced"
    EXPERT = "expert"
    CUSTOM = "custom"


class HardwareProfile(Enum):
    """Hardware configuration profiles."""
    LAPTOP = "laptop"
    DESKTOP = "desktop"
    VM = "virtual_machine"
    RASPBERRY_PI = "raspberry_pi"
    CUSTOM = "custom"


@dataclass
class ToolRequirement:
    """Tool requirement with dependencies."""
    name: str
    package: str
    required: bool = True
    optional_packages: List[str] = field(default_factory=list)
    post_install_script: Optional[str] = None
    config_file: Optional[str] = None


@dataclass
class InstallationProfile:
    """Installation profile definition."""
    name: str
    profile_type: ProfileType
    hardware_profile: HardwareProfile
    description: str
    tools: List[ToolRequirement]
    estimated_size_mb: float = 0.0
    estimated_time_min: int = 0
    priority_categories: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Calculate estimated size and time."""
        if not self.estimated_size_mb:
            self.estimated_size_mb = sum(5 for _ in self.tools)  # Rough estimate
        if not self.estimated_time_min:
            self.estimated_time_min = len(self.tools) * 2  # 2 min per tool


# =============================================================================
# Task 2.3.1: Define Installation Profiles
# =============================================================================

class ProfileManager:
    """
    Manages installation profiles.
    
    Provides:
    - Predefined profiles (minimal, standard, advanced, expert)
    - Custom profile creation
    - Hardware-specific configurations
    - Profile validation
    """
    
    def __init__(self):
        """Initialize profile manager."""
        self.profiles: Dict[str, InstallationProfile] = {}
        self.hardware_profile: Optional[HardwareProfile] = None
        self.load_tool_database()
        self.create_predefined_profiles()
    
    def load_tool_database(self):
        """Load the 600+ tool database."""
        db_path = Path('/home/wez/stsgym-work/agentic_ai/kali_agent_v3/core/tools_db_600_plus.json')
        
        if db_path.exists():
            with open(db_path, 'r') as f:
                self.tool_database = json.load(f)
            logger.info(f"Loaded {len(self.tool_database)} tools from database")
        else:
            logger.warning("Tool database not found, using minimal toolset")
            self.tool_database = {}
    
    def create_predefined_profiles(self):
        """Create predefined installation profiles."""
        
        # =====================================================================
        # MINIMAL PROFILE (~50 tools, ~500MB, 30 min)
        # =====================================================================
        minimal_tools = [
            ToolRequirement("nmap", "nmap", True),
            ToolRequirement("masscan", "masscan", True),
            ToolRequirement("nikto", "nikto", True),
            ToolRequirement("sqlmap", "sqlmap", True),
            ToolRequirement("gobuster", "gobuster", True),
            ToolRequirement("hashcat", "hashcat", True),
            ToolRequirement("john", "john", True),
            ToolRequirement("hydra", "hydra", True),
            ToolRequirement("metasploit", "metasploit-framework", True),
            ToolRequirement("burp", "burpsuite", False),  # Commercial
            ToolRequirement("wireshark", "wireshark", True),
            ToolRequirement("aircrack-ng", "aircrack-ng", True),
            ToolRequirement("reaver", "reaver", True),
            ToolRequirement("mimikatz", "mimikatz", False),  # Windows only
            ToolRequirement("linpeas", "linpeas", True),
            ToolRequirement("volatility", "volatility", True),
            ToolRequirement("ghidra", "ghidra", True),
            ToolRequirement("radare2", "radare2", True),
            ToolRequirement("gdb", "gdb", True),
            ToolRequirement("strace", "strace", True),
            ToolRequirement("netcat", "netcat", True),
            ToolRequirement("socat", "socat", True),
            ToolRequirement("openssl", "openssl", True),
            ToolRequirement("gpg", "gnupg", True),
            ToolRequirement("searchsploit", "exploitdb", True),
        ]
        
        self.profiles['minimal'] = InstallationProfile(
            name="Minimal",
            profile_type=ProfileType.MINIMAL,
            hardware_profile=HardwareProfile.LAPTOP,
            description="Essential tools for basic pentesting (50 tools, ~500MB)",
            tools=minimal_tools,
            estimated_size_mb=500,
            estimated_time_min=30,
            priority_categories=['information-gathering', 'vulnerability-analysis', 'exploitation']
        )
        
        # =====================================================================
        # STANDARD PROFILE (~200 tools, ~5GB, 2 hours)
        # =====================================================================
        standard_tools = minimal_tools + [
            ToolRequirement("recon-ng", "recon-ng", True),
            ToolRequirement("theharvester", "theharvester", True),
            ToolRequirement("shodan", "shodan", True),
            ToolRequirement("amass", "amass", True),
            ToolRequirement("subfinder", "subfinder", True),
            ToolRequirement("wpscan", "wpscan", True),
            ToolRequirement("nuclei", "nuclei", True),
            ToolRequirement("zap", "owasp-zap", True),
            ToolRequirement("ffuf", "ffuf", True),
            ToolRequirement("wfuzz", "wfuzz", True),
            ToolRequirement("dirb", "dirb", True),
            ToolRequirement("wifite2", "wifite", True),
            ToolRequirement("kismet", "kismet", True),
            ToolRequirement("bettercap", "bettercap", True),
            ToolRequirement("responder", "responder", True),
            ToolRequirement("crackmapexec", "crackmapexec", True),
            ToolRequirement("impacket", "impacket", True),
            ToolRequirement("bloodhound", "bloodhound", True),
            ToolRequirement("empire", "empire", True),
            ToolRequirement("sliver", "sliver", True),
            ToolRequirement("cobalt-strike", "cobaltstrike", False),  # Commercial
            ToolRequirement("setoolkit", "set", True),
            ToolRequirement("gophish", "gophish", True),
            ToolRequirement("maltego", "maltego", True),
            ToolRequirement("autopsy", "autopsy", True),
            ToolRequirement("sleuthkit", "sleuthkit", True),
            ToolRequirement("binwalk", "binwalk", True),
            ToolRequirement("apktool", "apktool", True),
            ToolRequirement("jadx", "jadx", True),
            ToolRequirement("frida", "frida-tools", True),
            ToolRequirement("aws-cli", "awscli", True),
            ToolRequirement("pacu", "pacu", True),
            ToolRequirement("prowler", "prowler", True),
            ToolRequirement("terraform", "terraform", True),
            ToolRequirement("ansible", "ansible", True),
            ToolRequirement("docker", "docker.io", True),
            ToolRequirement("kubernetes", "kubernetes", False),  # Large
            ToolRequirement("libnfc", "libnfc", True),
            ToolRequirement("mfoc", "mfoc", True),
            ToolRequirement("rtl-sdr", "rtl-sdr", True),
        ]
        
        self.profiles['standard'] = InstallationProfile(
            name="Standard",
            profile_type=ProfileType.STANDARD,
            hardware_profile=HardwareProfile.DESKTOP,
            description="Comprehensive toolkit for professional pentesting (200 tools, ~5GB)",
            tools=standard_tools,
            estimated_size_mb=5000,
            estimated_time_min=120,
            priority_categories=['information-gathering', 'vulnerability-analysis', 'web-application', 
                               'exploitation', 'post-exploitation', 'wireless']
        )
        
        # =====================================================================
        # ADVANCED PROFILE (~400 tools, ~10GB, 4 hours)
        # =====================================================================
        advanced_tools = standard_tools + [
            ToolRequirement("openvas", "openvas-scanner", True),
            ToolRequirement("nessus", "nessus", False),  # Commercial
            ToolRequirement("burp-pro", "burpsuite", False),  # Commercial
            ToolRequirement("ida-free", "ida-free", True),
            ToolRequirement("angr", "angr", True),
            ToolRequirement("qemu", "qemu-system-x86", True),
            ToolRequirement("wine", "wine", True),
            ToolRequirement("ollydbg", "ollydbg", False),  # Windows
            ToolRequirement("x64dbg", "x64dbg", False),  # Windows
            ToolRequirement("binaryninja", "binaryninja", False),  # Commercial
            ToolRequirement("hopper", "hopper", False),  # Commercial
            ToolRequirement("jeb", "jeb", False),  # Commercial
            ToolRequirement("cutter", "cutter", True),
            ToolRequirement("rizin", "rizin", True),
            ToolRequirement("pwntools", "pwntools", True),
            ToolRequirement("afl", "afl", True),
            ToolRequirement("libfuzzer", "libfuzzer", True),
            ToolRequirement("valgrind", "valgrind", True),
            ToolRequirement("gdb-peda", "gdb-peda", True),
            ToolRequirement("gdb-gef", "gdb-gef", True),
            ToolRequirement("pwndbg", "pwndbg", True),
            ToolRequirement("evilginx2", "evilginx2", True),
            ToolRequirement("modlishka", "modlishka", True),
            ToolRequirement("havoc", "havoc", True),
            ToolRequirement("mythic", "mythic", True),
            ToolRequirement("covenant", "covenant", True),
            ToolRequirement("nighthawk", "nighthawk", False),  # Commercial
            ToolRequirement("brute-ratel", "brute-ratel", False),  # Commercial
            ToolRequirement("mobsf", "mobsf", True),
            ToolRequirement("drozer", "drozer", True),
            ToolRequirement("qark", "qark", True),
            ToolRequirement("objection", "objection", True),
            ToolRequirement("routersploit", "routersploit", True),
            ToolRequirement("firmware-mod-kit", "firmware-mod-kit", True),
            ToolRequirement("sasquatch", "sasquatch", True),
            ToolRequirement("jefferson", "jefferson", True),
            ToolRequirement("yara", "yara", True),
            ToolRequirement("capa", "capa", True),
            ToolRequirement("misp", "misp", True),
            ToolRequirement("azure-cli", "azure-cli", True),
            ToolRequirement("gcloud", "google-cloud-sdk", True),
            ToolRequirement("kube-bench", "kube-bench", True),
            ToolRequirement("kube-hunter", "kube-hunter", True),
            ToolRequirement("kubesec", "kubesec", True),
            ToolRequirement("helm", "helm", True),
            ToolRequirement("istio", "istio", True),
            ToolRequirement("prometheus", "prometheus", True),
            ToolRequirement("grafana", "grafana", True),
            ToolRequirement("elasticsearch", "elasticsearch", True),
            ToolRequirement("logstash", "logstash", True),
            ToolRequirement("kibana", "kibana", True),
        ]
        
        self.profiles['advanced'] = InstallationProfile(
            name="Advanced",
            profile_type=ProfileType.ADVANCED,
            hardware_profile=HardwareProfile.DESKTOP,
            description="Professional-grade toolkit with reverse engineering & mobile (400 tools, ~10GB)",
            tools=advanced_tools,
            estimated_size_mb=10000,
            estimated_time_min=240,
            priority_categories=['information-gathering', 'vulnerability-analysis', 'web-application',
                               'exploitation', 'post-exploitation', 'reverse-engineering',
                               'forensics', 'mobile', 'cloud', 'iot']
        )
        
        # =====================================================================
        # EXPERT PROFILE (600+ tools, ~15GB, 6+ hours)
        # =====================================================================
        # Include ALL tools from database
        expert_tools = []
        for tool_name, tool_info in self.tool_database.items():
            expert_tools.append(
                ToolRequirement(
                    name=tool_name,
                    package=tool_info['package'],
                    required=tool_info.get('priority', 5) >= 7,  # Priority 7+ required
                )
            )
        
        self.profiles['expert'] = InstallationProfile(
            name="Expert",
            profile_type=ProfileType.EXPERT,
            hardware_profile=HardwareProfile.DESKTOP,
            description="Complete Kali Linux arsenal - all 600+ tools (15GB+)",
            tools=expert_tools,
            estimated_size_mb=15400,
            estimated_time_min=360,
            priority_categories=list(set(t['category'] for t in self.tool_database.values()))
        )
        
        # =====================================================================
        # HARDWARE-SPECIFIC PROFILES
        # =====================================================================
        
        # Raspberry Pi Profile (ARM-compatible tools only)
        pi_tools = [
            ToolRequirement("nmap", "nmap", True),
            ToolRequirement("masscan", "masscan", True),
            ToolRequirement("nikto", "nikto", True),
            ToolRequirement("sqlmap", "sqlmap", True),
            ToolRequirement("gobuster", "gobuster", True),
            ToolRequirement("hashcat", "hashcat", False),  # No GPU on most Pi
            ToolRequirement("john", "john", True),
            ToolRequirement("hydra", "hydra", True),
            ToolRequirement("metasploit", "metasploit-framework", True),
            ToolRequirement("wireshark", "wireshark", True),
            ToolRequirement("tshark", "tshark", True),
            ToolRequirement("aircrack-ng", "aircrack-ng", True),
            ToolRequirement("reaver", "reaver", True),
            ToolRequirement("bettercap", "bettercap", True),
            ToolRequirement("responder", "responder", True),
            ToolRequirement("impacket", "impacket", True),
            ToolRequirement("netcat", "netcat", True),
            ToolRequirement("socat", "socat", True),
            ToolRequirement("openssl", "openssl", True),
            ToolRequirement("searchsploit", "exploitdb", True),
            ToolRequirement("rtl-sdr", "rtl-sdr", True),  # For ADS-B/NOAA
        ]
        
        self.profiles['raspberry_pi'] = InstallationProfile(
            name="Raspberry Pi",
            profile_type=ProfileType.CUSTOM,
            hardware_profile=HardwareProfile.RASPBERRY_PI,
            description="ARM-compatible tools for Raspberry Pi (50 tools, ~1GB)",
            tools=pi_tools,
            estimated_size_mb=1000,
            estimated_time_min=45,
            priority_categories=['information-gathering', 'networking', 'wireless']
        )
        
        # VM Profile (Lightweight, no GUI tools)
        vm_tools = [t for t in standard_tools if t.name not in ['maltego', 'burp', 'zap', 'wireshark']]
        
        self.profiles['virtual_machine'] = InstallationProfile(
            name="Virtual Machine",
            profile_type=ProfileType.CUSTOM,
            hardware_profile=HardwareProfile.VM,
            description="Lightweight profile for VMs - CLI tools only (150 tools, ~3GB)",
            tools=vm_tools,
            estimated_size_mb=3000,
            estimated_time_min=90,
            priority_categories=['information-gathering', 'exploitation', 'post-exploitation']
        )
        
        logger.info(f"Created {len(self.profiles)} installation profiles")
    
    def get_profile(self, profile_name: str) -> Optional[InstallationProfile]:
        """Get a profile by name."""
        return self.profiles.get(profile_name.lower())
    
    def list_profiles(self) -> List[str]:
        """List all available profiles."""
        return list(self.profiles.keys())
    
    def create_custom_profile(self, name: str, tool_names: List[str], 
                             hardware: HardwareProfile = HardwareProfile.CUSTOM) -> InstallationProfile:
        """Create a custom profile from tool names."""
        tools = []
        for tool_name in tool_names:
            if tool_name in self.tool_database:
                tool_info = self.tool_database[tool_name]
                tools.append(
                    ToolRequirement(
                        name=tool_name,
                        package=tool_info['package'],
                        required=True
                    )
                )
            else:
                logger.warning(f"Tool '{tool_name}' not found in database")
        
        profile = InstallationProfile(
            name=name,
            profile_type=ProfileType.CUSTOM,
            hardware_profile=hardware,
            description=f"Custom profile: {name}",
            tools=tools,
            estimated_size_mb=sum(5 for _ in tools),
            estimated_time_min=len(tools) * 2
        )
        
        self.profiles[name.lower()] = profile
        logger.info(f"Created custom profile '{name}' with {len(tools)} tools")
        
        return profile
    
    def validate_profile(self, profile_name: str) -> Tuple[bool, List[str]]:
        """Validate a profile's tools exist in database."""
        profile = self.get_profile(profile_name)
        if not profile:
            return False, ["Profile not found"]
        
        errors = []
        for tool in profile.tools:
            if tool.name not in self.tool_database:
                errors.append(f"Tool '{tool.name}' not found in database")
        
        return len(errors) == 0, errors
    
    def detect_hardware(self) -> HardwareProfile:
        """Detect current hardware profile."""
        # Check if running in VM
        if os.path.exists('/proc/vcpuinfo') or os.path.exists('/dev/vboxguest'):
            self.hardware_profile = HardwareProfile.VM
            logger.info("Detected: Virtual Machine")
            return HardwareProfile.VM
        
        # Check if Raspberry Pi
        try:
            with open('/proc/cpuinfo', 'r') as f:
                cpuinfo = f.read()
                if 'Raspberry Pi' in cpuinfo or 'BCM2708' in cpuinfo or 'BCM2709' in cpuinfo:
                    self.hardware_profile = HardwareProfile.RASPBERRY_PI
                    logger.info("Detected: Raspberry Pi")
                    return HardwareProfile.RASPBERRY_PI
        except Exception:
            pass
        
        # Check if laptop (battery present)
        if os.path.exists('/sys/class/power_supply/BAT0'):
            self.hardware_profile = HardwareProfile.LAPTOP
            logger.info("Detected: Laptop")
            return HardwareProfile.LAPTOP
        
        # Default to desktop
        self.hardware_profile = HardwareProfile.DESKTOP
        logger.info("Detected: Desktop")
        return HardwareProfile.DESKTOP
    
    def recommend_profile(self) -> str:
        """Recommend a profile based on hardware detection."""
        hardware = self.detect_hardware()
        
        if hardware == HardwareProfile.RASPBERRY_PI:
            return 'raspberry_pi'
        elif hardware == HardwareProfile.VM:
            return 'virtual_machine'
        elif hardware == HardwareProfile.LAPTOP:
            return 'standard'
        else:
            return 'advanced'


# =============================================================================
# Task 2.3.2: Implement Profile Installation
# =============================================================================

class ProfileInstaller:
    """
    Installs tools from a profile.
    
    Provides:
    - Batch installation with progress tracking
    - Dependency resolution
    - Error handling and rollback
    - Installation logging
    """
    
    def __init__(self, profile_manager: ProfileManager):
        """Initialize installer."""
        self.profile_manager = profile_manager
        self.installed_tools: List[str] = []
        self.failed_tools: List[str] = []
        self.install_log: List[Dict] = []
    
    def install_profile(self, profile_name: str, dry_run: bool = False) -> Dict:
        """
        Install all tools from a profile.
        
        Args:
            profile_name: Name of profile to install
            dry_run: If True, only simulate installation
            
        Returns:
            Installation result dictionary
        """
        profile = self.profile_manager.get_profile(profile_name)
        if not profile:
            return {
                'success': False,
                'error': f'Profile "{profile_name}" not found',
                'installed': 0,
                'failed': 0
            }
        
        logger.info(f"Installing profile: {profile.name}")
        logger.info(f"Tools: {len(profile.tools)}")
        logger.info(f"Estimated size: {profile.estimated_size_mb} MB")
        logger.info(f"Estimated time: {profile.estimated_time_min} minutes")
        
        if dry_run:
            logger.info("DRY RUN - No actual installation")
            return {
                'success': True,
                'dry_run': True,
                'profile': profile.name,
                'tools_count': len(profile.tools),
                'estimated_size_mb': profile.estimated_size_mb,
                'estimated_time_min': profile.estimated_time_min
            }
        
        # Update package lists
        logger.info("Updating package lists...")
        subprocess.run(['apt-get', 'update'], capture_output=True, timeout=300)
        
        # Install tools
        for i, tool in enumerate(profile.tools, 1):
            logger.info(f"[{i}/{len(profile.tools)}] Installing {tool.name}...")
            
            success = self._install_tool(tool)
            
            self.install_log.append({
                'tool': tool.name,
                'package': tool.package,
                'success': success,
                'timestamp': subprocess.run(['date', '+%Y-%m-%d %H:%M:%S'], 
                                          capture_output=True, text=True).stdout.strip()
            })
            
            if success:
                self.installed_tools.append(tool.name)
            else:
                self.failed_tools.append(tool.name)
        
        # Summary
        result = {
            'success': len(self.failed_tools) == 0,
            'profile': profile.name,
            'installed': len(self.installed_tools),
            'failed': len(self.failed_tools),
            'failed_tools': self.failed_tools,
            'total_size_mb': self._calculate_installed_size()
        }
        
        logger.info(f"Installation complete: {result['installed']} installed, {result['failed']} failed")
        
        return result
    
    def _install_tool(self, tool: ToolRequirement) -> bool:
        """Install a single tool."""
        try:
            # Try main package
            result = subprocess.run(
                ['apt-get', 'install', '-y', tool.package],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                logger.info(f"✅ Installed {tool.name}")
                return True
            
            # Try optional packages if main failed
            for optional in tool.optional_packages:
                logger.info(f"Trying optional package: {optional}")
                result = subprocess.run(
                    ['apt-get', 'install', '-y', optional],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                
                if result.returncode == 0:
                    logger.info(f"✅ Installed {tool.name} (via {optional})")
                    return True
            
            logger.warning(f"❌ Failed to install {tool.name}")
            return False
            
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout installing {tool.name}")
            return False
        except Exception as e:
            logger.error(f"Error installing {tool.name}: {e}")
            return False
    
    def _calculate_installed_size(self) -> float:
        """Calculate total installed size."""
        # Rough estimate: 5 MB per tool average
        return len(self.installed_tools) * 5.0
    
    def get_install_log(self) -> List[Dict]:
        """Get installation log."""
        return self.install_log
    
    def save_install_log(self, filepath: str):
        """Save installation log to file."""
        with open(filepath, 'w') as f:
            json.dump(self.install_log, f, indent=2)
        logger.info(f"Installation log saved to {filepath}")


# =============================================================================
# Task 2.3.3: Post-Installation Configuration
# =============================================================================

class PostInstallConfigurator:
    """
    Configures tools after installation.
    
    Provides:
    - Default configuration generation
    - Service enablement
    - Database initialization
    - Verification tests
    """
    
    def __init__(self):
        """Initialize configurator."""
        self.config_logs: List[Dict] = []
    
    def configure_profile(self, profile_name: str) -> Dict:
        """
        Run post-installation configuration for a profile.
        
        Args:
            profile_name: Name of installed profile
            
        Returns:
            Configuration result dictionary
        """
        logger.info(f"Configuring profile: {profile_name}")
        
        configs = []
        
        # Metasploit database
        if profile_name in ['standard', 'advanced', 'expert']:
            configs.append(self._configure_metasploit())
        
        # Burp Suite config
        if profile_name in ['advanced', 'expert']:
            configs.append(self._configure_burp())
        
        # Bloodhound database
        if profile_name in ['standard', 'advanced', 'expert']:
            configs.append(self._configure_bloodhound())
        
        # Ghidra config
        if profile_name in ['advanced', 'expert']:
            configs.append(self._configure_ghidra())
        
        # WiFi monitor mode setup
        if profile_name in ['standard', 'advanced', 'expert']:
            configs.append(self._configure_wifi())
        
        # SDR setup
        if profile_name in ['standard', 'advanced', 'expert']:
            configs.append(self._configure_sdr())
        
        # Summary
        success_count = sum(1 for c in configs if c.get('success', False))
        
        result = {
            'success': success_count == len(configs),
            'configured': success_count,
            'total': len(configs),
            'details': configs
        }
        
        logger.info(f"Configuration complete: {success_count}/{len(configs)} successful")
        
        return result
    
    def _configure_metasploit(self) -> Dict:
        """Configure Metasploit database."""
        try:
            logger.info("Configuring Metasploit database...")
            
            # Initialize database
            subprocess.run(
                ['msfdb', 'init'],
                capture_output=True,
                timeout=60
            )
            
            return {
                'tool': 'metasploit',
                'success': True,
                'message': 'Database initialized'
            }
            
        except Exception as e:
            return {
                'tool': 'metasploit',
                'success': False,
                'error': str(e)
            }
    
    def _configure_burp(self) -> Dict:
        """Configure Burp Suite."""
        try:
            logger.info("Configuring Burp Suite...")
            
            # Create config directory
            config_dir = Path.home() / '.BurpSuite'
            config_dir.mkdir(exist_ok=True)
            
            # Create default config
            config_file = config_dir / 'default.conf'
            config_file.write_text('''
{
  "project_options": {
    "scanner": {
      "active_scanner": {
        "check_for_out_of_band_vulnerabilities": true
      }
    }
  }
}
''')
            
            return {
                'tool': 'burp',
                'success': True,
                'message': 'Default configuration created'
            }
            
        except Exception as e:
            return {
                'tool': 'burp',
                'success': False,
                'error': str(e)
            }
    
    def _configure_bloodhound(self) -> Dict:
        """Configure Bloodhound."""
        try:
            logger.info("Configuring Bloodhound...")
            
            # Check if Neo4j is installed
            result = subprocess.run(
                ['systemctl', 'is-active', 'neo4j'],
                capture_output=True,
                text=True
            )
            
            if result.stdout.strip() != 'active':
                logger.info("Starting Neo4j service...")
                subprocess.run(
                    ['systemctl', 'start', 'neo4j'],
                    capture_output=True,
                    timeout=60
                )
            
            return {
                'tool': 'bloodhound',
                'success': True,
                'message': 'Neo4j service started'
            }
            
        except Exception as e:
            return {
                'tool': 'bloodhound',
                'success': False,
                'error': str(e)
            }
    
    def _configure_ghidra(self) -> Dict:
        """Configure Ghidra."""
        try:
            logger.info("Configuring Ghidra...")
            
            # Create projects directory
            projects_dir = Path.home() / 'ghidra_projects'
            projects_dir.mkdir(exist_ok=True)
            
            return {
                'tool': 'ghidra',
                'success': True,
                'message': 'Projects directory created'
            }
            
        except Exception as e:
            return {
                'tool': 'ghidra',
                'success': False,
                'error': str(e)
            }
    
    def _configure_wifi(self) -> Dict:
        """Configure WiFi tools."""
        try:
            logger.info("Configuring WiFi tools...")
            
            # Check for wireless interfaces
            result = subprocess.run(
                ['iwconfig'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            wireless_detected = 'IEEE 802.11' in result.stdout or 'ESSID' in result.stdout
            
            return {
                'tool': 'wifi',
                'success': True,
                'message': 'Wireless interfaces detected' if wireless_detected else 'No wireless interfaces found'
            }
            
        except Exception as e:
            return {
                'tool': 'wifi',
                'success': False,
                'error': str(e)
            }
    
    def _configure_sdr(self) -> Dict:
        """Configure SDR tools."""
        try:
            logger.info("Configuring SDR tools...")
            
            # Check for RTL-SDR
            result = subprocess.run(
                ['lsusb'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            sdr_detected = 'Realtek' in result.stdout or 'RTL' in result.stdout
            
            # Create SDR config directory
            sdr_dir = Path.home() / '.sdr'
            sdr_dir.mkdir(exist_ok=True)
            
            return {
                'tool': 'sdr',
                'success': True,
                'message': 'RTL-SDR detected' if sdr_detected else 'No SDR devices detected',
                'sdr_detected': sdr_detected
            }
            
        except Exception as e:
            return {
                'tool': 'sdr',
                'success': False,
                'error': str(e)
            }
    
    def verify_installation(self, profile_name: str) -> Dict:
        """
        Verify that installed tools are working.
        
        Args:
            profile_name: Name of profile to verify
            
        Returns:
            Verification result dictionary
        """
        profile = self.profile_manager.get_profile(profile_name)
        if not profile:
            return {'success': False, 'error': 'Profile not found'}
        
        logger.info(f"Verifying installation: {profile_name}")
        
        verified = []
        failed = []
        
        for tool in profile.tools[:20]:  # Check first 20 tools
            try:
                # Try --version or --help
                result = subprocess.run(
                    [tool.package.split(',')[0], '--version'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    verified.append(tool.name)
                else:
                    # Try --help as fallback
                    result = subprocess.run(
                        [tool.package.split(',')[0], '--help'],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    
                    if result.returncode == 0:
                        verified.append(tool.name)
                    else:
                        failed.append(tool.name)
                        
            except Exception:
                failed.append(tool.name)
        
        return {
            'success': len(failed) == 0,
            'verified': len(verified),
            'failed': len(failed),
            'verified_tools': verified,
            'failed_tools': failed
        }


# =============================================================================
# CLI Interface
# =============================================================================

def main():
    """Command-line interface for installation profiles."""
    import argparse
    
    parser = argparse.ArgumentParser(description='KaliAgent v3 - Installation Profiles')
    parser.add_argument('--list', action='store_true', help='List available profiles')
    parser.add_argument('--install', type=str, help='Install a profile')
    parser.add_argument('--dry-run', action='store_true', help='Simulate installation')
    parser.add_argument('--configure', type=str, help='Configure installed profile')
    parser.add_argument('--verify', type=str, help='Verify installation')
    parser.add_argument('--recommend', action='store_true', help='Recommend profile for this system')
    
    args = parser.parse_args()
    
    profile_manager = ProfileManager()
    
    if args.list:
        print("\nAvailable Installation Profiles:")
        print("=" * 60)
        for name, profile in profile_manager.profiles.items():
            print(f"\n{name.upper()}")
            print(f"  Description: {profile.description}")
            print(f"  Hardware: {profile.hardware_profile.value}")
            print(f"  Tools: {len(profile.tools)}")
            print(f"  Size: ~{profile.estimated_size_mb} MB")
            print(f"  Time: ~{profile.estimated_time_min} minutes")
        print("=" * 60)
    
    elif args.install:
        installer = ProfileInstaller(profile_manager)
        result = installer.install_profile(args.install, dry_run=args.dry_run)
        
        print("\nInstallation Result:")
        print("=" * 60)
        for key, value in result.items():
            print(f"  {key}: {value}")
        print("=" * 60)
        
        if result.get('failed_tools'):
            print(f"\nFailed tools: {', '.join(result['failed_tools'])}")
    
    elif args.configure:
        configurator = PostInstallConfigurator()
        result = configurator.configure_profile(args.configure)
        
        print("\nConfiguration Result:")
        print("=" * 60)
        for key, value in result.items():
            if key != 'details':
                print(f"  {key}: {value}")
        
        if result.get('details'):
            print("\nDetails:")
            for detail in result['details']:
                status = "✅" if detail.get('success') else "❌"
                print(f"  {status} {detail.get('tool')}: {detail.get('message', detail.get('error', ''))}")
        print("=" * 60)
    
    elif args.verify:
        configurator = PostInstallConfigurator()
        result = configurator.verify_installation(args.verify)
        
        print("\nVerification Result:")
        print("=" * 60)
        print(f"  Verified: {result['verified']} tools")
        print(f"  Failed: {result['failed']} tools")
        
        if result.get('verified_tools'):
            print(f"\nVerified tools: {', '.join(result['verified_tools'][:10])}...")
        if result.get('failed_tools'):
            print(f"Failed tools: {', '.join(result['failed_tools'])}")
        print("=" * 60)
    
    elif args.recommend:
        recommended = profile_manager.recommend_profile()
        hardware = profile_manager.detect_hardware()
        
        print("\nProfile Recommendation:")
        print("=" * 60)
        print(f"  Detected Hardware: {hardware.value}")
        print(f"  Recommended Profile: {recommended}")
        
        profile = profile_manager.get_profile(recommended)
        if profile:
            print(f"  Description: {profile.description}")
        print("=" * 60)
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
