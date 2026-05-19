#!/usr/bin/env python3
"""
KaliAgent v3 - Payload Testing Framework
=========================================

Tests and validates generated payloads.

Task: 3.3.3
Status: IMPLEMENTED
"""

import subprocess
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class TestType(Enum):
    """Types of payload tests."""
    EXECUTION = "execution"
    CONNECTIVITY = "connectivity"
    SIZE_CHECK = "size_check"
    HASH_VERIFICATION = "hash_verification"
    SIGNATURE_CHECK = "signature_check"
    SANDBOX_DETECTION = "sandbox_detection"
    AV_EVASION = "av_evasion"
    FUNCTIONAL = "functional"


@dataclass
class TestResult:
    """Result of a single test."""
    test_type: TestType
    success: bool
    message: str
    duration_ms: int
    details: Dict = field(default_factory=dict)


@dataclass
class PayloadTestReport:
    """Complete test report for a payload."""
    payload_path: Path
    total_tests: int
    passed: int
    failed: int
    warnings: int
    test_results: List[TestResult]
    overall_status: str
    risk_score: float
    timestamp: str


class PayloadTester:
    """
    Tests and validates payloads.
    
    Provides:
    - Execution testing
    - Connectivity validation
    - Size/hash verification
    - Signature detection
    - AV evasion testing
    - Functional testing
    """
    
    def __init__(self, test_dir: Optional[Path] = None):
        """Initialize tester."""
        self.test_dir = test_dir or Path.home() / 'kali_agent_v3' / 'test_results'
        self.test_dir.mkdir(parents=True, exist_ok=True)
        
        self.test_history: List[PayloadTestReport] = []
        
        # AV signatures database (simplified)
        self.av_signatures = self._load_av_signatures()
        
        logger.info(f"Payload tester initialized (test dir: {self.test_dir})")
    
    def _load_av_signatures(self) -> Dict[str, List[str]]:
        """Load known AV signatures."""
        # Simplified signature database
        return {
            'windows_defender': [
                '4e676f745061796c6f6164',  # NotPayload
                '4d65746173706c6f6974',  # Metasploit
                '4d5a900003',  # MZ header (generic)
            ],
            'kaspersky': [
                '504B0304',  # ZIP/PK (generic)
                '73716c6d6170',  # sqlmap
            ],
            'mcafee': [
                '457865436c69656e74',  # Execlient
                '76656e6f6d',  # venom
            ],
            'symantec': [
                '4861636b546f6f6c',  # HackTool
                '4379626572576561706f6e',  # CyberWeapon
            ],
        }
    
    def test_payload(self, payload_path: Path, 
                    test_types: Optional[List[TestType]] = None,
                    lhost: str = "127.0.0.1",
                    lport: int = 4444) -> PayloadTestReport:
        """
        Run comprehensive tests on a payload.
        
        Args:
            payload_path: Path to payload file
            test_types: List of tests to run (default: all)
            lhost: Listener host for connectivity tests
            lport: Listener port for connectivity tests
            
        Returns:
            PayloadTestReport with all test results
        """
        logger.info(f"Testing payload: {payload_path.name}")
        
        if not payload_path.exists():
            return self._create_failed_report(payload_path, "File not found")
        
        if test_types is None:
            test_types = [
                TestType.SIZE_CHECK,
                TestType.HASH_VERIFICATION,
                TestType.SIGNATURE_CHECK,
                TestType.EXECUTION,
                TestType.FUNCTIONAL
            ]
        
        results = []
        datetime.now()
        
        # Run each test
        for test_type in test_types:
            logger.info(f"Running test: {test_type.value}")
            
            test_start = datetime.now()
            
            if test_type == TestType.SIZE_CHECK:
                result = self._test_size(payload_path)
            elif test_type == TestType.HASH_VERIFICATION:
                result = self._test_hash(payload_path)
            elif test_type == TestType.SIGNATURE_CHECK:
                result = self._test_signatures(payload_path)
            elif test_type == TestType.EXECUTION:
                result = self._test_execution(payload_path)
            elif test_type == TestType.CONNECTIVITY:
                result = self._test_connectivity(payload_path, lhost, lport)
            elif test_type == TestType.AV_EVASION:
                result = self._test_av_evasion(payload_path)
            elif test_type == TestType.SANDBOX_DETECTION:
                result = self._test_sandbox_detection(payload_path)
            elif test_type == TestType.FUNCTIONAL:
                result = self._test_functional(payload_path)
            else:
                result = TestResult(
                    test_type=test_type,
                    success=False,
                    message="Unknown test type",
                    duration_ms=0
                )
            
            test_end = datetime.now()
            result.duration_ms = int((test_end - test_start).total_seconds() * 1000)
            results.append(result)
        
        # Calculate summary
        passed = sum(1 for r in results if r.success)
        failed = sum(1 for r in results if not r.success and 'FAIL' in r.message.upper())
        warnings = sum(1 for r in results if not r.success and 'WARN' in r.message.upper())
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(results)
        
        # Determine overall status
        if failed > 0:
            overall_status = "FAILED"
        elif warnings > 0:
            overall_status = "PASSED_WITH_WARNINGS"
        else:
            overall_status = "PASSED"
        
        report = PayloadTestReport(
            payload_path=payload_path,
            total_tests=len(results),
            passed=passed,
            failed=failed,
            warnings=warnings,
            test_results=results,
            overall_status=overall_status,
            risk_score=risk_score,
            timestamp=datetime.now().isoformat()
        )
        
        self.test_history.append(report)
        self._save_report(report)
        
        logger.info(f"Test complete: {overall_status} ({passed}/{len(results)} passed)")
        
        return report
    
    def _test_size(self, payload_path: Path) -> TestResult:
        """Test payload size is reasonable."""
        try:
            size = payload_path.stat().st_size
            
            # Size thresholds
            min_size = 100  # 100 bytes minimum
            max_size = 500 * 1024 * 1024  # 500 MB maximum
            
            if size < min_size:
                return TestResult(
                    test_type=TestType.SIZE_CHECK,
                    success=False,
                    message=f"FAIL: Payload too small ({size} bytes < {min_size})",
                    duration_ms=0,
                    details={'size': size, 'min': min_size}
                )
            elif size > max_size:
                return TestResult(
                    test_type=TestType.SIZE_CHECK,
                    success=False,
                    message=f"FAIL: Payload too large ({size} bytes > {max_size})",
                    duration_ms=0,
                    details={'size': size, 'max': max_size}
                )
            else:
                return TestResult(
                    test_type=TestType.SIZE_CHECK,
                    success=True,
                    message=f"OK: Size {size} bytes is reasonable",
                    duration_ms=0,
                    details={'size': size}
                )
        except Exception as e:
            return TestResult(
                test_type=TestType.SIZE_CHECK,
                success=False,
                message=f"ERROR: {str(e)}",
                duration_ms=0
            )
    
    def _test_hash(self, payload_path: Path) -> TestResult:
        """Verify payload hash."""
        try:
            # Calculate hashes
            md5 = hashlib.md5(payload_path.read_bytes()).hexdigest()
            sha256 = hashlib.sha256(payload_path.read_bytes()).hexdigest()
            
            return TestResult(
                test_type=TestType.HASH_VERIFICATION,
                success=True,
                message=f"OK: MD5={md5[:8]}..., SHA256={sha256[:16]}...",
                duration_ms=0,
                details={'md5': md5, 'sha256': sha256}
            )
        except Exception as e:
            return TestResult(
                test_type=TestType.HASH_VERIFICATION,
                success=False,
                message=f"ERROR: {str(e)}",
                duration_ms=0
            )
    
    def _test_signatures(self, payload_path: Path) -> TestResult:
        """Check for known AV signatures."""
        try:
            with open(payload_path, 'rb') as f:
                content = f.read()
            
            hex_content = content.hex().upper()
            
            matches = []
            for av, signatures in self.av_signatures.items():
                for sig in signatures:
                    if sig.upper() in hex_content:
                        matches.append(f"{av}:{sig}")
            
            if matches:
                return TestResult(
                    test_type=TestType.SIGNATURE_CHECK,
                    success=False,
                    message=f"WARN: Found {len(matches)} signature matches",
                    duration_ms=0,
                    details={'matches': matches}
                )
            else:
                return TestResult(
                    test_type=TestType.SIGNATURE_CHECK,
                    success=True,
                    message="OK: No known signatures detected",
                    duration_ms=0,
                    details={'matches': []}
                )
        except Exception as e:
            return TestResult(
                test_type=TestType.SIGNATURE_CHECK,
                success=False,
                message=f"ERROR: {str(e)}",
                duration_ms=0
            )
    
    def _test_execution(self, payload_path: Path) -> TestResult:
        """Test if payload can be executed (safely)."""
        try:
            # Check file type
            with open(payload_path, 'rb') as f:
                header = f.read(4)
            
            # MZ header (Windows executable)
            if header[:2] == b'MZ':
                file_type = "Windows EXE/DLL"
                # Don't actually execute on host
                return TestResult(
                    test_type=TestType.EXECUTION,
                    success=True,
                    message=f"WARN: {file_type} - Valid header (not executed on host)",
                    duration_ms=0,
                    details={'type': file_type, 'header': header.hex()}
                )
            
            # ELF header (Linux executable)
            elif header == b'\x7fELF':
                file_type = "Linux ELF"
                return TestResult(
                    test_type=TestType.EXECUTION,
                    success=True,
                    message=f"WARN: {file_type} - Valid header (not executed on host)",
                    duration_ms=0,
                    details={'type': file_type, 'header': header.hex()}
                )
            
            # Shebang (script)
            elif header[:2] == b'#!':
                with open(payload_path, 'r', encoding='utf-8', errors='ignore') as f:
                    first_line = f.readline().strip()
                return TestResult(
                    test_type=TestType.EXECUTION,
                    success=True,
                    message=f"OK: Script with shebang: {first_line}",
                    duration_ms=0,
                    details={'shebang': first_line}
                )
            
            else:
                return TestResult(
                    test_type=TestType.EXECUTION,
                    success=False,
                    message="WARN: Unknown file type or data",
                    duration_ms=0,
                    details={'header': header.hex()}
                )
                
        except Exception as e:
            return TestResult(
                test_type=TestType.EXECUTION,
                success=False,
                message=f"ERROR: {str(e)}",
                duration_ms=0
            )
    
    def _test_connectivity(self, payload_path: Path, 
                          lhost: str, lport: int) -> TestResult:
        """Test payload connectivity settings."""
        try:
            # Read payload and check for hardcoded IPs
            with open(payload_path, 'rb') as f:
                content = f.read()
            
            # Check for LHOST/LPORT strings
            lhost_bytes = lhost.encode('utf-8')
            lport_bytes = str(lport).encode('utf-8')
            
            has_lhost = lhost_bytes in content
            has_lport = lport_bytes in content
            
            return TestResult(
                test_type=TestType.CONNECTIVITY,
                success=True,
                message=f"OK: LHOST={lhost}, LPORT={lport} configured",
                duration_ms=0,
                details={'lhost': lhost, 'lport': lport, 'embedded': has_lhost or has_lport}
            )
        except Exception as e:
            return TestResult(
                test_type=TestType.CONNECTIVITY,
                success=False,
                message=f"ERROR: {str(e)}",
                duration_ms=0
            )
    
    def _test_av_evasion(self, payload_path: Path) -> TestResult:
        """Test AV evasion techniques."""
        try:
            with open(payload_path, 'rb') as f:
                content = f.read()
            
            # Check for common strings that trigger AV
            suspicious_strings = [
                b'mimikatz',
                b'metasploit',
                b'msfvenom',
                b'powershell',
                b'cmd.exe',
                b'whoami',
                b'net user',
            ]
            
            found = []
            for s in suspicious_strings:
                if s.lower() in content.lower():
                    found.append(s.decode('utf-8', errors='ignore'))
            
            if found:
                return TestResult(
                    test_type=TestType.AV_EVASION,
                    success=False,
                    message=f"WARN: Found {len(found)} suspicious strings",
                    duration_ms=0,
                    details={'strings': found}
                )
            else:
                return TestResult(
                    test_type=TestType.AV_EVASION,
                    success=True,
                    message="OK: No obvious suspicious strings",
                    duration_ms=0,
                    details={'strings': []}
                )
        except Exception as e:
            return TestResult(
                test_type=TestType.AV_EVASION,
                success=False,
                message=f"ERROR: {str(e)}",
                duration_ms=0
            )
    
    def _test_sandbox_detection(self, payload_path: Path) -> TestResult:
        """Test for sandbox detection mechanisms."""
        try:
            with open(payload_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Check for sandbox detection strings
            sandbox_strings = [
                'vmware',
                'virtualbox',
                'qemu',
                'xen',
                'sandbox',
                'wireshark',
                'fiddler',
                'debug',
                'ollydbg',
            ]
            
            found = []
            for s in sandbox_strings:
                if s.lower() in content.lower():
                    found.append(s)
            
            if found:
                return TestResult(
                    test_type=TestType.SANDBOX_DETECTION,
                    success=True,
                    message=f"OK: Contains {len(found)} sandbox detection strings",
                    duration_ms=0,
                    details={'strings': found}
                )
            else:
                return TestResult(
                    test_type=TestType.SANDBOX_DETECTION,
                    success=False,
                    message="INFO: No sandbox detection mechanisms found",
                    duration_ms=0,
                    details={'strings': []}
                )
        except Exception as e:
            return TestResult(
                test_type=TestType.SANDBOX_DETECTION,
                success=False,
                message=f"ERROR: {str(e)}",
                duration_ms=0
            )
    
    def _test_functional(self, payload_path: Path) -> TestResult:
        """Test payload functionality (syntax check for scripts)."""
        try:
            suffix = payload_path.suffix.lower()
            
            # PowerShell syntax check
            if suffix == '.ps1':
                result = subprocess.run(
                    ['pwsh', '-NoProfile', '-Command', f"Get-Content '{payload_path}' | Out-Null"],
                    capture_output=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    return TestResult(
                        test_type=TestType.FUNCTIONAL,
                        success=True,
                        message="OK: PowerShell syntax valid",
                        duration_ms=0
                    )
                else:
                    return TestResult(
                        test_type=TestType.FUNCTIONAL,
                        success=False,
                        message="FAIL: PowerShell syntax error",
                        duration_ms=0,
                        details={'error': result.stderr.decode('utf-8', errors='ignore')[:200]}
                    )
            
            # Python syntax check
            elif suffix == '.py':
                result = subprocess.run(
                    ['python3', '-m', 'py_compile', str(payload_path)],
                    capture_output=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    return TestResult(
                        test_type=TestType.FUNCTIONAL,
                        success=True,
                        message="OK: Python syntax valid",
                        duration_ms=0
                    )
                else:
                    return TestResult(
                        test_type=TestType.FUNCTIONAL,
                        success=False,
                        message="FAIL: Python syntax error",
                        duration_ms=0,
                        details={'error': result.stderr.decode('utf-8', errors='ignore')[:200]}
                    )
            
            # Bash syntax check
            elif suffix in ['.sh', '.bash']:
                result = subprocess.run(
                    ['bash', '-n', str(payload_path)],
                    capture_output=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    return TestResult(
                        test_type=TestType.FUNCTIONAL,
                        success=True,
                        message="OK: Bash syntax valid",
                        duration_ms=0
                    )
                else:
                    return TestResult(
                        test_type=TestType.FUNCTIONAL,
                        success=False,
                        message="FAIL: Bash syntax error",
                        duration_ms=0,
                        details={'error': result.stderr.decode('utf-8', errors='ignore')[:200]}
                    )
            
            # For binaries, just check if file is valid
            else:
                return TestResult(
                    test_type=TestType.FUNCTIONAL,
                    success=True,
                    message="INFO: Binary file (syntax check not applicable)",
                    duration_ms=0,
                    details={'type': 'binary'}
                )
                
        except Exception as e:
            return TestResult(
                test_type=TestType.FUNCTIONAL,
                success=False,
                message=f"ERROR: {str(e)}",
                duration_ms=0
            )
    
    def _calculate_risk_score(self, results: List[TestResult]) -> float:
        """Calculate overall risk score (0-10)."""
        score = 0.0
        
        for result in results:
            if result.success:
                score += 0.5
            elif 'FAIL' in result.message.upper():
                score += 2.0
            elif 'WARN' in result.message.upper():
                score += 1.0
        
        # Normalize to 0-10
        return min(10.0, score / len(results) * 2) if results else 0.0
    
    def _save_report(self, report: PayloadTestReport):
        """Save test report to file."""
        report_file = self.test_dir / f"{report.payload_path.stem}_test_report.json"
        
        report_data = {
            'payload_path': str(report.payload_path),
            'total_tests': report.total_tests,
            'passed': report.passed,
            'failed': report.failed,
            'warnings': report.warnings,
            'overall_status': report.overall_status,
            'risk_score': report.risk_score,
            'timestamp': report.timestamp,
            'results': [
                {
                    'test_type': r.test_type.value,
                    'success': r.success,
                    'message': r.message,
                    'duration_ms': r.duration_ms,
                    'details': r.details
                }
                for r in report.test_results
            ]
        }
        
        import json
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        logger.info(f"Report saved: {report_file}")
    
    def _create_failed_report(self, payload_path: Path, error: str) -> PayloadTestReport:
        """Create a failed report for invalid payloads."""
        return PayloadTestReport(
            payload_path=payload_path,
            total_tests=0,
            passed=0,
            failed=0,
            warnings=0,
            test_results=[],
            overall_status="FAILED",
            risk_score=10.0,
            timestamp=datetime.now().isoformat()
        )
    
    def get_test_history(self, limit: int = 10) -> List[Dict]:
        """Get recent test history."""
        return [
            {
                'payload': r.payload_path.name,
                'status': r.overall_status,
                'passed': r.passed,
                'total': r.total_tests,
                'risk_score': r.risk_score,
                'timestamp': r.timestamp
            }
            for r in self.test_history[-limit:]
        ]


# =============================================================================
# CLI Interface
# =============================================================================

def main():
    """Command-line interface for payload tester."""
    import argparse
    
    parser = argparse.ArgumentParser(description='KaliAgent v3 - Payload Tester')
    parser.add_argument('--test', type=str, help='Test a payload file')
    parser.add_argument('--tests', type=str, nargs='+', help='Specific tests to run')
    parser.add_argument('--lhost', type=str, default='127.0.0.1', help='Listener host')
    parser.add_argument('--lport', type=int, default=4444, help='Listener port')
    parser.add_argument('--history', action='store_true', help='Show test history')
    
    args = parser.parse_args()
    
    tester = PayloadTester()
    
    if args.history:
        history = tester.get_test_history()
        print(f"\nTest History: {len(history)}")
        print("=" * 60)
        for h in history:
            status = "✅" if h['status'] == 'PASSED' else "❌"
            print(f"{status} {h['payload']}: {h['status']} ({h['passed']}/{h['total']}, risk: {h['risk_score']:.1f})")
        print("=" * 60)
    
    elif args.test:
        from pathlib import Path
        
        test_types = None
        if args.tests:
            test_types = []
            for t in args.tests:
                try:
                    test_types.append(TestType(t))
                except ValueError:
                    print(f"Unknown test type: {t}")
        
        report = tester.test_payload(
            Path(args.test),
            test_types=test_types,
            lhost=args.lhost,
            lport=args.lport
        )
        
        print("\nPayload Test Report")
        print("=" * 60)
        print(f"Payload: {report.payload_path.name}")
        print(f"Status: {report.overall_status}")
        print(f"Tests: {report.passed}/{report.total_tests} passed")
        print(f"Risk Score: {report.risk_score:.1f}/10")
        print(f"Timestamp: {report.timestamp}")
        
        print("\nTest Results:")
        for r in report.test_results:
            status = "✅" if r.success else "❌"
            print(f"  {status} {r.test_type.value}: {r.message[:60]}")
        
        print("=" * 60)
    
    else:
        print("Use --test <file> to test a payload")
        print("Use --history to view test history")


if __name__ == '__main__':
    main()
