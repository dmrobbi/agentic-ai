#!/usr/bin/env python3
"""
KaliAgent v3 - AV Signature Database
=====================================

Comprehensive AV signature database for evasion testing.

Task: 3.5.2
Status: IMPLEMENTED
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


@dataclass
class AVSignature:
    """AV signature definition."""
    id: str
    vendor: str
    name: str
    description: str
    pattern: str  # Hex pattern or string
    pattern_type: str  # 'hex', 'string', 'regex'
    severity: str  # 'low', 'medium', 'high', 'critical'
    category: str
    first_seen: str
    last_updated: str
    false_positive_rate: float  # 0.0 - 1.0
    detection_rate: float  # 0.0 - 1.0


@dataclass
class SignatureDatabase:
    """AV signature database."""
    version: str
    last_updated: str
    total_signatures: int
    signatures_by_vendor: Dict[str, int]
    signatures_by_category: Dict[str, int]
    signatures: List[AVSignature]


class AVSignatureDatabase:
    """
    Manages AV signature database.
    
    Provides:
    - Signature storage and retrieval
    - Pattern matching
    - Detection rate tracking
    - False positive analysis
    """
    
    def __init__(self, db_path: Optional[Path] = None):
        """Initialize signature database."""
        self.db_path = db_path or Path.home() / 'kali_agent_v3' / 'av_signatures.json'
        self.signatures: List[AVSignature] = []
        self.signature_index: Dict[str, AVSignature] = {}
        
        self._load_or_create_database()
        
        logger.info(f"AV signature database initialized ({len(self.signatures)} signatures)")
    
    def _load_or_create_database(self):
        """Load existing database or create new one."""
        if self.db_path.exists():
            self._load_database()
        else:
            self._create_database()
    
    def _load_database(self):
        """Load database from file."""
        try:
            with open(self.db_path, 'r') as f:
                data = json.load(f)
            
            for sig_data in data.get('signatures', []):
                sig = AVSignature(**sig_data)
                self.signatures.append(sig)
                self.signature_index[sig.id] = sig
            
            logger.info(f"Loaded {len(self.signatures)} signatures from {self.db_path}")
            
        except Exception as e:
            logger.error(f"Failed to load database: {e}")
            self._create_database()
    
    def _create_database(self):
        """Create initial signature database."""
        logger.info("Creating initial AV signature database...")
        
        # Add signatures for common malware/pentest tools
        self._add_metasploit_signatures()
        self._add_mimikatz_signatures()
        self._add_cobalt_strike_signatures()
        self._add_generic_signatures()
        self._add_powershell_signatures()
        self._add_webshell_signatures()
        
        # Save database
        self._save_database()
        
        logger.info(f"Created database with {len(self.signatures)} signatures")
    
    def _add_metasploit_signatures(self):
        """Add Metasploit signatures."""
        signatures = [
            AVSignature(
                id='msf_001',
                vendor='Microsoft',
                name='Trojan:Win32/Metasploit',
                description='Metasploit payload detector',
                pattern='4d65746173706c6f6974',  # Metasploit (hex)
                pattern_type='hex',
                severity='high',
                category='remote_access',
                first_seen='2015-01-15',
                last_updated='2026-04-01',
                false_positive_rate=0.02,
                detection_rate=0.95
            ),
            AVSignature(
                id='msf_002',
                vendor='Kaspersky',
                name='Exploit.Win32.MSF',
                description='Metasploit exploit framework',
                pattern='6d736676656e6f6d',  # msfvenom (hex)
                pattern_type='hex',
                severity='high',
                category='exploit_kit',
                first_seen='2014-06-20',
                last_updated='2026-03-15',
                false_positive_rate=0.01,
                detection_rate=0.92
            ),
            AVSignature(
                id='msf_003',
                vendor='Symantec',
                name='Hacktool.Metasploit',
                description='Metasploit penetration testing tool',
                pattern='meterpreter',
                pattern_type='string',
                severity='medium',
                category='hacktool',
                first_seen='2013-03-10',
                last_updated='2026-02-28',
                false_positive_rate=0.05,
                detection_rate=0.88
            ),
            AVSignature(
                id='msf_004',
                vendor='McAfee',
                name='Artemis!Metasploit',
                description='Generic Metasploit detection',
                pattern='726576657273655f746370',  # reverse_tcp (hex)
                pattern_type='hex',
                severity='high',
                category='remote_access',
                first_seen='2016-08-22',
                last_updated='2026-04-10',
                false_positive_rate=0.03,
                detection_rate=0.90
            ),
            AVSignature(
                id='msf_005',
                vendor='ESET',
                name='Win32/HackTool.Metasploit.A',
                description='Metasploit hacktool',
                pattern='payload',
                pattern_type='string',
                severity='medium',
                category='hacktool',
                first_seen='2014-11-05',
                last_updated='2026-03-20',
                false_positive_rate=0.10,
                detection_rate=0.75
            ),
        ]
        
        for sig in signatures:
            self.signatures.append(sig)
            self.signature_index[sig.id] = sig
    
    def _add_mimikatz_signatures(self):
        """Add Mimikatz signatures."""
        signatures = [
            AVSignature(
                id='mim_001',
                vendor='Microsoft',
                name='Tool:Win32/Mimikatz',
                description='Mimikatz credential extractor',
                pattern='6d696d696b61747a',  # mimikatz (hex)
                pattern_type='hex',
                severity='critical',
                category='credential_theft',
                first_seen='2014-02-18',
                last_updated='2026-04-15',
                false_positive_rate=0.01,
                detection_rate=0.98
            ),
            AVSignature(
                id='mim_002',
                vendor='Kaspersky',
                name='HackTool.Win32.Mimikatz',
                description='Mimikatz password extractor',
                pattern='sekurlsa',
                pattern_type='string',
                severity='critical',
                category='credential_theft',
                first_seen='2013-09-12',
                last_updated='2026-03-28',
                false_positive_rate=0.005,
                detection_rate=0.99
            ),
            AVSignature(
                id='mim_003',
                vendor='Symantec',
                name='Infostealer.Mimikatz',
                description='Mimikatz information stealer',
                pattern='lsass',
                pattern_type='string',
                severity='high',
                category='credential_theft',
                first_seen='2014-05-30',
                last_updated='2026-04-05',
                false_positive_rate=0.08,
                detection_rate=0.85
            ),
            AVSignature(
                id='mim_004',
                vendor='CrowdStrike',
                name='CREDENTIAL_THEFT.mimikatz',
                description='Mimikatz credential theft',
                pattern='kerberos',
                pattern_type='string',
                severity='critical',
                category='credential_theft',
                first_seen='2015-07-14',
                last_updated='2026-04-12',
                false_positive_rate=0.02,
                detection_rate=0.96
            ),
        ]
        
        for sig in signatures:
            self.signatures.append(sig)
            self.signature_index[sig.id] = sig
    
    def _add_cobalt_strike_signatures(self):
        """Add Cobalt Strike signatures."""
        signatures = [
            AVSignature(
                id='cs_001',
                vendor='Microsoft',
                name='Trojan:Win32/CobaltStrike',
                description='Cobalt Strike beacon',
                pattern='436f62616c74537472696b65',  # CobaltStrike (hex)
                pattern_type='hex',
                severity='critical',
                category='remote_access',
                first_seen='2016-04-10',
                last_updated='2026-04-18',
                false_positive_rate=0.01,
                detection_rate=0.97
            ),
            AVSignature(
                id='cs_002',
                vendor='FireEye',
                name='COBALTSTROKE.Beacon',
                description='Cobalt Strike C2 beacon',
                pattern='beacon',
                pattern_type='string',
                severity='critical',
                category='c2',
                first_seen='2015-11-22',
                last_updated='2026-04-10',
                false_positive_rate=0.02,
                detection_rate=0.95
            ),
            AVSignature(
                id='cs_003',
                vendor='CrowdStrike',
                name='C2.COBALTSTRIKE',
                description='Cobalt Strike command and control',
                pattern='sleeptime',
                pattern_type='string',
                severity='critical',
                category='c2',
                first_seen='2017-02-28',
                last_updated='2026-03-30',
                false_positive_rate=0.01,
                detection_rate=0.94
            ),
        ]
        
        for sig in signatures:
            self.signatures.append(sig)
            self.signature_index[sig.id] = sig
    
    def _add_generic_signatures(self):
        """Add generic malware signatures."""
        signatures = [
            AVSignature(
                id='gen_001',
                vendor='Microsoft',
                name='Trojan:Win32/Generic',
                description='Generic trojan detector',
                pattern='4d5a900003',  # MZ header + DOS stub
                pattern_type='hex',
                severity='medium',
                category='generic',
                first_seen='2010-01-01',
                last_updated='2026-04-01',
                false_positive_rate=0.15,
                detection_rate=0.60
            ),
            AVSignature(
                id='gen_002',
                vendor='Kaspersky',
                name='HEUR:Trojan.Win32.Generic',
                description='Heuristic trojan detection',
                pattern='virtualalloc',
                pattern_type='string',
                severity='medium',
                category='heuristic',
                first_seen='2012-06-15',
                last_updated='2026-03-25',
                false_positive_rate=0.12,
                detection_rate=0.65
            ),
            AVSignature(
                id='gen_003',
                vendor='Symantec',
                name='Suspicious.Insight',
                description='Behavioral detection',
                pattern='createprocess',
                pattern_type='string',
                severity='low',
                category='behavioral',
                first_seen='2014-08-20',
                last_updated='2026-04-08',
                false_positive_rate=0.20,
                detection_rate=0.55
            ),
            AVSignature(
                id='gen_004',
                vendor='McAfee',
                name='Artemis!Suspicious',
                description='Cloud-based suspicious detection',
                pattern='shellcode',
                pattern_type='string',
                severity='medium',
                category='cloud',
                first_seen='2015-03-12',
                last_updated='2026-04-15',
                false_positive_rate=0.10,
                detection_rate=0.70
            ),
        ]
        
        for sig in signatures:
            self.signatures.append(sig)
            self.signature_index[sig.id] = sig
    
    def _add_powershell_signatures(self):
        """Add PowerShell-specific signatures."""
        signatures = [
            AVSignature(
                id='ps_001',
                vendor='Microsoft',
                name='PowerShell/Invoke-Mimikatz',
                description='PowerShell mimikatz invocation',
                pattern='invoke-mimikatz',
                pattern_type='string',
                severity='critical',
                category='powershell',
                first_seen='2015-05-10',
                last_updated='2026-04-12',
                false_positive_rate=0.01,
                detection_rate=0.97
            ),
            AVSignature(
                id='ps_002',
                vendor='Microsoft',
                name='PowerShell/EncodedCommand',
                description='Encoded PowerShell command',
                pattern='encodedcommand',
                pattern_type='string',
                severity='high',
                category='powershell',
                first_seen='2014-12-01',
                last_updated='2026-04-10',
                false_positive_rate=0.05,
                detection_rate=0.88
            ),
            AVSignature(
                id='ps_003',
                vendor='CrowdStrike',
                name='POWERSTATION.Downloader',
                description='PowerShell downloader',
                pattern='downloadstring',
                pattern_type='string',
                severity='high',
                category='powershell',
                first_seen='2016-01-20',
                last_updated='2026-03-28',
                false_positive_rate=0.03,
                detection_rate=0.92
            ),
            AVSignature(
                id='ps_004',
                vendor='FireEye',
                name='PowerShell/CobaltStrike',
                description='PowerShell Cobalt Strike loader',
                pattern='iex',
                pattern_type='string',
                severity='critical',
                category='powershell',
                first_seen='2017-04-15',
                last_updated='2026-04-05',
                false_positive_rate=0.08,
                detection_rate=0.82
            ),
        ]
        
        for sig in signatures:
            self.signatures.append(sig)
            self.signature_index[sig.id] = sig
    
    def _add_webshell_signatures(self):
        """Add webshell signatures."""
        signatures = [
            AVSignature(
                id='ws_001',
                vendor='Microsoft',
                name='Webshell:PHP/Backdoor',
                description='PHP backdoor webshell',
                pattern='eval(base64_decode',
                pattern_type='string',
                severity='critical',
                category='webshell',
                first_seen='2013-07-08',
                last_updated='2026-04-01',
                false_positive_rate=0.02,
                detection_rate=0.94
            ),
            AVSignature(
                id='ws_002',
                vendor='Kaspersky',
                name='Backdoor.PHP.Webshell',
                description='Generic PHP webshell',
                pattern='system($_REQUEST',
                pattern_type='string',
                severity='critical',
                category='webshell',
                first_seen='2012-03-15',
                last_updated='2026-03-20',
                false_positive_rate=0.01,
                detection_rate=0.96
            ),
            AVSignature(
                id='ws_003',
                vendor='Symantec',
                name='Webshell.ASPX',
                description='ASPX webshell',
                pattern='page.validate',
                pattern_type='string',
                severity='high',
                category='webshell',
                first_seen='2014-09-22',
                last_updated='2026-04-08',
                false_positive_rate=0.03,
                detection_rate=0.90
            ),
        ]
        
        for sig in signatures:
            self.signatures.append(sig)
            self.signature_index[sig.id] = sig
    
    def _save_database(self):
        """Save database to file."""
        data = {
            'version': '1.0.0',
            'last_updated': datetime.now().isoformat(),
            'total_signatures': len(self.signatures),
            'signatures_by_vendor': self._count_by_vendor(),
            'signatures_by_category': self._count_by_category(),
            'signatures': [
                {
                    'id': s.id,
                    'vendor': s.vendor,
                    'name': s.name,
                    'description': s.description,
                    'pattern': s.pattern,
                    'pattern_type': s.pattern_type,
                    'severity': s.severity,
                    'category': s.category,
                    'first_seen': s.first_seen,
                    'last_updated': s.last_updated,
                    'false_positive_rate': s.false_positive_rate,
                    'detection_rate': s.detection_rate
                }
                for s in self.signatures
            ]
        }
        
        with open(self.db_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Database saved to {self.db_path}")
    
    def _count_by_vendor(self) -> Dict[str, int]:
        """Count signatures by vendor."""
        counts = {}
        for sig in self.signatures:
            counts[sig.vendor] = counts.get(sig.vendor, 0) + 1
        return counts
    
    def _count_by_category(self) -> Dict[str, int]:
        """Count signatures by category."""
        counts = {}
        for sig in self.signatures:
            counts[sig.category] = counts.get(sig.category, 0) + 1
        return counts
    
    def scan_for_signatures(self, data: bytes) -> List[AVSignature]:
        """
        Scan data for known signatures.
        
        Args:
            data: Binary data to scan
            
        Returns:
            List of matched signatures
        """
        matches = []
        hex_data = data.hex().upper()
        text_data = data.decode('utf-8', errors='ignore').lower()
        
        for sig in self.signatures:
            matched = False
            
            if sig.pattern_type == 'hex':
                if sig.pattern.upper() in hex_data:
                    matched = True
            elif sig.pattern_type == 'string':
                if sig.pattern.lower() in text_data:
                    matched = True
            elif sig.pattern_type == 'regex':
                import re
                if re.search(sig.pattern, text_data, re.IGNORECASE):
                    matched = True
            
            if matched:
                matches.append(sig)
        
        # Sort by severity
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        matches.sort(key=lambda s: severity_order.get(s.severity, 0), reverse=True)
        
        return matches
    
    def get_statistics(self) -> Dict:
        """Get database statistics."""
        return {
            'total_signatures': len(self.signatures),
            'by_vendor': self._count_by_vendor(),
            'by_category': self._count_by_category(),
            'by_severity': self._count_by_severity(),
            'average_detection_rate': sum(s.detection_rate for s in self.signatures) / len(self.signatures) if self.signatures else 0,
            'average_false_positive_rate': sum(s.false_positive_rate for s in self.signatures) / len(self.signatures) if self.signatures else 0
        }
    
    def _count_by_severity(self) -> Dict[str, int]:
        """Count signatures by severity."""
        counts = {}
        for sig in self.signatures:
            counts[sig.severity] = counts.get(sig.severity, 0) + 1
        return counts
    
    def add_signature(self, signature: AVSignature):
        """Add a new signature."""
        self.signatures.append(signature)
        self.signature_index[signature.id] = signature
        self._save_database()
        
        logger.info(f"Added signature: {signature.id}")
    
    def remove_signature(self, signature_id: str) -> bool:
        """Remove a signature by ID."""
        if signature_id in self.signature_index:
            sig = self.signature_index.pop(signature_id)
            self.signatures.remove(sig)
            self._save_database()
            
            logger.info(f"Removed signature: {signature_id}")
            return True
        
        return False
    
    def search_signatures(self, query: str) -> List[AVSignature]:
        """Search signatures by keyword."""
        query = query.lower()
        
        matches = []
        for sig in self.signatures:
            if (query in sig.name.lower() or
                query in sig.description.lower() or
                query in sig.vendor.lower() or
                query in sig.category.lower()):
                matches.append(sig)
        
        return matches


# =============================================================================
# CLI Interface
# =============================================================================

def main():
    """Command-line interface for AV signature database."""
    import argparse
    
    parser = argparse.ArgumentParser(description='KaliAgent v3 - AV Signature Database')
    parser.add_argument('--stats', action='store_true', help='Show statistics')
    parser.add_argument('--search', type=str, help='Search signatures')
    parser.add_argument('--scan', type=str, help='Scan file for signatures')
    parser.add_argument('--list', action='store_true', help='List all signatures')
    
    args = parser.parse_args()
    
    db = AVSignatureDatabase()
    
    if args.stats:
        stats = db.get_statistics()
        print("\nAV Signature Database Statistics:")
        print("=" * 60)
        print(f"Total Signatures: {stats['total_signatures']}")
        print(f"Average Detection Rate: {stats['average_detection_rate']:.1%}")
        print(f"Average False Positive Rate: {stats['average_false_positive_rate']:.1%}")
        
        print("\nBy Vendor:")
        for vendor, count in sorted(stats['by_vendor'].items(), key=lambda x: -x[1]):
            print(f"  {vendor}: {count}")
        
        print("\nBy Category:")
        for cat, count in sorted(stats['by_category'].items(), key=lambda x: -x[1]):
            print(f"  {cat}: {count}")
        
        print("\nBy Severity:")
        for sev, count in sorted(stats['by_severity'].items(), key=lambda x: -x[1]):
            print(f"  {sev}: {count}")
        
        print("=" * 60)
    
    elif args.search:
        results = db.search_signatures(args.search)
        print(f"\nSearch Results for '{args.search}': {len(results)} matches")
        print("=" * 60)
        for sig in results:
            print(f"  • [{sig.severity.upper()}] {sig.vendor} - {sig.name}")
            print(f"    {sig.description}")
        print("=" * 60)
    
    elif args.scan:
        from pathlib import Path
        with open(Path(args.scan), 'rb') as f:
            data = f.read()
        
        matches = db.scan_for_signatures(data)
        print(f"\nScan Results: {len(matches)} signatures matched")
        print("=" * 60)
        for sig in matches:
            print(f"  ⚠️  [{sig.severity.upper()}] {sig.vendor} - {sig.name}")
            print(f"      Detection Rate: {sig.detection_rate:.1%}")
            print(f"      False Positive Rate: {sig.false_positive_rate:.1%}")
        print("=" * 60)
    
    elif args.list:
        print(f"\nAll Signatures: {len(db.signatures)}")
        print("=" * 60)
        for sig in db.signatures:
            print(f"  [{sig.severity.upper():8}] {sig.vendor:15} - {sig.name}")
        print("=" * 60)
    
    else:
        print("Use --stats, --search, --scan, or --list")


if __name__ == '__main__':
    main()
