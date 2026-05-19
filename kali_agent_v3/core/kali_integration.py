#!/usr/bin/env python3
"""
KaliAgent v3 - Kali Linux Integration Module
=============================================

Detects Kali Linux environment, verifies installation,
and provides version/edition information.

Task: 1.1.1, 1.1.2, 1.1.3
Status: IMPLEMENTED
"""

import os
import re
import subprocess
import json
from typing import Dict, List, Tuple
from dataclasses import dataclass


@dataclass
class KaliVersion:
    """Kali Linux version information."""
    version: str
    edition: str  # default, light, everything, tools
    rolling_status: bool
    kernel_version: str
    architecture: str


@dataclass
class RepoConfig:
    """Kali repository configuration."""
    repos_enabled: bool
    is_configured: bool
    repositories: List[str]
    kali_rolling_enabled: bool
    custom_overrides: List[str]


@dataclass
class ToolCategories:
    """Installed Kali tool categories."""
    installed_categories: List[str]
    missing_categories: List[str]
    coverage_pct: float
    total_categories: int
    tools_per_category: Dict[str, int]


class KaliIntegration:
    """
    Kali Linux environment detection and integration.
    
    Provides methods to:
    - Detect Kali Linux installation
    - Verify repository configuration
    - Identify installed tool categories
    """
    
    # Official Kali Linux tool categories
    KALI_CATEGORIES = [
        'kali-tools-top10',
        'kali-tools-information-gathering',
        'kali-tools-vulnerability',
        'kali-tools-web',
        'kali-tools-wireless',
        'kali-tools-exploitation',
        'kali-tools-sniffing',
        'kali-tools-postexploit',
        'kali-tools-forensics',
        'kali-tools-reporting',
        'kali-tools-reverse-engineering',
        'kali-tools-password',
        'kali-tools-crypto-stress',
        'kali-tools-social-engineering',
    ]
    
    def __init__(self):
        """Initialize Kali integration."""
        self.kali_version_file = '/etc/kali-version'
        self.sources_list_file = '/etc/apt/sources.list'
        self.sources_list_d_dir = '/etc/apt/sources.list.d'
    
    # =========================================================================
    # Task 1.1.1: Detect Kali Linux Installation
    # =========================================================================
    
    def detect_kali(self) -> Tuple[bool, KaliVersion]:
        """
        Detect if running on Kali Linux and return version info.
        
        Returns:
            Tuple of (is_kali, KaliVersion object)
            
        Example:
            >>> kali = KaliIntegration()
            >>> is_kali, version = kali.detect_kali()
            >>> print(f"Kali {version.version} ({version.edition})")
        """
        # Check if Kali version file exists
        if not os.path.exists(self.kali_version_file):
            # Not Kali Linux (might be Debian/Ubuntu)
            return False, self._get_non_kali_version()
        
        # Read Kali version
        try:
            with open(self.kali_version_file, 'r') as f:
                version_content = f.read().strip()
        except Exception:
            return False, KaliVersion(
                version='unknown',
                edition='unknown',
                rolling_status=False,
                kernel_version='unknown',
                architecture='unknown'
            )
        
        # Parse version info
        version = self._parse_kali_version(version_content)
        
        return True, version
    
    def _get_non_kali_version(self) -> KaliVersion:
        """Get version info for non-Kali systems (Debian/Ubuntu)."""
        try:
            # Try to get OS info from /etc/os-release
            with open('/etc/os-release', 'r') as f:
                os_release = f.read()
            
            # Extract distribution info
            distro_match = re.search(r'PRETTY_NAME="([^"]+)"', os_release)
            distro = distro_match.group(1) if distro_match else 'Unknown'
            
            return KaliVersion(
                version=distro,
                edition='non-kali',
                rolling_status=False,
                kernel_version=os.uname().release,
                architecture=os.uname().machine
            )
        except Exception:
            return KaliVersion(
                version='unknown',
                edition='unknown',
                rolling_status=False,
                kernel_version='unknown',
                architecture='unknown'
            )
    
    def _parse_kali_version(self, content: str) -> KaliVersion:
        """Parse Kali version file content."""
        # Version file typically contains: "Kali Linux Version 2024.1"
        version_match = re.search(r'Kali Linux Version ([\d.]+)', content)
        version = version_match.group(1) if version_match else 'unknown'
        
        # Determine edition based on installed meta-packages
        edition = self._detect_edition()
        
        # Check if rolling (kali-rolling is the standard since 2020)
        rolling_status = self._is_rolling_installation()
        
        return KaliVersion(
            version=version,
            edition=edition,
            rolling_status=rolling_status,
            kernel_version=os.uname().release,
            architecture=os.uname().machine
        )
    
    def _detect_edition(self) -> str:
        """Detect Kali edition (default, light, everything, tools)."""
        # Check for edition-specific meta-packages
        edition_packages = {
            'everything': 'kali-linux-everything',
            'light': 'kali-linux-light',
            'default': 'kali-linux-default',
            'tools': 'kali-tools-',  # Any kali-tools-* package
        }
        
        for edition, package in edition_packages.items():
            if self._is_package_installed(package):
                return edition
        
        return 'custom'  # Custom installation
    
    def _is_rolling_installation(self) -> bool:
        """Check if this is a kali-rolling installation."""
        try:
            result = subprocess.run(
                ['apt-cache', 'policy', 'kali-linux-default'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # Check if candidate version is from kali-rolling
            if 'kali-rolling' in result.stdout:
                return True
            
            return False
        except Exception:
            return False
    
    def _is_package_installed(self, package_pattern: str) -> bool:
        """Check if a package (or package matching pattern) is installed."""
        try:
            result = subprocess.run(
                ['dpkg', '-l', package_pattern],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # Check for 'ii' status (installed)
            for line in result.stdout.split('\n'):
                if line.startswith('ii'):
                    return True
            
            return False
        except Exception:
            return False
    
    # =========================================================================
    # Task 1.1.2: Check Kali Repository Configuration
    # =========================================================================
    
    def check_repository_config(self) -> RepoConfig:
        """
        Check Kali repository configuration.
        
        Returns:
            RepoConfig object with repository status
            
        Example:
            >>> kali = KaliIntegration()
            >>> config = kali.check_repository_config()
            >>> print(f"Kali-rolling enabled: {config.kali_rolling_enabled}")
        """
        repositories = []
        custom_overrides = []
        kali_rolling_enabled = False
        
        # Parse main sources.list
        try:
            with open(self.sources_list_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        repositories.append(line)
                        
                        # Check for kali-rolling
                        if 'kali-rolling' in line and line.startswith('deb'):
                            kali_rolling_enabled = True
                        
                        # Check for custom overrides
                        if 'http' in line and 'kali.org' not in line:
                            custom_overrides.append(line)
        except FileNotFoundError:
            pass
        
        # Parse sources.list.d directory
        try:
            for filename in os.listdir(self.sources_list_d_dir):
                if filename.endswith('.list'):
                    filepath = os.path.join(self.sources_list_d_dir, filename)
                    try:
                        with open(filepath, 'r') as f:
                            for line in f:
                                line = line.strip()
                                if line and not line.startswith('#'):
                                    repositories.append(line)
                                    
                                    if 'kali-rolling' in line and line.startswith('deb'):
                                        kali_rolling_enabled = True
                                    
                                    if 'http' in line and 'kali.org' not in line:
                                        custom_overrides.append(line)
                    except Exception:
                        continue
        except FileNotFoundError:
            pass
        
        # Determine if properly configured
        is_configured = (
            len(repositories) > 0 and
            any('kali.org' in repo for repo in repositories) and
            kali_rolling_enabled
        )
        
        return RepoConfig(
            repos_enabled=len(repositories) > 0,
            is_configured=is_configured,
            repositories=repositories,
            kali_rolling_enabled=kali_rolling_enabled,
            custom_overrides=custom_overrides
        )
    
    # =========================================================================
    # Task 1.1.3: Identify Installed Tool Categories
    # =========================================================================
    
    def identify_installed_categories(self) -> ToolCategories:
        """
        Identify installed Kali tool categories.
        
        Returns:
            ToolCategories object with installation status
            
        Example:
            >>> kali = KaliIntegration()
            >>> categories = kali.identify_installed_categories()
            >>> print(f"Coverage: {categories.coverage_pct}%")
        """
        installed_categories = []
        missing_categories = []
        tools_per_category = {}
        
        for category in self.KALI_CATEGORIES:
            if self._is_package_installed(category):
                installed_categories.append(category)
                
                # Count tools in this category
                tool_count = self._count_tools_in_category(category)
                tools_per_category[category] = tool_count
            else:
                missing_categories.append(category)
                tools_per_category[category] = 0
        
        total_categories = len(self.KALI_CATEGORIES)
        coverage_pct = (len(installed_categories) / total_categories) * 100 if total_categories > 0 else 0
        
        return ToolCategories(
            installed_categories=installed_categories,
            missing_categories=missing_categories,
            coverage_pct=round(coverage_pct, 2),
            total_categories=total_categories,
            tools_per_category=tools_per_category
        )
    
    def _count_tools_in_category(self, category: str) -> int:
        """Count individual tools in a category package."""
        try:
            # Get package dependencies
            result = subprocess.run(
                ['apt-cache', 'depends', category],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # Count dependencies (tools)
            tool_count = 0
            for line in result.stdout.split('\n'):
                if line.startswith('  Depends:') or line.startswith('  |'):
                    tool_count += 1
            
            return tool_count
        except Exception:
            return 0
    
    # =========================================================================
    # Utility Methods
    # =========================================================================
    
    def get_full_status(self) -> Dict:
        """
        Get complete Kali environment status.
        
        Returns:
            Dictionary with all status information
            
        Example:
            >>> kali = KaliIntegration()
            >>> status = kali.get_full_status()
            >>> print(json.dumps(status, indent=2))
        """
        is_kali, version = self.detect_kali()
        repo_config = self.check_repository_config()
        categories = self.identify_installed_categories()
        
        return {
            'is_kali': is_kali,
            'version': {
                'version': version.version,
                'edition': version.edition,
                'rolling': version.rolling_status,
                'kernel': version.kernel_version,
                'architecture': version.architecture
            },
            'repositories': {
                'enabled': repo_config.repos_enabled,
                'configured': repo_config.is_configured,
                'kali_rolling': repo_config.kali_rolling_enabled,
                'custom_overrides': repo_config.custom_overrides,
                'repository_list': repo_config.repositories
            },
            'tool_categories': {
                'installed': categories.installed_categories,
                'missing': categories.missing_categories,
                'coverage_pct': categories.coverage_pct,
                'total_categories': categories.total_categories,
                'tools_per_category': categories.tools_per_category
            }
        }
    
    def verify_kali_ready(self) -> Tuple[bool, List[str]]:
        """
        Verify system is ready for KaliAgent v3.
        
        Returns:
            Tuple of (is_ready, list of issues)
        """
        issues = []
        
        # Check if Kali Linux
        is_kali, version = self.detect_kali()
        if not is_kali:
            issues.append(f"Not running on Kali Linux (running: {version.version})")
        
        # Check repository configuration
        repo_config = self.check_repository_config()
        if not repo_config.is_configured:
            issues.append("Kali repositories not properly configured")
        
        if not repo_config.kali_rolling_enabled:
            issues.append("kali-rolling repository not enabled")
        
        # Check tool categories
        categories = self.identify_installed_categories()
        if categories.coverage_pct < 50:
            issues.append(f"Low tool coverage: {categories.coverage_pct}% (minimum 50% recommended)")
        
        is_ready = len(issues) == 0
        
        return is_ready, issues


# =============================================================================
# CLI Interface
# =============================================================================

def main():
    """Command-line interface for Kali integration."""
    import argparse
    
    parser = argparse.ArgumentParser(description='KaliAgent v3 - Kali Linux Integration')
    parser.add_argument('--status', action='store_true', help='Show full status')
    parser.add_argument('--version', action='store_true', help='Show version info')
    parser.add_argument('--repos', action='store_true', help='Check repository config')
    parser.add_argument('--categories', action='store_true', help='Show tool categories')
    parser.add_argument('--verify', action='store_true', help='Verify Kali ready')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    
    args = parser.parse_args()
    
    kali = KaliIntegration()
    
    if args.status or (not any([args.version, args.repos, args.categories, args.verify])):
        result = kali.get_full_status()
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"Kali Linux: {'Yes' if result['is_kali'] else 'No'}")
            print(f"Version: {result['version']['version']} ({result['version']['edition']})")
            print(f"Kernel: {result['version']['kernel']}")
            print(f"Architecture: {result['version']['architecture']}")
            print(f"Rolling: {'Yes' if result['version']['rolling'] else 'No'}")
            print("\nRepositories:")
            print(f"  Enabled: {'Yes' if result['repositories']['enabled'] else 'No'}")
            print(f"  Configured: {'Yes' if result['repositories']['configured'] else 'No'}")
            print(f"  Kali-rolling: {'Yes' if result['repositories']['kali_rolling'] else 'No'}")
            print("\nTool Categories:")
            print(f"  Installed: {len(result['tool_categories']['installed'])}/{result['tool_categories']['total_categories']}")
            print(f"  Coverage: {result['tool_categories']['coverage_pct']}%")
    
    elif args.version:
        is_kali, version = kali.detect_kali()
        if args.json:
            print(json.dumps({
                'is_kali': is_kali,
                'version': version.version,
                'edition': version.edition,
                'rolling': version.rolling_status,
                'kernel': version.kernel_version,
                'architecture': version.architecture
            }, indent=2))
        else:
            print(f"Kali Linux: {version.version} ({version.edition})")
            print(f"Kernel: {version.kernel_version}")
            print(f"Architecture: {version.architecture}")
    
    elif args.repos:
        config = kali.check_repository_config()
        if args.json:
            print(json.dumps({
                'enabled': config.repos_enabled,
                'configured': config.is_configured,
                'kali_rolling': config.kali_rolling_enabled,
                'custom_overrides': config.custom_overrides,
                'repositories': config.repositories
            }, indent=2))
        else:
            print(f"Repositories Enabled: {'Yes' if config.repos_enabled else 'No'}")
            print(f"Properly Configured: {'Yes' if config.is_configured else 'No'}")
            print(f"Kali-rolling Enabled: {'Yes' if config.kali_rolling_enabled else 'No'}")
            if config.custom_overrides:
                print(f"Custom Overrides: {len(config.custom_overrides)}")
    
    elif args.categories:
        categories = kali.identify_installed_categories()
        if args.json:
            print(json.dumps({
                'installed': categories.installed_categories,
                'missing': categories.missing_categories,
                'coverage_pct': categories.coverage_pct,
                'tools_per_category': categories.tools_per_category
            }, indent=2))
        else:
            print(f"Installed Categories ({len(categories.installed_categories)}/{categories.total_categories}):")
            for cat in categories.installed_categories:
                print(f"  ✅ {cat} ({categories.tools_per_category[cat]} tools)")
            print(f"\nMissing Categories ({len(categories.missing_categories)}):")
            for cat in categories.missing_categories:
                print(f"  ❌ {cat}")
            print(f"\nCoverage: {categories.coverage_pct}%")
    
    elif args.verify:
        is_ready, issues = kali.verify_kali_ready()
        if args.json:
            print(json.dumps({
                'ready': is_ready,
                'issues': issues
            }, indent=2))
        else:
            if is_ready:
                print("✅ System is ready for KaliAgent v3!")
            else:
                print("❌ System is NOT ready for KaliAgent v3")
                print("\nIssues found:")
                for issue in issues:
                    print(f"  - {issue}")


if __name__ == '__main__':
    main()
