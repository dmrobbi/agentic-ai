#!/usr/bin/env python3
"""
Tests for KaliAgent v3 - Kali Linux Integration Module

Task: 1.1.1, 1.1.2, 1.1.3
Status: IMPLEMENTED
"""

import pytest
import os
import sys
from unittest.mock import patch, MagicMock

# Add core to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'core'))

from kali_integration import KaliIntegration, KaliVersion, RepoConfig, ToolCategories


class TestKaliDetection:
    """Test Task 1.1.1: Detect Kali Linux installation"""
    
    def test_kali_version_file_exists(self):
        """Test detection when Kali version file exists"""
        kali = KaliIntegration()
        
        with patch('os.path.exists', return_value=True):
            with patch('builtins.open', MagicMock(return_value=MagicMock(read=MagicMock(return_value='Kali Linux Version 2024.1')))):
                with patch('os.uname') as mock_uname:
                    mock_uname.return_value.release = '6.6.9-amd64'
                    mock_uname.return_value.machine = 'x86_64'
                    
                    with patch.object(kali, '_detect_edition', return_value='default'):
                        with patch.object(kali, '_is_rolling_installation', return_value=True):
                            is_kali, version = kali.detect_kali()
                            
                            assert is_kali is True
                            assert version.version == '2024.1'
                            assert version.edition == 'default'
                            assert version.rolling_status is True
                            assert version.kernel_version == '6.6.9-amd64'
                            assert version.architecture == 'x86_64'
    
    def test_kali_version_file_missing(self):
        """Test detection when not on Kali Linux"""
        kali = KaliIntegration()
        
        with patch('os.path.exists', return_value=False):
            with patch('builtins.open', MagicMock(return_value=MagicMock(read=MagicMock(return_value='PRETTY_NAME="Ubuntu 22.04"')))):
                with patch('os.uname') as mock_uname:
                    mock_uname.return_value.release = '5.15.0-generic'
                    mock_uname.return_value.machine = 'x86_64'
                    
                    is_kali, version = kali.detect_kali()
                    
                    assert is_kali is False
                    assert 'Ubuntu' in version.version or version.version == 'unknown'
                    assert version.edition == 'non-kali'
    
    def test_detect_edition_everything(self):
        """Test edition detection for kali-linux-everything"""
        kali = KaliIntegration()
        
        with patch.object(kali, '_is_package_installed') as mock_installed:
            mock_installed.side_effect = lambda pkg: pkg == 'kali-linux-everything'
            
            edition = kali._detect_edition()
            assert edition == 'everything'
    
    def test_detect_edition_light(self):
        """Test edition detection for kali-linux-light"""
        kali = KaliIntegration()
        
        with patch.object(kali, '_is_package_installed') as mock_installed:
            mock_installed.side_effect = lambda pkg: pkg == 'kali-linux-light'
            
            edition = kali._detect_edition()
            assert edition == 'light'
    
    def test_detect_edition_default(self):
        """Test edition detection for kali-linux-default"""
        kali = KaliIntegration()
        
        with patch.object(kali, '_is_package_installed') as mock_installed:
            mock_installed.side_effect = lambda pkg: pkg in ['kali-linux-default', 'kali-tools-']
            
            edition = kali._detect_edition()
            assert edition == 'default'
    
    def test_is_rolling_installation_true(self):
        """Test rolling detection when kali-rolling is enabled"""
        kali = KaliIntegration()
        
        mock_result = MagicMock()
        mock_result.stdout = 'Candidate: 2024.1\n 500 http://http.kali.org/kali kali-rolling/main amd64 Packages'
        mock_result.stderr = ''
        
        with patch('subprocess.run', return_value=mock_result):
            is_rolling = kali._is_rolling_installation()
            assert is_rolling is True
    
    def test_is_rolling_installation_false(self):
        """Test rolling detection when kali-rolling is not enabled"""
        kali = KaliIntegration()
        
        mock_result = MagicMock()
        mock_result.stdout = 'Candidate: 2023.4\n 500 http://http.kali.org/kali kali-last-snapshot/main amd64 Packages'
        mock_result.stderr = ''
        
        with patch('subprocess.run', return_value=mock_result):
            is_rolling = kali._is_rolling_installation()
            assert is_rolling is False
    
    def test_is_package_installed_true(self):
        """Test package installation check when installed"""
        kali = KaliIntegration()
        
        mock_result = MagicMock()
        mock_result.stdout = 'ii  nmap  7.94+dfsg1-1  amd64  Network scanner'
        mock_result.stderr = ''
        
        with patch('subprocess.run', return_value=mock_result):
            is_installed = kali._is_package_installed('nmap')
            assert is_installed is True
    
    def test_is_package_installed_false(self):
        """Test package installation check when not installed"""
        kali = KaliIntegration()
        
        mock_result = MagicMock()
        mock_result.stdout = 'dpkg-query: no packages found matching nonexistent-package'
        mock_result.stderr = ''
        
        with patch('subprocess.run', return_value=mock_result):
            is_installed = kali._is_package_installed('nonexistent-package')
            assert is_installed is False


class TestRepositoryConfig:
    """Test Task 1.1.2: Check Kali repository configuration"""
    
    def test_repos_configured_correctly(self):
        """Test repository config when properly configured"""
        kali = KaliIntegration()
        
        mock_sources = 'deb http://http.kali.org/kali kali-rolling main contrib non-free\n'
        
        with patch('builtins.open', MagicMock(return_value=MagicMock(read=MagicMock(return_value=mock_sources)))):
            with patch('os.listdir', return_value=[]):
                config = kali.check_repository_config()
                
                assert config.repos_enabled is True
                assert config.is_configured is True
                assert config.kali_rolling_enabled is True
                assert len(config.repositories) == 1
                assert len(config.custom_overrides) == 0
    
    def test_repos_with_custom_overrides(self):
        """Test repository config with custom repositories"""
        kali = KaliIntegration()
        
        mock_sources = '''deb http://http.kali.org/kali kali-rolling main contrib non-free
deb http://custom.repo.example.com custom main
'''
        
        with patch('builtins.open', MagicMock(return_value=MagicMock(read=MagicMock(return_value=mock_sources)))):
            with patch('os.listdir', return_value=[]):
                config = kali.check_repository_config()
                
                assert config.repos_enabled is True
                assert config.is_configured is True
                assert config.kali_rolling_enabled is True
                assert len(config.repositories) == 2
                assert len(config.custom_overrides) == 1
                assert 'custom.repo.example.com' in config.custom_overrides[0]
    
    def test_repos_not_configured(self):
        """Test repository config when not configured"""
        kali = KaliIntegration()
        
        mock_sources = 'deb http://archive.ubuntu.com/ubuntu jammy main\n'
        
        with patch('builtins.open', MagicMock(return_value=MagicMock(read=MagicMock(return_value=mock_sources)))):
            with patch('os.listdir', return_value=[]):
                config = kali.check_repository_config()
                
                assert config.repos_enabled is True
                assert config.is_configured is False
                assert config.kali_rolling_enabled is False
    
    def test_repos_file_missing(self):
        """Test repository config when sources.list missing"""
        kali = KaliIntegration()
        
        with patch('builtins.open', side_effect=FileNotFoundError()):
            with patch('os.listdir', side_effect=FileNotFoundError()):
                config = kali.check_repository_config()
                
                assert config.repos_enabled is False
                assert config.is_configured is False
                assert config.kali_rolling_enabled is False
                assert len(config.repositories) == 0
    
    def test_sources_list_d_parsing(self):
        """Test parsing of sources.list.d directory"""
        kali = KaliIntegration()
        
        mock_main_sources = 'deb http://http.kali.org/kali kali-rolling main\n'
        mock_extra_sources = 'deb http://extra.kali.org/kali kali-rolling contrib\n'
        
        def mock_open_func(filepath, *args, **kwargs):
            if 'sources.list' in str(filepath):
                return MagicMock(read=MagicMock(return_value=mock_main_sources))
            elif 'extra.list' in str(filepath):
                return MagicMock(read=MagicMock(return_value=mock_extra_sources))
            else:
                raise FileNotFoundError()
        
        with patch('builtins.open', MagicMock(side_effect=mock_open_func)):
            with patch('os.listdir', return_value=['extra.list']):
                config = kali.check_repository_config()
                
                assert config.repos_enabled is True
                assert config.is_configured is True
                assert len(config.repositories) == 2


class TestToolCategories:
    """Test Task 1.1.3: Identify installed tool categories"""
    
    def test_all_categories_installed(self):
        """Test when all categories are installed"""
        kali = KaliIntegration()
        
        with patch.object(kali, '_is_package_installed', return_value=True):
            with patch.object(kali, '_count_tools_in_category', return_value=10):
                categories = kali.identify_installed_categories()
                
                assert len(categories.installed_categories) == len(kali.KALI_CATEGORIES)
                assert len(categories.missing_categories) == 0
                assert categories.coverage_pct == 100.0
                assert categories.total_categories == len(kali.KALI_CATEGORIES)
                assert all(count == 10 for count in categories.tools_per_category.values())
    
    def test_no_categories_installed(self):
        """Test when no categories are installed"""
        kali = KaliIntegration()
        
        with patch.object(kali, '_is_package_installed', return_value=False):
            categories = kali.identify_installed_categories()
            
            assert len(categories.installed_categories) == 0
            assert len(categories.missing_categories) == len(kali.KALI_CATEGORIES)
            assert categories.coverage_pct == 0.0
    
    def test_partial_categories_installed(self):
        """Test when some categories are installed"""
        kali = KaliIntegration()
        
        def mock_installed(pkg):
            return pkg in ['kali-tools-top10', 'kali-tools-web', 'kali-tools-wireless']
        
        with patch.object(kali, '_is_package_installed', side_effect=mock_installed):
            with patch.object(kali, '_count_tools_in_category', return_value=5):
                categories = kali.identify_installed_categories()
                
                assert len(categories.installed_categories) == 3
                assert len(categories.missing_categories) == len(kali.KALI_CATEGORIES) - 3
                assert categories.coverage_pct == 20.0  # 3/15 = 20%
    
    def test_count_tools_in_category(self):
        """Test counting tools in a category"""
        kali = KaliIntegration()
        
        mock_result = MagicMock()
        mock_result.stdout = '''nmap
  Depends: nmap-common
  |  Depends: libssl3
  Depends: libc6
  |  Depends: libpcap0.8
'''
        mock_result.stderr = ''
        
        with patch('subprocess.run', return_value=mock_result):
            count = kali._count_tools_in_category('kali-tools-top10')
            assert count == 4  # 4 dependency lines
    
    def test_count_tools_error_handling(self):
        """Test tool counting with subprocess error"""
        kali = KaliIntegration()
        
        with patch('subprocess.run', side_effect=Exception('Command failed')):
            count = kali._count_tools_in_category('kali-tools-top10')
            assert count == 0  # Should return 0 on error


class TestFullStatus:
    """Test get_full_status method"""
    
    def test_full_status_structure(self):
        """Test full status returns correct structure"""
        kali = KaliIntegration()
        
        with patch.object(kali, 'detect_kali', return_value=(True, KaliVersion('2024.1', 'default', True, '6.6.9', 'x86_64'))):
            with patch.object(kali, 'check_repository_config', return_value=RepoConfig(True, True, ['deb http://http.kali.org/kali kali-rolling main'], True, [])):
                with patch.object(kali, 'identify_installed_categories', return_value=ToolCategories(['kali-tools-top10'], [], 100.0, 1, {'kali-tools-top10': 10})):
                    status = kali.get_full_status()
                    
                    assert 'is_kali' in status
                    assert 'version' in status
                    assert 'repositories' in status
                    assert 'tool_categories' in status
                    
                    assert status['is_kali'] is True
                    assert status['version']['version'] == '2024.1'
                    assert status['repositories']['kali_rolling'] is True
                    assert status['tool_categories']['coverage_pct'] == 100.0


class TestVerifyKaliReady:
    """Test verify_kali_ready method"""
    
    def test_system_ready(self):
        """Test when system is ready"""
        kali = KaliIntegration()
        
        with patch.object(kali, 'detect_kali', return_value=(True, KaliVersion('2024.1', 'default', True, '6.6.9', 'x86_64'))):
            with patch.object(kali, 'check_repository_config', return_value=RepoConfig(True, True, [], True, [])):
                with patch.object(kali, 'identify_installed_categories', return_value=ToolCategories(['kali-tools-top10'], [], 100.0, 1, {})):
                    is_ready, issues = kali.verify_kali_ready()
                    
                    assert is_ready is True
                    assert len(issues) == 0
    
    def test_system_not_ready_not_kali(self):
        """Test when system is not Kali"""
        kali = KaliIntegration()
        
        with patch.object(kali, 'detect_kali', return_value=(False, KaliVersion('Ubuntu 22.04', 'non-kali', False, '5.15.0', 'x86_64'))):
            with patch.object(kali, 'check_repository_config', return_value=RepoConfig(False, False, [], False, [])):
                with patch.object(kali, 'identify_installed_categories', return_value=ToolCategories([], [], 0.0, 0, {})):
                    is_ready, issues = kali.verify_kali_ready()
                    
                    assert is_ready is False
                    assert len(issues) > 0
                    assert any('Not running on Kali' in issue for issue in issues)
    
    def test_system_not_ready_low_coverage(self):
        """Test when tool coverage is too low"""
        kali = KaliIntegration()
        
        with patch.object(kali, 'detect_kali', return_value=(True, KaliVersion('2024.1', 'default', True, '6.6.9', 'x86_64'))):
            with patch.object(kali, 'check_repository_config', return_value=RepoConfig(True, True, [], True, [])):
                with patch.object(kali, 'identify_installed_categories', return_value=ToolCategories([], ['kali-tools-top10'], 0.0, 1, {})):
                    is_ready, issues = kali.verify_kali_ready()
                    
                    assert is_ready is False
                    assert any('Low tool coverage' in issue for issue in issues)


# =============================================================================
# Integration Tests (require real Kali system)
# =============================================================================

@pytest.mark.integration
class TestIntegrationOnRealKali:
    """Integration tests that run on real Kali Linux system"""
    
    def test_real_kali_detection(self):
        """Test detection on real Kali system"""
        kali = KaliIntegration()
        is_kali, version = kali.detect_kali()
        
        # On a real Kali system, this should pass
        if os.path.exists('/etc/kali-version'):
            assert is_kali is True
            assert version.version != 'unknown'
            assert version.edition != 'unknown'
    
    def test_real_repo_config(self):
        """Test repo config on real Kali system"""
        kali = KaliIntegration()
        config = kali.check_repository_config()
        
        if os.path.exists('/etc/apt/sources.list'):
            assert config.repos_enabled is True
    
    def test_real_categories(self):
        """Test category detection on real Kali system"""
        kali = KaliIntegration()
        categories = kali.identify_installed_categories()
        
        assert categories.total_categories > 0
        assert categories.coverage_pct >= 0.0 and categories.coverage_pct <= 100.0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
