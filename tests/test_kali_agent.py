"""
KaliAgent Unit Tests
=====================

Tests for KaliAgent tool orchestration, safety controls, playbooks,
and Metasploit integration.
"""

import pytest
from datetime import datetime, timedelta
from pathlib import Path

from agentic_ai.agents.cyber.kali import (
    KaliAgent,
    ToolCategory,
    AuthorizationLevel,
    ExecutionMode,
    ToolDefinition,
    _validate_command_args,
)
from agentic_ai.infrastructure.utils import utcnow


class TestKaliAgentInitialization:
    """Test KaliAgent initialization and configuration."""
    
    def test_init_default(self):
        """Test default initialization."""
        agent = KaliAgent()
        assert agent.agent_id == "kali-agent"
        assert agent.workspace.exists()
        assert agent.log_dir.exists()
        assert len(agent.tools) > 50
        assert agent.safe_mode is True
        assert agent.dry_run is False
        assert agent.max_concurrent_jobs == 5
    
    def test_init_custom_workspace(self):
        """Test initialization with custom workspace."""
        workspace = "/tmp/kali-test-workspace"
        agent = KaliAgent(workspace=workspace, log_dir=f"{workspace}/logs")
        assert agent.workspace == Path(workspace)
        assert agent.workspace.exists()
    
    def test_tool_count_by_category(self):
        """Test tool distribution across categories."""
        agent = KaliAgent()
        cats = {}
        for tool in agent.tools.values():
            cat = tool.category.value
            cats[cat] = cats.get(cat, 0) + 1
        
        # Verify minimum tools per category
        assert cats.get("reconnaissance", 0) >= 8
        assert cats.get("web_application", 0) >= 8
        assert cats.get("password", 0) >= 6
        assert cats.get("wireless", 0) >= 3
        assert cats.get("post_exploitation", 0) >= 3
        assert cats.get("forensics", 0) >= 3


class TestAuthorization:
    """Test authorization levels and safety controls."""
    
    def test_authorization_levels(self):
        """Test authorization level enumeration."""
        assert AuthorizationLevel.NONE.value == 0
        assert AuthorizationLevel.BASIC.value == 1
        assert AuthorizationLevel.ADVANCED.value == 2
        assert AuthorizationLevel.CRITICAL.value == 3
    
    def test_set_authorization(self):
        """Test setting authorization level."""
        agent = KaliAgent()
        
        # Default is NONE (0) - BASIC (1) tools should fail
        authorized, msg = agent.check_authorization("nmap")
        assert authorized is False and "Authorization level" in msg
        
        # Set BASIC (1)
        agent.set_authorization(AuthorizationLevel.BASIC)
        authorized, msg = agent.check_authorization("nmap")
        assert authorized is True, f"nmap should be authorized with BASIC: {msg}"
        
        # Metasploit requires CRITICAL (3)
        authorized, msg = agent.check_authorization("metasploit")
        assert authorized is False and "3 required" in msg  # CRITICAL = 3
        
        # Set CRITICAL (3)
        agent.set_authorization(AuthorizationLevel.CRITICAL)
        authorized, msg = agent.check_authorization("metasploit")
        assert authorized is True, f"metasploit should be authorized with CRITICAL: {msg}"
    
    def test_authorization_expiry(self):
        """Test authorization with expiry."""
        agent = KaliAgent()
        
        # Expired authorization
        expired = utcnow() - timedelta(hours=1)
        result = agent.set_authorization(AuthorizationLevel.BASIC, expires_at=expired)
        assert result is False
    
    def test_revoke_authorization(self):
        """Test revoking authorization."""
        agent = KaliAgent()
        agent.set_authorization(AuthorizationLevel.CRITICAL)
        
        authorized, msg = agent.check_authorization("nmap")
        assert authorized is True, f"nmap should be authorized: {msg}"
        
        agent.revoke_authorization()
        # After revoke, authorization returns to NONE (0)
        authorized, msg = agent.check_authorization("nmap")
        # With NONE, BASIC tools should fail
        assert authorized is False and "Authorization level" in msg


class TestSafetyControls:
    """Test IP whitelist/blacklist and target validation."""
    
    def test_ip_whitelist(self):
        """Test IP whitelist functionality."""
        agent = KaliAgent()
        
        # Set whitelist
        agent.set_ip_whitelist(["192.0.2.0/24", "198.51.100.100"])
        assert agent.ip_whitelist is not None
        
        # Validate allowed target
        valid, msg = agent.validate_target("198.51.100.100")
        assert valid is True
        
        # Validate blocked target
        valid, msg = agent.validate_target("8.8.8.8")
        assert valid is False
        assert "not in whitelist" in msg
        
        # Clear whitelist
        agent.clear_ip_whitelist()
        assert agent.ip_whitelist is None
    
    def test_ip_blacklist(self):
        """Test IP blacklist functionality."""
        agent = KaliAgent()
        
        # Add to blacklist
        agent.add_to_blacklist("192.0.2.1")
        assert "192.0.2.1" in agent.ip_blacklist
        
        # Validate blacklisted target
        valid, msg = agent.validate_target("192.0.2.1")
        assert valid is False
        assert "blacklisted" in msg
        
        # Remove from blacklist
        agent.remove_from_blacklist("192.0.2.1")
        assert "192.0.2.1" not in agent.ip_blacklist
    
    def test_blacklist_takes_precedence(self):
        """Test blacklist takes precedence over whitelist."""
        agent = KaliAgent()
        
        # Set both whitelist and blacklist with same IP
        agent.set_ip_whitelist(["192.0.2.100"])
        agent.add_to_blacklist("192.0.2.100")
        
        # Should be blocked (blacklist wins)
        valid, msg = agent.validate_target("192.0.2.100")
        assert valid is False
        assert "blacklisted" in msg


class TestDryRunAndSafeMode:
    """Test dry-run and safe mode functionality."""
    
    def test_dry_run_mode(self):
        """Test dry-run mode prevents execution."""
        agent = KaliAgent()
        agent.set_authorization(AuthorizationLevel.BASIC)
        agent.enable_dry_run()
        
        result = agent.nmap_scan("scanme.nmap.org")
        
        assert result.status == "completed"
        assert "DRY-RUN" in result.stdout
        assert result.exit_code == 0
        
        agent.disable_dry_run()
    
    def test_safe_mode(self):
        """Test safe mode toggle."""
        agent = KaliAgent()
        
        assert agent.safe_mode is True
        agent.disable_safe_mode()
        assert agent.safe_mode is False
        agent.enable_safe_mode()
        assert agent.safe_mode is True


class TestToolExecution:
    """Test tool execution and validation."""
    
    def test_execute_unknown_tool(self):
        """Test execution of unknown tool fails."""
        agent = KaliAgent()
        agent.set_authorization(AuthorizationLevel.BASIC)
        
        result = agent.execute_tool("nonexistent_tool", {})
        
        assert result.status == "failed"
        assert "Unknown tool" in result.stderr
    
    def test_missing_required_argument(self):
        """Test execution fails with missing required argument."""
        agent = KaliAgent()
        agent.set_authorization(AuthorizationLevel.BASIC)
        
        # Nmap requires 'target'
        result = agent.execute_tool("nmap", {})
        
        assert result.status == "failed"
        assert "Missing required argument" in result.stderr
    
    def test_nmap_scan_method(self):
        """Test nmap_scan convenience method."""
        agent = KaliAgent()
        agent.set_authorization(AuthorizationLevel.BASIC)
        agent.enable_dry_run()
        
        result = agent.nmap_scan(
            target="scanme.nmap.org",
            ports="1-1000",
            version_detect=True,
        )
        
        assert result.tool_name == "nmap"
        assert "nmap" in result.command
        assert "scanme.nmap.org" in result.command
    
    def test_gobuster_scan_method(self):
        """Test gobuster_scan convenience method."""
        agent = KaliAgent()
        agent.set_authorization(AuthorizationLevel.BASIC)
        agent.enable_dry_run()
        
        result = agent.gobuster_scan(
            target="https://example.com",
            wordlist="/usr/share/wordlists/dirb/common.txt",
            mode="dir",
        )
        
        assert result.tool_name == "gobuster"
        assert "gobuster" in result.command


class TestOutputParsers:
    """Test output parsing functionality."""
    
    def test_parse_json_output(self):
        """Test JSON output parsing."""
        agent = KaliAgent()
        
        json_output = '{"status": "success", "findings": 5}'
        parsed = agent._parse_json(json_output)
        
        assert parsed is not None
        assert parsed["status"] == "success"
        assert parsed["findings"] == 5
    
    def test_parse_csv_output(self):
        """Test CSV output parsing."""
        agent = KaliAgent()
        
        csv_output = "port,protocol,state\n80,tcp,open\n443,tcp,open"
        parsed = agent._parse_csv(csv_output)
        
        assert parsed is not None
        assert len(parsed) == 2
        assert parsed[0]["port"] == "80"
    
    def test_parse_nikto_output(self):
        """Test Nikto output parsing."""
        agent = KaliAgent()
        
        nikto_output = """
+ Server: Apache/2.4.41
+ /admin/: Admin directory found. CRITICAL
+ /backup/: Backup files exposed. HIGH
"""
        parsed = agent._parse_nikto(nikto_output)
        
        assert parsed is not None
        assert parsed["total"] >= 2  # At least 2 vulns
        assert any(v["severity"] == "critical" for v in parsed["vulnerabilities"])
    
    def test_parse_gobuster_output(self):
        """Test Gobuster output parsing."""
        agent = KaliAgent()
        
        gobuster_output = """
/admin                (Status: 301)
/login                (Status: 200)
/api                  (Status: 403)
"""
        parsed = agent._parse_gobuster(gobuster_output)
        
        assert parsed is not None
        assert parsed["total_found"] == 3
        assert any(p["path"] == "/admin" for p in parsed["paths"])


class TestPlaybooks:
    """Test automated playbook execution."""
    
    def test_recon_playbook_structure(self):
        """Test recon playbook returns expected structure."""
        agent = KaliAgent()
        agent.set_authorization(AuthorizationLevel.BASIC)
        agent.enable_dry_run()
        
        results = agent.run_recon_playbook(
            target="192.0.2.100",
            domain="example.com",
        )
        
        assert "nmap" in results
        assert "theharvester" in results
        assert "amass" in results
        assert "dnsrecon" in results
    
    def test_web_audit_playbook_structure(self):
        """Test web audit playbook returns expected structure."""
        agent = KaliAgent()
        agent.set_authorization(AuthorizationLevel.ADVANCED)
        agent.enable_dry_run()
        
        results = agent.run_web_audit_playbook(
            url="https://example.com",
            target="93.184.216.34",
        )
        
        assert "gobuster" in results
        assert "nikto" in results
        assert "wpscan" in results
        assert "sqlmap" in results
    
    def test_password_audit_playbook_structure(self):
        """Test password audit playbook returns expected structure."""
        agent = KaliAgent()
        agent.set_authorization(AuthorizationLevel.ADVANCED)
        agent.enable_dry_run()
        
        results = agent.run_password_audit_playbook(
            hash_file="hashes.txt",
            wordlist="/usr/share/wordlists/rockyou.txt",
        )
        
        assert "john" in results
    
    def test_playbook_report_generation(self):
        """Test playbook report generation."""
        agent = KaliAgent()
        agent.set_authorization(AuthorizationLevel.BASIC)
        agent.enable_dry_run()
        
        results = agent.run_recon_playbook(
            target="192.0.2.100",
            domain="example.com",
        )
        
        report = agent.generate_playbook_report(
            playbook_name="recon",
            results=results,
            output_format="markdown",
        )
        
        assert "# Playbook Report: recon" in report
        assert "Generated:" in report
        assert "Tools Executed:" in report
        assert "## Summary" in report


class TestMetasploitIntegration:
    """Test Metasploit RPC integration."""
    
    def test_metasploit_rpc_initialization(self):
        """Test Metasploit RPC client initialization."""
        from agentic_ai.agents.cyber.kali import MetasploitRPC
        
        msf = MetasploitRPC(host="127.0.0.1", port=55553)
        
        assert msf.host == "127.0.0.1"
        assert msf.port == 55553
        assert msf.token is None
        assert msf.url == "http://127.0.0.1:55553/api"
    
    def test_connect_metasploit_method(self):
        """Test connect_metasploit convenience method."""
        agent = KaliAgent()
        
        # Without password (should create but not authenticate)
        result = agent.connect_metasploit(host="127.0.0.1", port=55553)
        assert result is False  # No password provided
        
        # Verify msfrpc was created
        assert agent.msfrpc is not None
        assert agent.msfrpc.host == "127.0.0.1"
    
    def test_disconnect_metasploit(self):
        """Test disconnect_metasploit."""
        agent = KaliAgent()
        agent.connect_metasploit(host="127.0.0.1", port=55553)
        
        result = agent.disconnect_metasploit()
        assert result is True
        assert agent.msfrpc is None


class TestReporting:
    """Test execution reporting."""
    
    def test_get_execution_history(self):
        """Test execution history retrieval."""
        agent = KaliAgent()
        agent.set_authorization(AuthorizationLevel.BASIC)
        agent.enable_dry_run()
        
        # Execute some tools
        agent.nmap_scan("192.0.2.1")
        agent.nikto_scan("example.com")
        
        history = agent.get_execution_history()
        
        assert len(history) >= 2
        assert all(hasattr(e, "tool_name") for e in history)
        assert all(hasattr(e, "status") for e in history)
    
    def test_generate_markdown_report(self):
        """Test markdown report generation."""
        agent = KaliAgent()
        agent.set_authorization(AuthorizationLevel.BASIC)
        agent.enable_dry_run()
        
        agent.nmap_scan("192.0.2.1")
        
        report = agent.generate_report(output_format="markdown")
        
        assert "# Kali Agent Execution Report" in report
        assert "Generated:" in report
        assert "Total Executions:" in report
    
    def test_generate_json_report(self):
        """Test JSON report generation."""
        agent = KaliAgent()
        agent.set_authorization(AuthorizationLevel.BASIC)
        agent.enable_dry_run()
        
        agent.nmap_scan("192.0.2.1")
        
        import json
        report = agent.generate_report(output_format="json")
        data = json.loads(report)
        
        assert isinstance(data, list)
        assert len(data) >= 1
        assert "execution_id" in data[0]
        assert "tool_name" in data[0]
        assert "status" in data[0]


class TestToolDatabase:
    """Test tool database completeness."""
    
    def test_reconnaissance_tools(self):
        """Test reconnaissance tools are present."""
        agent = KaliAgent()
        recon_tools = ["nmap", "masscan", "theHarvester", 
                       "amass", "subfinder", "dnsrecon", "shodan"]
        
        for tool in recon_tools:
            assert tool in agent.tools, f"Missing recon tool: {tool}"
    
    def test_web_application_tools(self):
        """Test web application tools are present."""
        agent = KaliAgent()
        web_tools = ["sqlmap", "burpsuite", "nikto", "dirb", 
                     "gobuster", "wpscan", "ffuf", "whatweb", "sslscan"]
        
        for tool in web_tools:
            assert tool in agent.tools, f"Missing web tool: {tool}"
    
    def test_password_tools(self):
        """Test password attack tools are present."""
        agent = KaliAgent()
        password_tools = ["john", "hashcat", "hydra", "medusa", 
                          "cewl", "crunch", "hash_identifier", "rsmangler"]
        
        for tool in password_tools:
            assert tool in agent.tools, f"Missing password tool: {tool}"
    
    def test_wireless_tools(self):
        """Test wireless tools are present."""
        agent = KaliAgent()
        wireless_tools = ["aircrack_ng", "reaver", "wifite", 
                          "kismet", "mdk4"]
        
        for tool in wireless_tools:
            assert tool in agent.tools, f"Missing wireless tool: {tool}"
    
    def test_post_exploitation_tools(self):
        """Test post-exploitation tools are present."""
        agent = KaliAgent()
        post_tools = ["mimikatz", "bloodhound", "empire", "lazagne"]
        
        for tool in post_tools:
            assert tool in agent.tools, f"Missing post-exploit tool: {tool}"
    
    def test_forensics_tools(self):
        """Test forensics tools are present."""
        agent = KaliAgent()
        forensics_tools = ["volatility", "foremost", "sleuthkit", "exiftool"]
        
        for tool in forensics_tools:
            assert tool in agent.tools, f"Missing forensics tool: {tool}"


class TestRedTeamIntegration:
    """Test RedTeam agent integration."""
    
    def test_redteam_kali_integration_available(self):
        """Test RedTeam has KaliAgent integration methods."""
        from agentic_ai.agents.cyber.redteam import RedTeamAgent
        
        agent = RedTeamAgent()
        
        # Check integration methods exist
        assert hasattr(agent, "execute_kali_recon")
        assert hasattr(agent, "execute_kali_web_audit")
        assert hasattr(agent, "execute_kali_password_audit")
        assert hasattr(agent, "execute_kali_full_engagement")
    
    def test_redteam_engagement_creation(self):
        """Test RedTeam engagement creation."""
        from agentic_ai.agents.cyber.redteam import (
            RedTeamAgent,
            EngagementType,
            EngagementStatus,
        )
        
        agent = RedTeamAgent()
        engagement = agent.create_engagement(
            name="Test Engagement",
            engagement_type=EngagementType.PENETRATION_TEST,
            start_date=utcnow(),
            scope=["192.0.2.0/24"],
            objectives=["Find vulns"],
        )
        
        assert engagement.engagement_id.startswith("eng-")
        assert engagement.name == "Test Engagement"
        assert engagement.status == EngagementStatus.PLANNING


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


class TestValidateCommandArgs:
    """Test _validate_command_args rejects shell metacharacters."""

    def test_safe_args_pass(self):
        """Normal args should pass validation."""
        _validate_command_args(["ls", "-la"])

    def test_semicolon_rejected(self):
        """Semicolon metacharacter should be rejected."""
        with pytest.raises(ValueError, match="Rejected dangerous metacharacter"):
            _validate_command_args(["ls; rm -rf /"])

    def test_pipe_rejected(self):
        """Pipe metacharacter should be rejected."""
        with pytest.raises(ValueError, match="Rejected dangerous metacharacter"):
            _validate_command_args(["ls | cat"])

    def test_command_substitution_rejected(self):
        """Command substitution $(...) should be rejected."""
        with pytest.raises(ValueError, match="Rejected dangerous metacharacter"):
            _validate_command_args(["$(whoami)"])

    def test_backtick_rejected(self):
        """Backtick metacharacter should be rejected."""
        with pytest.raises(ValueError, match="Rejected dangerous metacharacter"):
            _validate_command_args(["`whoami`"])

    def test_ampersand_rejected(self):
        """Ampersand metacharacter should be rejected."""
        with pytest.raises(ValueError, match="Rejected dangerous metacharacter"):
            _validate_command_args(["ls & echo pwned"])
