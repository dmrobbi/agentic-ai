"""
Tests for Developer Agent
==========================

Unit tests for the developer agent implementation.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import MagicMock

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestDeveloperAgent:
    """Test the DeveloperAgent class."""
    
    @pytest.fixture
    def mock_inference(self):
        """Mock inference server."""
        mock = MagicMock()
        mock.generate = MagicMock(return_value="Generated code")
        mock.chat = MagicMock(return_value="Chat response")
        return mock
    
    @pytest.fixture
    def mock_state_store(self):
        """Mock state store."""
        mock = MagicMock()
        mock.get_agent_state = MagicMock(return_value=None)
        mock.save_agent_state = MagicMock()
        return mock
    
    @pytest.fixture
    def mock_bus(self):
        """Mock message bus."""
        mock = MagicMock()
        mock.connect = MagicMock()
        mock.disconnect = MagicMock()
        mock.subscribe_agent = MagicMock()
        mock.publish_status = MagicMock()
        return mock
    
    @pytest.fixture
    def temp_project(self, tmp_path):
        """Create a temporary project directory."""
        project = tmp_path / "test_project"
        project.mkdir()
        (project / "main.py").write_text("def hello():\n    print('Hello')\n")
        (project / "tests").mkdir()
        return project
    
    def test_developer_agent_initialization(self, mock_inference, mock_state_store, mock_bus, temp_project):
        """Test developer agent initializes correctly."""
        from agentic_ai.agents.developer import DeveloperAgent
        from agentic_ai.agents.base import Permission
        
        agent = DeveloperAgent(
            agent_id="dev-001",
            name="TestDeveloper",
            project_path=str(temp_project),
        )
        
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        assert agent.agent_id == "dev-001"
        assert agent.name == "TestDeveloper"
        assert agent.agent_type == "developer"
        assert agent.permission == Permission.STANDARD
        assert agent.project_path == temp_project
    
    def test_developer_has_correct_tools(self, mock_inference, mock_state_store, mock_bus, temp_project):
        """Test developer agent has expected tools registered."""
        from agentic_ai.agents.developer import DeveloperAgent
        
        agent = DeveloperAgent(project_path=str(temp_project))
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        tool_names = list(agent._tools.keys())
        
        # Should have developer tools
        assert "read_file" in tool_names
        assert "write_file" in tool_names
        assert "list_files" in tool_names
        assert "run_tests" in tool_names
        assert "analyze_code" in tool_names
    
    @pytest.mark.asyncio
    async def test_read_file_tool(self, mock_inference, mock_state_store, mock_bus, temp_project):
        """Test reading a file."""
        from agentic_ai.agents.developer import DeveloperAgent
        
        agent = DeveloperAgent(project_path=str(temp_project))
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        result = await agent.call_tool("read_file", path="main.py")
        
        assert "error" not in result
        assert result["path"] == "main.py"
        assert "hello" in result["content"]
    
    @pytest.mark.asyncio
    async def test_write_file_tool(self, mock_inference, mock_state_store, mock_bus, temp_project):
        """Test writing a file."""
        from agentic_ai.agents.developer import DeveloperAgent
        
        agent = DeveloperAgent(project_path=str(temp_project))
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        result = await agent.call_tool("write_file", path="new_file.py", content="# New file\n")
        
        assert "error" not in result
        assert result["path"] == "new_file.py"
        assert (temp_project / "new_file.py").exists()
    
    @pytest.mark.asyncio
    async def test_list_files_tool(self, mock_inference, mock_state_store, mock_bus, temp_project):
        """Test listing files."""
        from agentic_ai.agents.developer import DeveloperAgent
        
        agent = DeveloperAgent(project_path=str(temp_project))
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        result = await agent.call_tool("list_files", path=".")
        
        assert "error" not in result
        assert "files" in result
        file_names = [f["name"] for f in result["files"]]
        assert "main.py" in file_names
        assert "tests" in file_names
    
    @pytest.mark.asyncio
    async def test_analyze_code_tool(self, mock_inference, mock_state_store, mock_bus, temp_project):
        """Test code analysis."""
        from agentic_ai.agents.developer import DeveloperAgent
        
        agent = DeveloperAgent(project_path=str(temp_project))
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        result = await agent.call_tool("analyze_code", path="main.py")
        
        assert "error" not in result
        assert "issues" in result
        assert "summary" in result
    
    @pytest.mark.asyncio
    async def test_perform_task_implement(self, mock_inference, mock_state_store, mock_bus, temp_project):
        """Test implement task."""
        from agentic_ai.agents.developer import DeveloperAgent
        
        agent = DeveloperAgent(project_path=str(temp_project))
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        result = await agent.perform_task("implement", {
            "description": "Create a hello world function",
            "files": ["hello.py"],
        })
        
        assert result["status"] == "implemented"
        assert "implementation" in result
    
    @pytest.mark.asyncio
    async def test_perform_task_review(self, mock_inference, mock_state_store, mock_bus, temp_project):
        """Test review task."""
        from agentic_ai.agents.developer import DeveloperAgent
        
        agent = DeveloperAgent(project_path=str(temp_project))
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        result = await agent.perform_task("review", {
            "path": "main.py",
        })
        
        assert result["status"] == "reviewed"
        assert "feedback" in result


class TestQAAgent:
    """Test the QAAgent class."""
    
    @pytest.fixture
    def temp_project(self, tmp_path):
        """Create a temporary project directory."""
        project = tmp_path / "test_project"
        project.mkdir()
        (project / "main.py").write_text("def add(a, b):\n    return a + b\n")
        (project / "tests").mkdir()
        return project
    
    @pytest.fixture
    def mock_inference(self):
        """Mock inference server."""
        mock = MagicMock()
        mock.generate = MagicMock(return_value="Generated tests")
        return mock
    
    @pytest.fixture
    def mock_state_store(self):
        """Mock state store."""
        mock = MagicMock()
        mock.get_agent_state = MagicMock(return_value=None)
        return mock
    
    @pytest.fixture
    def mock_bus(self):
        """Mock message bus."""
        mock = MagicMock()
        return mock
    
    def test_qa_agent_initialization(self, temp_project, mock_inference, mock_state_store, mock_bus):
        """Test QA agent initializes correctly."""
        from agentic_ai.agents.qa import QAAgent
        from agentic_ai.agents.base import Permission
        
        agent = QAAgent(
            agent_id="qa-001",
            name="TestQA",
            project_path=str(temp_project),
        )
        
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        assert agent.agent_id == "qa-001"
        assert agent.agent_type == "qa"
        assert agent.permission == Permission.READ_ONLY
    
    def test_qa_has_correct_tools(self, temp_project, mock_inference, mock_state_store, mock_bus):
        """Test QA agent has expected tools."""
        from agentic_ai.agents.qa import QAAgent
        
        agent = QAAgent(project_path=str(temp_project))
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        tool_names = list(agent._tools.keys())
        
        assert "generate_tests" in tool_names
        assert "run_tests" in tool_names
        assert "analyze_coverage" in tool_names
        assert "find_bugs" in tool_names
        assert "check_quality" in tool_names
    
    @pytest.mark.asyncio
    async def test_find_bugs_tool(self, temp_project, mock_inference, mock_state_store, mock_bus):
        """Test finding bugs."""
        from agentic_ai.agents.qa import QAAgent
        
        agent = QAAgent(project_path=str(temp_project))
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        result = await agent.call_tool("find_bugs", path="main.py", severity="medium")
        
        assert "error" not in result
        assert "bugs" in result or "analysis" in result
    
    @pytest.mark.asyncio
    async def test_check_quality_tool(self, temp_project, mock_inference, mock_state_store, mock_bus):
        """Test quality checking."""
        from agentic_ai.agents.qa import QAAgent
        
        agent = QAAgent(project_path=str(temp_project))
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        result = await agent.call_tool("check_quality", path="main.py")
        
        assert "error" not in result
        assert "metrics" in result
        assert "quality_score" in result
    
    @pytest.mark.asyncio
    async def test_perform_task_generate_tests(self, temp_project, mock_inference, mock_state_store, mock_bus):
        """Test generate tests task."""
        from agentic_ai.agents.qa import QAAgent
        
        agent = QAAgent(project_path=str(temp_project))
        agent.inference = mock_inference
        agent.state_store = mock_state_store
        agent.bus = mock_bus
        
        result = await agent.perform_task("generate_tests", {
            "path": "main.py",
            "test_type": "unit",
        })
        
        assert "path" in result
        assert "tests" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])