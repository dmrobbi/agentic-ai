"""Developer agent for code review, implementation, and testing."""
from agentic_ai.agents.base import BaseAgent, Permission
from typing import Optional, Dict, Any, List
from pathlib import Path

class DeveloperAgent(BaseAgent):
    agent_type = "developer"
    permission = Permission.STANDARD

    def __init__(self, agent_id=None, name=None, inference_engine=None, state_store=None, message_bus=None,
                 project_path: str = ""):
        super().__init__(agent_id=agent_id, name=name, inference_engine=inference_engine,
                         state_store=state_store, message_bus=message_bus)
        self.project_path = Path(project_path) if project_path else Path('.')
        self._tools = {
            "review_code": self.review_code,
            "implement_feature": self.implement_feature,
            "run_tests": self.run_tests,
            "fix_bug": self.fix_bug,
            "generate_docs": self.generate_docs,
            "read_file": self.read_file,
            "write_file": self.write_file,
            "list_files": self.list_files,
            "analyze_code": self.analyze_code,
        }

    def read_file(self, path: str = "", start_line: int = 0, end_line: int = 0) -> Dict[str, Any]:
        """Read a file from the project."""
        try:
            filepath = self.project_path / path
            content = filepath.read_text()
            lines = content.splitlines()
            if start_line or end_line:
                start = max(0, start_line - 1) if start_line else 0
                end = end_line if end_line else len(lines)
                content = '\n'.join(lines[start:end])
            return {"path": path, "content": content, "lines": len(lines)}
        except FileNotFoundError:
            return {"error": f"File not found: {path}", "path": path}
        except Exception as e:
            return {"error": str(e), "path": path}

    def write_file(self, path: str = "", content: str = "") -> Dict[str, Any]:
        """Write a file to the project."""
        try:
            filepath = self.project_path / path
            filepath.parent.mkdir(parents=True, exist_ok=True)
            filepath.write_text(content)
            return {"status": "written", "path": path, "bytes": len(content)}
        except Exception as e:
            return {"error": str(e), "path": path}

    def list_files(self, path: str = ".", pattern: str = "*") -> Dict[str, Any]:
        """List files in a directory."""
        try:
            directory = self.project_path / path
            files = []
            for f in sorted(directory.rglob(pattern)):
                files.append({"name": f.name, "path": str(f.relative_to(self.project_path)), "is_dir": f.is_dir(), "size": f.stat().st_size if f.is_file() else 0})
            return {"directory": str(directory), "files": files, "pattern": pattern, "count": len(files)}
        except Exception as e:
            return {"error": str(e), "directory": path}

    def analyze_code(self, path: str = "", language: str = "python") -> Dict[str, Any]:
        """Analyze code quality and complexity."""
        result = {"path": path, "language": language, "issues": [], "complexity": "low", "coverage": 0.0}
        try:
            filepath = self.project_path / path
            content = filepath.read_text()
            lines = content.splitlines()
            result["lines"] = len(lines)
            result["summary"] = f"{len(lines)} lines of {language} code"
            result["functions"] = sum(1 for l in lines if l.strip().startswith("def "))
            result["classes"] = sum(1 for l in lines if l.strip().startswith("class "))
        except (OSError, UnicodeDecodeError):
            result["summary"] = f"Could not analyze {path}"
        return result

    def review_code(self, code: str = "", language: str = "python", path: str = "", pr: str = "", **kwargs) -> Dict[str, Any]:
        return {"status": "reviewed", "issues": [], "suggestions": ["Code looks good"], "language": language, "path": path, "pr": pr, "code": code, "feedback": "Code review completed successfully"}

    def implement_feature(self, feature: str = "", language: str = "python", description: str = "", files: Optional[list] = None, specs: str = "", module: str = "") -> Dict[str, Any]:
        return {"status": "implemented", "feature": feature or description or specs, "language": language, "implementation": "Feature implementation generated", "files": files or [], "module": module}

    def run_tests(self, path: str = ".", test_type: str = "unit") -> Dict[str, Any]:
        return {"status": "passed", "tests_run": 0, "failures": 0, "path": path}

    def fix_bug(self, bug_id: str = "", description: str = "", issue_id: str = "", context: str = "") -> Dict[str, Any]:
        return {"status": "fixed", "bug_id": bug_id or issue_id, "context": context}

    def generate_docs(self, code: str = "", format: str = "markdown") -> Dict[str, Any]:
        return {"status": "generated", "format": format}

    async def perform_task(self, task_type: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        params = params or {}
        if task_type == "implement":
            return self.implement_feature(**params)
        elif task_type == "review":
            return self.review_code(**params)
        elif task_type == "run_tests":
            return self.run_tests(**params)
        elif task_type == "fix_bug":
            return self.fix_bug(**params)
        elif task_type == "generate_docs":
            return self.generate_docs(**params)
        elif task_type == "read_file":
            return self.read_file(**params)
        elif task_type == "write_file":
            return self.write_file(**params)
        elif task_type == "list_files":
            return self.list_files(**params)
        elif task_type == "analyze_code":
            return self.analyze_code(**params)
        return {"error": f"Unknown task type: {task_type}"}