"""Registry + CLI runner tests: every registered id resolves and instantiates."""
import importlib

import pytest

from agentic_ai.agents.registry import AGENT_REGISTRY, create_agent, list_agents, resolve_agent_class


def test_registry_nonempty_and_unique():
    assert len(AGENT_REGISTRY) >= 30
    assert len(list_agents()) == len(AGENT_REGISTRY)


def test_every_id_resolves_to_a_class():
    for agent_id, (module_path, class_name, _, _) in AGENT_REGISTRY.items():
        cls = resolve_agent_class(agent_id)
        assert cls.__name__ == class_name, agent_id
        assert cls.__module__ == module_path, agent_id


def test_known_agents_instantiate_without_inference():
    # a sample across categories, incl. the plain-class cyber variant
    for agent_id in ("security", "developer", "compliance", "chaos_monkey", "kali_v2"):
        agent = create_agent(agent_id)
        assert agent is not None


def test_unknown_id_is_actionable():
    with pytest.raises(KeyError) as exc:
        resolve_agent_class("product")
    assert "product" in str(exc.value)
    assert "Known ids" in str(exc.value)


def test_cli_agent_run_scan_code(capsys):
    cli = importlib.import_module("agentic_ai.cli")
    agent = cli.make_agent("security")
    result = agent.scan_code('password = "hunter2"')
    assert isinstance(result, list) and result
    assert result[0].threat_type.value == "hardcoded_secrets"
