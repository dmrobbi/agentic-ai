# Agent Capability Matrix

Complete reference of the Agentic AI agents. Agent ids are generated from
`agentic_ai/agents/registry.py`; real callable ops per agent live in
`skills/agentic-roles/references/role-ops.md` (the per-agent "Capabilities"
tables below are descriptive, not literal method names - use
`agenticai agent ops <id>` for the truth). Run any agent without an LLM:

```bash
agenticai agent card <id>    # dry-run instantiation + agent card
agenticai agent ops  <id>    # real op menu
agenticai agent run  <id> --op <op> --args '{...}'
```

## Quick Reference

| ID | Agent | Category | Capabilities | Tests |
|----|-------|----------|--------------|-------|
| `base` | Base Agent | Core | 21 | 8 |
| `developer` | Developer Agent | Core | 30 | 12 |
| `qa` | QA Agent | Core | 32 | 10 |
| `sysadmin` | SysAdmin Agent | Core | 29 | 10 |
| `lead` | Lead Agent | Core | 34 | 8 |
| `sales` | Sales Agent | Business | 33 | 8 |
| `finance` | Finance Agent | Business | 26 | 8 |
| `hr` | HR Agent | Business | 38 | 8 |
| `marketing` | Marketing Agent | Business | 37 | 8 |
| `research` | Research Agent | Data | 40 | 8 |
| `data_analyst` | Data Analyst Agent | Data | 31 | 8 |
| `data_governance` | Data Governance Agent | Data | 44 | 8 |
| `devops` | DevOps Agent | Operations | 43 | 8 |
| `support` | Support Agent | Operations | 34 | 8 |
| `integration` | Integration Agent | Operations | 36 | 8 |
| `communications` | Communications Agent | Operations | 40 | 8 |
| `legal` | Legal Agent | Governance | 33 | 8 |
| `compliance` | Compliance Agent | Governance | 43 | 10 |
| `privacy` | Privacy Agent | Governance | 54 | 10 |
| `risk` | Risk Agent | Governance | 44 | 8 |
| `ethics` | Ethics Agent | Governance | 43 | 8 |
| `security` | Security Agent | Cyber | 41 | 12 |
| `kali` | Kali Agent | Cyber | 195 | 44 |
| `kali_v2` | Kali Agent V2 | Cyber | 129 | 15 |
| `soc` | SOC Agent | Cyber | 48 | 10 |
| `vulnman` | VulnMan Agent | Cyber | 38 | 10 |
| `redteam` | RedTeam Agent | Cyber | 43 | 10 |
| `malware` | Malware Agent | Cyber | 45 | 10 |
| `cloud_security` | CloudSecurity Agent | Operations | 38 | 10 |
| `ml_ops` | MLOps Agent | Data | 41 | 10 |
| `supply_chain` | SupplyChain Agent | Governance | 42 | 10 |
| `audit` | Audit Agent | Governance | 41 | 10 |
| `vendor_risk` | VendorRisk Agent | Governance | 47 | 10 |
| `chaos_monkey` | ChaosMonkey Agent | Operations | 44 | 10 |
| `biblical_scholar` | Biblical Scholar Agent | Specialized | 13 | 0 |
| `redteam_v2` | Red Team Agent V2 Agent | Cyber | 14 | 0 |
| `social_media` | Social Media Agent | Business | 49 | 87 |


### Base Agent (`base.py`)

**Purpose**: Base class for all agents in the framework.

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `call_tool` | Call a tool by name with keyword arguments. | — | — |
| `can_create_project` | Check if agent can create projects. | — | — |
| `can_manage_agents` | Check if agent can manage other agents. | — | — |
| `can_read` | Check if agent has read permission. | — | — |
| `can_write` | Check if agent has write permission. | — | — |
| `generate_id` | Generate a unique ID with the given prefix (static version). | — | — |
| `get_agent_card` | Generate an A2A-compatible agent card describing this agent. | — | — |
| `get_status` | Get agent status. | — | — |
| `get_transparency_log` | Get the transparency log entries. | — | — |
| `input_guardrail` | Validate/sanitize input through guardrail pipeline. Returns (sanitized_prompt, is_safe). | — | — |
| `log` | Log an action for transparency. | — | — |
| `output_guardrail` | Validate/sanitize output through guardrail pipeline. Returns (sanitized_response, is_safe). | — | — |
| `perform_task` | Perform a task. Override in subclasses. | — | — |
| `process_message` | Process an incoming message. Override in subclasses. | — | — |
| `reason` | Iterative ReAct reasoning loop: think→act→observe. | — | — |
| `receive_message` | Receive a message from another agent. | — | — |
| `reflect` | Self-critique: evaluate response quality and suggest improvements. | — | — |
| `register_tool` | Register a tool with the agent. | — | — |
| `send_message` | Send a message to another agent. | — | — |
| `think` | Use LLM inference to reason about something. Optionally validate against a Pydantic model. | — | — |
| `tool_guardrail` | Check if tool call is permitted. Returns is_allowed. | — | — |

**File**: `agentic_ai/agents/base.py`

### Developer Agent (`developer.py`)

**Purpose**: Code implementation and review.

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `analyze_code` | Analyze code quality and complexity. | — | — |
| `call_tool` | Call a tool by name with keyword arguments. | — | — |
| `can_create_project` | Check if agent can create projects. | — | — |
| `can_manage_agents` | Check if agent can manage other agents. | — | — |
| `can_read` | Check if agent has read permission. | — | — |
| `can_write` | Check if agent has write permission. | — | — |
| `fix_bug` | fix bug | — | — |
| `generate_docs` | generate docs | — | — |
| `generate_id` | Generate a unique ID with the given prefix (static version). | — | — |
| `get_agent_card` | Generate an A2A-compatible agent card describing this agent. | — | — |
| `get_status` | Get agent status. | — | — |
| `get_transparency_log` | Get the transparency log entries. | — | — |
| `implement_feature` | implement feature | — | — |
| `input_guardrail` | Validate/sanitize input through guardrail pipeline. Returns (sanitized_prompt, is_safe). | — | — |
| `list_files` | List files in a directory. | — | — |
| `log` | Log an action for transparency. | — | — |
| `output_guardrail` | Validate/sanitize output through guardrail pipeline. Returns (sanitized_response, is_safe). | — | — |
| `perform_task` | perform task | — | — |
| `process_message` | Process an incoming message. Override in subclasses. | — | — |
| `read_file` | Read a file from the project. | — | — |
| `reason` | Iterative ReAct reasoning loop: think→act→observe. | — | — |
| `receive_message` | Receive a message from another agent. | — | — |
| `reflect` | Self-critique: evaluate response quality and suggest improvements. | — | — |
| `register_tool` | Register a tool with the agent. | — | — |
| `review_code` | review code | — | — |
| `run_tests` | run tests | — | — |
| `send_message` | Send a message to another agent. | — | — |
| `think` | Use LLM inference to reason about something. Optionally validate against a Pydantic model. | — | — |
| `tool_guardrail` | Check if tool call is permitted. Returns is_allowed. | — | — |
| `write_file` | Write a file to the project. | — | — |

**File**: `agentic_ai/agents/developer.py`

### QA Agent (`qa.py`)

**Purpose**: Testing and quality assurance.

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `analyze_coverage` | Analyze coverage | `code: str, tests: list` | `coverage: CoverageReport` |
| `call_tool` | Call a tool by name with keyword arguments. | — | — |
| `can_create_project` | Check if agent can create projects. | — | — |
| `can_manage_agents` | Check if agent can manage other agents. | — | — |
| `can_read` | Check if agent has read permission. | — | — |
| `can_write` | Check if agent has write permission. | — | — |
| `check_quality` | check quality | — | — |
| `create_test_plan` | create test plan | — | — |
| `execute_tests` | execute tests | — | — |
| `find_bugs` | Static analysis | `code: str` | `bugs: list` |
| `generate_id` | Generate a unique ID with the given prefix (static version). | — | — |
| `get_agent_card` | Generate an A2A-compatible agent card describing this agent. | — | — |
| `get_status` | Get agent status. | — | — |
| `get_transparency_log` | Get the transparency log entries. | — | — |
| `input_guardrail` | Validate/sanitize input through guardrail pipeline. Returns (sanitized_prompt, is_safe). | — | — |
| `list_files` | list files | — | — |
| `log` | Log an action for transparency. | — | — |
| `output_guardrail` | Validate/sanitize output through guardrail pipeline. Returns (sanitized_response, is_safe). | — | — |
| `perform_task` | perform task | — | — |
| `process_message` | Process an incoming message. Override in subclasses. | — | — |
| `read_file` | read file | — | — |
| `reason` | Iterative ReAct reasoning loop: think→act→observe. | — | — |
| `receive_message` | Receive a message from another agent. | — | — |
| `reflect` | Self-critique: evaluate response quality and suggest improvements. | — | — |
| `register_tool` | Register a tool with the agent. | — | — |
| `regression_test` | regression test | — | — |
| `report_bug` | report bug | — | — |
| `send_message` | Send a message to another agent. | — | — |
| `think` | Use LLM inference to reason about something. Optionally validate against a Pydantic model. | — | — |
| `tool_guardrail` | Check if tool call is permitted. Returns is_allowed. | — | — |
| `validate_feature` | validate feature | — | — |
| `write_file` | write file | — | — |

**File**: `agentic_ai/agents/qa.py`

### SysAdmin Agent (`sysadmin.py`)

**Purpose**: System administration agent for infrastructure management.

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `analyze_logs` | Log analysis | `logs: str, patterns: list` | `insights: list` |
| `call_tool` | Call a tool by name with keyword arguments. | — | — |
| `can_create_project` | Check if agent can create projects. | — | — |
| `can_manage_agents` | Check if agent can manage other agents. | — | — |
| `can_read` | Check if agent has read permission. | — | — |
| `can_write` | Check if agent has write permission. | — | — |
| `check_service` | Check or manage a system service. | — | — |
| `check_system` | System health check | `target: str` | `health: SystemHealth` |
| `create_incident` | Create incident | `title: str, severity: str` | `incident: Incident` |
| `generate_id` | Generate a unique ID with the given prefix (static version). | — | — |
| `get_agent_card` | Generate an A2A-compatible agent card describing this agent. | — | — |
| `get_status` | Get agent status. | — | — |
| `get_system_status` | get system status | — | — |
| `get_transparency_log` | Get the transparency log entries. | — | — |
| `input_guardrail` | Validate/sanitize input through guardrail pipeline. Returns (sanitized_prompt, is_safe). | — | — |
| `list_incidents` | list incidents | — | — |
| `log` | Log an action for transparency. | — | — |
| `output_guardrail` | Validate/sanitize output through guardrail pipeline. Returns (sanitized_response, is_safe). | — | — |
| `perform_task` | perform task | — | — |
| `process_message` | Process an incoming message. Override in subclasses. | — | — |
| `reason` | Iterative ReAct reasoning loop: think→act→observe. | — | — |
| `receive_message` | Receive a message from another agent. | — | — |
| `reflect` | Self-critique: evaluate response quality and suggest improvements. | — | — |
| `register_tool` | Register a tool with the agent. | — | — |
| `resolve_incident` | resolve incident | — | — |
| `run_command` | Execute command | `command: str, target: str` | `output: str, exit_code: int` |
| `send_message` | Send a message to another agent. | — | — |
| `think` | Use LLM inference to reason about something. Optionally validate against a Pydantic model. | — | — |
| `tool_guardrail` | Check if tool call is permitted. Returns is_allowed. | — | — |

**File**: `agentic_ai/agents/sysadmin.py`

### Lead Agent (`lead.py`)

**Purpose**: Orchestration and coordination.

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `analyze_request` | Analyze a request and determine which agent should handle it. | — | — |
| `broadcast_and_collect` | Send prompt to all agents, collect responses. | — | — |
| `call_tool` | Call a tool by name with keyword arguments. | — | — |
| `can_create_project` | Check if agent can create projects. | — | — |
| `can_manage_agents` | Check if agent can manage other agents. | — | — |
| `can_read` | Check if agent has read permission. | — | — |
| `can_write` | Check if agent has write permission. | — | — |
| `create_task` | create task | — | — |
| `create_workflow` | create workflow | — | — |
| `decompose_and_parallel` | Decompose a task into subtasks, run agents in parallel, merge results. | — | — |
| `delegate_task` | delegate task | — | — |
| `execute_workflow` | execute workflow | — | — |
| `generate_id` | Generate a unique ID with the given prefix (static version). | — | — |
| `get_agent_card` | Generate an A2A-compatible agent card describing this agent. | — | — |
| `get_status` | get status | — | — |
| `get_transparency_log` | Get the transparency log entries. | — | — |
| `input_guardrail` | Validate/sanitize input through guardrail pipeline. Returns (sanitized_prompt, is_safe). | — | — |
| `log` | Log an action for transparency. | — | — |
| `output_guardrail` | Validate/sanitize output through guardrail pipeline. Returns (sanitized_response, is_safe). | — | — |
| `perform_task` | Perform a task by type. Called with positional args: perform_task("type", {params}). | — | — |
| `process_message` | Process an incoming message. Override in subclasses. | — | — |
| `reason` | Iterative ReAct reasoning loop: think→act→observe. | — | — |
| `receive_message` | Receive a message from another agent. | — | — |
| `reflect` | Self-critique: evaluate response quality and suggest improvements. | — | — |
| `register_agent` | Register an agent with the lead. | — | — |
| `register_tool` | Register a tool with the agent. | — | — |
| `request_approval` | Request human approval for an action. | — | — |
| `round_robin` | Agents take turns in sequence responding to a prompt. | — | — |
| `route_task` | route task | — | — |
| `selector` | Select the best agent for a task, then delegate. | — | — |
| `send_message` | Send a message to another agent. | — | — |
| `spawn_conversation` | Create a sub-conversation with a group of agents. | — | — |
| `think` | Use LLM inference to reason about something. Optionally validate against a Pydantic model. | — | — |
| `tool_guardrail` | Check if tool call is permitted. Returns is_allowed. | — | — |

**File**: `agentic_ai/agents/lead.py`

### Sales Agent (`sales.py`)

**Purpose**: Sales agent: CRM, BANT/ICP qualification, productized price book,

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `call_tool` | Call a tool by name with keyword arguments. | — | — |
| `can_create_project` | Check if agent can create projects. | — | — |
| `can_manage_agents` | Check if agent can manage other agents. | — | — |
| `can_read` | Check if agent has read permission. | — | — |
| `can_write` | Check if agent has write permission. | — | — |
| `create_lead` | Create sales lead | `contact: dict, source: str` | `lead: Lead` |
| `create_opportunity` | Create opportunity | `lead_id: str, value: float` | `opportunity: Opportunity` |
| `draft_outreach` | Draft (never send) a personalized outreach email for a lead. | — | — |
| `forecast` | Weighted pipeline grouped by close quarter (undated ops bucketed separately). | — | — |
| `generate_id` | Generate a unique ID with the given prefix (static version). | — | — |
| `generate_proposal` | Generate proposal | `opportunity_id: str` | `proposal: str` |
| `get_agent_card` | Generate an A2A-compatible agent card describing this agent. | — | — |
| `get_lead` | Fetch one lead's summary by id or email. | — | — |
| `get_status` | Get agent status. | — | — |
| `get_transparency_log` | Get the transparency log entries. | — | — |
| `input_guardrail` | Validate/sanitize input through guardrail pipeline. Returns (sanitized_prompt, is_safe). | — | — |
| `lead_summary` | Flat dict view of a lead for results and reports. | — | — |
| `log` | Log an action for transparency. | — | — |
| `output_guardrail` | Validate/sanitize output through guardrail pipeline. Returns (sanitized_response, is_safe). | — | — |
| `perform_task` | Dispatch a task by type; payload is merged into kwargs. | — | — |
| `pipeline_report` | Owner-facing pipeline snapshot: stages, weighted totals, quotes, leads. | — | — |
| `price_book` | Return the productized price book (single source, owner-tunable). | — | — |
| `process_message` | Process an incoming message. Override in subclasses. | — | — |
| `qualify_lead` | Qualify lead | `lead_id: str, criteria: dict` | `qualification: Qualification` |
| `quote` | Build a quote from the price book: line items + MRR + year-1 total. | — | — |
| `reason` | Iterative ReAct reasoning loop: think→act→observe. | — | — |
| `receive_message` | Receive a message from another agent. | — | — |
| `reflect` | Self-critique: evaluate response quality and suggest improvements. | — | — |
| `register_tool` | Register a tool with the agent. | — | — |
| `send_message` | Send a message to another agent. | — | — |
| `think` | Use LLM inference to reason about something. Optionally validate against a Pydantic model. | — | — |
| `tool_guardrail` | Check if tool call is permitted. Returns is_allowed. | — | — |
| `update_pipeline` | Move an opportunity to a validated stage; probability follows the table. | — | — |

**File**: `agentic_ai/agents/sales.py`

### Finance Agent (`finance.py`)

**Purpose**: Finance agent for transaction, budget, and invoice management.

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `analyze_spending` | Analyze spending | `period: str, category: str` | `analysis: SpendingAnalysis` |
| `call_tool` | Call a tool by name with keyword arguments. | — | — |
| `can_create_project` | Check if agent can create projects. | — | — |
| `can_manage_agents` | Check if agent can manage other agents. | — | — |
| `can_read` | Check if agent has read permission. | — | — |
| `can_write` | Check if agent has write permission. | — | — |
| `create_budget` | Create budget | `period: str, categories: dict` | `budget: Budget` |
| `create_invoice` | create invoice | — | — |
| `generate_id` | Generate a unique ID with the given prefix (static version). | — | — |
| `generate_report` | Generate financial report | `period: str, type: str` | `report: FinancialReport` |
| `get_agent_card` | Generate an A2A-compatible agent card describing this agent. | — | — |
| `get_status` | Get agent status. | — | — |
| `get_transparency_log` | Get the transparency log entries. | — | — |
| `input_guardrail` | Validate/sanitize input through guardrail pipeline. Returns (sanitized_prompt, is_safe). | — | — |
| `log` | Log an action for transparency. | — | — |
| `output_guardrail` | Validate/sanitize output through guardrail pipeline. Returns (sanitized_response, is_safe). | — | — |
| `perform_task` | perform task | — | — |
| `process_message` | Process an incoming message. Override in subclasses. | — | — |
| `reason` | Iterative ReAct reasoning loop: think→act→observe. | — | — |
| `receive_message` | Receive a message from another agent. | — | — |
| `record_transaction` | Record transaction | `type: str, amount: float` | `transaction: Transaction` |
| `reflect` | Self-critique: evaluate response quality and suggest improvements. | — | — |
| `register_tool` | Register a tool with the agent. | — | — |
| `send_message` | Send a message to another agent. | — | — |
| `think` | Use LLM inference to reason about something. Optionally validate against a Pydantic model. | — | — |
| `tool_guardrail` | Check if tool call is permitted. Returns is_allowed. | — | — |

**File**: `agentic_ai/agents/finance.py`

### HR Agent (`hr.py`)

**Purpose**: HR Agent for employee management, onboarding,

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `approve_time_off` | Approve time off request. | — | — |
| `call_tool` | Call a tool by name with keyword arguments. | — | — |
| `can_create_project` | Check if agent can create projects. | — | — |
| `can_manage_agents` | Check if agent can manage other agents. | — | — |
| `can_read` | Check if agent has read permission. | — | — |
| `can_write` | Check if agent has write permission. | — | — |
| `complete_onboarding_task` | Mark onboarding task as complete. | — | — |
| `create_onboarding` | Create onboarding checklist for new employee. | — | — |
| `create_review` | Create performance review. | — | — |
| `generate_id` | Generate a unique ID with the given prefix (static version). | — | — |
| `get_agent_card` | Generate an A2A-compatible agent card describing this agent. | — | — |
| `get_employee` | Get employee by ID. | — | — |
| `get_employees` | Get employees with filtering. | — | — |
| `get_hr_metrics` | Get HR metrics summary. | — | — |
| `get_onboarding_progress` | Get onboarding progress for employee. | — | — |
| `get_reviews` | Get reviews with filtering. | — | — |
| `get_state` | Get agent state summary. | — | — |
| `get_status` | Get agent status. | — | — |
| `get_time_off_requests` | Get time off requests with filtering. | — | — |
| `get_transparency_log` | Get the transparency log entries. | — | — |
| `hire_employee` | Hire a new employee. | — | — |
| `input_guardrail` | Validate/sanitize input through guardrail pipeline. Returns (sanitized_prompt, is_safe). | — | — |
| `log` | Log an action for transparency. | — | — |
| `output_guardrail` | Validate/sanitize output through guardrail pipeline. Returns (sanitized_response, is_safe). | — | — |
| `perform_task` | Perform a task. Override in subclasses. | — | — |
| `process_message` | Process an incoming message. Override in subclasses. | — | — |
| `reason` | Iterative ReAct reasoning loop: think→act→observe. | — | — |
| `receive_message` | Receive a message from another agent. | — | — |
| `reflect` | Self-critique: evaluate response quality and suggest improvements. | — | — |
| `register_tool` | Register a tool with the agent. | — | — |
| `reject_time_off` | Reject time off request. | — | — |
| `request_time_off` | Request time off. | — | — |
| `send_message` | Send a message to another agent. | — | — |
| `submit_review` | Submit completed review. | — | — |
| `terminate_employee` | Terminate an employee. | — | — |
| `think` | Use LLM inference to reason about something. Optionally validate against a Pydantic model. | — | — |
| `tool_guardrail` | Check if tool call is permitted. Returns is_allowed. | — | — |
| `update_employee` | Update employee information. | — | — |

**File**: `agentic_ai/agents/hr.py`

### Marketing Agent (`marketing.py`)

**Purpose**: Marketing Agent for campaign management, content creation,

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `call_tool` | Call a tool by name with keyword arguments. | — | — |
| `can_create_project` | Check if agent can create projects. | — | — |
| `can_manage_agents` | Check if agent can manage other agents. | — | — |
| `can_read` | Check if agent has read permission. | — | — |
| `can_write` | Check if agent has write permission. | — | — |
| `complete_ab_test` | Complete A/B test with results. | — | — |
| `create_ab_test` | Create A/B test. | — | — |
| `create_campaign` | Create campaign | `name: str, channels: list` | `campaign: Campaign` |
| `create_content` | Create content piece. | — | — |
| `generate_blog_titles` | Generate blog title variations. | — | — |
| `generate_email_subjects` | Generate email subject line variations. | — | — |
| `generate_id` | Generate a unique ID with the given prefix (static version). | — | — |
| `generate_social_posts` | Generate social media post variations. | — | — |
| `get_ab_tests` | Get A/B tests with filtering. | — | — |
| `get_agent_card` | Generate an A2A-compatible agent card describing this agent. | — | — |
| `get_analytics_summary` | Get analytics summary. | — | — |
| `get_campaigns` | Get campaigns with filtering. | — | — |
| `get_state` | Get agent state summary. | — | — |
| `get_status` | Get agent status. | — | — |
| `get_transparency_log` | Get the transparency log entries. | — | — |
| `input_guardrail` | Validate/sanitize input through guardrail pipeline. Returns (sanitized_prompt, is_safe). | — | — |
| `log` | Log an action for transparency. | — | — |
| `output_guardrail` | Validate/sanitize output through guardrail pipeline. Returns (sanitized_response, is_safe). | — | — |
| `perform_task` | Perform a task. Override in subclasses. | — | — |
| `process_message` | Process an incoming message. Override in subclasses. | — | — |
| `publish_content` | Publish content. | — | — |
| `reason` | Iterative ReAct reasoning loop: think→act→observe. | — | — |
| `receive_message` | Receive a message from another agent. | — | — |
| `reflect` | Self-critique: evaluate response quality and suggest improvements. | — | — |
| `register_tool` | Register a tool with the agent. | — | — |
| `schedule_social_post` | Schedule a social media post. | — | — |
| `send_message` | Send a message to another agent. | — | — |
| `think` | Use LLM inference to reason about something. Optionally validate against a Pydantic model. | — | — |
| `tool_guardrail` | Check if tool call is permitted. Returns is_allowed. | — | — |
| `track_analytics` | Track marketing analytics. | — | — |
| `track_campaign_metrics` | Track campaign performance metrics. | — | — |
| `update_campaign_status` | Update campaign status. | — | — |

**File**: `agentic_ai/agents/marketing.py`

### Research Agent (`research.py`)

**Purpose**: Research Agent for literature review, research synthesis,

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `add_citation` | Add a citation between publications. | — | — |
| `add_finding` | Add finding to project. | — | — |
| `add_publication` | Add a publication to the library. | — | — |
| `add_publication_to_project` | Add publication to project. | — | — |
| `add_topic` | Add a research topic. | — | — |
| `call_tool` | Call a tool by name with keyword arguments. | — | — |
| `can_create_project` | Check if agent can create projects. | — | — |
| `can_manage_agents` | Check if agent can manage other agents. | — | — |
| `can_read` | Check if agent has read permission. | — | — |
| `can_write` | Check if agent has write permission. | — | — |
| `create_project` | Create a research project. | — | — |
| `find_related_publications` | Find publications related to a given publication. | — | — |
| `format_citation` | Format citation in specified style. | — | — |
| `generate_id` | Generate a unique ID with the given prefix (static version). | — | — |
| `generate_literature_review` | Generate literature review for a topic. | — | — |
| `get_agent_card` | Generate an A2A-compatible agent card describing this agent. | — | — |
| `get_citations_by` | Get all citations made by a publication. | — | — |
| `get_citations_for` | Get all citations for a publication. | — | — |
| `get_project` | Get project by ID. | — | — |
| `get_projects` | Get projects with filtering. | — | — |
| `get_publications` | Get publications with filtering. | — | — |
| `get_state` | Get agent state summary. | — | — |
| `get_status` | Get agent status. | — | — |
| `get_topic_summary` | Get summary for a topic. | — | — |
| `get_transparency_log` | Get the transparency log entries. | — | — |
| `input_guardrail` | Validate/sanitize input through guardrail pipeline. Returns (sanitized_prompt, is_safe). | — | — |
| `log` | Log an action for transparency. | — | — |
| `output_guardrail` | Validate/sanitize output through guardrail pipeline. Returns (sanitized_response, is_safe). | — | — |
| `perform_task` | Perform a task. Override in subclasses. | — | — |
| `process_message` | Process an incoming message. Override in subclasses. | — | — |
| `reason` | Iterative ReAct reasoning loop: think→act→observe. | — | — |
| `receive_message` | Receive a message from another agent. | — | — |
| `reflect` | Self-critique: evaluate response quality and suggest improvements. | — | — |
| `register_tool` | Register a tool with the agent. | — | — |
| `search_publications` | Search publications by title, abstract, or keywords. | — | — |
| `send_message` | Send a message to another agent. | — | — |
| `think` | Use LLM inference to reason about something. Optionally validate against a Pydantic model. | — | — |
| `tool_guardrail` | Check if tool call is permitted. Returns is_allowed. | — | — |
| `update_citation_count` | Update citation count for a publication. | — | — |
| `update_project_status` | Update project status. | — | — |

**File**: `agentic_ai/agents/research.py`

### Data Analyst Agent (`data_analyst.py`)

**Purpose**: Data Analyst Agent for statistical analysis, insights,

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `calculate_statistics` | Calculate descriptive statistics for a column. | — | — |
| `call_tool` | Call a tool by name with keyword arguments. | — | — |
| `can_create_project` | Check if agent can create projects. | — | — |
| `can_manage_agents` | Check if agent can manage other agents. | — | — |
| `can_read` | Check if agent has read permission. | — | — |
| `can_write` | Check if agent has write permission. | — | — |
| `detect_anomalies` | Detect anomalies using z-score method. | — | — |
| `detect_correlations` | Detect correlation between two columns. | — | — |
| `detect_trends` | Detect trends in time-series data. | — | — |
| `generate_id` | Generate a unique ID with the given prefix (static version). | — | — |
| `generate_insights` | Generate automated insights for a dataset. | — | — |
| `generate_report` | Generate a comprehensive analysis report. | — | — |
| `get_agent_card` | Generate an A2A-compatible agent card describing this agent. | — | — |
| `get_report` | Get a report by ID. | — | — |
| `get_state` | Get agent state summary. | — | — |
| `get_status` | Get agent status. | — | — |
| `get_transparency_log` | Get the transparency log entries. | — | — |
| `input_guardrail` | Validate/sanitize input through guardrail pipeline. Returns (sanitized_prompt, is_safe). | — | — |
| `load_data` | Load data into cache for analysis. | — | — |
| `log` | Log an action for transparency. | — | — |
| `output_guardrail` | Validate/sanitize output through guardrail pipeline. Returns (sanitized_response, is_safe). | — | — |
| `perform_task` | Perform a task. Override in subclasses. | — | — |
| `process_message` | Process an incoming message. Override in subclasses. | — | — |
| `reason` | Iterative ReAct reasoning loop: think→act→observe. | — | — |
| `receive_message` | Receive a message from another agent. | — | — |
| `reflect` | Self-critique: evaluate response quality and suggest improvements. | — | — |
| `register_dataset` | Register a dataset for analysis. | — | — |
| `register_tool` | Register a tool with the agent. | — | — |
| `send_message` | Send a message to another agent. | — | — |
| `think` | Use LLM inference to reason about something. Optionally validate against a Pydantic model. | — | — |
| `tool_guardrail` | Check if tool call is permitted. Returns is_allowed. | — | — |

**File**: `agentic_ai/agents/data_analyst.py`

### Data Governance Agent (`data_governance.py`)

**Purpose**: Data Governance Agent for data classification, retention,

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `add_lineage` | Add data lineage record. | — | — |
| `approve_access` | Approve access request. | — | — |
| `call_tool` | Call a tool by name with keyword arguments. | — | — |
| `can_create_project` | Check if agent can create projects. | — | — |
| `can_manage_agents` | Check if agent can manage other agents. | — | — |
| `can_read` | Check if agent has read permission. | — | — |
| `can_write` | Check if agent has write permission. | — | — |
| `classify_data` | Auto-classify data based on content keywords. | — | — |
| `create_quality_rule` | Create data quality rule. | — | — |
| `create_retention_policy` | Create retention policy. | — | — |
| `deny_access` | Deny access request. | — | — |
| `execute_quality_check` | Execute quality check and record result. | — | — |
| `generate_id` | Generate a unique ID with the given prefix (static version). | — | — |
| `get_access_requests` | Get access requests with filtering. | — | — |
| `get_agent_card` | Generate an A2A-compatible agent card describing this agent. | — | — |
| `get_assets` | Get assets with filtering. | — | — |
| `get_assets_due_for_action` | Get assets due for retention action. | — | — |
| `get_compliance_summary` | Get compliance summary for regulated data. | — | — |
| `get_governance_report` | Generate data governance report. | — | — |
| `get_lineage` | Get data lineage for an asset. | — | — |
| `get_quality_issues` | Get quality issues with filtering. | — | — |
| `get_quality_score` | Calculate overall quality score for an asset. | — | — |
| `get_retention_period` | Get retention period for an asset. | — | — |
| `get_state` | Get agent state summary. | — | — |
| `get_status` | Get agent status. | — | — |
| `get_transparency_log` | Get the transparency log entries. | — | — |
| `input_guardrail` | Validate/sanitize input through guardrail pipeline. Returns (sanitized_prompt, is_safe). | — | — |
| `log` | Log an action for transparency. | — | — |
| `output_guardrail` | Validate/sanitize output through guardrail pipeline. Returns (sanitized_response, is_safe). | — | — |
| `perform_task` | Perform a task. Override in subclasses. | — | — |
| `process_message` | Process an incoming message. Override in subclasses. | — | — |
| `reason` | Iterative ReAct reasoning loop: think→act→observe. | — | — |
| `receive_message` | Receive a message from another agent. | — | — |
| `reflect` | Self-critique: evaluate response quality and suggest improvements. | — | — |
| `register_asset` | Register a data asset. | — | — |
| `register_tool` | Register a tool with the agent. | — | — |
| `request_access` | Request access to data asset. | — | — |
| `resolve_quality_issue` | Resolve a quality issue. | — | — |
| `revoke_access` | Revoke approved access. | — | — |
| `send_message` | Send a message to another agent. | — | — |
| `think` | Use LLM inference to reason about something. Optionally validate against a Pydantic model. | — | — |
| `tool_guardrail` | Check if tool call is permitted. Returns is_allowed. | — | — |
| `update_asset_metrics` | Update asset metrics. | — | — |
| `update_lineage_status` | Update lineage execution status. | — | — |

**File**: `agentic_ai/agents/data_governance.py`

### DevOps Agent (`devops.py`)

**Purpose**: DevOps Agent for infrastructure automation, CI/CD,

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `acknowledge_alert` | Acknowledge an alert. | — | — |
| `call_tool` | Call a tool by name with keyword arguments. | — | — |
| `can_create_project` | Check if agent can create projects. | — | — |
| `can_manage_agents` | Check if agent can manage other agents. | — | — |
| `can_read` | Check if agent has read permission. | — | — |
| `can_write` | Check if agent has write permission. | — | — |
| `check_thresholds` | Check metrics against thresholds and create alerts. | — | — |
| `create_alert` | Create a monitoring alert. | — | — |
| `create_deployment` | Create a new deployment. | — | — |
| `create_pipeline` | Create a new CI/CD pipeline. | — | — |
| `create_task` | Create a DevOps task. | — | — |
| `generate_id` | Generate a unique ID with the given prefix (static version). | — | — |
| `get_active_alerts` | Get active (unresolved) alerts. | — | — |
| `get_agent_card` | Generate an A2A-compatible agent card describing this agent. | — | — |
| `get_cost_report` | Generate cost optimization report. | — | — |
| `get_deployments` | Get deployments with filtering. | — | — |
| `get_infrastructure_summary` | Get infrastructure summary. | — | — |
| `get_pipelines` | Get pipelines with filtering. | — | — |
| `get_resource_costs` | Calculate resource costs for time period. | — | — |
| `get_state` | Get agent state summary. | — | — |
| `get_status` | Get agent status. | — | — |
| `get_transparency_log` | Get the transparency log entries. | — | — |
| `input_guardrail` | Validate/sanitize input through guardrail pipeline. Returns (sanitized_prompt, is_safe). | — | — |
| `log` | Log an action for transparency. | — | — |
| `output_guardrail` | Validate/sanitize output through guardrail pipeline. Returns (sanitized_response, is_safe). | — | — |
| `perform_task` | Perform a task. Override in subclasses. | — | — |
| `process_message` | Process an incoming message. Override in subclasses. | — | — |
| `reason` | Iterative ReAct reasoning loop: think→act→observe. | — | — |
| `receive_message` | Receive a message from another agent. | — | — |
| `record_metric` | Record a metric data point. | — | — |
| `reflect` | Self-critique: evaluate response quality and suggest improvements. | — | — |
| `register_resource` | Register an infrastructure resource. | — | — |
| `register_tool` | Register a tool with the agent. | — | — |
| `resolve_alert` | Resolve an alert. | — | — |
| `rollback_deployment` | Rollback deployment to previous version. | — | — |
| `run_command` | Execute a command on a target. | — | — |
| `send_message` | Send a message to another agent. | — | — |
| `start_pipeline` | Start a queued pipeline. | — | — |
| `think` | Use LLM inference to reason about something. Optionally validate against a Pydantic model. | — | — |
| `tool_guardrail` | Check if tool call is permitted. Returns is_allowed. | — | — |
| `update_deployment_status` | Update deployment status. | — | — |
| `update_pipeline_stage` | Update pipeline stage status. | — | — |
| `update_resource_status` | Update resource status. | — | — |

**File**: `agentic_ai/agents/devops.py`

### Support Agent (`support.py`)

**Purpose**: Support Agent for ticket management, auto-responses,

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `add_knowledge_article` | Add a new knowledge base article. | — | — |
| `add_message` | Add a message to a ticket. | — | — |
| `call_tool` | Call a tool by name with keyword arguments. | — | — |
| `can_create_project` | Check if agent can create projects. | — | — |
| `can_manage_agents` | Check if agent can manage other agents. | — | — |
| `can_read` | Check if agent has read permission. | — | — |
| `can_write` | Check if agent has write permission. | — | — |
| `check_sla_breaches` | Check for SLA breaches. | — | — |
| `create_ticket` | Create support ticket | `subject: str, description: str` | `ticket: Ticket` |
| `generate_id` | Generate a unique ID with the given prefix (static version). | — | — |
| `get_agent_card` | Generate an A2A-compatible agent card describing this agent. | — | — |
| `get_auto_response` | Get auto-response for ticket based on category. | — | — |
| `get_state` | Get agent state summary. | — | — |
| `get_status` | Get agent status. | — | — |
| `get_support_metrics` | Get support metrics report. | — | — |
| `get_tickets` | Get tickets with filtering. | — | — |
| `get_transparency_log` | Get the transparency log entries. | — | — |
| `input_guardrail` | Validate/sanitize input through guardrail pipeline. Returns (sanitized_prompt, is_safe). | — | — |
| `log` | Log an action for transparency. | — | — |
| `output_guardrail` | Validate/sanitize output through guardrail pipeline. Returns (sanitized_response, is_safe). | — | — |
| `perform_task` | Perform a task. Override in subclasses. | — | — |
| `process_message` | Process an incoming message. Override in subclasses. | — | — |
| `rate_article` | Rate a knowledge base article. | — | — |
| `reason` | Iterative ReAct reasoning loop: think→act→observe. | — | — |
| `receive_message` | Receive a message from another agent. | — | — |
| `record_satisfaction` | Record customer satisfaction score. | — | — |
| `reflect` | Self-critique: evaluate response quality and suggest improvements. | — | — |
| `register_tool` | Register a tool with the agent. | — | — |
| `resolve_ticket` | Resolve a ticket. | — | — |
| `search_knowledge_base` | Search knowledge base articles. | — | — |
| `send_message` | Send a message to another agent. | — | — |
| `think` | Use LLM inference to reason about something. Optionally validate against a Pydantic model. | — | — |
| `tool_guardrail` | Check if tool call is permitted. Returns is_allowed. | — | — |
| `update_ticket_status` | Update ticket status. | — | — |

**File**: `agentic_ai/agents/support.py`

### Integration Agent (`integration.py`)

**Purpose**: Integration Agent for API connections, webhooks,

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `call_tool` | Call a tool by name with keyword arguments. | — | — |
| `can_create_project` | Check if agent can create projects. | — | — |
| `can_manage_agents` | Check if agent can manage other agents. | — | — |
| `can_read` | Check if agent has read permission. | — | — |
| `can_write` | Check if agent has write permission. | — | — |
| `create_connection` | Create a new API connection. | — | — |
| `create_sync_job` | Create a data synchronization job. | — | — |
| `create_webhook` | Create a new webhook. | — | — |
| `generate_id` | Generate a unique ID with the given prefix (static version). | — | — |
| `get_agent_card` | Generate an A2A-compatible agent card describing this agent. | — | — |
| `get_connections` | Get connections with filtering. | — | — |
| `get_integration_health` | Get overall integration health summary. | — | — |
| `get_logs` | Get integration logs. | — | — |
| `get_state` | Get agent state summary. | — | — |
| `get_status` | Get agent status. | — | — |
| `get_sync_jobs` | Get sync jobs with filtering. | — | — |
| `get_transparency_log` | Get the transparency log entries. | — | — |
| `get_webhooks` | Get webhooks with filtering. | — | — |
| `input_guardrail` | Validate/sanitize input through guardrail pipeline. Returns (sanitized_prompt, is_safe). | — | — |
| `log` | Log an action for transparency. | — | — |
| `output_guardrail` | Validate/sanitize output through guardrail pipeline. Returns (sanitized_response, is_safe). | — | — |
| `pause_webhook` | Pause a webhook. | — | — |
| `perform_task` | Perform a task. Override in subclasses. | — | — |
| `process_message` | Process an incoming message. Override in subclasses. | — | — |
| `reason` | Iterative ReAct reasoning loop: think→act→observe. | — | — |
| `receive_message` | Receive a message from another agent. | — | — |
| `reflect` | Self-critique: evaluate response quality and suggest improvements. | — | — |
| `register_tool` | Register a tool with the agent. | — | — |
| `remove_connection` | Remove a connection. | — | — |
| `run_sync_job` | Execute a sync job. | — | — |
| `send_message` | Send a message to another agent. | — | — |
| `test_connection` | Test API connection. | — | — |
| `think` | Use LLM inference to reason about something. Optionally validate against a Pydantic model. | — | — |
| `tool_guardrail` | Check if tool call is permitted. Returns is_allowed. | — | — |
| `trigger_webhook` | Trigger a webhook. | — | — |
| `update_connection_status` | Update connection status. | — | — |

**File**: `agentic_ai/agents/integration.py`

### Communications Agent (`communications.py`)

**Purpose**: Communications Agent for multi-channel messaging,

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `add_contact` | Add a contact. | — | — |
| `call_tool` | Call a tool by name with keyword arguments. | — | — |
| `can_create_project` | Check if agent can create projects. | — | — |
| `can_manage_agents` | Check if agent can manage other agents. | — | — |
| `can_read` | Check if agent has read permission. | — | — |
| `can_write` | Check if agent has write permission. | — | — |
| `complete_campaign` | Complete a campaign. | — | — |
| `create_campaign` | Create a communication campaign. | — | — |
| `create_template` | Create a message template. | — | — |
| `generate_id` | Generate a unique ID with the given prefix (static version). | — | — |
| `get_agent_card` | Generate an A2A-compatible agent card describing this agent. | — | — |
| `get_campaign_performance` | Get campaign performance metrics. | — | — |
| `get_campaigns` | Get campaigns with filtering. | — | — |
| `get_channel_health` | Get channel health status. | — | — |
| `get_contacts` | Get contacts with filtering. | — | — |
| `get_delivery_stats` | Get delivery statistics. | — | — |
| `get_messages` | Get messages with filtering. | — | — |
| `get_state` | Get agent state summary. | — | — |
| `get_status` | Get agent status. | — | — |
| `get_templates` | Get templates with filtering. | — | — |
| `get_transparency_log` | Get the transparency log entries. | — | — |
| `input_guardrail` | Validate/sanitize input through guardrail pipeline. Returns (sanitized_prompt, is_safe). | — | — |
| `log` | Log an action for transparency. | — | — |
| `output_guardrail` | Validate/sanitize output through guardrail pipeline. Returns (sanitized_response, is_safe). | — | — |
| `perform_task` | Perform a task. Override in subclasses. | — | — |
| `process_message` | Process an incoming message. Override in subclasses. | — | — |
| `reason` | Iterative ReAct reasoning loop: think→act→observe. | — | — |
| `receive_message` | Receive a message from another agent. | — | — |
| `reflect` | Self-critique: evaluate response quality and suggest improvements. | — | — |
| `register_tool` | Register a tool with the agent. | — | — |
| `render_template` | Render a template with values. | — | — |
| `schedule_message` | Schedule message | `time: datetime, message: dict` | `scheduled: ScheduledMessage` |
| `send_email` | Send email | `to: str, subject: str, body: str` | `status: bool` |
| `send_message` | Send a message. | — | — |
| `start_campaign` | Start a campaign. | — | — |
| `think` | Use LLM inference to reason about something. Optionally validate against a Pydantic model. | — | — |
| `tool_guardrail` | Check if tool call is permitted. Returns is_allowed. | — | — |
| `update_campaign_metrics` | Update campaign metrics. | — | — |
| `update_message_status` | Update message delivery status. | — | — |
| `update_preferences` | Update contact communication preferences. | — | — |

**File**: `agentic_ai/agents/communications.py`

### Legal Agent (`legal.py`)

**Purpose**: Legal Agent for contract review, document generation,

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `add_clause_to_document` | Add clause to document. | — | — |
| `call_tool` | Call a tool by name with keyword arguments. | — | — |
| `can_create_project` | Check if agent can create projects. | — | — |
| `can_manage_agents` | Check if agent can manage other agents. | — | — |
| `can_read` | Check if agent has read permission. | — | — |
| `can_write` | Check if agent has write permission. | — | — |
| `create_document` | Create a legal document. | — | — |
| `create_legal_matter` | Create a legal matter (tracked as a legal document). | — | — |
| `generate_id` | Generate a unique ID with the given prefix (static version). | — | — |
| `generate_nda_template` | Generate NDA template. | — | — |
| `generate_terms_template` | Generate Terms of Service template. | — | — |
| `get_agent_card` | Generate an A2A-compatible agent card describing this agent. | — | — |
| `get_compliance_status` | Get overall compliance status. | — | — |
| `get_documents` | Get documents with filtering. | — | — |
| `get_expiring_documents` | Get documents expiring within specified days. | — | — |
| `get_state` | Get agent state summary. | — | — |
| `get_status` | Get agent status. | — | — |
| `get_transparency_log` | Get the transparency log entries. | — | — |
| `input_guardrail` | Validate/sanitize input through guardrail pipeline. Returns (sanitized_prompt, is_safe). | — | — |
| `log` | Log an action for transparency. | — | — |
| `output_guardrail` | Validate/sanitize output through guardrail pipeline. Returns (sanitized_response, is_safe). | — | — |
| `perform_task` | Perform a task. Override in subclasses. | — | — |
| `process_message` | Process an incoming message. Override in subclasses. | — | — |
| `reason` | Iterative ReAct reasoning loop: think→act→observe. | — | — |
| `receive_message` | Receive a message from another agent. | — | — |
| `reflect` | Self-critique: evaluate response quality and suggest improvements. | — | — |
| `register_tool` | Register a tool with the agent. | — | — |
| `review_contract` | Review contract | `contract: str, clauses: list` | `review: ContractReview` |
| `run_compliance_check` | Run compliance check against regulation. | — | — |
| `send_message` | Send a message to another agent. | — | — |
| `think` | Use LLM inference to reason about something. Optionally validate against a Pydantic model. | — | — |
| `tool_guardrail` | Check if tool call is permitted. Returns is_allowed. | — | — |
| `update_document_status` | Update document status. | — | — |

**File**: `agentic_ai/agents/legal.py`

### Compliance Agent (`compliance.py`)

**Purpose**: Compliance Agent for regulatory compliance tracking,

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `add_certificate` | Add a compliance certificate. | — | — |
| `add_regulation` | Add a regulatory framework to track. | — | — |
| `approve_policy` | Approve a policy. | — | — |
| `call_tool` | Call a tool by name with keyword arguments. | — | — |
| `can_create_project` | Check if agent can create projects. | — | — |
| `can_manage_agents` | Check if agent can manage other agents. | — | — |
| `can_read` | Check if agent has read permission. | — | — |
| `can_write` | Check if agent has write permission. | — | — |
| `complete_audit` | Complete an audit. | — | — |
| `create_assessment` | Create a compliance assessment. | — | — |
| `create_audit` | Create a compliance audit. | — | — |
| `create_control` | Create a compliance control. | — | — |
| `create_finding` | Create a compliance finding. | — | — |
| `create_policy` | Create a policy document. | — | — |
| `generate_id` | Generate a unique ID with the given prefix (static version). | — | — |
| `get_agent_card` | Generate an A2A-compatible agent card describing this agent. | — | — |
| `get_audits` | Get audits with filtering. | — | — |
| `get_compliance_report` | Generate comprehensive compliance report. | — | — |
| `get_controls` | Get controls with filtering. | — | — |
| `get_findings` | Get findings with filtering. | — | — |
| `get_framework_status` | Get status for a specific framework. | — | — |
| `get_policies` | Get policies with filtering. | — | — |
| `get_policies_due_for_review` | Get policies due for review. | — | — |
| `get_regulations` | Get regulations with filtering. | — | — |
| `get_state` | Get agent state summary. | — | — |
| `get_status` | Get agent status. | — | — |
| `get_transparency_log` | Get the transparency log entries. | — | — |
| `input_guardrail` | Validate/sanitize input through guardrail pipeline. Returns (sanitized_prompt, is_safe). | — | — |
| `log` | Log an action for transparency. | — | — |
| `output_guardrail` | Validate/sanitize output through guardrail pipeline. Returns (sanitized_response, is_safe). | — | — |
| `perform_task` | Perform a task. Override in subclasses. | — | — |
| `process_message` | Process an incoming message. Override in subclasses. | — | — |
| `reason` | Iterative ReAct reasoning loop: think→act→observe. | — | — |
| `receive_message` | Receive a message from another agent. | — | — |
| `reflect` | Self-critique: evaluate response quality and suggest improvements. | — | — |
| `register_tool` | Register a tool with the agent. | — | — |
| `resolve_finding` | Resolve a finding. | — | — |
| `send_message` | Send a message to another agent. | — | — |
| `start_audit` | Start an audit. | — | — |
| `test_control` | Test a control and update status. | — | — |
| `think` | Use LLM inference to reason about something. Optionally validate against a Pydantic model. | — | — |
| `tool_guardrail` | Check if tool call is permitted. Returns is_allowed. | — | — |
| `update_regulation_status` | Update regulation compliance status based on controls. | — | — |

**File**: `agentic_ai/agents/compliance.py`

### Privacy Agent (`privacy.py`)

**Purpose**: Privacy Agent for GDPR, CCPA, and privacy regulation compliance,

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `DataSubjectRight` | Data subject rights. | — | — |
| `PrivacyRegulation` | Privacy regulations. | — | — |
| `ProcessingPurpose` | Data processing purposes. | — | — |
| `add_processing_activity` | Add a processing activity (Record of Processing Activities). | — | — |
| `add_risk_to_pia` | Add identified risk to PIA. | — | — |
| `approve_pia` | Approve a PIA. | — | — |
| `call_tool` | Call a tool by name with keyword arguments. | — | — |
| `can_create_project` | Check if agent can create projects. | — | — |
| `can_manage_agents` | Check if agent can manage other agents. | — | — |
| `can_read` | Check if agent has read permission. | — | — |
| `can_write` | Check if agent has write permission. | — | — |
| `check_valid_consent` | Check if valid consent exists for a purpose. | — | — |
| `close_breach` | Close a breach with full documentation. | — | — |
| `contain_breach` | Mark breach as contained. | — | — |
| `create_data_request` | Create a data subject request with flexible interface. | — | — |
| `create_pia` | Create a Privacy Impact Assessment. | — | — |
| `create_request` | Create a data subject rights request. | — | — |
| `fulfill_access_request` | Fulfill an access request with data export. | — | — |
| `fulfill_erasure_request` | Fulfill an erasure (deletion) request. | — | — |
| `generate_id` | Generate a unique ID with the given prefix (static version). | — | — |
| `get_agent_card` | Generate an A2A-compatible agent card describing this agent. | — | — |
| `get_breaches` | Get breaches with filtering. | — | — |
| `get_compliance_report` | Generate privacy compliance report. | — | — |
| `get_consents` | Get consent records with filtering. | — | — |
| `get_data_subject` | Get data subject by ID. | — | — |
| `get_data_subjects` | Get data subjects with filtering. | — | — |
| `get_pias` | Get PIAs with filtering. | — | — |
| `get_processing_activities` | Get processing activities with filtering. | — | — |
| `get_regulation_compliance` | Get compliance status for a specific regulation. | — | — |
| `get_requests` | Get requests with filtering. | — | — |
| `get_state` | Get agent state summary. | — | — |
| `get_status` | Get agent status. | — | — |
| `get_transparency_log` | Get the transparency log entries. | — | — |
| `input_guardrail` | Validate/sanitize input through guardrail pipeline. Returns (sanitized_prompt, is_safe). | — | — |
| `log` | Log an action for transparency. | — | — |
| `notify_authority` | Record authority notification. | — | — |
| `output_guardrail` | Validate/sanitize output through guardrail pipeline. Returns (sanitized_response, is_safe). | — | — |
| `perform_task` | Perform a task. Override in subclasses. | — | — |
| `process_message` | Process an incoming message. Override in subclasses. | — | — |
| `reason` | Iterative ReAct reasoning loop: think→act→observe. | — | — |
| `receive_message` | Receive a message from another agent. | — | — |
| `record_consent` | Record consent given. | — | — |
| `reflect` | Self-critique: evaluate response quality and suggest improvements. | — | — |
| `register_data_subject` | Register a data subject. | — | — |
| `register_processing_activity` | Alias for add_processing_activity with more flexible interface. | — | — |
| `register_tool` | Register a tool with the agent. | — | — |
| `report_breach` | Report a data breach. | — | — |
| `send_message` | Send a message to another agent. | — | — |
| `think` | Use LLM inference to reason about something. Optionally validate against a Pydantic model. | — | — |
| `tool_guardrail` | Check if tool call is permitted. Returns is_allowed. | — | — |
| `update_request_status` | Update request status. | — | — |
| `verify_data_subject` | Verify data subject identity. | — | — |
| `verify_request` | Verify a request (identity verification complete). | — | — |
| `withdraw_consent` | Withdraw consent. | — | — |

**File**: `agentic_ai/agents/privacy.py`

### Risk Agent (`risk.py`)

**Purpose**: Risk Agent for Enterprise Risk Management (ERM),

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `assess_risk` | Assess risk | `risk: Risk` | `assessment: RiskAssessment` |
| `call_tool` | Call a tool by name with keyword arguments. | — | — |
| `can_create_project` | Check if agent can create projects. | — | — |
| `can_manage_agents` | Check if agent can manage other agents. | — | — |
| `can_read` | Check if agent has read permission. | — | — |
| `can_write` | Check if agent has write permission. | — | — |
| `complete_assessment` | Complete a risk assessment. | — | — |
| `create_assessment` | Create a risk assessment. | — | — |
| `create_control` | Create a risk control. | — | — |
| `create_kri` | Create a Key Risk Indicator. | — | — |
| `generate_id` | Generate a unique ID with the given prefix (static version). | — | — |
| `get_agent_card` | Generate an A2A-compatible agent card describing this agent. | — | — |
| `get_assessments` | Get assessments with filtering. | — | — |
| `get_controls` | Get controls with filtering. | — | — |
| `get_events` | Get events with filtering. | — | — |
| `get_high_priority_risks` | Get high priority risks sorted by score. | — | — |
| `get_kris` | Get KRIs with filtering. | — | — |
| `get_kris_at_risk` | Get KRIs in yellow or red status. | — | — |
| `get_risk_appetite_status` | Get risk appetite compliance status. | — | — |
| `get_risk_dashboard` | Generate risk dashboard summary. | — | — |
| `get_risk_register` | Generate risk register report. | — | — |
| `get_risks` | Get risks with filtering. | — | — |
| `get_state` | Get agent state summary. | — | — |
| `get_status` | Get agent status. | — | — |
| `get_transparency_log` | Get the transparency log entries. | — | — |
| `identify_risk` | Identify a new risk. | — | — |
| `input_guardrail` | Validate/sanitize input through guardrail pipeline. Returns (sanitized_prompt, is_safe). | — | — |
| `log` | Log an action for transparency. | — | — |
| `output_guardrail` | Validate/sanitize output through guardrail pipeline. Returns (sanitized_response, is_safe). | — | — |
| `perform_task` | Perform a task. Override in subclasses. | — | — |
| `plan_treatment` | Plan risk treatment. | — | — |
| `process_message` | Process an incoming message. Override in subclasses. | — | — |
| `reason` | Iterative ReAct reasoning loop: think→act→observe. | — | — |
| `receive_message` | Receive a message from another agent. | — | — |
| `reflect` | Self-critique: evaluate response quality and suggest improvements. | — | — |
| `register_tool` | Register a tool with the agent. | — | — |
| `report_event` | Report a risk event/incident. | — | — |
| `resolve_event` | Resolve a risk event. | — | — |
| `send_message` | Send a message to another agent. | — | — |
| `test_control` | Test control effectiveness. | — | — |
| `think` | Use LLM inference to reason about something. Optionally validate against a Pydantic model. | — | — |
| `tool_guardrail` | Check if tool call is permitted. Returns is_allowed. | — | — |
| `update_kri_value` | Update KRI value and calculate status. | — | — |
| `update_risk_status` | Update risk status. | — | — |

**File**: `agentic_ai/agents/risk.py`

### Ethics Agent (`ethics.py`)

**Purpose**: Ethics Agent for AI ethics review, bias detection,

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `add_explainability_record` | Add explainability record. | — | — |
| `add_finding` | Add finding to ethics assessment. | — | — |
| `call_tool` | Call a tool by name with keyword arguments. | — | — |
| `can_create_project` | Check if agent can create projects. | — | — |
| `can_manage_agents` | Check if agent can manage other agents. | — | — |
| `can_read` | Check if agent has read permission. | — | — |
| `can_write` | Check if agent has write permission. | — | — |
| `complete_assessment` | Complete ethics assessment. | — | — |
| `configure_oversight` | Configure human oversight for a model. | — | — |
| `create_ethics_assessment` | Create ethics assessment for a model. | — | — |
| `create_remediation_plan` | Create remediation plan for bias. | — | — |
| `detect_bias` | Record detected bias. | — | — |
| `generate_fairness_report` | Generate fairness metrics report. | — | — |
| `generate_id` | Generate a unique ID with the given prefix (static version). | — | — |
| `get_agent_card` | Generate an A2A-compatible agent card describing this agent. | — | — |
| `get_bias_assessments` | Get bias assessments with filtering. | — | — |
| `get_ethics_report` | Generate comprehensive ethics report. | — | — |
| `get_explainability` | Get explainability records for a model. | — | — |
| `get_fairness_reports` | Get fairness reports with filtering. | — | — |
| `get_incidents` | Get incidents with filtering. | — | — |
| `get_model_ethics_profile` | Get comprehensive ethics profile for a model. | — | — |
| `get_models` | Get models with filtering. | — | — |
| `get_oversight_config` | Get oversight configuration for a model. | — | — |
| `get_state` | Get agent state summary. | — | — |
| `get_status` | Get agent status. | — | — |
| `get_transparency_log` | Get the transparency log entries. | — | — |
| `input_guardrail` | Validate/sanitize input through guardrail pipeline. Returns (sanitized_prompt, is_safe). | — | — |
| `log` | Log an action for transparency. | — | — |
| `mark_bias_mitigated` | Mark bias as mitigated. | — | — |
| `output_guardrail` | Validate/sanitize output through guardrail pipeline. Returns (sanitized_response, is_safe). | — | — |
| `perform_task` | Perform a task. Override in subclasses. | — | — |
| `process_message` | Process an incoming message. Override in subclasses. | — | — |
| `reason` | Iterative ReAct reasoning loop: think→act→observe. | — | — |
| `receive_message` | Receive a message from another agent. | — | — |
| `reflect` | Self-critique: evaluate response quality and suggest improvements. | — | — |
| `register_model` | Register an AI model for ethics oversight. | — | — |
| `register_tool` | Register a tool with the agent. | — | — |
| `report_incident` | Report ethical incident. | — | — |
| `resolve_incident` | Resolve ethical incident. | — | — |
| `send_message` | Send a message to another agent. | — | — |
| `think` | Use LLM inference to reason about something. Optionally validate against a Pydantic model. | — | — |
| `tool_guardrail` | Check if tool call is permitted. Returns is_allowed. | — | — |
| `update_model_risk` | Update model risk level. | — | — |

**File**: `agentic_ai/agents/ethics.py`

### Security Agent (`security.py`)

**Purpose**: Security Agent for vulnerability scanning, incident response,

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `add_control` | Add a control to a security assessment. | — | — |
| `call_tool` | Call a tool by name with keyword arguments. | — | — |
| `can_create_project` | Check if agent can create projects. | — | — |
| `can_manage_agents` | Check if agent can manage other agents. | — | — |
| `can_read` | Check if agent has read permission. | — | — |
| `can_write` | Check if agent has write permission. | — | — |
| `check_rate_limit` | Check if action is within rate limits. | — | — |
| `create_assessment` | Create a security assessment. | — | — |
| `create_incident` | Create a new security incident. | — | — |
| `detect_anomalies` | Detect anomalies in access logs. | — | — |
| `generate_id` | Generate a unique ID with the given prefix (static version). | — | — |
| `generate_secure_secret` | Generate a cryptographically secure secret. | — | — |
| `generate_security_report` | Generate a security status report. | — | — |
| `get_agent_card` | Generate an A2A-compatible agent card describing this agent. | — | — |
| `get_incidents` | Get incidents with optional filtering. | — | — |
| `get_policy` | Get a security policy by ID. | — | — |
| `get_secrets_due_for_rotation` | Get secrets due for rotation within specified days. | — | — |
| `get_state` | Get agent state summary. | — | — |
| `get_status` | Get agent status. | — | — |
| `get_transparency_log` | Get the transparency log entries. | — | — |
| `input_guardrail` | Validate/sanitize input through guardrail pipeline. Returns (sanitized_prompt, is_safe). | — | — |
| `log` | Log an action for transparency. | — | — |
| `log_access` | Log an access event for security analysis. | — | — |
| `output_guardrail` | Validate/sanitize output through guardrail pipeline. Returns (sanitized_response, is_safe). | — | — |
| `perform_task` | Perform a task. Override in subclasses. | — | — |
| `process_message` | Process an incoming message. Override in subclasses. | — | — |
| `reason` | Iterative ReAct reasoning loop: think→act→observe. | — | — |
| `receive_message` | Receive a message from another agent. | — | — |
| `reflect` | Self-critique: evaluate response quality and suggest improvements. | — | — |
| `register_secret` | Register a secret for rotation tracking. | — | — |
| `register_tool` | Register a tool with the agent. | — | — |
| `rotate_secret` | Rotate a secret. | — | — |
| `scan_code` | Scan code for security vulnerabilities. | — | — |
| `scan_directory` | Scan a directory recursively for security vulnerabilities. | — | — |
| `scan_file` | Scan a file for security vulnerabilities. | — | — |
| `send_message` | Send a message to another agent. | — | — |
| `think` | Use LLM inference to reason about something. Optionally validate against a Pydantic model. | — | — |
| `tool_guardrail` | Check if tool call is permitted. Returns is_allowed. | — | — |
| `update_incident_status` | Update incident status. | — | — |
| `update_policy` | Update a security policy. | — | — |
| `validate_password` | Validate password against security policy. | — | — |

**File**: `agentic_ai/agents/security.py`

### SOC Agent (`soc.py`)

**Purpose**: Security Operations Agent for SIEM integration,

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `add_ioc` | Add indicator of compromise to incident. | — | — |
| `add_threat_intel` | Add threat intelligence indicator. | — | — |
| `add_timeline_entry` | Add entry to incident timeline. | — | — |
| `call_tool` | Call a tool by name with keyword arguments. | — | — |
| `can_create_project` | Check if agent can create projects. | — | — |
| `can_manage_agents` | Check if agent can manage other agents. | — | — |
| `can_read` | Check if agent has read permission. | — | — |
| `can_write` | Check if agent has write permission. | — | — |
| `close_incident` | Close an incident with full documentation. | — | — |
| `create_alert` | Create a security alert. | — | — |
| `create_hunt` | Create a threat hunting query. | — | — |
| `create_incident` | Create a security incident. | — | — |
| `escalate_alert` | Escalate alert to incident. | — | — |
| `execute_hunt` | Execute a threat hunt and record findings. | — | — |
| `generate_id` | Generate a unique ID with the given prefix (static version). | — | — |
| `get_agent_card` | Generate an A2A-compatible agent card describing this agent. | — | — |
| `get_alerts` | Get alerts with filtering. | — | — |
| `get_attack_mapping` | Map incident to MITRE ATT&CK framework. | — | — |
| `get_hunts` | Get hunts with filtering. | — | — |
| `get_incidents` | Get incidents with filtering. | — | — |
| `get_soc_metrics` | Get SOC operational metrics. | — | — |
| `get_state` | Get agent state summary. | — | — |
| `get_status` | Get agent status. | — | — |
| `get_threat_intel` | Get threat intel with filtering. | — | — |
| `get_transparency_log` | Get the transparency log entries. | — | — |
| `get_wazuh_metrics` | Combined local+poller status, suitable for a daily report. | — | — |
| `ingest_wazuh_alert` | Convert one Wazuh alert JSON into a SecurityAlert and add to local state. | — | — |
| `ingest_wazuh_alerts` | Ingest a batch of Wazuh alerts. | — | — |
| `input_guardrail` | Validate/sanitize input through guardrail pipeline. Returns (sanitized_prompt, is_safe). | — | — |
| `log` | Log an action for transparency. | — | — |
| `output_guardrail` | Validate/sanitize output through guardrail pipeline. Returns (sanitized_response, is_safe). | — | — |
| `perform_task` | Perform a task. Override in subclasses. | — | — |
| `process_message` | Process an incoming message. Override in subclasses. | — | — |
| `reason` | Iterative ReAct reasoning loop: think→act→observe. | — | — |
| `receive_message` | Receive a message from another agent. | — | — |
| `record_outbound_subject` | Record that an incident was emailed out, so a future reply can | — | — |
| `reflect` | Self-critique: evaluate response quality and suggest improvements. | — | — |
| `register_tool` | Register a tool with the agent. | — | — |
| `report_security_incident` | Report a security incident. Convenience method that maps to create_incident. | — | — |
| `search_threat_intel` | Search threat intel by value. | — | — |
| `send_message` | Send a message to another agent. | — | — |
| `start_wazuh_poller` | Build a WazuhPoller that calls ingest_wazuh_alerts on each poll. | — | — |
| `stop_wazuh_poller` | stop wazuh poller | — | — |
| `think` | Use LLM inference to reason about something. Optionally validate against a Pydantic model. | — | — |
| `tool_guardrail` | Check if tool call is permitted. Returns is_allowed. | — | — |
| `triage_alert` | Triage security alert | `alert_id: str` | `triage: AlertTriage` |
| `triage_inbound_email` | Process one inbound email addressed to a SOC inbox (reports@). | — | — |
| `update_incident_status` | Update incident status. Accepts IncidentStatus enum or string. | — | — |

**File**: `agentic_ai/agents/cyber/soc.py`

### VulnMan Agent (`vulnman.py`)

**Purpose**: Vulnerability Management Agent for scanning,

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `add_asset` | Add an asset to inventory. | — | — |
| `add_patch` | Add a patch to track. | — | — |
| `add_vulnerability` | Add a vulnerability finding. | — | — |
| `call_tool` | Call a tool by name with keyword arguments. | — | — |
| `can_create_project` | Check if agent can create projects. | — | — |
| `can_manage_agents` | Check if agent can manage other agents. | — | — |
| `can_read` | Check if agent has read permission. | — | — |
| `can_write` | Check if agent has write permission. | — | — |
| `complete_scan` | Mark a scan as completed. | — | — |
| `create_scan` | Create a vulnerability scan. | — | — |
| `deploy_patch` | Simulate patch deployment. | — | — |
| `generate_id` | Generate a unique ID with the given prefix (static version). | — | — |
| `get_agent_card` | Generate an A2A-compatible agent card describing this agent. | — | — |
| `get_asset_risk_profile` | Get risk profile for an asset. | — | — |
| `get_assets` | Get assets with filtering. | — | — |
| `get_overdue_vulnerabilities` | Get vulnerabilities past due date. | — | — |
| `get_patches` | Get patches with filtering. | — | — |
| `get_remediation_priority` | Get prioritized remediation list. | — | — |
| `get_scans` | Get scans with filtering. | — | — |
| `get_state` | Get agent state summary. | — | — |
| `get_status` | Get agent status. | — | — |
| `get_transparency_log` | Get the transparency log entries. | — | — |
| `get_vuln_metrics` | Get vulnerability management metrics. | — | — |
| `get_vulnerabilities` | Get vulnerabilities with filtering. | — | — |
| `input_guardrail` | Validate/sanitize input through guardrail pipeline. Returns (sanitized_prompt, is_safe). | — | — |
| `log` | Log an action for transparency. | — | — |
| `output_guardrail` | Validate/sanitize output through guardrail pipeline. Returns (sanitized_response, is_safe). | — | — |
| `perform_task` | Perform a task. Override in subclasses. | — | — |
| `process_message` | Process an incoming message. Override in subclasses. | — | — |
| `reason` | Iterative ReAct reasoning loop: think→act→observe. | — | — |
| `receive_message` | Receive a message from another agent. | — | — |
| `reflect` | Self-critique: evaluate response quality and suggest improvements. | — | — |
| `register_tool` | Register a tool with the agent. | — | — |
| `send_message` | Send a message to another agent. | — | — |
| `think` | Use LLM inference to reason about something. Optionally validate against a Pydantic model. | — | — |
| `tool_guardrail` | Check if tool call is permitted. Returns is_allowed. | — | — |
| `update_asset_vuln_count` | Update asset vulnerability count. | — | — |
| `update_vulnerability_status` | Update vulnerability status. | — | — |

**File**: `agentic_ai/agents/cyber/vulnman.py`

### RedTeam Agent (`redteam.py`)

**Purpose**: Red Team Agent for offensive security operations,

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `add_credential` | Add discovered credential. | — | — |
| `add_finding` | Add a security finding. | — | — |
| `add_service_to_target` | Add service to target. | — | — |
| `add_target` | Add a target to the engagement. | — | — |
| `add_target_to_engagement` | Add target to engagement. | — | — |
| `call_tool` | Call a tool by name with keyword arguments. | — | — |
| `can_create_project` | Check if agent can create projects. | — | — |
| `can_manage_agents` | Check if agent can manage other agents. | — | — |
| `can_read` | Check if agent has read permission. | — | — |
| `can_write` | Check if agent has write permission. | — | — |
| `create_attack_path` | Document an attack path. | — | — |
| `create_engagement` | Create a new engagement. | — | — |
| `execute_kali_full_engagement` | Execute full engagement using KaliAgent playbooks. | — | — |
| `execute_kali_password_audit` | Execute password cracking audit using KaliAgent. | — | — |
| `execute_kali_recon` | Execute reconnaissance using KaliAgent. | — | — |
| `execute_kali_web_audit` | Execute web application audit using KaliAgent. | — | — |
| `generate_engagement_report` | Generate engagement report. | — | — |
| `generate_id` | Generate a unique ID with the given prefix (static version). | — | — |
| `get_agent_card` | Generate an A2A-compatible agent card describing this agent. | — | — |
| `get_attack_paths` | Get attack paths with filtering. | — | — |
| `get_credentials` | Get credentials with filtering. | — | — |
| `get_engagements` | Get engagements with filtering. | — | — |
| `get_findings` | Get findings with filtering. | — | — |
| `get_state` | Get agent state summary. | — | — |
| `get_status` | Get agent status. | — | — |
| `get_targets` | Get targets with filtering. | — | — |
| `get_transparency_log` | Get the transparency log entries. | — | — |
| `input_guardrail` | Validate/sanitize input through guardrail pipeline. Returns (sanitized_prompt, is_safe). | — | — |
| `log` | Log an action for transparency. | — | — |
| `mark_finding_reported` | Mark finding as reported. | — | — |
| `mark_target_compromised` | Mark target as compromised. | — | — |
| `output_guardrail` | Validate/sanitize output through guardrail pipeline. Returns (sanitized_response, is_safe). | — | — |
| `perform_task` | Perform a task. Override in subclasses. | — | — |
| `process_message` | Process an incoming message. Override in subclasses. | — | — |
| `reason` | Iterative ReAct reasoning loop: think→act→observe. | — | — |
| `receive_message` | Receive a message from another agent. | — | — |
| `reflect` | Self-critique: evaluate response quality and suggest improvements. | — | — |
| `register_tool` | Register a tool with the agent. | — | — |
| `send_message` | Send a message to another agent. | — | — |
| `test_credential` | Test if credential is valid. | — | — |
| `think` | Use LLM inference to reason about something. Optionally validate against a Pydantic model. | — | — |
| `tool_guardrail` | Check if tool call is permitted. Returns is_allowed. | — | — |
| `update_engagement_status` | Update engagement status. | — | — |

**File**: `agentic_ai/agents/cyber/redteam.py`

### Malware Agent (`malware.py`)

**Purpose**: Malware Analysis Agent for reverse engineering,

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `add_analysis_results` | Add detailed analysis results. | — | — |
| `add_ioc` | Add indicator of compromise. | — | — |
| `add_ioc_to_campaign` | Add IOC to campaign. | — | — |
| `add_sample` | Add malware sample for analysis. | — | — |
| `add_sample_to_campaign` | Add sample to campaign. | — | — |
| `call_tool` | Call a tool by name with keyword arguments. | — | — |
| `can_create_project` | Check if agent can create projects. | — | — |
| `can_manage_agents` | Check if agent can manage other agents. | — | — |
| `can_read` | Check if agent has read permission. | — | — |
| `can_write` | Check if agent has write permission. | — | — |
| `complete_analysis` | Complete analysis with results. | — | — |
| `create_analysis` | Create malware analysis. | — | — |
| `create_campaign` | Create malware campaign. | — | — |
| `create_yara_rule` | Create YARA rule. | — | — |
| `generate_id` | Generate a unique ID with the given prefix (static version). | — | — |
| `generate_ioc_report` | Generate IOC report for malware family. | — | — |
| `get_agent_card` | Generate an A2A-compatible agent card describing this agent. | — | — |
| `get_analyses` | Get analyses with filtering. | — | — |
| `get_analysis_summary` | Get malware analysis summary. | — | — |
| `get_campaigns` | Get campaigns with filtering. | — | — |
| `get_iocs` | Get IOCs with filtering. | — | — |
| `get_sample` | Get sample by ID. | — | — |
| `get_sample_by_hash` | Get sample by hash (MD5, SHA1, or SHA256). | — | — |
| `get_sample_report` | Generate detailed sample report. | — | — |
| `get_similar_samples` | Find similar samples based on SSDEEP or characteristics. | — | — |
| `get_state` | Get agent state summary. | — | — |
| `get_status` | Get agent status. | — | — |
| `get_transparency_log` | Get the transparency log entries. | — | — |
| `get_yara_rules` | Get YARA rules with filtering. | — | — |
| `identify_malware_family` | Identify malware family based on analysis. | — | — |
| `input_guardrail` | Validate/sanitize input through guardrail pipeline. Returns (sanitized_prompt, is_safe). | — | — |
| `log` | Log an action for transparency. | — | — |
| `mark_ioc_false_positive` | Mark IOC as false positive. | — | — |
| `output_guardrail` | Validate/sanitize output through guardrail pipeline. Returns (sanitized_response, is_safe). | — | — |
| `perform_task` | Perform a task. Override in subclasses. | — | — |
| `process_message` | Process an incoming message. Override in subclasses. | — | — |
| `reason` | Iterative ReAct reasoning loop: think→act→observe. | — | — |
| `receive_message` | Receive a message from another agent. | — | — |
| `reflect` | Self-critique: evaluate response quality and suggest improvements. | — | — |
| `register_tool` | Register a tool with the agent. | — | — |
| `send_message` | Send a message to another agent. | — | — |
| `start_analysis` | Start analysis. | — | — |
| `think` | Use LLM inference to reason about something. Optionally validate against a Pydantic model. | — | — |
| `tool_guardrail` | Check if tool call is permitted. Returns is_allowed. | — | — |
| `update_yara_rule` | Update YARA rule. | — | — |

**File**: `agentic_ai/agents/cyber/malware.py`

### CloudSecurity Agent (`cloud_security.py`)

**Purpose**: Cloud Security Agent for CSPM, compliance checking,

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `add_account` | Add cloud account for monitoring. | — | — |
| `add_resource` | Add cloud resource for monitoring. | — | — |
| `call_tool` | Call a tool by name with keyword arguments. | — | — |
| `can_create_project` | Check if agent can create projects. | — | — |
| `can_manage_agents` | Check if agent can manage other agents. | — | — |
| `can_read` | Check if agent has read permission. | — | — |
| `can_write` | Check if agent has write permission. | — | — |
| `check_resource_compliance` | Check resource against policies. | — | — |
| `create_finding` | Create security finding. | — | — |
| `create_policy` | Create custom security policy. | — | — |
| `create_remediation` | Create remediation action. | — | — |
| `execute_remediation` | Mark remediation as executed. | — | — |
| `generate_id` | Generate a unique ID with the given prefix (static version). | — | — |
| `get_account_risk_profile` | Get risk profile for a cloud account. | — | — |
| `get_accounts` | Get accounts with filtering. | — | — |
| `get_agent_card` | Generate an A2A-compatible agent card describing this agent. | — | — |
| `get_cloud_security_report` | Generate cloud security report. | — | — |
| `get_compliance_score` | Calculate compliance score for a framework. | — | — |
| `get_findings` | Get findings with filtering. | — | — |
| `get_policies` | Get policies with filtering. | — | — |
| `get_resources` | Get resources with filtering. | — | — |
| `get_state` | Get agent state summary. | — | — |
| `get_status` | Get agent status. | — | — |
| `get_transparency_log` | Get the transparency log entries. | — | — |
| `input_guardrail` | Validate/sanitize input through guardrail pipeline. Returns (sanitized_prompt, is_safe). | — | — |
| `log` | Log an action for transparency. | — | — |
| `output_guardrail` | Validate/sanitize output through guardrail pipeline. Returns (sanitized_response, is_safe). | — | — |
| `perform_task` | Perform a task. Override in subclasses. | — | — |
| `process_message` | Process an incoming message. Override in subclasses. | — | — |
| `reason` | Iterative ReAct reasoning loop: think→act→observe. | — | — |
| `receive_message` | Receive a message from another agent. | — | — |
| `reflect` | Self-critique: evaluate response quality and suggest improvements. | — | — |
| `register_tool` | Register a tool with the agent. | — | — |
| `send_message` | Send a message to another agent. | — | — |
| `think` | Use LLM inference to reason about something. Optionally validate against a Pydantic model. | — | — |
| `tool_guardrail` | Check if tool call is permitted. Returns is_allowed. | — | — |
| `update_account_scan` | Update account scan results. | — | — |
| `update_finding_status` | Update finding status. | — | — |

**File**: `agentic_ai/agents/cloud_security.py`

### Kali Agent (`kali.py`)

**Purpose**: Kali Linux Tool Orchestration Agent

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `ad_command_catalog` | The per-step command catalog (target/dc injected). | — | — |
| `ad_detection_notes` | The blue-team pairing (TTP-level notes). | — | — |
| `ad_index` | The module's own shapes (a stable API for the composer). | — | — |
| `add_to_blacklist` | Add IP to blacklist (always blocked). | — | — |
| `aging_exploit_queue` | Unpatched finding ages x exploit availability -> the priority queue (fleet flag). | — | — |
| `aircrack_crack` | WiFi password cracking. | — | — |
| `amass_enum` | Subdomain enumeration with Amass. | — | — |
| `analyzer_catalog` | The analyzer/flow INDEX; cls filters; unknown classes refuse. | — | — |
| `analyzer_lookup` | One catalog row by id (case-insensitive); a miss = found:False. | — | — |
| `api_auth_surface_catalog` | Auth-surface rows (surface / check / detection) for the style. | — | — |
| `api_index` | api index | — | — |
| `api_policy` | api policy | — | — |
| `api_step_catalog` | Per-style discovery/enum command steps (target-free templates). | — | — |
| `api_vuln_classes` | The per-style vuln-class name list. | — | — |
| `api_vuln_commands` | Per-style per-class SAFE command sets for the scrubbed target. | — | — |
| `attach_consent` | Attach an owner-signed consent record (KA-060; KA-INT-4). | — | — |
| `audit_config` | Offline scan of a config text against the vendor's rule rows. | — | — |
| `authorize_tool` | RBAC role consult against the tool DB | `tool_name, role` | `(bool, reason)` |
| `binwalk_analyze` | Firmware analysis. | — | — |
| `bloodhound_collect` | Active Directory reconnaissance. | — | — |
| `build_threat_brief` | Newsroom feed -> the daily security threat brief (fleet flag). | — | — |
| `call_tool` | Call a tool by name with keyword arguments. | — | — |
| `can_create_project` | Check if agent can create projects. | — | — |
| `can_manage_agents` | Check if agent can manage other agents. | — | — |
| `can_read` | Check if agent has read permission. | — | — |
| `can_write` | Check if agent has write permission. | — | — |
| `cewl_generate` | Custom wordlist generator. | — | — |
| `channel_measurement` | The metric rows per channel (None = the overview). | — | — |
| `check_authorization` | Check if tool execution is authorized. | — | — |
| `classify_postexp_command` | Classify one command as evidence or as a forbidden mutation class. | — | — |
| `clear_ip_whitelist` | Clear IP whitelist. | — | — |
| `cloud_detection_notes` | cloud detection notes | — | — |
| `cloud_index` | cloud index | — | — |
| `compose_battery_notification` | Battery completion -> the composed dry-mode owner mail (fleet flag). | — | — |
| `compose_report_email` | Engagement report -> the composed dry-mode email dict (fleet flag). | — | — |
| `config_audit_rules` | The vendor's curated config-audit rule rows (None lists the | — | — |
| `connect_metasploit` | Connect to Metasploit RPC. | — | — |
| `container_index` | container index | — | — |
| `container_tool_catalog` | container tool catalog | — | — |
| `contract_nets` | The exact lab/testnet vocabulary vs the refused mainnet labels. | — | — |
| `contract_policy` | The hard policy rows behind every planning op. | — | — |
| `create_evidence_bundle` | Evidence bundle: tar + manifest + sha256 | `source_dir, out_path, engagement_id` | `bundle: dict` |
| `crunch_generate` | Wordlist generator. | — | — |
| `device_enum_catalog` | The per-kind enum command set (None lists the kinds). | — | — |
| `device_index` | The kind/vendor list + the lab policy rows. | — | — |
| `dirb_scan` | Web content scanner. | — | — |
| `disable_audit_logging` | Disable audit logging. | — | — |
| `disable_dry_run` | Disable dry-run mode. | — | — |
| `disable_safe_mode` | Disable safe mode (allows system changes). | — | — |
| `disconnect_metasploit` | Disconnect from Metasploit RPC. | — | — |
| `dnsrecon_scan` | DNS enumeration. | — | — |
| `enable_audit_logging` | Enable audit logging for all executions. | — | — |
| `enable_dry_run` | Enable dry-run mode (commands logged but not executed). | — | — |
| `enable_safe_mode` | Enable safe mode (read-only operations). | — | — |
| `execute_metasploit_exploit` | Execute a Metasploit exploit. | — | — |
| `execute_tool` | Execute a Kali Linux tool. | — | — |
| `ffuf_fuzz` | Fast web fuzzer. | — | — |
| `finding_class_catalog` | The finding taxonomy with its catalog pairing (id namespace " | — | — |
| `firmware_flow` | The 6-phase static firmware flow; refuses non-lab staging. | — | — |
| `firmware_step_catalog` | The raw firmware templates (placeholders kept for reuse). | — | — |
| `forensics_index` | forensics index | — | — |
| `forensics_policy` | forensics policy | — | — |
| `forensics_step_catalog` | forensics step catalog | — | — |
| `full_engagement_index` | The composition contract as data (stage order, per-stage | — | — |
| `generate_id` | Generate a unique ID with the given prefix (static version). | — | — |
| `generate_playbook_report` | Generate playbook execution report. | — | — |
| `generate_report` | Generate execution report. | — | — |
| `get_agent_card` | Generate an A2A-compatible agent card describing this agent. | — | — |
| `get_execution_history` | Get execution history with filtering. | — | — |
| `get_metasploit_modules` | Get available Metasploit modules. | — | — |
| `get_metasploit_sessions` | Get active Metasploit sessions. | — | — |
| `get_status` | Get agent status. | — | — |
| `get_tool_info` | Get detailed tool information. | — | — |
| `get_transparency_log` | Get the transparency log entries. | — | — |
| `gobuster_scan` | Directory/DNS brute-force with Gobuster. | — | — |
| `hydra_bruteforce` | Brute force login with Hydra. | — | — |
| `iam_blast_radius_checklist` | iam blast radius checklist | — | — |
| `ics_iot_detection_notes` | The blue-team pairing (TTP-level notes). | — | — |
| `ics_iot_index` | The module's own shapes (a stable API for the composer). | — | — |
| `input_guardrail` | Validate/sanitize input through guardrail pipeline. Returns (sanitized_prompt, is_safe). | — | — |
| `john_crack` | Crack passwords with John the Ripper. | — | — |
| `joomscan_scan` | Joomla vulnerability scanner. | — | — |
| `jwt_analysis` | Decoded-claims structural analysis (no key material; no decoding). | — | — |
| `k8s_rbac_checklist` | k8s rbac checklist | — | — |
| `kevstig_fan_out` | kevstig coverage -> recommendations | `coverage: dict` | `report: dict` |
| `list_tools` | List available tools. | — | — |
| `log` | Log an action for transparency. | — | — |
| `malware_index` | The kinds + policy + gate summary. | — | — |
| `malware_policy` | The policy rows the malware arc carries. | — | — |
| `medusa_bruteforce` | Parallel brute forcer. | — | — |
| `metasploit_session_command` | Execute command in Metasploit session. | — | — |
| `mobile_detection_notes` | mobile detection notes | — | — |
| `mobile_index` | mobile index | — | — |
| `nikto_scan` | Perform Nikto web server scan. | — | — |
| `nmap_scan` | Perform Nmap network scan. | — | — |
| `oauth_flow_catalog` | OAuth grant method catalog; None returns the flow list. | — | — |
| `oauth_grant_assessment` | Assessment arc rows for one OAuth grant flow. | — | — |
| `osint_detection_notes` | osint detection notes | — | — |
| `osint_index` | osint index | — | — |
| `osint_step_catalog` | osint step catalog | — | — |
| `output_guardrail` | Validate/sanitize output through guardrail pipeline. Returns (sanitized_response, is_safe). | — | — |
| `perform_task` | Perform a task. Override in subclasses. | — | — |
| `plan_ad` | 6-phase lab-only AD assessment plan | `scope: str` | `plan: dict` |
| `plan_analyzer_sweep` | Ordered per-tool runsheet for the lab; tools default to the | — | — |
| `plan_api` | REST/GraphQL methodology arcs + auth-surface catalogs | `target, style` | `plan: dict` |
| `plan_cloud` | Per-cloud sandbox-account plan + IAM blast radius | `target, cloud` | `plan: dict` |
| `plan_container_escape` | Container escape-surface planner + RBAC/tool catalogs | `target` | `plan: dict` |
| `plan_contract_audit` | Testnet-only contract audit arc + analyzer sweep | `target, net` | `plan: dict` |
| `plan_detonation` | Detonation plan; refuses without a sandbox record | `sample_label, sandbox` | `plan/refusal` |
| `plan_device_audit` | Lab-only device audit plan + offline config audit | `device_label, kind` | `plan: dict` |
| `plan_engagement_tickets` | Unresolved engagement findings -> soc-tickets open payloads (fleet flag). | — | — |
| `plan_finding_triage` | Map raw finding ids onto the taxonomy; unknown labels come " | — | — |
| `plan_forensics` | Analyst arcs per kind + evidence handling | `target, kind` | `plan: dict` |
| `plan_full_engagement` | Composes recon -> web -> xss -> privesc (+ extension lanes) | `target, platform` | `plan: dict` |
| `plan_impersonation_exercise` | The consent-gated impersonation SIMULATION plan - coarse | — | — |
| `plan_mobile_apk` | APK static-first planner (IPA sibling op) | `path, ...` | `plan: dict` |
| `plan_mobile_ipa` | plan mobile ipa | — | — |
| `plan_modbus` | Modbus TCP/RTU read-only arc (S7 + firmware siblings) | `target_label, staging` | `plan: dict` |
| `plan_osint` | Per-lane OSINT planners (domain/email/persona) | `lane, ...` | `plan: dict` |
| `plan_phishing_simulation` | Consent-gated simulation plan (impersonation sibling op) | `consent, audience_label` | `plan: dict` |
| `plan_postexp` | Evidence-only post-exploitation arcs + mutation gate | `target, arc` | `plan: dict` |
| `plan_privesc` | 6-phase escalation plan + capability index | `target, platform` | `plan: dict` |
| `plan_redteam` | 13-phase red-team arc | `scope: str` | `plan: dict` |
| `plan_remediation_tickets` | Failed lab verifications -> SOC remediation ticket plan (fleet flag). | — | — |
| `plan_s7` | The 6-phase read-only S7comm plan; refuses non-lab staging. | — | — |
| `plan_static` | Static-first malware analysis arc (4 sample kinds) | `sample_label, kind` | `plan: dict` |
| `plan_web_pentest` | 8-phase web engagement plan | `target: str` | `plan: dict` |
| `plan_webauth` | SSO/OAuth/JWT methodology arc (decoded-only) | `target` | `plan: dict` |
| `plan_wireless_capture` | Monitor-mode capture planner + rogue-AP play | `target, ...` | `plan: dict` |
| `plan_xss_exploit` | 7-phase XSS methodology | `target: str` | `plan: dict` |
| `postexp_arcs` | The planning arcs with their audit/report modes (no execution). | — | — |
| `postexp_credential_classes` | Credential-access class discovery rows (locations only, never | — | — |
| `postexp_gate` | Gate a plan dict: refuse every mutation-class command, allow | — | — |
| `postexp_policy` | The evidence-only policy rows plus the enforced mutation classes. | — | — |
| `postexp_step_catalog` | Per-arc read-only enumeration steps; None returns the arc list. | — | — |
| `privesc_capability_lookup` | Index rows for a binary name (case-insensitive; optional | — | — |
| `privesc_index` | Load the committed capability index. | — | — |
| `process_message` | Process an incoming message. Override in subclasses. | — | — |
| `protocol_command_catalog` | The per-protocol read-only command rows (values injected). | — | — |
| `push_soc_memories` | Engagement summaries -> tenant SOC memory records (fleet flag). | — | — |
| `reason` | Iterative ReAct reasoning loop: think→act→observe. | — | — |
| `reaver_attack` | WPS brute force attack. | — | — |
| `receive_message` | Receive a message from another agent. | — | — |
| `redteam_catalog` | Load the generated red-team tool catalog (13 phases, ~725 tools). | — | — |
| `redteam_countermeasures` | Detection/countermeasure notes for a phase (the blue-team pairing). | — | — |
| `redteam_phase_tools` | Every tool cataloged under a phase (name, url, purpose, origin | — | — |
| `redteam_tool_lookup` | Search the whole catalog by tool-name fragment (max 25 hits). | — | — |
| `reflect` | Self-critique: evaluate response quality and suggest improvements. | — | — |
| `register_tool` | Register a tool with the agent. | — | — |
| `remove_from_blacklist` | Remove IP from blacklist. | — | — |
| `revoke_authorization` | Revoke authorization. | — | — |
| `rogue_ap_playbook` | The rogue-AP play (lab-RF-tagged; consent noted in phase 1). | — | — |
| `role_allows_dry_run` | Planning/inspection is unrestricted for every role (KA-051). | — | — |
| `run_ad_audit_playbook` | Run Active Directory audit playbook. | — | — |
| `run_password_audit_playbook` | Run password cracking playbook. | — | — |
| `run_recon_playbook` | Run comprehensive reconnaissance playbook. | — | — |
| `run_web_audit_playbook` | Run web application audit playbook. | — | — |
| `run_wireless_audit_playbook` | Run wireless security audit playbook. | — | — |
| `safety_gate_chain` | Run the composed P4 gate chain (KA-INT-4) for one planned | — | — |
| `searchsploit_search` | Search Exploit Database. | — | — |
| `send_message` | Send a message to another agent. | — | — |
| `set_authorization` | Set authorization level for tool execution. | — | — |
| `set_ip_whitelist` | Set IP whitelist (only these targets allowed). | — | — |
| `soc_watch_pairing` | The SOC watch rows per exercise (None = the overview). | — | — |
| `socialeng_index` | The overview: exercises, channels, scenarios + the policy. | — | — |
| `socialeng_policy` | The lab-only policy rows (the consent gate included). | — | — |
| `sqlmap_scan` | Perform SQLMap SQL injection scan. | — | — |
| `static_step_catalog` | The per-kind raw static analyst templates (placeholders intact); | — | — |
| `subfinder_scan` | Subdomain discovery. | — | — |
| `testnet_gate` | Validate a lab/testnet designation (+ optional target) through | — | — |
| `theharvester_scan` | Email and subdomain harvesting. | — | — |
| `think` | Use LLM inference to reason about something. Optionally validate against a Pydantic model. | — | — |
| `tool_guardrail` | Check if tool call is permitted. Returns is_allowed. | — | — |
| `validate_target` | Validate target against whitelist/blacklist. | — | — |
| `verify_evidence_bundle` | Wrap KA-082's verifier. | — | — |
| `verify_laya_decisions` | Independent double-check of laya's escalated decisions (fleet flag). | — | — |
| `verify_soc_findings` | SOC findings -> verification plans | `findings: list` | `plan: dict` |
| `volatility_analyze` | Memory forensics. | — | — |
| `web_enum_commands` | Enumeration command catalog for a target, grouped by step. | — | — |
| `web_pentest_report_outline` | Report scaffold; findings is an optional list of dicts | — | — |
| `web_recon_commands` | Reconnaissance command catalog for a target, grouped by step. | — | — |
| `web_vuln_commands` | Per-vulnerability-class command sets; None returns the class list. | — | — |
| `webauth_index` | Flow, protocol, and policy summary for the WebAuth surface. | — | — |
| `webauth_policy` | The WebAuth policy rows every op result carries. | — | — |
| `webauth_redirect_checks` | Structural redirect-URI validation rows plus the general checks. | — | — |
| `webauth_sso_surface` | SSO handshake checks for a protocol; None returns the list. | — | — |
| `webauth_token_storage` | Token storage position checklist plus the SOC pairings. | — | — |
| `wireless_detection_notes` | wireless detection notes | — | — |
| `wireless_index` | wireless index | — | — |
| `wpscan_scan` | WordPress security scan. | — | — |
| `xss_callback_commands` | OOB/callback infrastructure commands for a callback host name. | — | — |
| `xss_catalog` | Load the generated XSS tooling catalog (5 phases, 15 tools). | — | — |
| `xss_countermeasures` | Prevention + detection pairing for the blue team. | — | — |
| `xss_filter_strategy` | Filter/CSP evasion STRATEGY classes with in-house notes | — | — |
| `xss_tool_lookup` | Search the whole catalog by tool-name fragment (max 25 hits). | — | — |

**File**: `agentic_ai/agents/cyber/kali.py`

### Kali Agent V2 (`kali_v2.py`)

**Purpose**: Enhanced KaliAgent with modern tools and intelligent features.

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `ad_command_catalog` | The per-step command catalog (target/dc injected). | — | — |
| `ad_detection_notes` | The blue-team pairing (TTP-level notes). | — | — |
| `ad_index` | The module's own shapes (a stable API for the composer). | — | — |
| `aging_exploit_queue` | Unpatched finding ages x exploit availability -> the priority queue (fleet flag). | — | — |
| `analyzer_catalog` | The analyzer/flow INDEX; cls filters; unknown classes refuse. | — | — |
| `analyzer_lookup` | One catalog row by id (case-insensitive); a miss = found:False. | — | — |
| `api_auth_surface_catalog` | Auth-surface rows (surface / check / detection) for the style. | — | — |
| `api_index` | api index | — | — |
| `api_policy` | api policy | — | — |
| `api_step_catalog` | Per-style discovery/enum command steps (target-free templates). | — | — |
| `api_vuln_classes` | The per-style vuln-class name list. | — | — |
| `api_vuln_commands` | Per-style per-class SAFE command sets for the scrubbed target. | — | — |
| `attach_consent` | Attach an owner-signed consent record (KA-060; KA-INT-4). | — | — |
| `audit_config` | Offline scan of a config text against the vendor's rule rows. | — | — |
| `authorize_tool` | RBAC role consult against the tool DB | `tool_name, role` | `(bool, reason)` |
| `build_threat_brief` | Newsroom feed -> the daily security threat brief (fleet flag). | — | — |
| `channel_measurement` | The metric rows per channel (None = the overview). | — | — |
| `check_authorization` | Level check for a tool | `tool_name: str` | `(bool, reason)` |
| `classify_postexp_command` | Classify one command as evidence or as a forbidden mutation class. | — | — |
| `cloud_detection_notes` | cloud detection notes | — | — |
| `cloud_index` | cloud index | — | — |
| `compose_battery_notification` | Battery completion -> the composed dry-mode owner mail (fleet flag). | — | — |
| `compose_report_email` | Engagement report -> the composed dry-mode email dict (fleet flag). | — | — |
| `config_audit_rules` | The vendor's curated config-audit rule rows (None lists the | — | — |
| `container_index` | container index | — | — |
| `container_tool_catalog` | container tool catalog | — | — |
| `contract_nets` | The exact lab/testnet vocabulary vs the refused mainnet labels. | — | — |
| `contract_policy` | The hard policy rows behind every planning op. | — | — |
| `create_evidence_bundle` | Evidence bundle (engagement explicit) | `source_dir, out_path, engagement_id` | `bundle: dict` |
| `device_enum_catalog` | The per-kind enum command set (None lists the kinds). | — | — |
| `device_index` | The kind/vendor list + the lab policy rows. | — | — |
| `disable_dry_run` | Disable dry-run mode. | — | — |
| `enable_dry_run` | Enable dry-run mode. | — | — |
| `finding_class_catalog` | The finding taxonomy with its catalog pairing (id namespace " | — | — |
| `firmware_flow` | The 6-phase static firmware flow; refuses non-lab staging. | — | — |
| `firmware_step_catalog` | The raw firmware templates (placeholders kept for reuse). | — | — |
| `forensics_index` | forensics index | — | — |
| `forensics_policy` | forensics policy | — | — |
| `forensics_step_catalog` | forensics step catalog | — | — |
| `full_engagement_index` | The composition contract as data (stage order, per-stage | — | — |
| `generate_remediation_plan` | Remediation plan for findings | `findings: list` | `plan: dict` |
| `get_state` | Get agent state. | — | — |
| `iam_blast_radius_checklist` | iam blast radius checklist | — | — |
| `ics_iot_detection_notes` | The blue-team pairing (TTP-level notes). | — | — |
| `ics_iot_index` | The module's own shapes (a stable API for the composer). | — | — |
| `jwt_analysis` | Decoded-claims structural analysis (no key material; no decoding). | — | — |
| `k8s_rbac_checklist` | k8s rbac checklist | — | — |
| `kevstig_fan_out` | kevstig coverage -> recommendations | `coverage: dict` | `report: dict` |
| `list_tools` | List available tools. | — | — |
| `malware_index` | The kinds + policy + gate summary. | — | — |
| `malware_policy` | The policy rows the malware arc carries. | — | — |
| `match_exploits_for_cve` | Find exploits for a CVE | `cve_id: str` | `match: dict` |
| `mobile_detection_notes` | mobile detection notes | — | — |
| `mobile_index` | mobile index | — | — |
| `oauth_flow_catalog` | OAuth grant method catalog; None returns the flow list. | — | — |
| `oauth_grant_assessment` | Assessment arc rows for one OAuth grant flow. | — | — |
| `osint_detection_notes` | osint detection notes | — | — |
| `osint_index` | osint index | — | — |
| `osint_step_catalog` | osint step catalog | — | — |
| `plan_ad` | 6-phase lab-only AD assessment plan | `scope: str` | `plan: dict` |
| `plan_analyzer_sweep` | Ordered per-tool runsheet for the lab; tools default to the | — | — |
| `plan_api` | REST/GraphQL methodology arcs + auth-surface catalogs | `target, style` | `plan: dict` |
| `plan_cloud` | Per-cloud sandbox-account plan + IAM blast radius | `target, cloud` | `plan: dict` |
| `plan_container_escape` | Container escape-surface planner + RBAC/tool catalogs | `target` | `plan: dict` |
| `plan_contract_audit` | Testnet-only contract audit arc + analyzer sweep | `target, net` | `plan: dict` |
| `plan_detonation` | Detonation plan; refuses without a sandbox record | `sample_label, sandbox` | `plan/refusal` |
| `plan_device_audit` | Lab-only device audit plan + offline config audit | `device_label, kind` | `plan: dict` |
| `plan_engagement_tickets` | Unresolved engagement findings -> soc-tickets open payloads (fleet flag). | — | — |
| `plan_finding_triage` | Map raw finding ids onto the taxonomy; unknown labels come " | — | — |
| `plan_forensics` | Analyst arcs per kind + evidence handling | `target, kind` | `plan: dict` |
| `plan_full_engagement` | Composes recon -> web -> xss -> privesc (+ extension lanes) | `target, platform` | `plan: dict` |
| `plan_impersonation_exercise` | The consent-gated impersonation SIMULATION plan - coarse | — | — |
| `plan_mobile_apk` | APK static-first planner (IPA sibling op) | `path, ...` | `plan: dict` |
| `plan_mobile_ipa` | plan mobile ipa | — | — |
| `plan_modbus` | Modbus TCP/RTU read-only arc (S7 + firmware siblings) | `target_label, staging` | `plan: dict` |
| `plan_osint` | Per-lane OSINT planners (domain/email/persona) | `lane, ...` | `plan: dict` |
| `plan_phishing_simulation` | Consent-gated simulation plan (impersonation sibling op) | `consent, audience_label` | `plan: dict` |
| `plan_postexp` | Evidence-only post-exploitation arcs + mutation gate | `target, arc` | `plan: dict` |
| `plan_privesc` | 6-phase escalation plan + capability index | `target, platform` | `plan: dict` |
| `plan_redteam` | The red-team phase arc for a scope: goal, tool count, and example | — | — |
| `plan_remediation_tickets` | Failed lab verifications -> SOC remediation ticket plan (fleet flag). | — | — |
| `plan_s7` | The 6-phase read-only S7comm plan; refuses non-lab staging. | — | — |
| `plan_static` | Static-first malware analysis arc (4 sample kinds) | `sample_label, kind` | `plan: dict` |
| `plan_web_pentest` | Return the 12-phase engagement plan for a target. | — | — |
| `plan_webauth` | SSO/OAuth/JWT methodology arc (decoded-only) | `target` | `plan: dict` |
| `plan_wireless_capture` | Monitor-mode capture planner + rogue-AP play | `target, ...` | `plan: dict` |
| `plan_xss_exploit` | The 7-phase XSS methodology plan for a target. | — | — |
| `postexp_arcs` | The planning arcs with their audit/report modes (no execution). | — | — |
| `postexp_credential_classes` | Credential-access class discovery rows (locations only, never | — | — |
| `postexp_gate` | Gate a plan dict: refuse every mutation-class command, allow | — | — |
| `postexp_policy` | The evidence-only policy rows plus the enforced mutation classes. | — | — |
| `postexp_step_catalog` | Per-arc read-only enumeration steps; None returns the arc list. | — | — |
| `privesc_capability_lookup` | Index rows for a binary name (case-insensitive; optional | — | — |
| `privesc_index` | Load the committed capability index. | — | — |
| `protocol_command_catalog` | The per-protocol read-only command rows (values injected). | — | — |
| `push_soc_memories` | Engagement summaries -> tenant SOC memory records (fleet flag). | — | — |
| `recommend_tools_for_target` | Get tool recommendations for a target. | — | — |
| `redteam_catalog` | Load the generated red-team tool catalog (13 phases, ~725 tools). | — | — |
| `redteam_countermeasures` | Detection/countermeasure notes for a phase (the blue-team pairing). | — | — |
| `redteam_phase_tools` | Every tool cataloged under a phase (name, url, purpose, origin | — | — |
| `redteam_tool_lookup` | Search the whole catalog by tool-name fragment (max 25 hits). | — | — |
| `rogue_ap_playbook` | The rogue-AP play (lab-RF-tagged; consent noted in phase 1). | — | — |
| `role_allows_dry_run` | Planning/inspection is unrestricted for every role (KA-051). | — | — |
| `safety_gate_chain` | Run the composed P4 gate chain (KA-INT-4) for one planned | — | — |
| `set_authorization` | Set authorization level. | — | — |
| `soc_watch_pairing` | The SOC watch rows per exercise (None = the overview). | — | — |
| `socialeng_index` | The overview: exercises, channels, scenarios + the policy. | — | — |
| `socialeng_policy` | The lab-only policy rows (the consent gate included). | — | — |
| `static_step_catalog` | The per-kind raw static analyst templates (placeholders intact); | — | — |
| `testnet_gate` | Validate a lab/testnet designation (+ optional target) through | — | — |
| `verify_evidence_bundle` | Wrap KA-082's verifier. | — | — |
| `verify_laya_decisions` | Independent double-check of laya's escalated decisions (fleet flag). | — | — |
| `verify_soc_findings` | SOC findings -> verification plans | `findings: list` | `plan: dict` |
| `web_enum_commands` | Enumeration command catalog for a target, grouped by step. | — | — |
| `web_pentest_report_outline` | Report scaffold; findings is an optional list of dicts | — | — |
| `web_recon_commands` | Reconnaissance command catalog for a target, grouped by step. | — | — |
| `web_vuln_commands` | Per-vulnerability-class command sets; None returns the class list. | — | — |
| `webauth_index` | Flow, protocol, and policy summary for the WebAuth surface. | — | — |
| `webauth_policy` | The WebAuth policy rows every op result carries. | — | — |
| `webauth_redirect_checks` | Structural redirect-URI validation rows plus the general checks. | — | — |
| `webauth_sso_surface` | SSO handshake checks for a protocol; None returns the list. | — | — |
| `webauth_token_storage` | Token storage position checklist plus the SOC pairings. | — | — |
| `wireless_detection_notes` | wireless detection notes | — | — |
| `wireless_index` | wireless index | — | — |
| `xss_callback_commands` | OOB/callback infrastructure commands for a callback host name. | — | — |
| `xss_catalog` | Load the generated XSS tooling catalog (5 phases, 15 tools). | — | — |
| `xss_countermeasures` | Prevention + detection pairing for the blue team. | — | — |
| `xss_filter_strategy` | Filter/CSP evasion STRATEGY classes with in-house notes | — | — |
| `xss_tool_lookup` | Search the whole catalog by tool-name fragment (max 25 hits). | — | — |

**File**: `agentic_ai/agents/cyber/kali_v2.py`

### Biblical Scholar Agent (`biblical_scholar.py`)

**Purpose**: Biblical Scholar Agent for religious text analysis,

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `add_text` | Add a religious text to the database. | — | — |
| `analyze_quote` | Analyze a religious quote for meaning, source, and significance. | — | — |
| `compare_concept` | Compare how a concept is understood across religions. | — | — |
| `get_comparative_study` | Get comparative study by ID. | — | — |
| `get_quote_analysis` | Get quote analysis by ID. | — | — |
| `get_random_text` | Get a random religious text. | — | — |
| `get_research` | Get research query by ID. | — | — |
| `get_state` | Get agent state summary. | — | — |
| `get_text` | Get text by ID. | — | — |
| `get_texts_by_religion` | Get all texts for a specific religion. | — | — |
| `get_texts_by_type` | Get all texts of a specific type. | — | — |
| `research_question` | Research a theological or biblical question. | — | — |
| `search_texts` | Search texts by content, title, or keywords. | — | — |

**File**: `agentic_ai/agents/biblical_scholar.py`

### MLOps Agent (`ml_ops.py`)

**Purpose**: MLOps Agent for ML lifecycle management,

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `call_tool` | Call a tool by name with keyword arguments. | — | — |
| `can_create_project` | Check if agent can create projects. | — | — |
| `can_manage_agents` | Check if agent can manage other agents. | — | — |
| `can_read` | Check if agent has read permission. | — | — |
| `can_write` | Check if agent has write permission. | — | — |
| `check_model_metrics` | Check metrics against thresholds and create alerts. | — | — |
| `complete_experiment` | Complete experiment with results. | — | — |
| `create_alert` | Create model alert. | — | — |
| `create_experiment` | Create ML experiment. | — | — |
| `create_monitor` | Create model monitor. | — | — |
| `deploy_model` | Deploy model | `model: str, environment: str` | `deployment: Deployment` |
| `generate_id` | Generate a unique ID with the given prefix (static version). | — | — |
| `get_agent_card` | Generate an A2A-compatible agent card describing this agent. | — | — |
| `get_alerts` | Get alerts with filtering. | — | — |
| `get_datasets` | Get datasets with filtering. | — | — |
| `get_deployments` | Get deployments with filtering. | — | — |
| `get_experiments` | Get experiments with filtering. | — | — |
| `get_mlops_dashboard` | Generate MLOps dashboard. | — | — |
| `get_model_performance` | Get model performance report. | — | — |
| `get_models` | Get models with filtering. | — | — |
| `get_state` | Get agent state summary. | — | — |
| `get_status` | Get agent status. | — | — |
| `get_transparency_log` | Get the transparency log entries. | — | — |
| `input_guardrail` | Validate/sanitize input through guardrail pipeline. Returns (sanitized_prompt, is_safe). | — | — |
| `log` | Log an action for transparency. | — | — |
| `output_guardrail` | Validate/sanitize output through guardrail pipeline. Returns (sanitized_response, is_safe). | — | — |
| `perform_task` | Perform a task. Override in subclasses. | — | — |
| `process_message` | Process an incoming message. Override in subclasses. | — | — |
| `reason` | Iterative ReAct reasoning loop: think→act→observe. | — | — |
| `receive_message` | Receive a message from another agent. | — | — |
| `reflect` | Self-critique: evaluate response quality and suggest improvements. | — | — |
| `register_dataset` | Register a dataset. | — | — |
| `register_model` | Register model in registry. | — | — |
| `register_tool` | Register a tool with the agent. | — | — |
| `resolve_alert` | Resolve alert. | — | — |
| `send_message` | Send a message to another agent. | — | — |
| `start_experiment` | Start experiment. | — | — |
| `think` | Use LLM inference to reason about something. Optionally validate against a Pydantic model. | — | — |
| `tool_guardrail` | Check if tool call is permitted. Returns is_allowed. | — | — |
| `update_deployment_status` | Update deployment status. | — | — |
| `update_model_stage` | Update model stage. | — | — |

**File**: `agentic_ai/agents/ml_ops.py`

### SupplyChain Agent (`supply_chain.py`)

**Purpose**: Supply Chain Agent for SBOM management, dependency tracking,

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `add_package` | Add package to inventory. | — | — |
| `add_vendor` | Add vendor to registry. | — | — |
| `add_vulnerability` | Add vulnerability for a package. | — | — |
| `analyze_sbom` | Analyze SBOM for vulnerabilities. | — | — |
| `calculate_vendor_risk` | Calculate vendor risk score. | — | — |
| `call_tool` | Call a tool by name with keyword arguments. | — | — |
| `can_create_project` | Check if agent can create projects. | — | — |
| `can_manage_agents` | Check if agent can manage other agents. | — | — |
| `can_read` | Check if agent has read permission. | — | — |
| `can_write` | Check if agent has write permission. | — | — |
| `complete_assessment` | Complete vendor assessment. | — | — |
| `create_assessment` | Create vendor assessment. | — | — |
| `create_sbom` | Create SBOM for a project. | — | — |
| `generate_id` | Generate a unique ID with the given prefix (static version). | — | — |
| `get_agent_card` | Generate an A2A-compatible agent card describing this agent. | — | — |
| `get_assessments` | Get assessments with filtering. | — | — |
| `get_dependency_tree` | Get dependency tree for a package. | — | — |
| `get_incidents` | Get incidents with filtering. | — | — |
| `get_packages` | Get packages with filtering. | — | — |
| `get_sboms` | Get SBOMs with filtering. | — | — |
| `get_state` | Get agent state summary. | — | — |
| `get_status` | Get agent status. | — | — |
| `get_supply_chain_report` | Generate supply chain security report. | — | — |
| `get_transparency_log` | Get the transparency log entries. | — | — |
| `get_vendor_risk_report` | Get vendor risk report. | — | — |
| `get_vendors` | Get vendors with filtering. | — | — |
| `get_vulnerabilities` | Get vulnerabilities with filtering. | — | — |
| `input_guardrail` | Validate/sanitize input through guardrail pipeline. Returns (sanitized_prompt, is_safe). | — | — |
| `log` | Log an action for transparency. | — | — |
| `output_guardrail` | Validate/sanitize output through guardrail pipeline. Returns (sanitized_response, is_safe). | — | — |
| `perform_task` | Perform a task. Override in subclasses. | — | — |
| `process_message` | Process an incoming message. Override in subclasses. | — | — |
| `reason` | Iterative ReAct reasoning loop: think→act→observe. | — | — |
| `receive_message` | Receive a message from another agent. | — | — |
| `reflect` | Self-critique: evaluate response quality and suggest improvements. | — | — |
| `register_tool` | Register a tool with the agent. | — | — |
| `report_incident` | Report supply chain security incident. | — | — |
| `resolve_incident` | Resolve security incident. | — | — |
| `send_message` | Send a message to another agent. | — | — |
| `think` | Use LLM inference to reason about something. Optionally validate against a Pydantic model. | — | — |
| `tool_guardrail` | Check if tool call is permitted. Returns is_allowed. | — | — |
| `update_vulnerability_status` | Update vulnerability status. | — | — |

**File**: `agentic_ai/agents/supply_chain.py`

### Audit Agent (`audit.py`)

**Purpose**: Audit Agent for internal audit planning, control testing,

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `add_control` | Add control for testing. | — | — |
| `call_tool` | Call a tool by name with keyword arguments. | — | — |
| `can_create_project` | Check if agent can create projects. | — | — |
| `can_manage_agents` | Check if agent can manage other agents. | — | — |
| `can_read` | Check if agent has read permission. | — | — |
| `can_write` | Check if agent has write permission. | — | — |
| `collect_evidence` | Collect audit evidence. | — | — |
| `complete_audit` | Complete audit. | — | — |
| `create_audit` | Create audit engagement | `title: str, type: str` | `audit: Audit` |
| `create_finding` | Create audit finding. | — | — |
| `create_workpaper` | Create audit workpaper. | — | — |
| `generate_audit_report` | Generate audit report. | — | — |
| `generate_id` | Generate a unique ID with the given prefix (static version). | — | — |
| `get_agent_card` | Generate an A2A-compatible agent card describing this agent. | — | — |
| `get_audit_dashboard` | Generate audit dashboard. | — | — |
| `get_audits` | Get audits with filtering. | — | — |
| `get_controls` | Get controls with filtering. | — | — |
| `get_evidence` | Get evidence with filtering. | — | — |
| `get_findings` | Get findings with filtering. | — | — |
| `get_state` | Get agent state summary. | — | — |
| `get_status` | Get agent status. | — | — |
| `get_transparency_log` | Get the transparency log entries. | — | — |
| `input_guardrail` | Validate/sanitize input through guardrail pipeline. Returns (sanitized_prompt, is_safe). | — | — |
| `log` | Log an action for transparency. | — | — |
| `output_guardrail` | Validate/sanitize output through guardrail pipeline. Returns (sanitized_response, is_safe). | — | — |
| `perform_task` | Perform a task. Override in subclasses. | — | — |
| `process_message` | Process an incoming message. Override in subclasses. | — | — |
| `reason` | Iterative ReAct reasoning loop: think→act→observe. | — | — |
| `receive_message` | Receive a message from another agent. | — | — |
| `reflect` | Self-critique: evaluate response quality and suggest improvements. | — | — |
| `register_tool` | Register a tool with the agent. | — | — |
| `review_evidence` | Mark evidence as reviewed. | — | — |
| `review_workpaper` | Review workpaper. | — | — |
| `send_message` | Send a message to another agent. | — | — |
| `start_audit` | Start audit fieldwork. | — | — |
| `test_control` | Test control effectiveness | `control: str, evidence: list` | `result: TestResult` |
| `think` | Use LLM inference to reason about something. Optionally validate against a Pydantic model. | — | — |
| `tool_guardrail` | Check if tool call is permitted. Returns is_allowed. | — | — |
| `update_audit_status` | Update audit status. | — | — |
| `update_finding` | Update finding details. | — | — |
| `update_finding_status` | Update finding status. | — | — |

**File**: `agentic_ai/agents/audit.py`

### VendorRisk Agent (`vendor_risk.py`)

**Purpose**: Vendor Risk Agent for third-party risk management,

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `acknowledge_alert` | Acknowledge alert. | — | — |
| `add_vendor` | Add vendor | `vendor: VendorData` | `vendor: Vendor` |
| `call_tool` | Call a tool by name with keyword arguments. | — | — |
| `can_create_project` | Check if agent can create projects. | — | — |
| `can_manage_agents` | Check if agent can manage other agents. | — | — |
| `can_read` | Check if agent has read permission. | — | — |
| `can_write` | Check if agent has write permission. | — | — |
| `complete_assessment` | Complete assessment. | — | — |
| `create_alert` | Create vendor risk alert. | — | — |
| `create_assessment` | Create vendor risk assessment. | — | — |
| `create_finding` | Create assessment finding. | — | — |
| `create_questionnaire` | Create vendor questionnaire. | — | — |
| `enable_monitoring` | Enable continuous monitoring for vendor. | — | — |
| `generate_id` | Generate a unique ID with the given prefix (static version). | — | — |
| `get_agent_card` | Generate an A2A-compatible agent card describing this agent. | — | — |
| `get_alerts` | Get alerts with filtering. | — | — |
| `get_assessments` | Get assessments with filtering. | — | — |
| `get_findings` | Get findings with filtering. | — | — |
| `get_monitors` | Get monitors with filtering. | — | — |
| `get_questionnaires` | Get questionnaires with filtering. | — | — |
| `get_state` | Get agent state summary. | — | — |
| `get_status` | Get agent status. | — | — |
| `get_transparency_log` | Get the transparency log entries. | — | — |
| `get_vendor_risk_dashboard` | Generate vendor risk dashboard. | — | — |
| `get_vendor_risk_report` | Generate vendor risk report. | — | — |
| `get_vendors` | Get vendors with filtering. | — | — |
| `get_vendors_due_for_assessment` | Get vendors due for assessment within specified days. | — | — |
| `input_guardrail` | Validate/sanitize input through guardrail pipeline. Returns (sanitized_prompt, is_safe). | — | — |
| `log` | Log an action for transparency. | — | — |
| `output_guardrail` | Validate/sanitize output through guardrail pipeline. Returns (sanitized_response, is_safe). | — | — |
| `perform_task` | Perform a task. Override in subclasses. | — | — |
| `process_message` | Process an incoming message. Override in subclasses. | — | — |
| `reason` | Iterative ReAct reasoning loop: think→act→observe. | — | — |
| `receive_message` | Receive a message from another agent. | — | — |
| `record_monitoring_result` | Record monitoring check result. | — | — |
| `reflect` | Self-critique: evaluate response quality and suggest improvements. | — | — |
| `register_tool` | Register a tool with the agent. | — | — |
| `resolve_alert` | Resolve alert. | — | — |
| `respond_to_question` | Record question response. | — | — |
| `send_message` | Send a message to another agent. | — | — |
| `send_questionnaire` | Send SIG questionnaire | `vendor_id: str, type: str` | `questionnaire: Questionnaire` |
| `start_assessment` | Start assessment. | — | — |
| `think` | Use LLM inference to reason about something. Optionally validate against a Pydantic model. | — | — |
| `tool_guardrail` | Check if tool call is permitted. Returns is_allowed. | — | — |
| `update_finding` | Update finding details. | — | — |
| `update_finding_status` | Update finding status. | — | — |
| `update_vendor_risk` | Update vendor residual risk. | — | — |

**File**: `agentic_ai/agents/vendor_risk.py`

### ChaosMonkey Agent (`chaos_monkey.py`)

**Purpose**: Chaos Monkey Agent for chaos engineering experiments,

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `AbortCondition` | Conditions that trigger experiment abort. | — | — |
| `ExperimentType` | Chaos experiment types. | — | — |
| `TargetType` | Target types for chaos experiments. | — | — |
| `abort_experiment` | Abort chaos experiment. | — | — |
| `add_blackout_window` | Add blackout window. | — | — |
| `add_metric_threshold` | Add metric threshold for abort conditions. | — | — |
| `add_safety_constraint` | Add safety constraint. | — | — |
| `assign_targets` | Assign targets to experiment. | — | — |
| `calculate_resiliency_score` | Calculate resiliency score for a service. | — | — |
| `call_tool` | Call a tool by name with keyword arguments. | — | — |
| `can_create_project` | Check if agent can create projects. | — | — |
| `can_manage_agents` | Check if agent can manage other agents. | — | — |
| `can_read` | Check if agent has read permission. | — | — |
| `can_write` | Check if agent has write permission. | — | — |
| `check_metric_thresholds` | Check if any metric thresholds are breached. | — | — |
| `complete_experiment` | Complete chaos experiment. | — | — |
| `create_experiment` | Create chaos experiment | `name: str, type: str` | `experiment: Experiment` |
| `execute_latency_injection` | Execute latency injection. | — | — |
| `execute_termination` | Execute instance termination. | — | — |
| `generate_id` | Generate a unique ID with the given prefix (static version). | — | — |
| `get_agent_card` | Generate an A2A-compatible agent card describing this agent. | — | — |
| `get_chaos_dashboard` | Generate chaos engineering dashboard. | — | — |
| `get_experiment_report` | Generate experiment report. | — | — |
| `get_experiments` | Get experiments with filtering. | — | — |
| `get_state` | Get agent state summary. | — | — |
| `get_status` | Get agent status. | — | — |
| `get_targets` | Get targets with filtering. | — | — |
| `get_transparency_log` | Get the transparency log entries. | — | — |
| `input_guardrail` | Validate/sanitize input through guardrail pipeline. Returns (sanitized_prompt, is_safe). | — | — |
| `log` | Log an action for transparency. | — | — |
| `output_guardrail` | Validate/sanitize output through guardrail pipeline. Returns (sanitized_response, is_safe). | — | — |
| `perform_task` | Perform a task. Override in subclasses. | — | — |
| `process_message` | Process an incoming message. Override in subclasses. | — | — |
| `reason` | Iterative ReAct reasoning loop: think→act→observe. | — | — |
| `receive_message` | Receive a message from another agent. | — | — |
| `reflect` | Self-critique: evaluate response quality and suggest improvements. | — | — |
| `register_target` | Register a target for chaos experiments. | — | — |
| `register_tool` | Register a tool with the agent. | — | — |
| `schedule_experiment` | Schedule experiment for execution. | — | — |
| `select_random_targets` | Randomly select targets for chaos experiment. | — | — |
| `send_message` | Send a message to another agent. | — | — |
| `start_experiment` | Start experiment | `experiment_id: str` | `run: ExperimentRun` |
| `think` | Use LLM inference to reason about something. Optionally validate against a Pydantic model. | — | — |
| `tool_guardrail` | Check if tool call is permitted. Returns is_allowed. | — | — |

**File**: `agentic_ai/agents/chaos_monkey.py`

### Red Team Agent V2 Agent (`redteam_v2.py`)

**Purpose**: Enhanced Red Team Agent with MITRE ATT&CK v12,

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `build_network_topology` | Build network topology from scan results. | — | — |
| `calculate_engagement_risk` | Calculate overall risk score for an engagement. | — | — |
| `create_attack_path` | Create an attack path with visualization data. | — | — |
| `create_detection_test` | Create a purple team detection test. | — | — |
| `execute_detection_test` | Record detection test execution. | — | — |
| `generate_attack_path_from_findings` | Automatically generate attack paths from findings. | — | — |
| `generate_executive_summary` | Generate executive summary for an engagement. | — | — |
| `get_detection_coverage` | Get detection coverage for an engagement. | — | — |
| `get_mitre_coverage` | Calculate MITRE coverage for an engagement. | — | — |
| `get_state` | Get agent state. | — | — |
| `get_technique` | Get MITRE technique details. | — | — |
| `get_techniques_by_tactic` | Get all techniques for a tactic. | — | — |
| `identify_pivot_points` | Identify lateral movement pivot points. | — | — |
| `map_finding_to_mitre` | Map a finding to MITRE ATT&CK techniques. | — | — |

**File**: `agentic_ai/agents/cyber/redteam_v2.py`

### Social Media Agent (`social_media.py`)

**Purpose**: Social media agent: calendars, drafts, engagement, listening, metrics.

**Capabilities**:
| Capability | Description | Input | Output |
|------------|-------------|-------|--------|
| `activity_log` | Audit view (from the shared queue): one activity (with its log) | — | — |
| `advocacy_pack` | Founder-led bundle: drafts for the owner's PERSONAL posting. | — | — |
| `authorize_activity` | THE owner gate: authorize an activity (post or email reply) for | — | — |
| `blitz_digest` | Render a special-edition digest DRAFT from the newest blitz's | — | — |
| `blitz_plan` | Plan a publishing blitz: pieces -> platform drafts (draft-only). | — | — |
| `blitz_report` | Rollout status for the newest blitz: per-piece and per-draft | — | — |
| `brand_check` | Pre-flight any draft text: banned claims, unsourced numbers, | — | — |
| `call_tool` | Call a tool by name with keyword arguments. | — | — |
| `campaign_sources` | Deterministic candidate material for a publishing blitz: recent | — | — |
| `can_create_project` | Check if agent can create projects. | — | — |
| `can_manage_agents` | Check if agent can manage other agents. | — | — |
| `can_read` | Check if agent has read permission. | — | — |
| `can_write` | Check if agent has write permission. | — | — |
| `content_calendar` | Plan calendar slots for the window: weekly cadence, weekdays only. | — | — |
| `crisis_note` | Hold-rules and template language during an active incident. | — | — |
| `draft_post` | Draft one generic post (draft-only; the owner sends it). | — | — |
| `draft_reply` | Render the reply for an inbound request (draft-only: nothing | — | — |
| `engagement_draft` | Draft (never send) a reply to a social mention. | — | — |
| `generate_id` | Generate a unique ID with the given prefix (static version). | — | — |
| `get_agent_card` | Generate an A2A-compatible agent card describing this agent. | — | — |
| `get_status` | Get agent status. | — | — |
| `get_transparency_log` | Get the transparency log entries. | — | — |
| `get_transport` | Social posting transports land behind platform tokens; none are | — | — |
| `hand_off` | Stage a platform-ready payload for the owner's click. | — | — |
| `hand_to_sales` | Turn an owner-picked mention into a CRM lead. | — | — |
| `input_guardrail` | Validate/sanitize input through guardrail pipeline. Returns (sanitized_prompt, is_safe). | — | — |
| `listen_report` | Roll up owner-fed mentions: tone split, keywords, spike, unanswered. | — | — |
| `log` | Log an action for transparency. | — | — |
| `mark_published` | Record that the OWNER posted this draft (data entry, not an action). | — | — |
| `mark_status` | Record an owner decision on a draft (approve/hand-off/archive). | — | — |
| `metrics_report` | KPI rollup over owner-entered per-post outcomes. | — | — |
| `next_peak` | Next matching weekday at the optimal UTC hour (>= now + 1h, so a | — | — |
| `output_guardrail` | Validate/sanitize output through guardrail pipeline. Returns (sanitized_response, is_safe). | — | — |
| `perform_task` | Dispatch a task by type; payload is merged into kwargs. | — | — |
| `post_queue` | The owner's work list: all drafts grouped by status. | — | — |
| `process_message` | Process an incoming message. Override in subclasses. | — | — |
| `reason` | Iterative ReAct reasoning loop: think→act→observe. | — | — |
| `receive_message` | Receive a message from another agent. | — | — |
| `reflect` | Self-critique: evaluate response quality and suggest improvements. | — | — |
| `register_tool` | Register a tool with the agent. | — | — |
| `repurpose` | Turn a newsroom article into platform-native DRAFTS of one story. | — | — |
| `send_message` | Send a message to another agent. | — | — |
| `set_policy` | THE owner policy gate on the loosened posting path: flip | — | — |
| `site_counters` | Pull the site's own cookie-free counters (home visits + per-article | — | — |
| `snapshot_counters` | Capture a named before/after point of the site's first-party | — | — |
| `think` | Use LLM inference to reason about something. Optionally validate against a Pydantic model. | — | — |
| `tick_activities` | Execute authorized activities whose optimal time has arrived: | — | — |
| `tool_guardrail` | Check if tool call is permitted. Returns is_allowed. | — | — |
| `week_summary` | Owner-facing snapshot: queue, published week, overdue slots, mentions. | — | — |

**File**: `agentic_ai/agents/social_media.py`

## Test Coverage Summary

| Category | Agents |
|----------|--------|
| Core | 5 |
| Business | 5 |
| Data | 4 |
| Operations | 6 |
| Governance | 8 |
| Specialized | 1 |
| Cyber | 8 |

| **Total** | 37 |
