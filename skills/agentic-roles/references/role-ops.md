# Role-agent operations reference

Generated from the registry (agentic_ai.agents.registry) - one section per
agent id. Run any op with `agenticai agent run <id> --op <op> --args '{...}'`;
`agent card <id>` instantiates without side effects.

## audit - AuditAgent

*Category:* Governance - Internal audit

| Op | Async | Source | Details |
|---|---|---|---|
| `add_control` |  | audit | Add control for testing. |
| `call_tool` | async | base | Call a tool by name with keyword arguments. |
| `can_create_project` |  | base | Check if agent can create projects. |
| `can_manage_agents` |  | base | Check if agent can manage other agents. |
| `can_read` |  | base | Check if agent has read permission. |
| `can_write` |  | base | Check if agent has write permission. |
| `collect_evidence` |  | audit | Collect audit evidence. |
| `complete_audit` |  | audit | Complete audit. |
| `create_audit` |  | audit | Create audit engagement. |
| `create_finding` |  | audit | Create audit finding. |
| `create_workpaper` |  | audit | Create audit workpaper. |
| `generate_audit_report` |  | audit | Generate audit report. |
| `generate_id` |  | base | Generate a unique ID with the given prefix (static version). |
| `get_agent_card` |  | base | Generate an A2A-compatible agent card describing this agent. |
| `get_audit_dashboard` |  | audit | Generate audit dashboard. |
| `get_audits` |  | audit | Get audits with filtering. |
| `get_controls` |  | audit | Get controls with filtering. |
| `get_evidence` |  | audit | Get evidence with filtering. |
| `get_findings` |  | audit | Get findings with filtering. |
| `get_state` |  | audit | Get agent state summary. |
| `get_status` |  | base | Get agent status. |
| `get_transparency_log` |  | base | Get the transparency log entries. |
| `input_guardrail` |  | base | Validate/sanitize input through guardrail pipeline. Returns (sanitized |
| `log` |  | base | Log an action for transparency. |
| `output_guardrail` |  | base | Validate/sanitize output through guardrail pipeline. Returns (sanitize |
| `perform_task` | async | base | Perform a task. Override in subclasses. |
| `process_message` | async | base | Process an incoming message. Override in subclasses. |
| `reason` | async | base | Iterative ReAct reasoning loop: think→act→observe. |
| `receive_message` |  | base | Receive a message from another agent. |
| `reflect` | async | base | Self-critique: evaluate response quality and suggest improvements. |
| `register_tool` |  | base | Register a tool with the agent. |
| `review_evidence` |  | audit | Mark evidence as reviewed. |
| `review_workpaper` |  | audit | Review workpaper. |
| `send_message` |  | base | Send a message to another agent. |
| `start_audit` |  | audit | Start audit fieldwork. |
| `test_control` |  | audit | Test control and record results. |
| `think` | async | base | Use LLM inference to reason about something. Optionally validate again |
| `tool_guardrail` |  | base | Check if tool call is permitted. Returns is_allowed. |
| `update_audit_status` |  | audit | Update audit status. |
| `update_finding` |  | audit | Update finding details. |
| `update_finding_status` |  | audit | Update finding status. |

## base - BaseAgent

*Category:* Core - Base agent functionality and shared protocol

| Op | Async | Source | Details |
|---|---|---|---|
| `call_tool` | async | base | Call a tool by name with keyword arguments. |
| `can_create_project` |  | base | Check if agent can create projects. |
| `can_manage_agents` |  | base | Check if agent can manage other agents. |
| `can_read` |  | base | Check if agent has read permission. |
| `can_write` |  | base | Check if agent has write permission. |
| `generate_id` |  | base | Generate a unique ID with the given prefix (static version). |
| `get_agent_card` |  | base | Generate an A2A-compatible agent card describing this agent. |
| `get_status` |  | base | Get agent status. |
| `get_transparency_log` |  | base | Get the transparency log entries. |
| `input_guardrail` |  | base | Validate/sanitize input through guardrail pipeline. Returns (sanitized |
| `log` |  | base | Log an action for transparency. |
| `output_guardrail` |  | base | Validate/sanitize output through guardrail pipeline. Returns (sanitize |
| `perform_task` | async | base | Perform a task. Override in subclasses. |
| `process_message` | async | base | Process an incoming message. Override in subclasses. |
| `reason` | async | base | Iterative ReAct reasoning loop: think→act→observe. |
| `receive_message` |  | base | Receive a message from another agent. |
| `reflect` | async | base | Self-critique: evaluate response quality and suggest improvements. |
| `register_tool` |  | base | Register a tool with the agent. |
| `send_message` |  | base | Send a message to another agent. |
| `think` | async | base | Use LLM inference to reason about something. Optionally validate again |
| `tool_guardrail` |  | base | Check if tool call is permitted. Returns is_allowed. |

## biblical_scholar - BiblicalScholarAgent

*Category:* Specialized - Biblical scholarship research

| Op | Async | Source | Details |
|---|---|---|---|
| `add_text` |  | biblical_scholar | Add a religious text to the database. |
| `analyze_quote` |  | biblical_scholar | Analyze a religious quote for meaning, source, and significance. |
| `compare_concept` |  | biblical_scholar | Compare how a concept is understood across religions. |
| `get_comparative_study` |  | biblical_scholar | Get comparative study by ID. |
| `get_quote_analysis` |  | biblical_scholar | Get quote analysis by ID. |
| `get_random_text` |  | biblical_scholar | Get a random religious text. |
| `get_research` |  | biblical_scholar | Get research query by ID. |
| `get_state` |  | biblical_scholar | Get agent state summary. |
| `get_text` |  | biblical_scholar | Get text by ID. |
| `get_texts_by_religion` |  | biblical_scholar | Get all texts for a specific religion. |
| `get_texts_by_type` |  | biblical_scholar | Get all texts of a specific type. |
| `research_question` |  | biblical_scholar | Research a theological or biblical question. |
| `search_texts` |  | biblical_scholar | Search texts by content, title, or keywords. |

## chaos_monkey - ChaosMonkeyAgent

*Category:* Operations - Chaos engineering

| Op | Async | Source | Details |
|---|---|---|---|
| `AbortCondition` |  | chaos_monkey | Conditions that trigger experiment abort. |
| `ExperimentType` |  | chaos_monkey | Chaos experiment types. |
| `TargetType` |  | chaos_monkey | Target types for chaos experiments. |
| `abort_experiment` |  | chaos_monkey | Abort chaos experiment. |
| `add_blackout_window` |  | chaos_monkey | Add blackout window. |
| `add_metric_threshold` |  | chaos_monkey | Add metric threshold for abort conditions. |
| `add_safety_constraint` |  | chaos_monkey | Add safety constraint. |
| `assign_targets` |  | chaos_monkey | Assign targets to experiment. |
| `calculate_resiliency_score` |  | chaos_monkey | Calculate resiliency score for a service. |
| `call_tool` | async | base | Call a tool by name with keyword arguments. |
| `can_create_project` |  | base | Check if agent can create projects. |
| `can_manage_agents` |  | base | Check if agent can manage other agents. |
| `can_read` |  | base | Check if agent has read permission. |
| `can_write` |  | base | Check if agent has write permission. |
| `check_metric_thresholds` |  | chaos_monkey | Check if any metric thresholds are breached. |
| `complete_experiment` |  | chaos_monkey | Complete chaos experiment. |
| `create_experiment` |  | chaos_monkey | Create chaos engineering experiment. |
| `execute_latency_injection` |  | chaos_monkey | Execute latency injection. |
| `execute_termination` |  | chaos_monkey | Execute instance termination. |
| `generate_id` |  | base | Generate a unique ID with the given prefix (static version). |
| `get_agent_card` |  | base | Generate an A2A-compatible agent card describing this agent. |
| `get_chaos_dashboard` |  | chaos_monkey | Generate chaos engineering dashboard. |
| `get_experiment_report` |  | chaos_monkey | Generate experiment report. |
| `get_experiments` |  | chaos_monkey | Get experiments with filtering. |
| `get_state` |  | chaos_monkey | Get agent state summary. |
| `get_status` |  | base | Get agent status. |
| `get_targets` |  | chaos_monkey | Get targets with filtering. |
| `get_transparency_log` |  | base | Get the transparency log entries. |
| `input_guardrail` |  | base | Validate/sanitize input through guardrail pipeline. Returns (sanitized |
| `log` |  | base | Log an action for transparency. |
| `output_guardrail` |  | base | Validate/sanitize output through guardrail pipeline. Returns (sanitize |
| `perform_task` | async | base | Perform a task. Override in subclasses. |
| `process_message` | async | base | Process an incoming message. Override in subclasses. |
| `reason` | async | base | Iterative ReAct reasoning loop: think→act→observe. |
| `receive_message` |  | base | Receive a message from another agent. |
| `reflect` | async | base | Self-critique: evaluate response quality and suggest improvements. |
| `register_target` |  | chaos_monkey | Register a target for chaos experiments. |
| `register_tool` |  | base | Register a tool with the agent. |
| `schedule_experiment` |  | chaos_monkey | Schedule experiment for execution. |
| `select_random_targets` |  | chaos_monkey | Randomly select targets for chaos experiment. |
| `send_message` |  | base | Send a message to another agent. |
| `start_experiment` |  | chaos_monkey | Start chaos experiment. |
| `think` | async | base | Use LLM inference to reason about something. Optionally validate again |
| `tool_guardrail` |  | base | Check if tool call is permitted. Returns is_allowed. |

## cloud_security - CloudSecurityAgent

*Category:* Operations - Cloud security posture

| Op | Async | Source | Details |
|---|---|---|---|
| `add_account` |  | cloud_security | Add cloud account for monitoring. |
| `add_resource` |  | cloud_security | Add cloud resource for monitoring. |
| `call_tool` | async | base | Call a tool by name with keyword arguments. |
| `can_create_project` |  | base | Check if agent can create projects. |
| `can_manage_agents` |  | base | Check if agent can manage other agents. |
| `can_read` |  | base | Check if agent has read permission. |
| `can_write` |  | base | Check if agent has write permission. |
| `check_resource_compliance` |  | cloud_security | Check resource against policies. |
| `create_finding` |  | cloud_security | Create security finding. |
| `create_policy` |  | cloud_security | Create custom security policy. |
| `create_remediation` |  | cloud_security | Create remediation action. |
| `execute_remediation` |  | cloud_security | Mark remediation as executed. |
| `generate_id` |  | base | Generate a unique ID with the given prefix (static version). |
| `get_account_risk_profile` |  | cloud_security | Get risk profile for a cloud account. |
| `get_accounts` |  | cloud_security | Get accounts with filtering. |
| `get_agent_card` |  | base | Generate an A2A-compatible agent card describing this agent. |
| `get_cloud_security_report` |  | cloud_security | Generate cloud security report. |
| `get_compliance_score` |  | cloud_security | Calculate compliance score for a framework. |
| `get_findings` |  | cloud_security | Get findings with filtering. |
| `get_policies` |  | cloud_security | Get policies with filtering. |
| `get_resources` |  | cloud_security | Get resources with filtering. |
| `get_state` |  | cloud_security | Get agent state summary. |
| `get_status` |  | base | Get agent status. |
| `get_transparency_log` |  | base | Get the transparency log entries. |
| `input_guardrail` |  | base | Validate/sanitize input through guardrail pipeline. Returns (sanitized |
| `log` |  | base | Log an action for transparency. |
| `output_guardrail` |  | base | Validate/sanitize output through guardrail pipeline. Returns (sanitize |
| `perform_task` | async | base | Perform a task. Override in subclasses. |
| `process_message` | async | base | Process an incoming message. Override in subclasses. |
| `reason` | async | base | Iterative ReAct reasoning loop: think→act→observe. |
| `receive_message` |  | base | Receive a message from another agent. |
| `reflect` | async | base | Self-critique: evaluate response quality and suggest improvements. |
| `register_tool` |  | base | Register a tool with the agent. |
| `send_message` |  | base | Send a message to another agent. |
| `think` | async | base | Use LLM inference to reason about something. Optionally validate again |
| `tool_guardrail` |  | base | Check if tool call is permitted. Returns is_allowed. |
| `update_account_scan` |  | cloud_security | Update account scan results. |
| `update_finding_status` |  | cloud_security | Update finding status. |

## communications - CommunicationsAgent

*Category:* Operations - Communications

| Op | Async | Source | Details |
|---|---|---|---|
| `add_contact` |  | communications | Add a contact. |
| `call_tool` | async | base | Call a tool by name with keyword arguments. |
| `can_create_project` |  | base | Check if agent can create projects. |
| `can_manage_agents` |  | base | Check if agent can manage other agents. |
| `can_read` |  | base | Check if agent has read permission. |
| `can_write` |  | base | Check if agent has write permission. |
| `complete_campaign` |  | communications | Complete a campaign. |
| `create_campaign` |  | communications | Create a communication campaign. |
| `create_template` |  | communications | Create a message template. |
| `generate_id` |  | base | Generate a unique ID with the given prefix (static version). |
| `get_agent_card` |  | base | Generate an A2A-compatible agent card describing this agent. |
| `get_campaign_performance` |  | communications | Get campaign performance metrics. |
| `get_campaigns` |  | communications | Get campaigns with filtering. |
| `get_channel_health` |  | communications | Get channel health status. |
| `get_contacts` |  | communications | Get contacts with filtering. |
| `get_delivery_stats` |  | communications | Get delivery statistics. |
| `get_messages` |  | communications | Get messages with filtering. |
| `get_state` |  | communications | Get agent state summary. |
| `get_status` |  | base | Get agent status. |
| `get_templates` |  | communications | Get templates with filtering. |
| `get_transparency_log` |  | base | Get the transparency log entries. |
| `input_guardrail` |  | base | Validate/sanitize input through guardrail pipeline. Returns (sanitized |
| `log` |  | base | Log an action for transparency. |
| `output_guardrail` |  | base | Validate/sanitize output through guardrail pipeline. Returns (sanitize |
| `perform_task` | async | base | Perform a task. Override in subclasses. |
| `process_message` | async | base | Process an incoming message. Override in subclasses. |
| `reason` | async | base | Iterative ReAct reasoning loop: think→act→observe. |
| `receive_message` |  | base | Receive a message from another agent. |
| `reflect` | async | base | Self-critique: evaluate response quality and suggest improvements. |
| `register_tool` |  | base | Register a tool with the agent. |
| `render_template` |  | communications | Render a template with values. |
| `schedule_message` |  | communications | Schedule a message for later delivery. |
| `send_email` |  | communications | Send an email (convenience method wrapping send_message). |
| `send_message` |  | communications | Send a message. |
| `start_campaign` |  | communications | Start a campaign. |
| `think` | async | base | Use LLM inference to reason about something. Optionally validate again |
| `tool_guardrail` |  | base | Check if tool call is permitted. Returns is_allowed. |
| `update_campaign_metrics` |  | communications | Update campaign metrics. |
| `update_message_status` |  | communications | Update message delivery status. |
| `update_preferences` |  | communications | Update contact communication preferences. |

## compliance - ComplianceAgent

*Category:* Governance - Compliance management

| Op | Async | Source | Details |
|---|---|---|---|
| `add_certificate` |  | compliance | Add a compliance certificate. |
| `add_regulation` |  | compliance | Add a regulatory framework to track. |
| `approve_policy` |  | compliance | Approve a policy. |
| `call_tool` | async | base | Call a tool by name with keyword arguments. |
| `can_create_project` |  | base | Check if agent can create projects. |
| `can_manage_agents` |  | base | Check if agent can manage other agents. |
| `can_read` |  | base | Check if agent has read permission. |
| `can_write` |  | base | Check if agent has write permission. |
| `complete_audit` |  | compliance | Complete an audit. |
| `create_assessment` |  | compliance | Create a compliance assessment. |
| `create_audit` |  | compliance | Create a compliance audit. |
| `create_control` |  | compliance | Create a compliance control. |
| `create_finding` |  | compliance | Create a compliance finding. |
| `create_policy` |  | compliance | Create a policy document. |
| `generate_id` |  | base | Generate a unique ID with the given prefix (static version). |
| `get_agent_card` |  | base | Generate an A2A-compatible agent card describing this agent. |
| `get_audits` |  | compliance | Get audits with filtering. |
| `get_compliance_report` |  | compliance | Generate comprehensive compliance report. |
| `get_controls` |  | compliance | Get controls with filtering. |
| `get_findings` |  | compliance | Get findings with filtering. |
| `get_framework_status` |  | compliance | Get status for a specific framework. |
| `get_policies` |  | compliance | Get policies with filtering. |
| `get_policies_due_for_review` |  | compliance | Get policies due for review. |
| `get_regulations` |  | compliance | Get regulations with filtering. |
| `get_state` |  | compliance | Get agent state summary. |
| `get_status` |  | base | Get agent status. |
| `get_transparency_log` |  | base | Get the transparency log entries. |
| `input_guardrail` |  | base | Validate/sanitize input through guardrail pipeline. Returns (sanitized |
| `log` |  | base | Log an action for transparency. |
| `output_guardrail` |  | base | Validate/sanitize output through guardrail pipeline. Returns (sanitize |
| `perform_task` | async | base | Perform a task. Override in subclasses. |
| `process_message` | async | base | Process an incoming message. Override in subclasses. |
| `reason` | async | base | Iterative ReAct reasoning loop: think→act→observe. |
| `receive_message` |  | base | Receive a message from another agent. |
| `reflect` | async | base | Self-critique: evaluate response quality and suggest improvements. |
| `register_tool` |  | base | Register a tool with the agent. |
| `resolve_finding` |  | compliance | Resolve a finding. |
| `send_message` |  | base | Send a message to another agent. |
| `start_audit` |  | compliance | Start an audit. |
| `test_control` |  | compliance | Test a control and update status. |
| `think` | async | base | Use LLM inference to reason about something. Optionally validate again |
| `tool_guardrail` |  | base | Check if tool call is permitted. Returns is_allowed. |
| `update_regulation_status` |  | compliance | Update regulation compliance status based on controls. |

## data_analyst - DataAnalystAgent

*Category:* Data - Data analysis

| Op | Async | Source | Details |
|---|---|---|---|
| `calculate_statistics` |  | data_analyst | Calculate descriptive statistics for a column. |
| `call_tool` | async | base | Call a tool by name with keyword arguments. |
| `can_create_project` |  | base | Check if agent can create projects. |
| `can_manage_agents` |  | base | Check if agent can manage other agents. |
| `can_read` |  | base | Check if agent has read permission. |
| `can_write` |  | base | Check if agent has write permission. |
| `detect_anomalies` |  | data_analyst | Detect anomalies using z-score method. |
| `detect_correlations` |  | data_analyst | Detect correlation between two columns. |
| `detect_trends` |  | data_analyst | Detect trends in time-series data. |
| `generate_id` |  | base | Generate a unique ID with the given prefix (static version). |
| `generate_insights` |  | data_analyst | Generate automated insights for a dataset. |
| `generate_report` |  | data_analyst | Generate a comprehensive analysis report. |
| `get_agent_card` |  | base | Generate an A2A-compatible agent card describing this agent. |
| `get_report` |  | data_analyst | Get a report by ID. |
| `get_state` |  | data_analyst | Get agent state summary. |
| `get_status` |  | base | Get agent status. |
| `get_transparency_log` |  | base | Get the transparency log entries. |
| `input_guardrail` |  | base | Validate/sanitize input through guardrail pipeline. Returns (sanitized |
| `load_data` |  | data_analyst | Load data into cache for analysis. |
| `log` |  | base | Log an action for transparency. |
| `output_guardrail` |  | base | Validate/sanitize output through guardrail pipeline. Returns (sanitize |
| `perform_task` | async | base | Perform a task. Override in subclasses. |
| `process_message` | async | base | Process an incoming message. Override in subclasses. |
| `reason` | async | base | Iterative ReAct reasoning loop: think→act→observe. |
| `receive_message` |  | base | Receive a message from another agent. |
| `reflect` | async | base | Self-critique: evaluate response quality and suggest improvements. |
| `register_dataset` |  | data_analyst | Register a dataset for analysis. |
| `register_tool` |  | base | Register a tool with the agent. |
| `send_message` |  | base | Send a message to another agent. |
| `think` | async | base | Use LLM inference to reason about something. Optionally validate again |
| `tool_guardrail` |  | base | Check if tool call is permitted. Returns is_allowed. |

## data_governance - DataGovernanceAgent

*Category:* Data - Data governance

| Op | Async | Source | Details |
|---|---|---|---|
| `add_lineage` |  | data_governance | Add data lineage record. |
| `approve_access` |  | data_governance | Approve access request. |
| `call_tool` | async | base | Call a tool by name with keyword arguments. |
| `can_create_project` |  | base | Check if agent can create projects. |
| `can_manage_agents` |  | base | Check if agent can manage other agents. |
| `can_read` |  | base | Check if agent has read permission. |
| `can_write` |  | base | Check if agent has write permission. |
| `classify_data` |  | data_governance | Auto-classify data based on content keywords. |
| `create_quality_rule` |  | data_governance | Create data quality rule. |
| `create_retention_policy` |  | data_governance | Create retention policy. |
| `deny_access` |  | data_governance | Deny access request. |
| `execute_quality_check` |  | data_governance | Execute quality check and record result. |
| `generate_id` |  | base | Generate a unique ID with the given prefix (static version). |
| `get_access_requests` |  | data_governance | Get access requests with filtering. |
| `get_agent_card` |  | base | Generate an A2A-compatible agent card describing this agent. |
| `get_assets` |  | data_governance | Get assets with filtering. |
| `get_assets_due_for_action` |  | data_governance | Get assets due for retention action. |
| `get_compliance_summary` |  | data_governance | Get compliance summary for regulated data. |
| `get_governance_report` |  | data_governance | Generate data governance report. |
| `get_lineage` |  | data_governance | Get data lineage for an asset. |
| `get_quality_issues` |  | data_governance | Get quality issues with filtering. |
| `get_quality_score` |  | data_governance | Calculate overall quality score for an asset. |
| `get_retention_period` |  | data_governance | Get retention period for an asset. |
| `get_state` |  | data_governance | Get agent state summary. |
| `get_status` |  | base | Get agent status. |
| `get_transparency_log` |  | base | Get the transparency log entries. |
| `input_guardrail` |  | base | Validate/sanitize input through guardrail pipeline. Returns (sanitized |
| `log` |  | base | Log an action for transparency. |
| `output_guardrail` |  | base | Validate/sanitize output through guardrail pipeline. Returns (sanitize |
| `perform_task` | async | base | Perform a task. Override in subclasses. |
| `process_message` | async | base | Process an incoming message. Override in subclasses. |
| `reason` | async | base | Iterative ReAct reasoning loop: think→act→observe. |
| `receive_message` |  | base | Receive a message from another agent. |
| `reflect` | async | base | Self-critique: evaluate response quality and suggest improvements. |
| `register_asset` |  | data_governance | Register a data asset. |
| `register_tool` |  | base | Register a tool with the agent. |
| `request_access` |  | data_governance | Request access to data asset. |
| `resolve_quality_issue` |  | data_governance | Resolve a quality issue. |
| `revoke_access` |  | data_governance | Revoke approved access. |
| `send_message` |  | base | Send a message to another agent. |
| `think` | async | base | Use LLM inference to reason about something. Optionally validate again |
| `tool_guardrail` |  | base | Check if tool call is permitted. Returns is_allowed. |
| `update_asset_metrics` |  | data_governance | Update asset metrics. |
| `update_lineage_status` |  | data_governance | Update lineage execution status. |

## developer - DeveloperAgent

*Category:* Core - Code implementation and review

| Op | Async | Source | Details |
|---|---|---|---|
| `analyze_code` |  | developer | Analyze code quality and complexity. |
| `call_tool` | async | base | Call a tool by name with keyword arguments. |
| `can_create_project` |  | base | Check if agent can create projects. |
| `can_manage_agents` |  | base | Check if agent can manage other agents. |
| `can_read` |  | base | Check if agent has read permission. |
| `can_write` |  | base | Check if agent has write permission. |
| `fix_bug` |  | developer |  |
| `generate_docs` |  | developer |  |
| `generate_id` |  | base | Generate a unique ID with the given prefix (static version). |
| `get_agent_card` |  | base | Generate an A2A-compatible agent card describing this agent. |
| `get_status` |  | base | Get agent status. |
| `get_transparency_log` |  | base | Get the transparency log entries. |
| `implement_feature` |  | developer |  |
| `input_guardrail` |  | base | Validate/sanitize input through guardrail pipeline. Returns (sanitized |
| `list_files` |  | developer | List files in a directory. |
| `log` |  | base | Log an action for transparency. |
| `output_guardrail` |  | base | Validate/sanitize output through guardrail pipeline. Returns (sanitize |
| `perform_task` | async | developer | Perform a task. Override in subclasses. |
| `process_message` | async | base | Process an incoming message. Override in subclasses. |
| `read_file` |  | developer | Read a file from the project. |
| `reason` | async | base | Iterative ReAct reasoning loop: think→act→observe. |
| `receive_message` |  | base | Receive a message from another agent. |
| `reflect` | async | base | Self-critique: evaluate response quality and suggest improvements. |
| `register_tool` |  | base | Register a tool with the agent. |
| `review_code` |  | developer |  |
| `run_tests` |  | developer |  |
| `send_message` |  | base | Send a message to another agent. |
| `think` | async | base | Use LLM inference to reason about something. Optionally validate again |
| `tool_guardrail` |  | base | Check if tool call is permitted. Returns is_allowed. |
| `write_file` |  | developer | Write a file to the project. |

## devops - DevOpsAgent

*Category:* Operations - DevOps and infrastructure

| Op | Async | Source | Details |
|---|---|---|---|
| `acknowledge_alert` |  | devops | Acknowledge an alert. |
| `call_tool` | async | base | Call a tool by name with keyword arguments. |
| `can_create_project` |  | base | Check if agent can create projects. |
| `can_manage_agents` |  | base | Check if agent can manage other agents. |
| `can_read` |  | base | Check if agent has read permission. |
| `can_write` |  | base | Check if agent has write permission. |
| `check_thresholds` |  | devops | Check metrics against thresholds and create alerts. |
| `create_alert` |  | devops | Create a monitoring alert. |
| `create_deployment` |  | devops | Create a new deployment. |
| `create_pipeline` |  | devops | Create a new CI/CD pipeline. |
| `create_task` |  | devops | Create a DevOps task. |
| `generate_id` |  | base | Generate a unique ID with the given prefix (static version). |
| `get_active_alerts` |  | devops | Get active (unresolved) alerts. |
| `get_agent_card` |  | base | Generate an A2A-compatible agent card describing this agent. |
| `get_cost_report` |  | devops | Generate cost optimization report. |
| `get_deployments` |  | devops | Get deployments with filtering. |
| `get_infrastructure_summary` |  | devops | Get infrastructure summary. |
| `get_pipelines` |  | devops | Get pipelines with filtering. |
| `get_resource_costs` |  | devops | Calculate resource costs for time period. |
| `get_state` |  | devops | Get agent state summary. |
| `get_status` |  | base | Get agent status. |
| `get_transparency_log` |  | base | Get the transparency log entries. |
| `input_guardrail` |  | base | Validate/sanitize input through guardrail pipeline. Returns (sanitized |
| `log` |  | base | Log an action for transparency. |
| `output_guardrail` |  | base | Validate/sanitize output through guardrail pipeline. Returns (sanitize |
| `perform_task` | async | base | Perform a task. Override in subclasses. |
| `process_message` | async | base | Process an incoming message. Override in subclasses. |
| `reason` | async | base | Iterative ReAct reasoning loop: think→act→observe. |
| `receive_message` |  | base | Receive a message from another agent. |
| `record_metric` |  | devops | Record a metric data point. |
| `reflect` | async | base | Self-critique: evaluate response quality and suggest improvements. |
| `register_resource` |  | devops | Register an infrastructure resource. |
| `register_tool` |  | base | Register a tool with the agent. |
| `resolve_alert` |  | devops | Resolve an alert. |
| `rollback_deployment` |  | devops | Rollback deployment to previous version. |
| `run_command` |  | devops | Execute a command on a target. |
| `send_message` |  | base | Send a message to another agent. |
| `start_pipeline` |  | devops | Start a queued pipeline. |
| `think` | async | base | Use LLM inference to reason about something. Optionally validate again |
| `tool_guardrail` |  | base | Check if tool call is permitted. Returns is_allowed. |
| `update_deployment_status` |  | devops | Update deployment status. |
| `update_pipeline_stage` |  | devops | Update pipeline stage status. |
| `update_resource_status` |  | devops | Update resource status. |

## ethics - EthicsAgent

*Category:* Governance - Ethics and AI safety

| Op | Async | Source | Details |
|---|---|---|---|
| `add_explainability_record` |  | ethics | Add explainability record. |
| `add_finding` |  | ethics | Add finding to ethics assessment. |
| `call_tool` | async | base | Call a tool by name with keyword arguments. |
| `can_create_project` |  | base | Check if agent can create projects. |
| `can_manage_agents` |  | base | Check if agent can manage other agents. |
| `can_read` |  | base | Check if agent has read permission. |
| `can_write` |  | base | Check if agent has write permission. |
| `complete_assessment` |  | ethics | Complete ethics assessment. |
| `configure_oversight` |  | ethics | Configure human oversight for a model. |
| `create_ethics_assessment` |  | ethics | Create ethics assessment for a model. |
| `create_remediation_plan` |  | ethics | Create remediation plan for bias. |
| `detect_bias` |  | ethics | Record detected bias. |
| `generate_fairness_report` |  | ethics | Generate fairness metrics report. |
| `generate_id` |  | base | Generate a unique ID with the given prefix (static version). |
| `get_agent_card` |  | base | Generate an A2A-compatible agent card describing this agent. |
| `get_bias_assessments` |  | ethics | Get bias assessments with filtering. |
| `get_ethics_report` |  | ethics | Generate comprehensive ethics report. |
| `get_explainability` |  | ethics | Get explainability records for a model. |
| `get_fairness_reports` |  | ethics | Get fairness reports with filtering. |
| `get_incidents` |  | ethics | Get incidents with filtering. |
| `get_model_ethics_profile` |  | ethics | Get comprehensive ethics profile for a model. |
| `get_models` |  | ethics | Get models with filtering. |
| `get_oversight_config` |  | ethics | Get oversight configuration for a model. |
| `get_state` |  | ethics | Get agent state summary. |
| `get_status` |  | base | Get agent status. |
| `get_transparency_log` |  | base | Get the transparency log entries. |
| `input_guardrail` |  | base | Validate/sanitize input through guardrail pipeline. Returns (sanitized |
| `log` |  | base | Log an action for transparency. |
| `mark_bias_mitigated` |  | ethics | Mark bias as mitigated. |
| `output_guardrail` |  | base | Validate/sanitize output through guardrail pipeline. Returns (sanitize |
| `perform_task` | async | base | Perform a task. Override in subclasses. |
| `process_message` | async | base | Process an incoming message. Override in subclasses. |
| `reason` | async | base | Iterative ReAct reasoning loop: think→act→observe. |
| `receive_message` |  | base | Receive a message from another agent. |
| `reflect` | async | base | Self-critique: evaluate response quality and suggest improvements. |
| `register_model` |  | ethics | Register an AI model for ethics oversight. |
| `register_tool` |  | base | Register a tool with the agent. |
| `report_incident` |  | ethics | Report ethical incident. |
| `resolve_incident` |  | ethics | Resolve ethical incident. |
| `send_message` |  | base | Send a message to another agent. |
| `think` | async | base | Use LLM inference to reason about something. Optionally validate again |
| `tool_guardrail` |  | base | Check if tool call is permitted. Returns is_allowed. |
| `update_model_risk` |  | ethics | Update model risk level. |

## finance - FinanceAgent

*Category:* Business - Financial operations

| Op | Async | Source | Details |
|---|---|---|---|
| `analyze_spending` |  | finance |  |
| `call_tool` | async | base | Call a tool by name with keyword arguments. |
| `can_create_project` |  | base | Check if agent can create projects. |
| `can_manage_agents` |  | base | Check if agent can manage other agents. |
| `can_read` |  | base | Check if agent has read permission. |
| `can_write` |  | base | Check if agent has write permission. |
| `create_budget` |  | finance |  |
| `create_invoice` |  | finance |  |
| `generate_id` |  | base | Generate a unique ID with the given prefix (static version). |
| `generate_report` |  | finance |  |
| `get_agent_card` |  | base | Generate an A2A-compatible agent card describing this agent. |
| `get_status` |  | base | Get agent status. |
| `get_transparency_log` |  | base | Get the transparency log entries. |
| `input_guardrail` |  | base | Validate/sanitize input through guardrail pipeline. Returns (sanitized |
| `log` |  | base | Log an action for transparency. |
| `output_guardrail` |  | base | Validate/sanitize output through guardrail pipeline. Returns (sanitize |
| `perform_task` | async | finance | Perform a task. Override in subclasses. |
| `process_message` | async | base | Process an incoming message. Override in subclasses. |
| `reason` | async | base | Iterative ReAct reasoning loop: think→act→observe. |
| `receive_message` |  | base | Receive a message from another agent. |
| `record_transaction` |  | finance |  |
| `reflect` | async | base | Self-critique: evaluate response quality and suggest improvements. |
| `register_tool` |  | base | Register a tool with the agent. |
| `send_message` |  | base | Send a message to another agent. |
| `think` | async | base | Use LLM inference to reason about something. Optionally validate again |
| `tool_guardrail` |  | base | Check if tool call is permitted. Returns is_allowed. |

## hr - HRAgent

*Category:* Business - Human resources

| Op | Async | Source | Details |
|---|---|---|---|
| `approve_time_off` |  | hr | Approve time off request. |
| `call_tool` | async | base | Call a tool by name with keyword arguments. |
| `can_create_project` |  | base | Check if agent can create projects. |
| `can_manage_agents` |  | base | Check if agent can manage other agents. |
| `can_read` |  | base | Check if agent has read permission. |
| `can_write` |  | base | Check if agent has write permission. |
| `complete_onboarding_task` |  | hr | Mark onboarding task as complete. |
| `create_onboarding` |  | hr | Create onboarding checklist for new employee. |
| `create_review` |  | hr | Create performance review. |
| `generate_id` |  | base | Generate a unique ID with the given prefix (static version). |
| `get_agent_card` |  | base | Generate an A2A-compatible agent card describing this agent. |
| `get_employee` |  | hr | Get employee by ID. |
| `get_employees` |  | hr | Get employees with filtering. |
| `get_hr_metrics` |  | hr | Get HR metrics summary. |
| `get_onboarding_progress` |  | hr | Get onboarding progress for employee. |
| `get_reviews` |  | hr | Get reviews with filtering. |
| `get_state` |  | hr | Get agent state summary. |
| `get_status` |  | base | Get agent status. |
| `get_time_off_requests` |  | hr | Get time off requests with filtering. |
| `get_transparency_log` |  | base | Get the transparency log entries. |
| `hire_employee` |  | hr | Hire a new employee. |
| `input_guardrail` |  | base | Validate/sanitize input through guardrail pipeline. Returns (sanitized |
| `log` |  | base | Log an action for transparency. |
| `output_guardrail` |  | base | Validate/sanitize output through guardrail pipeline. Returns (sanitize |
| `perform_task` | async | base | Perform a task. Override in subclasses. |
| `process_message` | async | base | Process an incoming message. Override in subclasses. |
| `reason` | async | base | Iterative ReAct reasoning loop: think→act→observe. |
| `receive_message` |  | base | Receive a message from another agent. |
| `reflect` | async | base | Self-critique: evaluate response quality and suggest improvements. |
| `register_tool` |  | base | Register a tool with the agent. |
| `reject_time_off` |  | hr | Reject time off request. |
| `request_time_off` |  | hr | Request time off. |
| `send_message` |  | base | Send a message to another agent. |
| `submit_review` |  | hr | Submit completed review. |
| `terminate_employee` |  | hr | Terminate an employee. |
| `think` | async | base | Use LLM inference to reason about something. Optionally validate again |
| `tool_guardrail` |  | base | Check if tool call is permitted. Returns is_allowed. |
| `update_employee` |  | hr | Update employee information. |

## integration - IntegrationAgent

*Category:* Operations - System integrations

| Op | Async | Source | Details |
|---|---|---|---|
| `call_tool` | async | base | Call a tool by name with keyword arguments. |
| `can_create_project` |  | base | Check if agent can create projects. |
| `can_manage_agents` |  | base | Check if agent can manage other agents. |
| `can_read` |  | base | Check if agent has read permission. |
| `can_write` |  | base | Check if agent has write permission. |
| `create_connection` |  | integration | Create a new API connection. |
| `create_sync_job` |  | integration | Create a data synchronization job. |
| `create_webhook` |  | integration | Create a new webhook. |
| `generate_id` |  | base | Generate a unique ID with the given prefix (static version). |
| `get_agent_card` |  | base | Generate an A2A-compatible agent card describing this agent. |
| `get_connections` |  | integration | Get connections with filtering. |
| `get_integration_health` |  | integration | Get overall integration health summary. |
| `get_logs` |  | integration | Get integration logs. |
| `get_state` |  | integration | Get agent state summary. |
| `get_status` |  | base | Get agent status. |
| `get_sync_jobs` |  | integration | Get sync jobs with filtering. |
| `get_transparency_log` |  | base | Get the transparency log entries. |
| `get_webhooks` |  | integration | Get webhooks with filtering. |
| `input_guardrail` |  | base | Validate/sanitize input through guardrail pipeline. Returns (sanitized |
| `log` |  | base | Log an action for transparency. |
| `output_guardrail` |  | base | Validate/sanitize output through guardrail pipeline. Returns (sanitize |
| `pause_webhook` |  | integration | Pause a webhook. |
| `perform_task` | async | base | Perform a task. Override in subclasses. |
| `process_message` | async | base | Process an incoming message. Override in subclasses. |
| `reason` | async | base | Iterative ReAct reasoning loop: think→act→observe. |
| `receive_message` |  | base | Receive a message from another agent. |
| `reflect` | async | base | Self-critique: evaluate response quality and suggest improvements. |
| `register_tool` |  | base | Register a tool with the agent. |
| `remove_connection` |  | integration | Remove a connection. |
| `run_sync_job` |  | integration | Execute a sync job. |
| `send_message` |  | base | Send a message to another agent. |
| `test_connection` |  | integration | Test API connection. |
| `think` | async | base | Use LLM inference to reason about something. Optionally validate again |
| `tool_guardrail` |  | base | Check if tool call is permitted. Returns is_allowed. |
| `trigger_webhook` |  | integration | Trigger a webhook. |
| `update_connection_status` |  | integration | Update connection status. |

## kali - KaliAgent

*Category:* Cyber - Kali Linux tooling agent (v1 interface; see also the kali-agent skill)

| Op | Async | Source | Details |
|---|---|---|---|
| `ad_command_catalog` |  | ad_pentest | The per-step command catalog (target/dc injected) (KA-032). |
| `ad_detection_notes` |  | ad_pentest | The blue-team pairing (TTP-level notes) (KA-032). |
| `ad_index` |  | ad_pentest | The module's own shapes (a stable API for the composer) (KA-032). |
| `add_to_blacklist` |  | kali | Add IP to blacklist (always blocked). |
| `aircrack_crack` |  | kali | WiFi password cracking. |
| `amass_enum` |  | kali | Subdomain enumeration with Amass. |
| `analyzer_catalog` |  | chain_ops | 17 static-analyzer/symbolic/fuzz/repo-audit rows (+lab_fork flags) (KA-046). |
| `analyzer_lookup` |  | chain_ops | One analyzer row by id (KA-046). |
| `api_auth_surface_catalog` |  | api_pentest | Per-style auth-surface rows (surface/check/detection) (KA-041). |
| `api_index` |  | api_pentest | REST/GraphQL style list + module policy (KA-041). |
| `api_policy` |  | api_pentest | planning_only + lab_or_authorized_targets_only rows (KA-041). |
| `api_step_catalog` |  | api_pentest | Per-style discovery/enum command steps (raw templates) (KA-041). |
| `api_vuln_classes` |  | api_pentest | Per-style vuln-class name list (KA-041). |
| `api_vuln_commands` |  | api_pentest | Per-class SAFE command sets for a scrubbed target (KA-041). |
| `audit_config` |  | network_device | Offline config audit vs per-vendor rule rows (findings with severity) (KA-040). |
| `authorize_tool` |  | kali | Consult an engagement RBAC role against the tool DB (KA-051). |
| `binwalk_analyze` |  | kali | Firmware analysis. |
| `bloodhound_collect` |  | kali | Active Directory reconnaissance. |
| `call_tool` | async | base | Call a tool by name with keyword arguments. |
| `can_create_project` |  | base | Check if agent can create projects. |
| `can_manage_agents` |  | base | Check if agent can manage other agents. |
| `can_read` |  | base | Check if agent has read permission. |
| `can_write` |  | base | Check if agent has write permission. |
| `cewl_generate` |  | kali | Custom wordlist generator. |
| `channel_measurement` |  | socialeng_ops | Per-channel measurement metrics ({metric,definition,source}) (KA-042). |
| `check_authorization` |  | kali | Check if tool execution is authorized. |
| `classify_postexp_command` |  | postexp | Command -> mutation-class classification (10 classes) (KA-044). |
| `clear_ip_whitelist` |  | kali | Clear IP whitelist. |
| `cloud_detection_notes` |  | cloud_pentest | Cloud detection/countermeasure notes (KA-033). |
| `cloud_index` |  | cloud_pentest | Cloud kinds + policy overview (KA-033). |
| `config_audit_rules` |  | network_device | Curated hardening rule rows across 4 vendor CLIs (KA-040). |
| `connect_metasploit` |  | kali | Connect to Metasploit RPC. |
| `container_index` |  | container_pentest | Container ops + policy overview (KA-034). |
| `container_tool_catalog` |  | container_pentest | Container tool catalog (KA-034). |
| `contract_nets` |  | chain_ops | Net label vocab (testnet allowed / mainnet refused) (KA-046). |
| `contract_policy` |  | chain_ops | testnet_only + planning-only policy rows (KA-046). |
| `create_evidence_bundle` |  | kali | Per-engagement evidence bundle: tar + manifest + sha256 (KA-082). |
| `crunch_generate` |  | kali | Wordlist generator. |
| `device_enum_catalog` |  | network_device | Per-kind show-class enum command templates (read-only) (KA-040). |
| `device_index` |  | network_device | Kinds + vendors + lab-only policy overview (KA-040). |
| `dirb_scan` |  | kali | Web content scanner. |
| `disable_audit_logging` |  | kali | Disable audit logging. |
| `disable_dry_run` |  | kali | Disable dry-run mode. |
| `disable_safe_mode` |  | kali | Disable safe mode (allows system changes). |
| `disconnect_metasploit` |  | kali | Disconnect from Metasploit RPC. |
| `dnsrecon_scan` |  | kali | DNS enumeration. |
| `enable_audit_logging` |  | kali | Enable audit logging for all executions. |
| `enable_dry_run` |  | kali | Enable dry-run mode (commands logged but not executed). |
| `enable_safe_mode` |  | kali | Enable safe mode (read-only operations). |
| `execute_metasploit_exploit` |  | kali | Execute a Metasploit exploit. |
| `execute_tool` |  | kali | Execute a Kali Linux tool. |
| `ffuf_fuzz` |  | kali | Fast web fuzzer. |
| `finding_class_catalog` |  | chain_ops | 18 finding classes with analyzer pairings (KA-046). |
| `firmware_flow` |  | ics_iot | The 6-phase static-only firmware flow (air-gapped lab required) (KA-043). |
| `firmware_step_catalog` |  | ics_iot | Raw {image} step templates per firmware phase (KA-043). |
| `forensics_index` |  | forensics_ops | Analyst workflows + policy overview (KA-038). |
| `forensics_policy` |  | forensics_ops | Read-only-on-originals policy rows (KA-038). |
| `forensics_step_catalog` |  | forensics_ops | Per-kind analyst step catalog (KA-038). |
| `full_engagement_index` |  | full_engagement | Composition contract: families, core arc, extension lanes (KA-050). |
| `generate_id` |  | base | Generate a unique ID with the given prefix (static version). |
| `generate_playbook_report` |  | kali | Generate playbook execution report. |
| `generate_report` |  | kali | Generate execution report. |
| `get_agent_card` |  | base | Generate an A2A-compatible agent card describing this agent. |
| `get_execution_history` |  | kali | Get execution history with filtering. |
| `get_metasploit_modules` |  | kali | Get available Metasploit modules. |
| `get_metasploit_sessions` |  | kali | Get active Metasploit sessions. |
| `get_status` |  | base | Get agent status. |
| `get_tool_info` |  | kali | Get detailed tool information. |
| `get_transparency_log` |  | base | Get the transparency log entries. |
| `gobuster_scan` |  | kali | Directory/DNS brute-force with Gobuster. |
| `hydra_bruteforce` |  | kali | Brute force login with Hydra. |
| `iam_blast_radius_checklist` |  | cloud_pentest | IAM blast-radius checklist rows (KA-033). |
| `ics_iot_detection_notes` |  | ics_iot | OT detection TTP-order notes (KA-043). |
| `ics_iot_index` |  | ics_iot | Protocols + ops + policy overview (KA-043). |
| `input_guardrail` |  | base | Validate/sanitize input through guardrail pipeline. Returns (sanitized |
| `john_crack` |  | kali | Crack passwords with John the Ripper. |
| `joomscan_scan` |  | kali | Joomla vulnerability scanner. |
| `jwt_analysis` |  | webauth_ops | Decoded-claims JWT assessment (never decodes/holds key material) (KA-045). |
| `k8s_rbac_checklist` |  | container_pentest | K8s RBAC checklist rows (KA-034). |
| `kevstig_fan_out` |  | kali | kevstig coverage.json -> routed CVEs + matching recommendations (KA-067). |
| `list_tools` |  | kali | List available tools. |
| `log` |  | base | Log an action for transparency. |
| `malware_index` |  | malware_ops | The four sample kinds + module policy overview (KA-039). |
| `malware_policy` |  | malware_ops | static_first + detonate_sandbox_only policy rows (KA-039). |
| `medusa_bruteforce` |  | kali | Parallel brute forcer. |
| `metasploit_session_command` |  | kali | Execute command in Metasploit session. |
| `mobile_detection_notes` |  | mobile_pentest | Mobile detection notes (KA-035). |
| `mobile_index` |  | mobile_pentest | APK/IPA ops + policy overview (KA-035). |
| `nikto_scan` |  | kali | Perform Nikto web server scan. |
| `nmap_scan` |  | kali | Perform Nmap network scan. |
| `oauth_flow_catalog` |  | webauth_ops | The 5 OAuth grant catalogs incl. deprecated implicit/password rows (KA-045). |
| `oauth_grant_assessment` |  | webauth_ops | Per-grant assessment arc (KA-045). |
| `osint_detection_notes` |  | osint_pentest | OSINT detection notes (KA-037). |
| `osint_index` |  | osint_pentest | OSINT lanes + policy overview (KA-037). |
| `osint_step_catalog` |  | osint_pentest | Per-lane read-only step catalog (KA-037). |
| `output_guardrail` |  | base | Validate/sanitize output through guardrail pipeline. Returns (sanitize |
| `perform_task` | async | base | Perform a task. Override in subclasses. |
| `plan_ad` |  | ad_pentest | The 6-phase lab-only AD plan (KA-032). |
| `plan_analyzer_sweep` |  | chain_ops | Ordered analyzer sweep plan (lab_fork flags respected) (KA-046). |
| `plan_api` |  | api_pentest | The 7-phase REST or GraphQL methodology arc (KA-041). |
| `plan_cloud` |  | cloud_pentest | The 6-phase sandbox-account plan per cloud (KA-033). |
| `plan_container_escape` |  | container_pentest | Escape-surface planner arcs (KA-034). |
| `plan_contract_audit` |  | chain_ops | The 7-phase testnet-only contract audit arc (KA-046). |
| `plan_detonation` |  | malware_ops | Detonation plan; refuses without a sandbox record (sandbox-only gate) (KA-039). |
| `plan_device_audit` |  | network_device | The 6-phase lab-only device audit arc (KA-040). |
| `plan_finding_triage` |  | chain_ops | Findings -> analyzer/tool triage mapping (KA-046). |
| `plan_forensics` |  | forensics_ops | The analyst arc per kind (KA-038). |
| `plan_full_engagement` |  | full_engagement | Composes recon -> web -> xss -> privesc (+extension lanes) into one scrubbed plan (KA-050). |
| `plan_impersonation_exercise` |  | socialeng_ops | Consent-gated impersonation exercise plan (scenario classes only) (KA-042). |
| `plan_mobile_apk` |  | mobile_pentest | APK static-first planner (KA-035). |
| `plan_mobile_ipa` |  | mobile_pentest | IPA static-first planner (KA-035). |
| `plan_modbus` |  | ics_iot | Modbus TCP/RTU read-only arc (passive tap) (KA-043). |
| `plan_osint` |  | osint_pentest | Per-lane OSINT plan (KA-037). |
| `plan_phishing_simulation` |  | socialeng_ops | Consent-gated phishing simulation plan (structure only, no payloads) (KA-042). |
| `plan_postexp` |  | postexp | Per-arc 5-phase evidence-only plan (KA-044). |
| `plan_privesc` |  | privesc | The 6-phase escalation plan for a target on a platform (KA-031). |
| `plan_redteam` |  | redteam_pentest | The red-team phase arc for a scope: goal, tool count, and example |
| `plan_s7` |  | ics_iot | S7comm read-only arc (port 102) (KA-043). |
| `plan_static` |  | malware_ops | The 6-phase static analysis arc (acquire/triage/static/family/gate/report) (KA-039). |
| `plan_web_pentest` |  | web_pentest | Return the 12-phase engagement plan for a target. |
| `plan_webauth` |  | webauth_ops | The 7-phase SSO/OAuth/JWT methodology arc (KA-045). |
| `plan_wireless_capture` |  | wireless_pentest | Monitor-mode capture planner (KA-036). |
| `plan_xss_exploit` |  | xss_exploit | The 7-phase XSS methodology plan for a target. |
| `postexp_arcs` |  | postexp | The 4 evidence-only arcs + aliases (KA-044). |
| `postexp_credential_classes` |  | postexp | Credential-SURFACE rows (locations only, never contents) (KA-044). |
| `postexp_gate` |  | postexp | Refuses every mutation-class step in a plan (re-plan reasons) (KA-044). |
| `postexp_policy` |  | postexp | evidence_only + mutation_forbidden rows (KA-044). |
| `postexp_step_catalog` |  | postexp | Per-arc read-only step catalogs (KA-044). |
| `privesc_capability_lookup` |  | privesc | Index rows for a binary name (case-insensitive; optional platform filter) (KA-031). |
| `privesc_index` |  | privesc | Load the committed capability index (KA-031). |
| `process_message` | async | base | Process an incoming message. Override in subclasses. |
| `protocol_command_catalog` |  | ics_iot | Per-protocol read-only command rows for a scrubbed target (KA-043). |
| `reason` | async | base | Iterative ReAct reasoning loop: think→act→observe. |
| `reaver_attack` |  | kali | WPS brute force attack. |
| `receive_message` |  | base | Receive a message from another agent. |
| `redteam_catalog` |  | redteam_pentest | Load the generated red-team tool catalog (13 phases, ~725 tools). |
| `redteam_countermeasures` |  | redteam_pentest | Detection/countermeasure notes for a phase (the blue-team pairing). |
| `redteam_phase_tools` |  | redteam_pentest | Every tool cataloged under a phase (name, url, purpose, origin |
| `redteam_tool_lookup` |  | redteam_pentest | Search the whole catalog by tool-name fragment (max 25 hits). |
| `reflect` | async | base | Self-critique: evaluate response quality and suggest improvements. |
| `register_tool` |  | base | Register a tool with the agent. |
| `remove_from_blacklist` |  | kali | Remove IP from blacklist. |
| `revoke_authorization` |  | kali | Revoke authorization. |
| `rogue_ap_playbook` |  | wireless_pentest | The rogue-AP play (lab-RF-tagged; consent noted in phase 1) (KA-036). |
| `role_allows_dry_run` |  | kali | Planning/inspection is unrestricted for every role (KA-051). |
| `run_ad_audit_playbook` |  | kali | Run Active Directory audit playbook. |
| `run_password_audit_playbook` |  | kali | Run password cracking playbook. |
| `run_recon_playbook` |  | kali | Run comprehensive reconnaissance playbook. |
| `run_web_audit_playbook` |  | kali | Run web application audit playbook. |
| `run_wireless_audit_playbook` |  | kali | Run wireless security audit playbook. |
| `searchsploit_search` |  | kali | Search Exploit Database. |
| `send_message` |  | base | Send a message to another agent. |
| `set_authorization` |  | kali | Set authorization level for tool execution. |
| `set_ip_whitelist` |  | kali | Set IP whitelist (only these targets allowed). |
| `soc_watch_pairing` |  | socialeng_ops | SOC detection watch rows paired to an exercise (KA-042). |
| `socialeng_index` |  | socialeng_ops | Ops + policy overview (KA-042). |
| `socialeng_policy` |  | socialeng_ops | lab_only/consent_required/no_payload_generation rows (KA-042). |
| `sqlmap_scan` |  | kali | Perform SQLMap SQL injection scan. |
| `static_step_catalog` |  | malware_ops | Per-kind read-only step templates ({sample} placeholders) (KA-039). |
| `subfinder_scan` |  | kali | Subdomain discovery. |
| `testnet_gate` |  | chain_ops | Net label/address gate (refuses mainnet forms) (KA-046). |
| `theharvester_scan` |  | kali | Email and subdomain harvesting. |
| `think` | async | base | Use LLM inference to reason about something. Optionally validate again |
| `tool_guardrail` |  | base | Check if tool call is permitted. Returns is_allowed. |
| `validate_target` |  | kali | Validate target against whitelist/blacklist. |
| `verify_evidence_bundle` |  | kali | Verify a bundle against its manifest (tamper detection; KA-082). |
| `verify_soc_findings` |  | kali | SOC findings -> per-finding verification plans; planners only (KA-066). |
| `volatility_analyze` |  | kali | Memory forensics. |
| `web_enum_commands` |  | web_pentest | Enumeration command catalog for a target, grouped by step. |
| `web_pentest_report_outline` |  | web_pentest | Report scaffold; findings is an optional list of dicts |
| `web_recon_commands` |  | web_pentest | Reconnaissance command catalog for a target, grouped by step. |
| `web_vuln_commands` |  | web_pentest | Per-vulnerability-class command sets; None returns the class list. |
| `webauth_index` |  | webauth_ops | Ops + policy overview (KA-045). |
| `webauth_policy` |  | webauth_ops | No-secrets/planning-only policy rows (KA-045). |
| `webauth_redirect_checks` |  | webauth_ops | Structural redirect-URI checks per client type (KA-045). |
| `webauth_sso_surface` |  | webauth_ops | OIDC/SAML handshake check rows (KA-045). |
| `webauth_token_storage` |  | webauth_ops | Token storage positions + SOC detection pairings (KA-045). |
| `wireless_detection_notes` |  | wireless_pentest | Wireless detection notes (KA-036). |
| `wireless_index` |  | wireless_pentest | Wireless ops + policy overview (KA-036). |
| `wpscan_scan` |  | kali | WordPress security scan. |
| `xss_callback_commands` |  | xss_exploit | OOB/callback infrastructure commands for a callback host name. |
| `xss_countermeasures` |  | xss_exploit | Prevention + detection pairing for the blue team. |
| `xss_filter_strategy` |  | xss_exploit | Filter/CSP evasion STRATEGY classes with in-house notes |
| `xss_tool_lookup` |  | xss_exploit | Search the whole catalog by tool-name fragment (max 25 hits). |

## kali_v2 - KaliAgentV2

*Category:* Cyber - Kali tooling v2 (standalone class)

| Op | Async | Source | Details |
|---|---|---|---|
| `ad_command_catalog` |  | ad_pentest | The per-step command catalog (target/dc injected) (KA-032). |
| `ad_detection_notes` |  | ad_pentest | The blue-team pairing (TTP-level notes) (KA-032). |
| `ad_index` |  | ad_pentest | The module's own shapes (a stable API for the composer) (KA-032). |
| `analyzer_catalog` |  | chain_ops | 17 static-analyzer/symbolic/fuzz/repo-audit rows (+lab_fork flags) (KA-046). |
| `analyzer_lookup` |  | chain_ops | One analyzer row by id (KA-046). |
| `api_auth_surface_catalog` |  | api_pentest | Per-style auth-surface rows (surface/check/detection) (KA-041). |
| `api_index` |  | api_pentest | REST/GraphQL style list + module policy (KA-041). |
| `api_policy` |  | api_pentest | planning_only + lab_or_authorized_targets_only rows (KA-041). |
| `api_step_catalog` |  | api_pentest | Per-style discovery/enum command steps (raw templates) (KA-041). |
| `api_vuln_classes` |  | api_pentest | Per-style vuln-class name list (KA-041). |
| `api_vuln_commands` |  | api_pentest | Per-class SAFE command sets for a scrubbed target (KA-041). |
| `audit_config` |  | network_device | Offline config audit vs per-vendor rule rows (findings with severity) (KA-040). |
| `authorize_tool` |  | kali_v2 | Consult an engagement RBAC role against the tool DB (KA-051). |
| `channel_measurement` |  | socialeng_ops | Per-channel measurement metrics ({metric,definition,source}) (KA-042). |
| `check_authorization` |  | kali_v2 | Check if tool can be executed. |
| `classify_postexp_command` |  | postexp | Command -> mutation-class classification (10 classes) (KA-044). |
| `cloud_detection_notes` |  | cloud_pentest | Cloud detection/countermeasure notes (KA-033). |
| `cloud_index` |  | cloud_pentest | Cloud kinds + policy overview (KA-033). |
| `config_audit_rules` |  | network_device | Curated hardening rule rows across 4 vendor CLIs (KA-040). |
| `container_index` |  | container_pentest | Container ops + policy overview (KA-034). |
| `container_tool_catalog` |  | container_pentest | Container tool catalog (KA-034). |
| `contract_nets` |  | chain_ops | Net label vocab (testnet allowed / mainnet refused) (KA-046). |
| `contract_policy` |  | chain_ops | testnet_only + planning-only policy rows (KA-046). |
| `create_evidence_bundle` |  | kali_v2 | Per-engagement evidence bundle: tar + manifest + sha256 (KA-082). |
| `device_enum_catalog` |  | network_device | Per-kind show-class enum command templates (read-only) (KA-040). |
| `device_index` |  | network_device | Kinds + vendors + lab-only policy overview (KA-040). |
| `disable_dry_run` |  | kali_v2 | Disable dry-run mode. |
| `enable_dry_run` |  | kali_v2 | Enable dry-run mode. |
| `finding_class_catalog` |  | chain_ops | 18 finding classes with analyzer pairings (KA-046). |
| `firmware_flow` |  | ics_iot | The 6-phase static-only firmware flow (air-gapped lab required) (KA-043). |
| `firmware_step_catalog` |  | ics_iot | Raw {image} step templates per firmware phase (KA-043). |
| `forensics_index` |  | forensics_ops | Analyst workflows + policy overview (KA-038). |
| `forensics_policy` |  | forensics_ops | Read-only-on-originals policy rows (KA-038). |
| `forensics_step_catalog` |  | forensics_ops | Per-kind analyst step catalog (KA-038). |
| `full_engagement_index` |  | full_engagement | Composition contract: families, core arc, extension lanes (KA-050). |
| `generate_remediation_plan` |  | kali_v2 | Generate remediation plan for findings. |
| `get_state` |  | kali_v2 | Get agent state. |
| `iam_blast_radius_checklist` |  | cloud_pentest | IAM blast-radius checklist rows (KA-033). |
| `ics_iot_detection_notes` |  | ics_iot | OT detection TTP-order notes (KA-043). |
| `ics_iot_index` |  | ics_iot | Protocols + ops + policy overview (KA-043). |
| `jwt_analysis` |  | webauth_ops | Decoded-claims JWT assessment (never decodes/holds key material) (KA-045). |
| `k8s_rbac_checklist` |  | container_pentest | K8s RBAC checklist rows (KA-034). |
| `kevstig_fan_out` |  | kali_v2 | kevstig coverage.json -> routed CVEs + matching recommendations (KA-067). |
| `list_tools` |  | kali_v2 | List available tools. |
| `malware_index` |  | malware_ops | The four sample kinds + module policy overview (KA-039). |
| `malware_policy` |  | malware_ops | static_first + detonate_sandbox_only policy rows (KA-039). |
| `match_exploits_for_cve` |  | kali_v2 | Find exploits for a CVE. |
| `mobile_detection_notes` |  | mobile_pentest | Mobile detection notes (KA-035). |
| `mobile_index` |  | mobile_pentest | APK/IPA ops + policy overview (KA-035). |
| `oauth_flow_catalog` |  | webauth_ops | The 5 OAuth grant catalogs incl. deprecated implicit/password rows (KA-045). |
| `oauth_grant_assessment` |  | webauth_ops | Per-grant assessment arc (KA-045). |
| `osint_detection_notes` |  | osint_pentest | OSINT detection notes (KA-037). |
| `osint_index` |  | osint_pentest | OSINT lanes + policy overview (KA-037). |
| `osint_step_catalog` |  | osint_pentest | Per-lane read-only step catalog (KA-037). |
| `plan_ad` |  | ad_pentest | The 6-phase lab-only AD plan (KA-032). |
| `plan_analyzer_sweep` |  | chain_ops | Ordered analyzer sweep plan (lab_fork flags respected) (KA-046). |
| `plan_api` |  | api_pentest | The 7-phase REST or GraphQL methodology arc (KA-041). |
| `plan_cloud` |  | cloud_pentest | The 6-phase sandbox-account plan per cloud (KA-033). |
| `plan_container_escape` |  | container_pentest | Escape-surface planner arcs (KA-034). |
| `plan_contract_audit` |  | chain_ops | The 7-phase testnet-only contract audit arc (KA-046). |
| `plan_detonation` |  | malware_ops | Detonation plan; refuses without a sandbox record (sandbox-only gate) (KA-039). |
| `plan_device_audit` |  | network_device | The 6-phase lab-only device audit arc (KA-040). |
| `plan_finding_triage` |  | chain_ops | Findings -> analyzer/tool triage mapping (KA-046). |
| `plan_forensics` |  | forensics_ops | The analyst arc per kind (KA-038). |
| `plan_full_engagement` |  | full_engagement | Composes recon -> web -> xss -> privesc (+extension lanes) into one scrubbed plan (KA-050). |
| `plan_impersonation_exercise` |  | socialeng_ops | Consent-gated impersonation exercise plan (scenario classes only) (KA-042). |
| `plan_mobile_apk` |  | mobile_pentest | APK static-first planner (KA-035). |
| `plan_mobile_ipa` |  | mobile_pentest | IPA static-first planner (KA-035). |
| `plan_modbus` |  | ics_iot | Modbus TCP/RTU read-only arc (passive tap) (KA-043). |
| `plan_osint` |  | osint_pentest | Per-lane OSINT plan (KA-037). |
| `plan_phishing_simulation` |  | socialeng_ops | Consent-gated phishing simulation plan (structure only, no payloads) (KA-042). |
| `plan_postexp` |  | postexp | Per-arc 5-phase evidence-only plan (KA-044). |
| `plan_privesc` |  | privesc | The 6-phase escalation plan for a target on a platform (KA-031). |
| `plan_redteam` |  | redteam_pentest | The red-team phase arc for a scope: goal, tool count, and example |
| `plan_s7` |  | ics_iot | S7comm read-only arc (port 102) (KA-043). |
| `plan_static` |  | malware_ops | The 6-phase static analysis arc (acquire/triage/static/family/gate/report) (KA-039). |
| `plan_web_pentest` |  | web_pentest | Return the 12-phase engagement plan for a target. |
| `plan_webauth` |  | webauth_ops | The 7-phase SSO/OAuth/JWT methodology arc (KA-045). |
| `plan_wireless_capture` |  | wireless_pentest | Monitor-mode capture planner (KA-036). |
| `plan_xss_exploit` |  | xss_exploit | The 7-phase XSS methodology plan for a target. |
| `postexp_arcs` |  | postexp | The 4 evidence-only arcs + aliases (KA-044). |
| `postexp_credential_classes` |  | postexp | Credential-SURFACE rows (locations only, never contents) (KA-044). |
| `postexp_gate` |  | postexp | Refuses every mutation-class step in a plan (re-plan reasons) (KA-044). |
| `postexp_policy` |  | postexp | evidence_only + mutation_forbidden rows (KA-044). |
| `postexp_step_catalog` |  | postexp | Per-arc read-only step catalogs (KA-044). |
| `privesc_capability_lookup` |  | privesc | Index rows for a binary name (case-insensitive; optional platform filter) (KA-031). |
| `privesc_index` |  | privesc | Load the committed capability index (KA-031). |
| `protocol_command_catalog` |  | ics_iot | Per-protocol read-only command rows for a scrubbed target (KA-043). |
| `recommend_tools_for_target` |  | kali_v2 | Get tool recommendations for a target. |
| `redteam_catalog` |  | redteam_pentest | Load the generated red-team tool catalog (13 phases, ~725 tools). |
| `redteam_countermeasures` |  | redteam_pentest | Detection/countermeasure notes for a phase (the blue-team pairing). |
| `redteam_phase_tools` |  | redteam_pentest | Every tool cataloged under a phase (name, url, purpose, origin |
| `redteam_tool_lookup` |  | redteam_pentest | Search the whole catalog by tool-name fragment (max 25 hits). |
| `rogue_ap_playbook` |  | wireless_pentest | The rogue-AP play (lab-RF-tagged; consent noted in phase 1) (KA-036). |
| `role_allows_dry_run` |  | kali_v2 | Planning/inspection is unrestricted for every role (KA-051). |
| `set_authorization` |  | kali_v2 | Set authorization level. |
| `soc_watch_pairing` |  | socialeng_ops | SOC detection watch rows paired to an exercise (KA-042). |
| `socialeng_index` |  | socialeng_ops | Ops + policy overview (KA-042). |
| `socialeng_policy` |  | socialeng_ops | lab_only/consent_required/no_payload_generation rows (KA-042). |
| `static_step_catalog` |  | malware_ops | Per-kind read-only step templates ({sample} placeholders) (KA-039). |
| `testnet_gate` |  | chain_ops | Net label/address gate (refuses mainnet forms) (KA-046). |
| `verify_evidence_bundle` |  | kali_v2 | Verify a bundle against its manifest (tamper detection; KA-082). |
| `verify_soc_findings` |  | kali_v2 | SOC findings -> per-finding verification plans; planners only (KA-066). |
| `web_enum_commands` |  | web_pentest | Enumeration command catalog for a target, grouped by step. |
| `web_pentest_report_outline` |  | web_pentest | Report scaffold; findings is an optional list of dicts |
| `web_recon_commands` |  | web_pentest | Reconnaissance command catalog for a target, grouped by step. |
| `web_vuln_commands` |  | web_pentest | Per-vulnerability-class command sets; None returns the class list. |
| `webauth_index` |  | webauth_ops | Ops + policy overview (KA-045). |
| `webauth_policy` |  | webauth_ops | No-secrets/planning-only policy rows (KA-045). |
| `webauth_redirect_checks` |  | webauth_ops | Structural redirect-URI checks per client type (KA-045). |
| `webauth_sso_surface` |  | webauth_ops | OIDC/SAML handshake check rows (KA-045). |
| `webauth_token_storage` |  | webauth_ops | Token storage positions + SOC detection pairings (KA-045). |
| `wireless_detection_notes` |  | wireless_pentest | Wireless detection notes (KA-036). |
| `wireless_index` |  | wireless_pentest | Wireless ops + policy overview (KA-036). |
| `xss_callback_commands` |  | xss_exploit | OOB/callback infrastructure commands for a callback host name. |
| `xss_countermeasures` |  | xss_exploit | Prevention + detection pairing for the blue team. |
| `xss_filter_strategy` |  | xss_exploit | Filter/CSP evasion STRATEGY classes with in-house notes |
| `xss_tool_lookup` |  | xss_exploit | Search the whole catalog by tool-name fragment (max 25 hits). |

## lead - LeadAgent

*Category:* Core - Orchestration and coordination

| Op | Async | Source | Details |
|---|---|---|---|
| `analyze_request` |  | lead | Analyze a request and determine which agent should handle it. |
| `broadcast_and_collect` | async | lead | Send prompt to all agents, collect responses. |
| `call_tool` | async | base | Call a tool by name with keyword arguments. |
| `can_create_project` |  | base | Check if agent can create projects. |
| `can_manage_agents` |  | base | Check if agent can manage other agents. |
| `can_read` |  | base | Check if agent has read permission. |
| `can_write` |  | base | Check if agent has write permission. |
| `create_task` |  | lead |  |
| `create_workflow` |  | lead |  |
| `decompose_and_parallel` | async | lead | Decompose a task into subtasks, run agents in parallel, merge results. |
| `delegate_task` |  | lead |  |
| `execute_workflow` |  | lead |  |
| `generate_id` |  | base | Generate a unique ID with the given prefix (static version). |
| `get_agent_card` |  | base | Generate an A2A-compatible agent card describing this agent. |
| `get_status` |  | lead | Get agent status. |
| `get_transparency_log` |  | base | Get the transparency log entries. |
| `input_guardrail` |  | base | Validate/sanitize input through guardrail pipeline. Returns (sanitized |
| `log` |  | base | Log an action for transparency. |
| `output_guardrail` |  | base | Validate/sanitize output through guardrail pipeline. Returns (sanitize |
| `perform_task` | async | lead | Perform a task by type. Called with positional args: perform_task("typ |
| `process_message` | async | base | Process an incoming message. Override in subclasses. |
| `reason` | async | base | Iterative ReAct reasoning loop: think→act→observe. |
| `receive_message` |  | base | Receive a message from another agent. |
| `reflect` | async | base | Self-critique: evaluate response quality and suggest improvements. |
| `register_agent` |  | lead | Register an agent with the lead. |
| `register_tool` |  | base | Register a tool with the agent. |
| `request_approval` | async | lead | Request human approval for an action. |
| `round_robin` | async | lead | Agents take turns in sequence responding to a prompt. |
| `route_task` |  | lead |  |
| `selector` | async | lead | Select the best agent for a task, then delegate. |
| `send_message` |  | base | Send a message to another agent. |
| `spawn_conversation` |  | lead | Create a sub-conversation with a group of agents. |
| `think` | async | base | Use LLM inference to reason about something. Optionally validate again |
| `tool_guardrail` |  | base | Check if tool call is permitted. Returns is_allowed. |

## legal - LegalAgent

*Category:* Governance - Legal operations

| Op | Async | Source | Details |
|---|---|---|---|
| `add_clause_to_document` |  | legal | Add clause to document. |
| `call_tool` | async | base | Call a tool by name with keyword arguments. |
| `can_create_project` |  | base | Check if agent can create projects. |
| `can_manage_agents` |  | base | Check if agent can manage other agents. |
| `can_read` |  | base | Check if agent has read permission. |
| `can_write` |  | base | Check if agent has write permission. |
| `create_document` |  | legal | Create a legal document. |
| `create_legal_matter` |  | legal | Create a legal matter (tracked as a legal document). |
| `generate_id` |  | base | Generate a unique ID with the given prefix (static version). |
| `generate_nda_template` |  | legal | Generate NDA template. |
| `generate_terms_template` |  | legal | Generate Terms of Service template. |
| `get_agent_card` |  | base | Generate an A2A-compatible agent card describing this agent. |
| `get_compliance_status` |  | legal | Get overall compliance status. |
| `get_documents` |  | legal | Get documents with filtering. |
| `get_expiring_documents` |  | legal | Get documents expiring within specified days. |
| `get_state` |  | legal | Get agent state summary. |
| `get_status` |  | base | Get agent status. |
| `get_transparency_log` |  | base | Get the transparency log entries. |
| `input_guardrail` |  | base | Validate/sanitize input through guardrail pipeline. Returns (sanitized |
| `log` |  | base | Log an action for transparency. |
| `output_guardrail` |  | base | Validate/sanitize output through guardrail pipeline. Returns (sanitize |
| `perform_task` | async | base | Perform a task. Override in subclasses. |
| `process_message` | async | base | Process an incoming message. Override in subclasses. |
| `reason` | async | base | Iterative ReAct reasoning loop: think→act→observe. |
| `receive_message` |  | base | Receive a message from another agent. |
| `reflect` | async | base | Self-critique: evaluate response quality and suggest improvements. |
| `register_tool` |  | base | Register a tool with the agent. |
| `review_contract` |  | legal | Review contract for risks and issues. |
| `run_compliance_check` |  | legal | Run compliance check against regulation. |
| `send_message` |  | base | Send a message to another agent. |
| `think` | async | base | Use LLM inference to reason about something. Optionally validate again |
| `tool_guardrail` |  | base | Check if tool call is permitted. Returns is_allowed. |
| `update_document_status` |  | legal | Update document status. |

## malware - MalwareAnalysisAgent

*Category:* Cyber - Malware analysis

| Op | Async | Source | Details |
|---|---|---|---|
| `add_analysis_results` |  | malware | Add detailed analysis results. |
| `add_ioc` |  | malware | Add indicator of compromise. |
| `add_ioc_to_campaign` |  | malware | Add IOC to campaign. |
| `add_sample` |  | malware | Add malware sample for analysis. |
| `add_sample_to_campaign` |  | malware | Add sample to campaign. |
| `call_tool` | async | base | Call a tool by name with keyword arguments. |
| `can_create_project` |  | base | Check if agent can create projects. |
| `can_manage_agents` |  | base | Check if agent can manage other agents. |
| `can_read` |  | base | Check if agent has read permission. |
| `can_write` |  | base | Check if agent has write permission. |
| `complete_analysis` |  | malware | Complete analysis with results. |
| `create_analysis` |  | malware | Create malware analysis. |
| `create_campaign` |  | malware | Create malware campaign. |
| `create_yara_rule` |  | malware | Create YARA rule. |
| `generate_id` |  | base | Generate a unique ID with the given prefix (static version). |
| `generate_ioc_report` |  | malware | Generate IOC report for malware family. |
| `get_agent_card` |  | base | Generate an A2A-compatible agent card describing this agent. |
| `get_analyses` |  | malware | Get analyses with filtering. |
| `get_analysis_summary` |  | malware | Get malware analysis summary. |
| `get_campaigns` |  | malware | Get campaigns with filtering. |
| `get_iocs` |  | malware | Get IOCs with filtering. |
| `get_sample` |  | malware | Get sample by ID. |
| `get_sample_by_hash` |  | malware | Get sample by hash (MD5, SHA1, or SHA256). |
| `get_sample_report` |  | malware | Generate detailed sample report. |
| `get_similar_samples` |  | malware | Find similar samples based on SSDEEP or characteristics. |
| `get_state` |  | malware | Get agent state summary. |
| `get_status` |  | base | Get agent status. |
| `get_transparency_log` |  | base | Get the transparency log entries. |
| `get_yara_rules` |  | malware | Get YARA rules with filtering. |
| `identify_malware_family` |  | malware | Identify malware family based on analysis. |
| `input_guardrail` |  | base | Validate/sanitize input through guardrail pipeline. Returns (sanitized |
| `log` |  | base | Log an action for transparency. |
| `mark_ioc_false_positive` |  | malware | Mark IOC as false positive. |
| `output_guardrail` |  | base | Validate/sanitize output through guardrail pipeline. Returns (sanitize |
| `perform_task` | async | base | Perform a task. Override in subclasses. |
| `process_message` | async | base | Process an incoming message. Override in subclasses. |
| `reason` | async | base | Iterative ReAct reasoning loop: think→act→observe. |
| `receive_message` |  | base | Receive a message from another agent. |
| `reflect` | async | base | Self-critique: evaluate response quality and suggest improvements. |
| `register_tool` |  | base | Register a tool with the agent. |
| `send_message` |  | base | Send a message to another agent. |
| `start_analysis` |  | malware | Start analysis. |
| `think` | async | base | Use LLM inference to reason about something. Optionally validate again |
| `tool_guardrail` |  | base | Check if tool call is permitted. Returns is_allowed. |
| `update_yara_rule` |  | malware | Update YARA rule. |

## marketing - MarketingAgent

*Category:* Business - Marketing campaigns

| Op | Async | Source | Details |
|---|---|---|---|
| `call_tool` | async | base | Call a tool by name with keyword arguments. |
| `can_create_project` |  | base | Check if agent can create projects. |
| `can_manage_agents` |  | base | Check if agent can manage other agents. |
| `can_read` |  | base | Check if agent has read permission. |
| `can_write` |  | base | Check if agent has write permission. |
| `complete_ab_test` |  | marketing | Complete A/B test with results. |
| `create_ab_test` |  | marketing | Create A/B test. |
| `create_campaign` |  | marketing | Create a new marketing campaign. |
| `create_content` |  | marketing | Create content piece. |
| `generate_blog_titles` |  | marketing | Generate blog title variations. |
| `generate_email_subjects` |  | marketing | Generate email subject line variations. |
| `generate_id` |  | base | Generate a unique ID with the given prefix (static version). |
| `generate_social_posts` |  | marketing | Generate social media post variations. |
| `get_ab_tests` |  | marketing | Get A/B tests with filtering. |
| `get_agent_card` |  | base | Generate an A2A-compatible agent card describing this agent. |
| `get_analytics_summary` |  | marketing | Get analytics summary. |
| `get_campaigns` |  | marketing | Get campaigns with filtering. |
| `get_state` |  | marketing | Get agent state summary. |
| `get_status` |  | base | Get agent status. |
| `get_transparency_log` |  | base | Get the transparency log entries. |
| `input_guardrail` |  | base | Validate/sanitize input through guardrail pipeline. Returns (sanitized |
| `log` |  | base | Log an action for transparency. |
| `output_guardrail` |  | base | Validate/sanitize output through guardrail pipeline. Returns (sanitize |
| `perform_task` | async | base | Perform a task. Override in subclasses. |
| `process_message` | async | base | Process an incoming message. Override in subclasses. |
| `publish_content` |  | marketing | Publish content. |
| `reason` | async | base | Iterative ReAct reasoning loop: think→act→observe. |
| `receive_message` |  | base | Receive a message from another agent. |
| `reflect` | async | base | Self-critique: evaluate response quality and suggest improvements. |
| `register_tool` |  | base | Register a tool with the agent. |
| `schedule_social_post` |  | marketing | Schedule a social media post. |
| `send_message` |  | base | Send a message to another agent. |
| `think` | async | base | Use LLM inference to reason about something. Optionally validate again |
| `tool_guardrail` |  | base | Check if tool call is permitted. Returns is_allowed. |
| `track_analytics` |  | marketing | Track marketing analytics. |
| `track_campaign_metrics` |  | marketing | Track campaign performance metrics. |
| `update_campaign_status` |  | marketing | Update campaign status. |

## ml_ops - MLOpsAgent

*Category:* Data - ML operations

| Op | Async | Source | Details |
|---|---|---|---|
| `call_tool` | async | base | Call a tool by name with keyword arguments. |
| `can_create_project` |  | base | Check if agent can create projects. |
| `can_manage_agents` |  | base | Check if agent can manage other agents. |
| `can_read` |  | base | Check if agent has read permission. |
| `can_write` |  | base | Check if agent has write permission. |
| `check_model_metrics` |  | ml_ops | Check metrics against thresholds and create alerts. |
| `complete_experiment` |  | ml_ops | Complete experiment with results. |
| `create_alert` |  | ml_ops | Create model alert. |
| `create_experiment` |  | ml_ops | Create ML experiment. |
| `create_monitor` |  | ml_ops | Create model monitor. |
| `deploy_model` |  | ml_ops | Deploy model to environment. |
| `generate_id` |  | base | Generate a unique ID with the given prefix (static version). |
| `get_agent_card` |  | base | Generate an A2A-compatible agent card describing this agent. |
| `get_alerts` |  | ml_ops | Get alerts with filtering. |
| `get_datasets` |  | ml_ops | Get datasets with filtering. |
| `get_deployments` |  | ml_ops | Get deployments with filtering. |
| `get_experiments` |  | ml_ops | Get experiments with filtering. |
| `get_mlops_dashboard` |  | ml_ops | Generate MLOps dashboard. |
| `get_model_performance` |  | ml_ops | Get model performance report. |
| `get_models` |  | ml_ops | Get models with filtering. |
| `get_state` |  | ml_ops | Get agent state summary. |
| `get_status` |  | base | Get agent status. |
| `get_transparency_log` |  | base | Get the transparency log entries. |
| `input_guardrail` |  | base | Validate/sanitize input through guardrail pipeline. Returns (sanitized |
| `log` |  | base | Log an action for transparency. |
| `output_guardrail` |  | base | Validate/sanitize output through guardrail pipeline. Returns (sanitize |
| `perform_task` | async | base | Perform a task. Override in subclasses. |
| `process_message` | async | base | Process an incoming message. Override in subclasses. |
| `reason` | async | base | Iterative ReAct reasoning loop: think→act→observe. |
| `receive_message` |  | base | Receive a message from another agent. |
| `reflect` | async | base | Self-critique: evaluate response quality and suggest improvements. |
| `register_dataset` |  | ml_ops | Register a dataset. |
| `register_model` |  | ml_ops | Register model in registry. |
| `register_tool` |  | base | Register a tool with the agent. |
| `resolve_alert` |  | ml_ops | Resolve alert. |
| `send_message` |  | base | Send a message to another agent. |
| `start_experiment` |  | ml_ops | Start experiment. |
| `think` | async | base | Use LLM inference to reason about something. Optionally validate again |
| `tool_guardrail` |  | base | Check if tool call is permitted. Returns is_allowed. |
| `update_deployment_status` |  | ml_ops | Update deployment status. |
| `update_model_stage` |  | ml_ops | Update model stage. |

## privacy - PrivacyAgent

*Category:* Governance - Privacy compliance

| Op | Async | Source | Details |
|---|---|---|---|
| `DataSubjectRight` |  | privacy | Data subject rights. |
| `PrivacyRegulation` |  | privacy | Privacy regulations. |
| `ProcessingPurpose` |  | privacy | Data processing purposes. |
| `add_processing_activity` |  | privacy | Add a processing activity (Record of Processing Activities). |
| `add_risk_to_pia` |  | privacy | Add identified risk to PIA. |
| `approve_pia` |  | privacy | Approve a PIA. |
| `call_tool` | async | base | Call a tool by name with keyword arguments. |
| `can_create_project` |  | base | Check if agent can create projects. |
| `can_manage_agents` |  | base | Check if agent can manage other agents. |
| `can_read` |  | base | Check if agent has read permission. |
| `can_write` |  | base | Check if agent has write permission. |
| `check_valid_consent` |  | privacy | Check if valid consent exists for a purpose. |
| `close_breach` |  | privacy | Close a breach with full documentation. |
| `contain_breach` |  | privacy | Mark breach as contained. |
| `create_data_request` |  | privacy | Create a data subject request with flexible interface. |
| `create_pia` |  | privacy | Create a Privacy Impact Assessment. |
| `create_request` |  | privacy | Create a data subject rights request. |
| `fulfill_access_request` |  | privacy | Fulfill an access request with data export. |
| `fulfill_erasure_request` |  | privacy | Fulfill an erasure (deletion) request. |
| `generate_id` |  | base | Generate a unique ID with the given prefix (static version). |
| `get_agent_card` |  | base | Generate an A2A-compatible agent card describing this agent. |
| `get_breaches` |  | privacy | Get breaches with filtering. |
| `get_compliance_report` |  | privacy | Generate privacy compliance report. |
| `get_consents` |  | privacy | Get consent records with filtering. |
| `get_data_subject` |  | privacy | Get data subject by ID. |
| `get_data_subjects` |  | privacy | Get data subjects with filtering. |
| `get_pias` |  | privacy | Get PIAs with filtering. |
| `get_processing_activities` |  | privacy | Get processing activities with filtering. |
| `get_regulation_compliance` |  | privacy | Get compliance status for a specific regulation. |
| `get_requests` |  | privacy | Get requests with filtering. |
| `get_state` |  | privacy | Get agent state summary. |
| `get_status` |  | base | Get agent status. |
| `get_transparency_log` |  | base | Get the transparency log entries. |
| `input_guardrail` |  | base | Validate/sanitize input through guardrail pipeline. Returns (sanitized |
| `log` |  | base | Log an action for transparency. |
| `notify_authority` |  | privacy | Record authority notification. |
| `output_guardrail` |  | base | Validate/sanitize output through guardrail pipeline. Returns (sanitize |
| `perform_task` | async | base | Perform a task. Override in subclasses. |
| `process_message` | async | base | Process an incoming message. Override in subclasses. |
| `reason` | async | base | Iterative ReAct reasoning loop: think→act→observe. |
| `receive_message` |  | base | Receive a message from another agent. |
| `record_consent` |  | privacy | Record consent given. |
| `reflect` | async | base | Self-critique: evaluate response quality and suggest improvements. |
| `register_data_subject` |  | privacy | Register a data subject. |
| `register_processing_activity` |  | privacy | Alias for add_processing_activity with more flexible interface. |
| `register_tool` |  | base | Register a tool with the agent. |
| `report_breach` |  | privacy | Report a data breach. |
| `send_message` |  | base | Send a message to another agent. |
| `think` | async | base | Use LLM inference to reason about something. Optionally validate again |
| `tool_guardrail` |  | base | Check if tool call is permitted. Returns is_allowed. |
| `update_request_status` |  | privacy | Update request status. |
| `verify_data_subject` |  | privacy | Verify data subject identity. |
| `verify_request` |  | privacy | Verify a request (identity verification complete). |
| `withdraw_consent` |  | privacy | Withdraw consent. |

## qa - QAAgent

*Category:* Core - Testing and quality assurance

| Op | Async | Source | Details |
|---|---|---|---|
| `analyze_coverage` |  | qa |  |
| `call_tool` | async | base | Call a tool by name with keyword arguments. |
| `can_create_project` |  | base | Check if agent can create projects. |
| `can_manage_agents` |  | base | Check if agent can manage other agents. |
| `can_read` |  | base | Check if agent has read permission. |
| `can_write` |  | base | Check if agent has write permission. |
| `check_quality` |  | qa |  |
| `create_test_plan` |  | qa |  |
| `execute_tests` |  | qa |  |
| `find_bugs` |  | qa |  |
| `generate_id` |  | base | Generate a unique ID with the given prefix (static version). |
| `get_agent_card` |  | base | Generate an A2A-compatible agent card describing this agent. |
| `get_status` |  | base | Get agent status. |
| `get_transparency_log` |  | base | Get the transparency log entries. |
| `input_guardrail` |  | base | Validate/sanitize input through guardrail pipeline. Returns (sanitized |
| `list_files` |  | qa |  |
| `log` |  | base | Log an action for transparency. |
| `output_guardrail` |  | base | Validate/sanitize output through guardrail pipeline. Returns (sanitize |
| `perform_task` | async | qa | Perform a task. Override in subclasses. |
| `process_message` | async | base | Process an incoming message. Override in subclasses. |
| `read_file` |  | qa |  |
| `reason` | async | base | Iterative ReAct reasoning loop: think→act→observe. |
| `receive_message` |  | base | Receive a message from another agent. |
| `reflect` | async | base | Self-critique: evaluate response quality and suggest improvements. |
| `register_tool` |  | base | Register a tool with the agent. |
| `regression_test` |  | qa |  |
| `report_bug` |  | qa |  |
| `send_message` |  | base | Send a message to another agent. |
| `think` | async | base | Use LLM inference to reason about something. Optionally validate again |
| `tool_guardrail` |  | base | Check if tool call is permitted. Returns is_allowed. |
| `validate_feature` |  | qa |  |
| `write_file` |  | qa |  |

## redteam - RedTeamAgent

*Category:* Cyber - Red team operations

| Op | Async | Source | Details |
|---|---|---|---|
| `add_credential` |  | redteam | Add discovered credential. |
| `add_finding` |  | redteam | Add a security finding. |
| `add_service_to_target` |  | redteam | Add service to target. |
| `add_target` |  | redteam | Add a target to the engagement. |
| `add_target_to_engagement` |  | redteam | Add target to engagement. |
| `call_tool` | async | base | Call a tool by name with keyword arguments. |
| `can_create_project` |  | base | Check if agent can create projects. |
| `can_manage_agents` |  | base | Check if agent can manage other agents. |
| `can_read` |  | base | Check if agent has read permission. |
| `can_write` |  | base | Check if agent has write permission. |
| `create_attack_path` |  | redteam | Document an attack path. |
| `create_engagement` |  | redteam | Create a new engagement. |
| `execute_kali_full_engagement` |  | redteam | Execute full engagement using KaliAgent playbooks. |
| `execute_kali_password_audit` |  | redteam | Execute password cracking audit using KaliAgent. |
| `execute_kali_recon` |  | redteam | Execute reconnaissance using KaliAgent. |
| `execute_kali_web_audit` |  | redteam | Execute web application audit using KaliAgent. |
| `generate_engagement_report` |  | redteam | Generate engagement report. |
| `generate_id` |  | base | Generate a unique ID with the given prefix (static version). |
| `get_agent_card` |  | base | Generate an A2A-compatible agent card describing this agent. |
| `get_attack_paths` |  | redteam | Get attack paths with filtering. |
| `get_credentials` |  | redteam | Get credentials with filtering. |
| `get_engagements` |  | redteam | Get engagements with filtering. |
| `get_findings` |  | redteam | Get findings with filtering. |
| `get_state` |  | redteam | Get agent state summary. |
| `get_status` |  | base | Get agent status. |
| `get_targets` |  | redteam | Get targets with filtering. |
| `get_transparency_log` |  | base | Get the transparency log entries. |
| `input_guardrail` |  | base | Validate/sanitize input through guardrail pipeline. Returns (sanitized |
| `log` |  | base | Log an action for transparency. |
| `mark_finding_reported` |  | redteam | Mark finding as reported. |
| `mark_target_compromised` |  | redteam | Mark target as compromised. |
| `output_guardrail` |  | base | Validate/sanitize output through guardrail pipeline. Returns (sanitize |
| `perform_task` | async | base | Perform a task. Override in subclasses. |
| `process_message` | async | base | Process an incoming message. Override in subclasses. |
| `reason` | async | base | Iterative ReAct reasoning loop: think→act→observe. |
| `receive_message` |  | base | Receive a message from another agent. |
| `reflect` | async | base | Self-critique: evaluate response quality and suggest improvements. |
| `register_tool` |  | base | Register a tool with the agent. |
| `send_message` |  | base | Send a message to another agent. |
| `test_credential` |  | redteam | Test if credential is valid. |
| `think` | async | base | Use LLM inference to reason about something. Optionally validate again |
| `tool_guardrail` |  | base | Check if tool call is permitted. Returns is_allowed. |
| `update_engagement_status` |  | redteam | Update engagement status. |

## redteam_v2 - RedTeamAgentV2

*Category:* Cyber - Red team operations (v2, standalone class)

| Op | Async | Source | Details |
|---|---|---|---|
| `build_network_topology` |  | redteam_v2 | Build network topology from scan results. |
| `calculate_engagement_risk` |  | redteam_v2 | Calculate overall risk score for an engagement. |
| `create_attack_path` |  | redteam_v2 | Create an attack path with visualization data. |
| `create_detection_test` |  | redteam_v2 | Create a purple team detection test. |
| `execute_detection_test` |  | redteam_v2 | Record detection test execution. |
| `generate_attack_path_from_findings` |  | redteam_v2 | Automatically generate attack paths from findings. |
| `generate_executive_summary` |  | redteam_v2 | Generate executive summary for an engagement. |
| `get_detection_coverage` |  | redteam_v2 | Get detection coverage for an engagement. |
| `get_mitre_coverage` |  | redteam_v2 | Calculate MITRE coverage for an engagement. |
| `get_state` |  | redteam_v2 | Get agent state. |
| `get_technique` |  | redteam_v2 | Get MITRE technique details. |
| `get_techniques_by_tactic` |  | redteam_v2 | Get all techniques for a tactic. |
| `identify_pivot_points` |  | redteam_v2 | Identify lateral movement pivot points. |
| `map_finding_to_mitre` |  | redteam_v2 | Map a finding to MITRE ATT&CK techniques. |

## research - ResearchAgent

*Category:* Data - Research and analysis

| Op | Async | Source | Details |
|---|---|---|---|
| `add_citation` |  | research | Add a citation between publications. |
| `add_finding` |  | research | Add finding to project. |
| `add_publication` |  | research | Add a publication to the library. |
| `add_publication_to_project` |  | research | Add publication to project. |
| `add_topic` |  | research | Add a research topic. |
| `call_tool` | async | base | Call a tool by name with keyword arguments. |
| `can_create_project` |  | base | Check if agent can create projects. |
| `can_manage_agents` |  | base | Check if agent can manage other agents. |
| `can_read` |  | base | Check if agent has read permission. |
| `can_write` |  | base | Check if agent has write permission. |
| `create_project` |  | research | Create a research project. |
| `find_related_publications` |  | research | Find publications related to a given publication. |
| `format_citation` |  | research | Format citation in specified style. |
| `generate_id` |  | base | Generate a unique ID with the given prefix (static version). |
| `generate_literature_review` |  | research | Generate literature review for a topic. |
| `get_agent_card` |  | base | Generate an A2A-compatible agent card describing this agent. |
| `get_citations_by` |  | research | Get all citations made by a publication. |
| `get_citations_for` |  | research | Get all citations for a publication. |
| `get_project` |  | research | Get project by ID. |
| `get_projects` |  | research | Get projects with filtering. |
| `get_publications` |  | research | Get publications with filtering. |
| `get_state` |  | research | Get agent state summary. |
| `get_status` |  | base | Get agent status. |
| `get_topic_summary` |  | research | Get summary for a topic. |
| `get_transparency_log` |  | base | Get the transparency log entries. |
| `input_guardrail` |  | base | Validate/sanitize input through guardrail pipeline. Returns (sanitized |
| `log` |  | base | Log an action for transparency. |
| `output_guardrail` |  | base | Validate/sanitize output through guardrail pipeline. Returns (sanitize |
| `perform_task` | async | base | Perform a task. Override in subclasses. |
| `process_message` | async | base | Process an incoming message. Override in subclasses. |
| `reason` | async | base | Iterative ReAct reasoning loop: think→act→observe. |
| `receive_message` |  | base | Receive a message from another agent. |
| `reflect` | async | base | Self-critique: evaluate response quality and suggest improvements. |
| `register_tool` |  | base | Register a tool with the agent. |
| `search_publications` |  | research | Search publications by title, abstract, or keywords. |
| `send_message` |  | base | Send a message to another agent. |
| `think` | async | base | Use LLM inference to reason about something. Optionally validate again |
| `tool_guardrail` |  | base | Check if tool call is permitted. Returns is_allowed. |
| `update_citation_count` |  | research | Update citation count for a publication. |
| `update_project_status` |  | research | Update project status. |

## risk - RiskAgent

*Category:* Governance - Risk management

| Op | Async | Source | Details |
|---|---|---|---|
| `assess_risk` |  | risk | Assess risk with controls consideration. |
| `call_tool` | async | base | Call a tool by name with keyword arguments. |
| `can_create_project` |  | base | Check if agent can create projects. |
| `can_manage_agents` |  | base | Check if agent can manage other agents. |
| `can_read` |  | base | Check if agent has read permission. |
| `can_write` |  | base | Check if agent has write permission. |
| `complete_assessment` |  | risk | Complete a risk assessment. |
| `create_assessment` |  | risk | Create a risk assessment. |
| `create_control` |  | risk | Create a risk control. |
| `create_kri` |  | risk | Create a Key Risk Indicator. |
| `generate_id` |  | base | Generate a unique ID with the given prefix (static version). |
| `get_agent_card` |  | base | Generate an A2A-compatible agent card describing this agent. |
| `get_assessments` |  | risk | Get assessments with filtering. |
| `get_controls` |  | risk | Get controls with filtering. |
| `get_events` |  | risk | Get events with filtering. |
| `get_high_priority_risks` |  | risk | Get high priority risks sorted by score. |
| `get_kris` |  | risk | Get KRIs with filtering. |
| `get_kris_at_risk` |  | risk | Get KRIs in yellow or red status. |
| `get_risk_appetite_status` |  | risk | Get risk appetite compliance status. |
| `get_risk_dashboard` |  | risk | Generate risk dashboard summary. |
| `get_risk_register` |  | risk | Generate risk register report. |
| `get_risks` |  | risk | Get risks with filtering. |
| `get_state` |  | risk | Get agent state summary. |
| `get_status` |  | base | Get agent status. |
| `get_transparency_log` |  | base | Get the transparency log entries. |
| `identify_risk` |  | risk | Identify a new risk. |
| `input_guardrail` |  | base | Validate/sanitize input through guardrail pipeline. Returns (sanitized |
| `log` |  | base | Log an action for transparency. |
| `output_guardrail` |  | base | Validate/sanitize output through guardrail pipeline. Returns (sanitize |
| `perform_task` | async | base | Perform a task. Override in subclasses. |
| `plan_treatment` |  | risk | Plan risk treatment. |
| `process_message` | async | base | Process an incoming message. Override in subclasses. |
| `reason` | async | base | Iterative ReAct reasoning loop: think→act→observe. |
| `receive_message` |  | base | Receive a message from another agent. |
| `reflect` | async | base | Self-critique: evaluate response quality and suggest improvements. |
| `register_tool` |  | base | Register a tool with the agent. |
| `report_event` |  | risk | Report a risk event/incident. |
| `resolve_event` |  | risk | Resolve a risk event. |
| `send_message` |  | base | Send a message to another agent. |
| `test_control` |  | risk | Test control effectiveness. |
| `think` | async | base | Use LLM inference to reason about something. Optionally validate again |
| `tool_guardrail` |  | base | Check if tool call is permitted. Returns is_allowed. |
| `update_kri_value` |  | risk | Update KRI value and calculate status. |
| `update_risk_status` |  | risk | Update risk status. |

## sales - SalesAgent

*Category:* Business - Sales and lead management

| Op | Async | Source | Details |
|---|---|---|---|
| `call_tool` | async | base | Call a tool by name with keyword arguments. |
| `can_create_project` |  | base | Check if agent can create projects. |
| `can_manage_agents` |  | base | Check if agent can manage other agents. |
| `can_read` |  | base | Check if agent has read permission. |
| `can_write` |  | base | Check if agent has write permission. |
| `create_lead` |  | sales |  |
| `create_opportunity` |  | sales |  |
| `generate_id` |  | base | Generate a unique ID with the given prefix (static version). |
| `generate_proposal` |  | sales |  |
| `get_agent_card` |  | base | Generate an A2A-compatible agent card describing this agent. |
| `get_status` |  | base | Get agent status. |
| `get_transparency_log` |  | base | Get the transparency log entries. |
| `input_guardrail` |  | base | Validate/sanitize input through guardrail pipeline. Returns (sanitized |
| `log` |  | base | Log an action for transparency. |
| `output_guardrail` |  | base | Validate/sanitize output through guardrail pipeline. Returns (sanitize |
| `perform_task` | async | sales | Perform a task by type. |
| `process_message` | async | base | Process an incoming message. Override in subclasses. |
| `qualify_lead` |  | sales |  |
| `reason` | async | base | Iterative ReAct reasoning loop: think→act→observe. |
| `receive_message` |  | base | Receive a message from another agent. |
| `reflect` | async | base | Self-critique: evaluate response quality and suggest improvements. |
| `register_tool` |  | base | Register a tool with the agent. |
| `send_message` |  | base | Send a message to another agent. |
| `think` | async | base | Use LLM inference to reason about something. Optionally validate again |
| `tool_guardrail` |  | base | Check if tool call is permitted. Returns is_allowed. |
| `update_pipeline` |  | sales |  |

## security - SecurityAgent

*Category:* Cyber - Security operations

| Op | Async | Source | Details |
|---|---|---|---|
| `add_control` |  | security | Add a control to a security assessment. |
| `call_tool` | async | base | Call a tool by name with keyword arguments. |
| `can_create_project` |  | base | Check if agent can create projects. |
| `can_manage_agents` |  | base | Check if agent can manage other agents. |
| `can_read` |  | base | Check if agent has read permission. |
| `can_write` |  | base | Check if agent has write permission. |
| `check_rate_limit` |  | security | Check if action is within rate limits. |
| `create_assessment` |  | security | Create a security assessment. |
| `create_incident` |  | security | Create a new security incident. |
| `detect_anomalies` |  | security | Detect anomalies in access logs. |
| `generate_id` |  | base | Generate a unique ID with the given prefix (static version). |
| `generate_secure_secret` |  | security | Generate a cryptographically secure secret. |
| `generate_security_report` |  | security | Generate a security status report. |
| `get_agent_card` |  | base | Generate an A2A-compatible agent card describing this agent. |
| `get_incidents` |  | security | Get incidents with optional filtering. |
| `get_policy` |  | security | Get a security policy by ID. |
| `get_secrets_due_for_rotation` |  | security | Get secrets due for rotation within specified days. |
| `get_state` |  | security | Get agent state summary. |
| `get_status` |  | base | Get agent status. |
| `get_transparency_log` |  | base | Get the transparency log entries. |
| `input_guardrail` |  | base | Validate/sanitize input through guardrail pipeline. Returns (sanitized |
| `log` |  | base | Log an action for transparency. |
| `log_access` |  | security | Log an access event for security analysis. |
| `output_guardrail` |  | base | Validate/sanitize output through guardrail pipeline. Returns (sanitize |
| `perform_task` | async | base | Perform a task. Override in subclasses. |
| `process_message` | async | base | Process an incoming message. Override in subclasses. |
| `reason` | async | base | Iterative ReAct reasoning loop: think→act→observe. |
| `receive_message` |  | base | Receive a message from another agent. |
| `reflect` | async | base | Self-critique: evaluate response quality and suggest improvements. |
| `register_secret` |  | security | Register a secret for rotation tracking. |
| `register_tool` |  | base | Register a tool with the agent. |
| `rotate_secret` |  | security | Rotate a secret. |
| `scan_code` |  | security | Scan code for security vulnerabilities. |
| `scan_directory` |  | security | Scan a directory recursively for security vulnerabilities. |
| `scan_file` |  | security | Scan a file for security vulnerabilities. |
| `send_message` |  | base | Send a message to another agent. |
| `think` | async | base | Use LLM inference to reason about something. Optionally validate again |
| `tool_guardrail` |  | base | Check if tool call is permitted. Returns is_allowed. |
| `update_incident_status` |  | security | Update incident status. |
| `update_policy` |  | security | Update a security policy. |
| `validate_password` |  | security | Validate password against security policy. |

## soc - SecurityOperationsAgent

*Category:* Cyber - Security operations center

| Op | Async | Source | Details |
|---|---|---|---|
| `add_ioc` |  | soc | Add indicator of compromise to incident. |
| `add_threat_intel` |  | soc | Add threat intelligence indicator. |
| `add_timeline_entry` |  | soc | Add entry to incident timeline. |
| `call_tool` | async | base | Call a tool by name with keyword arguments. |
| `can_create_project` |  | base | Check if agent can create projects. |
| `can_manage_agents` |  | base | Check if agent can manage other agents. |
| `can_read` |  | base | Check if agent has read permission. |
| `can_write` |  | base | Check if agent has write permission. |
| `close_incident` |  | soc | Close an incident with full documentation. |
| `create_alert` |  | soc | Create a security alert. |
| `create_hunt` |  | soc | Create a threat hunting query. |
| `create_incident` |  | soc | Create a security incident. |
| `escalate_alert` |  | soc | Escalate alert to incident. |
| `execute_hunt` |  | soc | Execute a threat hunt and record findings. |
| `generate_id` |  | base | Generate a unique ID with the given prefix (static version). |
| `get_agent_card` |  | base | Generate an A2A-compatible agent card describing this agent. |
| `get_alerts` |  | soc | Get alerts with filtering. |
| `get_attack_mapping` |  | soc | Map incident to MITRE ATT&CK framework. |
| `get_hunts` |  | soc | Get hunts with filtering. |
| `get_incidents` |  | soc | Get incidents with filtering. |
| `get_soc_metrics` |  | soc | Get SOC operational metrics. |
| `get_state` |  | soc | Get agent state summary. |
| `get_status` |  | base | Get agent status. |
| `get_threat_intel` |  | soc | Get threat intel with filtering. |
| `get_transparency_log` |  | base | Get the transparency log entries. |
| `get_wazuh_metrics` |  | soc | Combined local+poller status, suitable for a daily report. |
| `ingest_wazuh_alert` |  | soc | Convert one Wazuh alert JSON into a SecurityAlert and add to local sta |
| `ingest_wazuh_alerts` |  | soc | Ingest a batch of Wazuh alerts. |
| `input_guardrail` |  | base | Validate/sanitize input through guardrail pipeline. Returns (sanitized |
| `log` |  | base | Log an action for transparency. |
| `output_guardrail` |  | base | Validate/sanitize output through guardrail pipeline. Returns (sanitize |
| `perform_task` | async | base | Perform a task. Override in subclasses. |
| `process_message` | async | base | Process an incoming message. Override in subclasses. |
| `reason` | async | base | Iterative ReAct reasoning loop: think→act→observe. |
| `receive_message` |  | base | Receive a message from another agent. |
| `record_outbound_subject` |  | soc | Record that an incident was emailed out, so a future reply can |
| `reflect` | async | base | Self-critique: evaluate response quality and suggest improvements. |
| `register_tool` |  | base | Register a tool with the agent. |
| `report_security_incident` |  | soc | Report a security incident. Convenience method that maps to create_inc |
| `search_threat_intel` |  | soc | Search threat intel by value. |
| `send_message` |  | base | Send a message to another agent. |
| `start_wazuh_poller` |  | soc | Build a WazuhPoller that calls ingest_wazuh_alerts on each poll. |
| `stop_wazuh_poller` |  | soc |  |
| `think` | async | base | Use LLM inference to reason about something. Optionally validate again |
| `tool_guardrail` |  | base | Check if tool call is permitted. Returns is_allowed. |
| `triage_alert` |  | soc | Triage a security alert. |
| `triage_inbound_email` |  | soc | Process one inbound email addressed to a SOC inbox (reports@). |
| `update_incident_status` |  | soc | Update incident status. Accepts IncidentStatus enum or string. |

## supply_chain - SupplyChainAgent

*Category:* Governance - Software supply chain

| Op | Async | Source | Details |
|---|---|---|---|
| `add_package` |  | supply_chain | Add package to inventory. |
| `add_vendor` |  | supply_chain | Add vendor to registry. |
| `add_vulnerability` |  | supply_chain | Add vulnerability for a package. |
| `analyze_sbom` |  | supply_chain | Analyze SBOM for vulnerabilities. |
| `calculate_vendor_risk` |  | supply_chain | Calculate vendor risk score. |
| `call_tool` | async | base | Call a tool by name with keyword arguments. |
| `can_create_project` |  | base | Check if agent can create projects. |
| `can_manage_agents` |  | base | Check if agent can manage other agents. |
| `can_read` |  | base | Check if agent has read permission. |
| `can_write` |  | base | Check if agent has write permission. |
| `complete_assessment` |  | supply_chain | Complete vendor assessment. |
| `create_assessment` |  | supply_chain | Create vendor assessment. |
| `create_sbom` |  | supply_chain | Create SBOM for a project. |
| `generate_id` |  | base | Generate a unique ID with the given prefix (static version). |
| `get_agent_card` |  | base | Generate an A2A-compatible agent card describing this agent. |
| `get_assessments` |  | supply_chain | Get assessments with filtering. |
| `get_dependency_tree` |  | supply_chain | Get dependency tree for a package. |
| `get_incidents` |  | supply_chain | Get incidents with filtering. |
| `get_packages` |  | supply_chain | Get packages with filtering. |
| `get_sboms` |  | supply_chain | Get SBOMs with filtering. |
| `get_state` |  | supply_chain | Get agent state summary. |
| `get_status` |  | base | Get agent status. |
| `get_supply_chain_report` |  | supply_chain | Generate supply chain security report. |
| `get_transparency_log` |  | base | Get the transparency log entries. |
| `get_vendor_risk_report` |  | supply_chain | Get vendor risk report. |
| `get_vendors` |  | supply_chain | Get vendors with filtering. |
| `get_vulnerabilities` |  | supply_chain | Get vulnerabilities with filtering. |
| `input_guardrail` |  | base | Validate/sanitize input through guardrail pipeline. Returns (sanitized |
| `log` |  | base | Log an action for transparency. |
| `output_guardrail` |  | base | Validate/sanitize output through guardrail pipeline. Returns (sanitize |
| `perform_task` | async | base | Perform a task. Override in subclasses. |
| `process_message` | async | base | Process an incoming message. Override in subclasses. |
| `reason` | async | base | Iterative ReAct reasoning loop: think→act→observe. |
| `receive_message` |  | base | Receive a message from another agent. |
| `reflect` | async | base | Self-critique: evaluate response quality and suggest improvements. |
| `register_tool` |  | base | Register a tool with the agent. |
| `report_incident` |  | supply_chain | Report supply chain security incident. |
| `resolve_incident` |  | supply_chain | Resolve security incident. |
| `send_message` |  | base | Send a message to another agent. |
| `think` | async | base | Use LLM inference to reason about something. Optionally validate again |
| `tool_guardrail` |  | base | Check if tool call is permitted. Returns is_allowed. |
| `update_vulnerability_status` |  | supply_chain | Update vulnerability status. |

## support - SupportAgent

*Category:* Operations - Customer support

| Op | Async | Source | Details |
|---|---|---|---|
| `add_knowledge_article` |  | support | Add a new knowledge base article. |
| `add_message` |  | support | Add a message to a ticket. |
| `call_tool` | async | base | Call a tool by name with keyword arguments. |
| `can_create_project` |  | base | Check if agent can create projects. |
| `can_manage_agents` |  | base | Check if agent can manage other agents. |
| `can_read` |  | base | Check if agent has read permission. |
| `can_write` |  | base | Check if agent has write permission. |
| `check_sla_breaches` |  | support | Check for SLA breaches. |
| `create_ticket` |  | support | Create a new support ticket. |
| `generate_id` |  | base | Generate a unique ID with the given prefix (static version). |
| `get_agent_card` |  | base | Generate an A2A-compatible agent card describing this agent. |
| `get_auto_response` |  | support | Get auto-response for ticket based on category. |
| `get_state` |  | support | Get agent state summary. |
| `get_status` |  | base | Get agent status. |
| `get_support_metrics` |  | support | Get support metrics report. |
| `get_tickets` |  | support | Get tickets with filtering. |
| `get_transparency_log` |  | base | Get the transparency log entries. |
| `input_guardrail` |  | base | Validate/sanitize input through guardrail pipeline. Returns (sanitized |
| `log` |  | base | Log an action for transparency. |
| `output_guardrail` |  | base | Validate/sanitize output through guardrail pipeline. Returns (sanitize |
| `perform_task` | async | base | Perform a task. Override in subclasses. |
| `process_message` | async | base | Process an incoming message. Override in subclasses. |
| `rate_article` |  | support | Rate a knowledge base article. |
| `reason` | async | base | Iterative ReAct reasoning loop: think→act→observe. |
| `receive_message` |  | base | Receive a message from another agent. |
| `record_satisfaction` |  | support | Record customer satisfaction score. |
| `reflect` | async | base | Self-critique: evaluate response quality and suggest improvements. |
| `register_tool` |  | base | Register a tool with the agent. |
| `resolve_ticket` |  | support | Resolve a ticket. |
| `search_knowledge_base` |  | support | Search knowledge base articles. |
| `send_message` |  | base | Send a message to another agent. |
| `think` | async | base | Use LLM inference to reason about something. Optionally validate again |
| `tool_guardrail` |  | base | Check if tool call is permitted. Returns is_allowed. |
| `update_ticket_status` |  | support | Update ticket status. |

## sysadmin - SysAdminAgent

*Category:* Core - System administration

| Op | Async | Source | Details |
|---|---|---|---|
| `analyze_logs` |  | sysadmin | Analyze system logs for a service. |
| `call_tool` | async | base | Call a tool by name with keyword arguments. |
| `can_create_project` |  | base | Check if agent can create projects. |
| `can_manage_agents` |  | base | Check if agent can manage other agents. |
| `can_read` |  | base | Check if agent has read permission. |
| `can_write` |  | base | Check if agent has write permission. |
| `check_service` |  | sysadmin | Check or manage a system service. |
| `check_system` |  | sysadmin |  |
| `create_incident` |  | sysadmin |  |
| `generate_id` |  | base | Generate a unique ID with the given prefix (static version). |
| `get_agent_card` |  | base | Generate an A2A-compatible agent card describing this agent. |
| `get_status` |  | base | Get agent status. |
| `get_system_status` |  | sysadmin |  |
| `get_transparency_log` |  | base | Get the transparency log entries. |
| `input_guardrail` |  | base | Validate/sanitize input through guardrail pipeline. Returns (sanitized |
| `list_incidents` |  | sysadmin |  |
| `log` |  | base | Log an action for transparency. |
| `output_guardrail` |  | base | Validate/sanitize output through guardrail pipeline. Returns (sanitize |
| `perform_task` | async | sysadmin | Perform a task. Override in subclasses. |
| `process_message` | async | base | Process an incoming message. Override in subclasses. |
| `reason` | async | base | Iterative ReAct reasoning loop: think→act→observe. |
| `receive_message` |  | base | Receive a message from another agent. |
| `reflect` | async | base | Self-critique: evaluate response quality and suggest improvements. |
| `register_tool` |  | base | Register a tool with the agent. |
| `resolve_incident` |  | sysadmin |  |
| `run_command` |  | sysadmin | Execute an allowlisted system command (safe mode — read-only diagnosti |
| `send_message` |  | base | Send a message to another agent. |
| `think` | async | base | Use LLM inference to reason about something. Optionally validate again |
| `tool_guardrail` |  | base | Check if tool call is permitted. Returns is_allowed. |

## vendor_risk - VendorRiskAgent

*Category:* Governance - Vendor risk management

| Op | Async | Source | Details |
|---|---|---|---|
| `acknowledge_alert` |  | vendor_risk | Acknowledge alert. |
| `add_vendor` |  | vendor_risk | Add vendor to registry. |
| `call_tool` | async | base | Call a tool by name with keyword arguments. |
| `can_create_project` |  | base | Check if agent can create projects. |
| `can_manage_agents` |  | base | Check if agent can manage other agents. |
| `can_read` |  | base | Check if agent has read permission. |
| `can_write` |  | base | Check if agent has write permission. |
| `complete_assessment` |  | vendor_risk | Complete assessment. |
| `create_alert` |  | vendor_risk | Create vendor risk alert. |
| `create_assessment` |  | vendor_risk | Create vendor risk assessment. |
| `create_finding` |  | vendor_risk | Create assessment finding. |
| `create_questionnaire` |  | vendor_risk | Create vendor questionnaire. |
| `enable_monitoring` |  | vendor_risk | Enable continuous monitoring for vendor. |
| `generate_id` |  | base | Generate a unique ID with the given prefix (static version). |
| `get_agent_card` |  | base | Generate an A2A-compatible agent card describing this agent. |
| `get_alerts` |  | vendor_risk | Get alerts with filtering. |
| `get_assessments` |  | vendor_risk | Get assessments with filtering. |
| `get_findings` |  | vendor_risk | Get findings with filtering. |
| `get_monitors` |  | vendor_risk | Get monitors with filtering. |
| `get_questionnaires` |  | vendor_risk | Get questionnaires with filtering. |
| `get_state` |  | vendor_risk | Get agent state summary. |
| `get_status` |  | base | Get agent status. |
| `get_transparency_log` |  | base | Get the transparency log entries. |
| `get_vendor_risk_dashboard` |  | vendor_risk | Generate vendor risk dashboard. |
| `get_vendor_risk_report` |  | vendor_risk | Generate vendor risk report. |
| `get_vendors` |  | vendor_risk | Get vendors with filtering. |
| `get_vendors_due_for_assessment` |  | vendor_risk | Get vendors due for assessment within specified days. |
| `input_guardrail` |  | base | Validate/sanitize input through guardrail pipeline. Returns (sanitized |
| `log` |  | base | Log an action for transparency. |
| `output_guardrail` |  | base | Validate/sanitize output through guardrail pipeline. Returns (sanitize |
| `perform_task` | async | base | Perform a task. Override in subclasses. |
| `process_message` | async | base | Process an incoming message. Override in subclasses. |
| `reason` | async | base | Iterative ReAct reasoning loop: think→act→observe. |
| `receive_message` |  | base | Receive a message from another agent. |
| `record_monitoring_result` |  | vendor_risk | Record monitoring check result. |
| `reflect` | async | base | Self-critique: evaluate response quality and suggest improvements. |
| `register_tool` |  | base | Register a tool with the agent. |
| `resolve_alert` |  | vendor_risk | Resolve alert. |
| `respond_to_question` |  | vendor_risk | Record question response. |
| `send_message` |  | base | Send a message to another agent. |
| `send_questionnaire` |  | vendor_risk | Send questionnaire to vendor. |
| `start_assessment` |  | vendor_risk | Start assessment. |
| `think` | async | base | Use LLM inference to reason about something. Optionally validate again |
| `tool_guardrail` |  | base | Check if tool call is permitted. Returns is_allowed. |
| `update_finding` |  | vendor_risk | Update finding details. |
| `update_finding_status` |  | vendor_risk | Update finding status. |
| `update_vendor_risk` |  | vendor_risk | Update vendor residual risk. |

## vulnman - VulnerabilityManagementAgent

*Category:* Cyber - Vulnerability management

| Op | Async | Source | Details |
|---|---|---|---|
| `add_asset` |  | vulnman | Add an asset to inventory. |
| `add_patch` |  | vulnman | Add a patch to track. |
| `add_vulnerability` |  | vulnman | Add a vulnerability finding. |
| `call_tool` | async | base | Call a tool by name with keyword arguments. |
| `can_create_project` |  | base | Check if agent can create projects. |
| `can_manage_agents` |  | base | Check if agent can manage other agents. |
| `can_read` |  | base | Check if agent has read permission. |
| `can_write` |  | base | Check if agent has write permission. |
| `complete_scan` |  | vulnman | Mark a scan as completed. |
| `create_scan` |  | vulnman | Create a vulnerability scan. |
| `deploy_patch` |  | vulnman | Simulate patch deployment. |
| `generate_id` |  | base | Generate a unique ID with the given prefix (static version). |
| `get_agent_card` |  | base | Generate an A2A-compatible agent card describing this agent. |
| `get_asset_risk_profile` |  | vulnman | Get risk profile for an asset. |
| `get_assets` |  | vulnman | Get assets with filtering. |
| `get_overdue_vulnerabilities` |  | vulnman | Get vulnerabilities past due date. |
| `get_patches` |  | vulnman | Get patches with filtering. |
| `get_remediation_priority` |  | vulnman | Get prioritized remediation list. |
| `get_scans` |  | vulnman | Get scans with filtering. |
| `get_state` |  | vulnman | Get agent state summary. |
| `get_status` |  | base | Get agent status. |
| `get_transparency_log` |  | base | Get the transparency log entries. |
| `get_vuln_metrics` |  | vulnman | Get vulnerability management metrics. |
| `get_vulnerabilities` |  | vulnman | Get vulnerabilities with filtering. |
| `input_guardrail` |  | base | Validate/sanitize input through guardrail pipeline. Returns (sanitized |
| `log` |  | base | Log an action for transparency. |
| `output_guardrail` |  | base | Validate/sanitize output through guardrail pipeline. Returns (sanitize |
| `perform_task` | async | base | Perform a task. Override in subclasses. |
| `process_message` | async | base | Process an incoming message. Override in subclasses. |
| `reason` | async | base | Iterative ReAct reasoning loop: think→act→observe. |
| `receive_message` |  | base | Receive a message from another agent. |
| `reflect` | async | base | Self-critique: evaluate response quality and suggest improvements. |
| `register_tool` |  | base | Register a tool with the agent. |
| `send_message` |  | base | Send a message to another agent. |
| `think` | async | base | Use LLM inference to reason about something. Optionally validate again |
| `tool_guardrail` |  | base | Check if tool call is permitted. Returns is_allowed. |
| `update_asset_vuln_count` |  | vulnman | Update asset vulnerability count. |
| `update_vulnerability_status` |  | vulnman | Update vulnerability status. |

