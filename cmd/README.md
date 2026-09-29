# Agentic AI CLI

Command-line interface for managing Agentic AI agents and operations.

## Installation

```bash
# Install from source
pip install -e .

# Or run directly
python -m agentic_ai.cli --help
```

## Quick Start

```bash
# Check agent status
agenticai status

# List all agents
agenticai agent list

# Create chaos experiment
agenticai chaos experiment create --name "Test" --type instance_termination

# List vendors
agenticai vendor list

# Create audit
agenticai audit create --title "SOC2 Audit" --type it_general
```

## Commands

### Agent Management
- `agenticai agent list` - List all registered agents
- `agenticai agent info <id>` - Get agent details
- `agenticai agent status` - Health check all agents

### Chaos Monkey
- `agenticai chaos experiment create` - Create new experiment
- `agenticai chaos experiment start` - Start experiment
- `agenticai chaos experiment list` - List experiments
- `agenticai chaos target list` - List chaos targets
- `agenticai chaos status` - Show chaos dashboard

### Vendor Risk
- `agenticai vendor list` - List vendors
- `agenticai vendor add` - Add new vendor
- `agenticai vendor assess` - Start assessment
- `agenticai vendor report` - Generate report

### Audit
- `agenticai audit list` - List audits
- `agenticai audit create` - Create audit
- `agenticai audit status` - Audit status
- `agenticai audit report` - Generate report

### Cloud Security
- `agenticai cloud account list` - List cloud accounts
- `agenticai cloud finding list` - List findings
- `agenticai cloud compliance` - Compliance scores

### ML Ops
- `agenticai ml model list` - List models
- `agenticai ml experiment list` - List experiments
- `agenticai ml drift check` - Check for drift

### Configuration
- `agenticai config get` - Get config value
- `agenticai config set` - Set config value
- `agenticai config list` - List all config

### System
- `agenticai doctor` - Health check
- `agenticai logs` - View logs

## Examples

### Run Chaos Experiment
```bash
# Create and start experiment
agenticai chaos experiment create \
  --name "AZ Failure Test" \
  --type az_failure \
  --severity high \
  --duration 30

# Check status
agenticai chaos status
```

### Vendor Assessment
```bash
# Add vendor
agenticai vendor add \
  --name "CloudProvider Inc" \
  --tier 1 \
  --category cloud

# Start assessment
agenticai vendor assess --vendor-id vendor-123

# Get report
agenticai vendor report --vendor-id vendor-123
```

### Audit Management
```bash
# Create SOC2 audit
agenticai audit create \
  --title "SOC2 Type II 2026" \
  --type it_general \
  --auditor "external@auditfirm.com"

# Check progress
agenticai audit status --audit-id audit-123
```

## Run any agent (generic surfaces, no LLM required)

```bash
agenticai agent list                       # registry: id, class, category
agenticai agent card security              # dry-run: instantiate + agent card
agenticai agent ops security               # op menu (Source column: role vs base)
agenticai agent run security --op scan_code \
  --args '{"code": "password = \"x\""}'    # one op, JSON out
agenticai agent run developer --task implement \
  --payload '{"feature": "x", "language": "python"}'
```

Agent ids come from `agentic_ai/agents/registry.py` (35 agent ids + base).
Aliases: chaos→chaos_monkey, vendor→vendor_risk, cloud→cloud_security,
ml/mlops→ml_ops. Verified examples: skills/agentic-roles/references/.
