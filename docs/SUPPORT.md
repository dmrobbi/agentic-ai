# SupportAgent - Customer Support & Ticket Management

**Version:** 1.0.0  
**Status:** Production Ready ✅

---

## Overview

The **SupportAgent** provides ticket management, auto-triage, auto-responses, knowledge base search, SLA tracking, and customer satisfaction tracking for customer support operations.

### Key Capabilities

- 🎫 **Ticket Management** - Create, triage, update, resolve tickets
- 🤖 **Auto-Triage** - Automatic category and priority assignment
- 💬 **Auto-Responses** - Category-based automated responses
- 📚 **Knowledge Base** - Search, rate, and manage articles
- ⏱️ **SLA Tracking** - Monitor response and resolution times
- ⭐ **Satisfaction** - Customer satisfaction scoring

---

## Quick Start

```python
from agentic_ai.agents.support import SupportAgent

# Initialize
support = SupportAgent()

# Create ticket (auto-triaged)
ticket = support.create_ticket(
    subject="Can't login",
    description="Forgot my password",
    customer_id="cust-123",
    customer_email="user@example.com",
)

print(f"Category: {ticket.category.value}")
print(f"Priority: {ticket.priority.value}")
```

---

## Ticket Management

### Create Ticket

```python
from agentic_ai.agents.support import SupportAgent, TicketPriority, TicketCategory

support = SupportAgent()

ticket = support.create_ticket(
    subject="Unable to access dashboard",
    description="Getting 403 error when trying to access analytics",
    customer_id="cust-001",
    customer_email="john@example.com",
    category=TicketCategory.TECHNICAL,  # Optional: auto-detected
    priority=TicketPriority.NORMAL,      # Optional: auto-detected
    tags=["dashboard", "403", "access"],
)
```

### Auto-Triage

Tickets are automatically categorized and prioritized based on content:

| Keywords | Category |
|----------|----------|
| password, login, account | ACCOUNT |
| billing, invoice, payment | BILLING |
| bug, error, crash | BUG_REPORT |
| feature, request, suggestion | FEATURE_REQUEST |
| api, integration, technical | TECHNICAL |

| Keywords | Priority |
|----------|----------|
| urgent, critical, down, emergency | HIGH |
| please, help, question | NORMAL |

### Update Ticket Status

```python
from agentic_ai.agents.support import TicketStatus

# In progress
support.update_ticket_status(
    ticket.ticket_id,
    TicketStatus.IN_PROGRESS,
    assigned_to="agent-1",
)

# Waiting for customer
support.update_ticket_status(
    ticket.ticket_id,
    TicketStatus.WAITING_CUSTOMER,
)

# Resolved
support.update_ticket_status(
    ticket.ticket_id,
    TicketStatus.RESOLVED,
)
```

### Add Messages

```python
# Agent response
support.add_message(
    ticket.ticket_id,
    "Thanks for contacting support. Can you tell me which browser you're using?",
    "agent@example.com",
    is_internal=False,
)

# Customer reply
support.add_message(
    ticket.ticket_id,
    "I'm using Chrome version 120",
    "customer",
)

# Internal note
support.add_message(
    ticket.ticket_id,
    "This seems related to the recent cache issue",
    "agent@example.com",
    is_internal=True,
)
```

### Resolve Ticket

```python
resolved = support.resolve_ticket(
    ticket.ticket_id,
    resolution="Cleared server-side cache, customer confirmed resolution",
    resolved_by="agent-1",
)

print(f"Resolution time: {resolved.resolution_time:.1f} minutes")
```

### Record Satisfaction

```python
support.record_satisfaction(ticket.ticket_id, score=5)  # 1-5
```

### Get Tickets

```python
# All tickets
tickets = support.get_tickets()

# Filter by status
open_tickets = support.get_tickets(status=TicketStatus.OPEN)

# Filter by priority
urgent = support.get_tickets(priority=TicketPriority.HIGH)

# Filter by category
technical = support.get_tickets(category=TicketCategory.TECHNICAL)

# Filter by assignee
my_tickets = support.get_tickets(assigned_to="agent-1")

# Limit results
recent = support.get_tickets(limit=10)
```

---

## Auto-Responses

### Get Auto-Response

```python
response = support.get_auto_response(ticket)

if response:
    print(f"Auto-response: {response}")
else:
    print("No auto-response available (requires human agent)")
```

### Default Auto-Responses

| Category | Trigger | Response |
|----------|---------|----------|
| ACCOUNT | password | Password reset instructions |
| ACCOUNT | locked | Account unlock instructions |
| BILLING | any | Billing contact info |
| FEATURE_REQUEST | any | Feature request acknowledgment |
| BUG_REPORT | any | Bug report acknowledgment |

### Customize Auto-Responses

```python
support.auto_responses['custom_issue'] = "For {issue_type}, please visit {base_url}/help/{issue_type}"

# Use in ticket handling
response = support.auto_responses['custom_issue'].format(
    issue_type="billing",
    base_url="https://example.com"
)
```

---

## Knowledge Base

### Search Knowledge Base

```python
articles = support.search_knowledge_base("password reset")

for article in articles:
    print(f"📄 {article.title}")
    print(f"   Category: {article.category}")
    print(f"   Views: {article.views}")
    print(f"   Helpful: {article.helpful_count} 👍")
```

### Rate Article

```python
# Mark as helpful
support.rate_article(article_id, helpful=True)

# Mark as not helpful
support.rate_article(article_id, helpful=False)
```

### Add Article

```python
article = support.add_knowledge_article(
    title="How to Enable Two-Factor Authentication",
    content="Step 1: Go to Settings. Step 2: Click Security...",
    category="security",
    tags=["2fa", "security", "authentication"],
)
```

---

## SLA Management

### Default SLAs

| Priority | First Response | Resolution |
|----------|---------------|------------|
| CRITICAL | 15 minutes | 1 hour |
| HIGH | 1 hour | 4 hours |
| NORMAL | 4 hours | 24 hours |
| LOW | 24 hours | 3 days |

### Check SLA Breaches

```python
breaches = support.check_sla_breaches()

if breaches:
    print(f"⚠️  {len(breaches)} SLA breach(es):")
    for breach in breaches:
        print(f"  - {breach.subject} ({breach.priority.value})")
```

---

## Support Metrics

### Get Metrics Report

```python
metrics = support.get_support_metrics(days=30)

print(f"Period: {metrics['period_days']} days")
print(f"Total Tickets: {metrics['total_tickets']}")
print(f"Open: {metrics['open_count']}")
print(f"Resolved: {metrics['resolved_count']}")

print(f"\nBy Status:")
for status, count in metrics['by_status'].items():
    print(f"  {status}: {count}")

print(f"\nBy Priority:")
for priority, count in metrics['by_priority'].items():
    print(f"  {priority}: {count}")

print(f"\nPerformance:")
print(f"  Avg Resolution: {metrics['avg_resolution_time_minutes']:.1f} min")
print(f"  Avg Satisfaction: {metrics['avg_satisfaction_score']:.1f}/5 ⭐")
print(f"  SLA Breaches: {metrics['sla_breaches']}")
```

---

## Ticket Statuses

| Status | Description |
|--------|-------------|
| `new` | Newly created ticket |
| `open` | Agent is working on it |
| `in_progress` | Actively being resolved |
| `waiting_customer` | Waiting for customer response |
| `resolved` | Issue resolved |
| `closed` | Ticket closed (final state) |

---

## Ticket Priorities

| Priority | Response Time | Use Case |
|----------|--------------|----------|
| `critical` | 15 min | System down, data loss |
| `high` | 1 hour | Major feature broken |
| `normal` | 4 hours | General issues |
| `low` | 24 hours | Feature requests, questions |

---

## Ticket Categories

| Category | Description |
|----------|-------------|
| `technical` | Technical issues, API, integration |
| `billing` | Invoices, payments, refunds |
| `account` | Login, password, profile |
| `feature_request` | New feature suggestions |
| `bug_report` | Bugs and errors |
| `general` | General inquiries |

---

## Examples

See `examples/support_tickets.py` for comprehensive examples:

```bash
cd ~/agentic-ai/agentic_ai
PYTHONPATH=. ./venv/bin/python examples/support_tickets.py
```

**Examples Include:**
1. Ticket creation & auto-triage
2. Complete ticket workflow
3. Auto-responses
4. Knowledge base management
5. SLA tracking
6. Support metrics

---

## Testing

```bash
# Run unit tests
pytest tests/test_support_agent.py -v
```

**Test Coverage:**
- Initialization (2 tests)
- Ticket management (8 tests)
- Auto-triage (2 tests)
- Auto-responses (2 tests)
- Knowledge base (3 tests)
- SLA management (1 test)
- Support metrics (1 test)
- Capabilities export (1 test)

---

## Lead Agent Integration

```python
from agentic_ai.agents.support import get_capabilities

caps = get_capabilities()

# Returns:
# {
#   'agent_type': 'support',
#   'version': '1.0.0',
#   'capabilities': ['create_ticket', 'resolve_ticket', ...],
#   'ticket_statuses': [...],
#   'ticket_priorities': [...],
#   'ticket_categories': [...],
# }
```

---

## Best Practices

### 1. Auto-Triage Tickets

```python
# Let the agent auto-triage
ticket = support.create_ticket(
    subject=subject,
    description=description,
    customer_id=customer_id,
    customer_email=email,
    # Don't specify category/priority - let AI detect
)

# Review auto-assigned values
print(f"Category: {ticket.category.value}")
print(f"Priority: {ticket.priority.value}")
```

### 2. Use Auto-Responses

```python
# Check for auto-response before manual reply
response = support.get_auto_response(ticket)

if response:
    support.add_message(ticket.ticket_id, response, "agent@example.com")
else:
    # Requires human agent
    assign_to_human(ticket)
```

### 3. Monitor SLAs

```python
# Check breaches every hour
breaches = support.check_sla_breaches()

for breach in breaches:
    # Escalate
    notify_manager(breach)
    
    # Take action
    support.update_ticket_status(
        breach.ticket_id,
        TicketStatus.IN_PROGRESS,
        assigned_to="senior-agent",
    )
```

### 4. Track Satisfaction

```python
# Record satisfaction on resolution
support.resolve_ticket(ticket_id, resolution, agent_id)
support.record_satisfaction(ticket_id, customer_rating)

# Monitor trends
metrics = support.get_support_metrics(days=7)
if metrics['avg_satisfaction_score'] < 4.0:
    print("Warning: Satisfaction dropping")
```

### 5. Maintain Knowledge Base

```python
# Search before creating new article
existing = support.search_knowledge_base(query)

if not existing:
    # Add new article from resolved ticket
    support.add_knowledge_article(
        title=ticket.subject,
        content=ticket.resolution,
        category=ticket.category.value,
    )
```

---

## Support

- **Documentation:** `docs/SUPPORT.md`
- **Examples:** `examples/support_tickets.py`
- **Tests:** `tests/test_support_agent.py`
- **Issues:** https://github.com/openclaw/openclaw/issues

---

**SupportAgent v1.0.0 - Production Ready** 🎫
