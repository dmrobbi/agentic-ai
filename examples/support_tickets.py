#!/usr/bin/env python3
"""
SupportAgent Examples
=====================

Demonstrates ticket management, auto-triage, knowledge base,
SLA tracking, and customer satisfaction.
"""

from agentic_ai.agents.support import (
    SupportAgent,
    TicketStatus,
    TicketPriority,
    TicketCategory,
)

import random


def example_ticket_creation():
    """Example: Ticket creation and auto-triage."""
    print("=" * 70)
    print("Example 1: Ticket Creation & Auto-Triage")
    print("=" * 70)
    print()
    
    agent = SupportAgent()
    
    # Create various tickets
    tickets_data = [
        ("Can't login", "I forgot my password and need to reset it"),
        ("Billing question", "I was charged twice this month"),
        ("App crashes on startup", "Every time I open the app it crashes immediately"),
        ("Feature request", "It would be great to have dark mode"),
        ("API integration help", "Need help with webhook setup"),
        ("General inquiry", "What are your business hours?"),
    ]
    
    print("Creating tickets...\n")
    
    for subject, description in tickets_data:
        ticket = agent.create_ticket(
            subject=subject,
            description=description,
            customer_id=f"cust-{len(agent.tickets)+1}",
            customer_email=f"user{len(agent.tickets)+1}@example.com",
        )
        
        print(f"Ticket #{ticket.ticket_id[-4:]}: {ticket.subject}")
        print(f"  Category: {ticket.category.value}")
        print(f"  Priority: {ticket.priority.value}")
        print(f"  Assigned: {ticket.assigned_to or 'Unassigned'}")
        print()


def example_ticket_workflow():
    """Example: Complete ticket workflow."""
    print("=" * 70)
    print("Example 2: Ticket Workflow")
    print("=" * 70)
    print()
    
    agent = SupportAgent()
    
    # Create ticket
    print("Creating ticket...")
    ticket = agent.create_ticket(
        subject="Unable to access dashboard",
        description="Getting 403 error when trying to access analytics dashboard",
        customer_id="cust-001",
        customer_email="john@example.com",
    )
    
    print(f"  Ticket created: {ticket.ticket_id}")
    print(f"  Status: {ticket.status.value}")
    print()
    
    # Agent responds
    print("Agent responds...")
    agent.add_message(
        ticket.ticket_id,
        "Hi John, thanks for contacting support. Can you tell me which browser you're using?",
        "agent@example.com",
    )
    agent.update_ticket_status(ticket.ticket_id, TicketStatus.IN_PROGRESS, "agent-1")
    print(f"  Status: {ticket.status.value}")
    print()
    
    # Customer replies
    print("Customer replies...")
    agent.add_message(
        ticket.ticket_id,
        "I'm using Chrome version 120",
        "customer",
    )
    print(f"  Status: {ticket.status.value}")
    print()
    
    # Agent resolves
    print("Agent resolves...")
    agent.add_message(
        ticket.ticket_id,
        "Thanks! I've cleared your cache on our end. Please try again and let me know if you still have issues.",
        "agent@example.com",
    )
    agent.update_ticket_status(ticket.ticket_id, TicketStatus.WAITING_CUSTOMER)
    
    # Customer confirms fix
    agent.add_message(
        ticket.ticket_id,
        "Working now, thanks!",
        "customer",
    )
    
    # Close ticket
    agent.resolve_ticket(
        ticket.ticket_id,
        "Cleared server-side cache, customer confirmed resolution",
        "agent-1",
    )
    
    print(f"  Status: {ticket.status.value}")
    print(f"  Resolution time: {ticket.resolution_time:.1f} minutes")
    print()
    
    # Customer satisfaction
    print("Customer rates support...")
    agent.record_satisfaction(ticket.ticket_id, 5)
    print(f"  Satisfaction score: {ticket.satisfaction_score}/5 ⭐")


def example_auto_responses():
    """Example: Auto-responses based on ticket category."""
    print("\n" + "=" * 70)
    print("Example 3: Auto-Responses")
    print("=" * 70)
    print()
    
    agent = SupportAgent()
    
    # Create tickets that trigger auto-responses
    scenarios = [
        ("Password reset needed", "I can't remember my password"),
        ("Billing inquiry", "Question about my latest invoice"),
        ("New feature idea", "Would love to see export to CSV"),
        ("Bug report", "Getting error 500 when uploading files"),
    ]
    
    print("Creating tickets and checking auto-responses...\n")
    
    for subject, description in scenarios:
        ticket = agent.create_ticket(
            subject=subject,
            description=description,
            customer_id=f"cust-{len(agent.tickets)+1}",
            customer_email="user@example.com",
        )
        
        response = agent.get_auto_response(ticket)
        
        print(f"Ticket: {ticket.subject}")
        print(f"  Category: {ticket.category.value}")
        if response:
            print(f"  Auto-response: {response[:80]}...")
        else:
            print("  Auto-response: None (requires human agent)")
        print()


def example_knowledge_base():
    """Example: Knowledge base search and management."""
    print("=" * 70)
    print("Example 4: Knowledge Base")
    print("=" * 70)
    print()
    
    agent = SupportAgent()
    
    # Search existing articles
    print("Searching knowledge base for 'password'...\n")
    articles = agent.search_knowledge_base("password")
    
    for article in articles:
        print(f"  📄 {article.title}")
        print(f"     Category: {article.category}")
        print(f"     Views: {article.views}")
        print(f"     Helpful: {article.helpful_count} 👍 / {article.not_helpful_count} 👎")
        print()
    
    # Add new article
    print("Adding new article...\n")
    new_article = agent.add_knowledge_article(
        title="How to Enable Two-Factor Authentication",
        content="Step 1: Go to Account Settings. Step 2: Click Security. Step 3: Enable 2FA...",
        category="security",
        tags=["2fa", "security", "authentication"],
    )
    
    print(f"  Added: {new_article.title}")
    print(f"  ID: {new_article.article_id}")
    print()
    
    # Rate article
    print("Rating article as helpful...")
    agent.rate_article(new_article.article_id, helpful=True)
    print(f"  New helpful count: {new_article.helpful_count}")


def example_sla_tracking():
    """Example: SLA tracking and breach detection."""
    print("\n" + "=" * 70)
    print("Example 5: SLA Tracking")
    print("=" * 70)
    print()
    
    agent = SupportAgent()
    
    # Show SLA policies
    print("SLA Policies:\n")
    for sla_id, sla in agent.slas.items():
        print(f"  {sla.name}:")
        print(f"    Priority: {sla.priority.value}")
        print(f"    First Response: {sla.first_response_minutes} minutes")
        print(f"    Resolution: {sla.resolution_minutes} minutes")
        print()
    
    # Create tickets with different priorities
    print("Creating tickets with different priorities...\n")
    
    priorities = [
        ("System down!", "Production is completely inaccessible", TicketPriority.CRITICAL),
        ("Feature broken", "Checkout button not working", TicketPriority.HIGH),
        ("Question", "How do I export data?", TicketPriority.NORMAL),
        ("Suggestion", "Add export feature", TicketPriority.LOW),
    ]
    
    for subject, desc, priority in priorities:
        ticket = agent.create_ticket(
            subject=subject,
            description=desc,
            customer_id=f"cust-{len(agent.tickets)+1}",
            customer_email="user@example.com",
            priority=priority,
        )
        print(f"  {ticket.subject} - {ticket.priority.value}")
    
    # Check for breaches
    print("\nChecking SLA breaches...")
    breaches = agent.check_sla_breaches()
    
    if breaches:
        print(f"  ⚠️  {len(breaches)} breach(es) detected:")
        for breach in breaches:
            print(f"    - {breach.subject} ({breach.priority.value})")
    else:
        print("  ✓ No SLA breaches")


def example_support_metrics():
    """Example: Support metrics and reporting."""
    print("\n" + "=" * 70)
    print("Example 6: Support Metrics")
    print("=" * 70)
    print()
    
    agent = SupportAgent()
    
    # Create sample data
    print("Creating sample tickets...\n")
    
    for i in range(20):
        priority = [TicketPriority.LOW, TicketPriority.NORMAL, TicketPriority.HIGH][i % 3]
        category = [TicketCategory.TECHNICAL, TicketCategory.BILLING, TicketCategory.ACCOUNT][i % 3]
        
        ticket = agent.create_ticket(
            subject=f"Ticket {i+1}",
            description=f"Sample ticket {i+1}",
            customer_id=f"cust-{i+1}",
            customer_email=f"user{i+1}@example.com",
            priority=priority,
            category=category,
        )
        
        # Resolve some
        if i % 2 == 0:
            agent.resolve_ticket(ticket.ticket_id, f"Resolved ticket {i+1}", "agent-1")
            agent.record_satisfaction(ticket.ticket_id, random.randint(3, 5))
    
    random.seed(42)
    
    # Get metrics
    print("Generating support metrics...\n")
    metrics = agent.get_support_metrics(days=30)
    
    print(f"Period: {metrics['period_days']} days")
    print("\nTicket Volume:")
    print(f"  Total: {metrics['total_tickets']}")
    print(f"  Open: {metrics['open_count']}")
    print(f"  Resolved: {metrics['resolved_count']}")
    
    print("\nBy Status:")
    for status, count in metrics['by_status'].items():
        print(f"  {status}: {count}")
    
    print("\nBy Priority:")
    for priority, count in metrics['by_priority'].items():
        print(f"  {priority}: {count}")
    
    print("\nBy Category:")
    for category, count in metrics['by_category'].items():
        print(f"  {category}: {count}")
    
    print("\nPerformance:")
    print(f"  Avg Resolution Time: {metrics['avg_resolution_time_minutes']:.1f} minutes")
    print(f"  Avg Satisfaction: {metrics['avg_satisfaction_score']:.1f}/5 ⭐")
    print(f"  SLA Breaches: {metrics['sla_breaches']}")


def main():
    import random
    random.seed(42)
    
    print("\n" + "=" * 70)
    print("SupportAgent - Comprehensive Examples")
    print("=" * 70)
    
    example_ticket_creation()
    example_ticket_workflow()
    example_auto_responses()
    example_knowledge_base()
    example_sla_tracking()
    example_support_metrics()
    
    print("\n" + "=" * 70)
    print("All examples complete!")
    print("=" * 70)
    print()
    print("Next steps:")
    print("  - Integrate with your ticketing system")
    print("  - Configure SLA policies")
    print("  - Build knowledge base articles")
    print("  - Set up automated reporting")
    print()


if __name__ == "__main__":
    main()
