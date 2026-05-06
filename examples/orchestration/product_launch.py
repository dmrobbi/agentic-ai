"""
Product Launch - Multi-Agent Orchestration Example
===================================================

Demonstrates coordinated product launch across multiple agents:
- Product Agent: Defines launch criteria, tracks milestones
- Marketing Agent: Creates campaigns, content, social media
- Sales Agent: Prepares leads, opportunities, proposals
- Support Agent: Readies documentation, training, ticket routing
- Communications Agent: Press releases, announcements
- DataAnalyst Agent: Launch metrics, KPI tracking

This example shows go-to-market coordination across teams.
"""

import sys
from datetime import datetime, timedelta
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from agentic_ai.agents.product import ProductAgent
from agentic_ai.agents.marketing import MarketingAgent
from agentic_ai.agents.sales import SalesAgent
from agentic_ai.agents.support import SupportAgent
from agentic_ai.agents.communications import CommunicationsAgent
from agentic_ai.agents.data_analyst import DataAnalystAgent


def format_date(dt: datetime) -> str:
    """Format datetime for display."""
    return dt.strftime("%Y-%m-%d")


def run_product_launch():
    """Execute product launch workflow."""
    
    print("=" * 80)
    print("PRODUCT LAUNCH - Multi-Agent Orchestration")
    print("=" * 80)
    print()
    
    # Initialize all agents
    product = ProductAgent()
    marketing = MarketingAgent()
    sales = SalesAgent()
    support = SupportAgent()
    comms = CommunicationsAgent()
    data = DataAnalystAgent()
    
    # Define launch date
    launch_date = datetime.utcnow() + timedelta(days=30)
    
    # ========================================================================
    # PHASE 1: PRODUCT DEFINITION
    # ========================================================================
    print("\n📦 PHASE 1: PRODUCT DEFINITION")
    print("-" * 80)
    
    # Product Agent creates new product
    print("\n[Product Agent] Defining new product...")
    
    new_product = product.create_product(
        name="CloudSecure Pro",
        description="Enterprise cloud security posture management platform",
        category="security",
        tier="enterprise",
        target_market=["enterprise", "mid-market"],
        pricing_model="subscription",
        price_usd=999.0,
        billing_cycle="monthly",
    )
    print(f"  ✓ Product created: {new_product.name}")
    print(f"  ✓ Category: {new_product.category}")
    print(f"  ✓ Price: ${new_product.price_usd}/{new_product.billing_cycle}")
    
    # Create launch milestone
    print("\n[Product Agent] Creating launch milestones...")
    
    launch_milestone = product.create_milestone(
        product_id=new_product.product_id,
        title="CloudSecure Pro GA Launch",
        milestone_type="launch",
        target_date=launch_date,
        status="in_progress",
    )
    print(f"  ✓ Launch milestone created: {launch_milestone.title}")
    print(f"    - Target date: {format_date(launch_milestone.target_date)}")
    
    # Define launch criteria
    launch_criteria = [
        product.create_feature(
            product_id=new_product.product_id,
            name="Multi-Cloud Support",
            description="AWS, GCP, Azure security monitoring",
            priority="critical",
            status="completed",
        ),
        product.create_feature(
            product_id=new_product.product_id,
            name="Compliance Dashboards",
            description="CIS, PCI-DSS, HIPAA, SOC2 compliance scoring",
            priority="critical",
            status="completed",
        ),
        product.create_feature(
            product_id=new_product.product_id,
            name="Automated Remediation",
            description="Auto-fix security misconfigurations",
            priority="high",
            status="in_progress",
        ),
        product.create_feature(
            product_id=new_product.product_id,
            name="API Integration",
            description="REST API for automation",
            priority="high",
            status="completed",
        ),
    ]
    print(f"  ✓ {len(launch_criteria)} launch features defined")
    
    # ========================================================================
    # PHASE 2: MARKETING CAMPAIGN
    # ========================================================================
    print("\n\n📢 PHASE 2: MARKETING CAMPAIGN")
    print("-" * 80)
    
    # Marketing Agent creates launch campaign
    print("\n[Marketing Agent] Creating launch campaign...")
    
    launch_campaign = marketing.create_campaign(
        name="CloudSecure Pro Launch Campaign",
        campaign_type="product_launch",
        start_date=datetime.utcnow(),
        end_date=launch_date + timedelta(days=30),
        budget=150000.0,
        target_audience="security decision makers at enterprise companies",
        goals=[
            "Generate 500 MQLs in first 30 days",
            "Achieve 50% brand awareness in target segment",
            "Drive 100 demo requests",
        ],
    )
    print(f"  ✓ Campaign created: {launch_campaign.name}")
    print(f"  ✓ Budget: ${launch_campaign.budget:,.0f}")
    print(f"  ✓ Duration: {launch_campaign.start_date.strftime('%Y-%m-%d')} to {launch_campaign.end_date.strftime('%Y-%m-%d')}")
    
    # Create content assets
    print("\n[Marketing Agent] Creating content assets...")
    
    content_assets = [
        marketing.create_content(
            campaign_id=launch_campaign.campaign_id,
            content_type="landing_page",
            title="CloudSecure Pro - Product Landing Page",
            status="in_progress",
            due_date=launch_date - timedelta(days=14),
        ),
        marketing.create_content(
            campaign_id=launch_campaign.campaign_id,
            content_type="video",
            title="Product Demo Video (3 min)",
            status="planned",
            due_date=launch_date - timedelta(days=7),
        ),
        marketing.create_content(
            campaign_id=launch_campaign.campaign_id,
            content_type="datasheet",
            title="CloudSecure Pro Technical Datasheet",
            status="in_progress",
            due_date=launch_date - timedelta(days=21),
        ),
        marketing.create_content(
            campaign_id=launch_campaign.campaign_id,
            content_type="case_study",
            title="Early Adopter Success Story",
            status="planned",
            due_date=launch_date + timedelta(days=14),
        ),
    ]
    print(f"  ✓ {len(content_assets)} content assets planned")
    
    # Plan social media campaign
    print("\n[Marketing Agent] Planning social media campaign...")
    
    social_posts = [
        marketing.schedule_social_post(
            platform="twitter",
            content="🚀 Excited to announce CloudSecure Pro! Enterprise-grade cloud security posture management. Learn more: [link] #CloudSecurity #CIS #DevSecOps",
            scheduled_time=launch_date,
            campaign_id=launch_campaign.campaign_id,
        ),
        marketing.schedule_social_post(
            platform="linkedin",
            content="We're thrilled to launch CloudSecure Pro, helping enterprises secure their multi-cloud infrastructure with automated compliance and remediation. See how it works: [link]",
            scheduled_time=launch_date,
            campaign_id=launch_campaign.campaign_id,
        ),
    ]
    print(f"  ✓ {len(social_posts)} social posts scheduled")
    
    # Plan launch event
    print("\n[Marketing Agent] Planning virtual launch event...")
    
    launch_event = marketing.create_event(
        name="CloudSecure Pro Launch Webinar",
        event_type="webinar",
        start_time=launch_date + timedelta(days=7, hours=10),
        duration_minutes=60,
        capacity=500,
        registration_url="https://events.example.com/cloudsecure-launch",
        speakers=[
            {"name": "Jane Smith", "title": "VP Product", "company": "Example Corp"},
            {"name": "John Doe", "title": "CISO", "company": "Early Adopter Inc"},
        ],
    )
    print(f"  ✓ Launch webinar scheduled: {format_date(launch_event.start_time)}")
    print(f"    - Capacity: {launch_event.capacity} attendees")
    
    # ========================================================================
    # PHASE 3: SALES PREPARATION
    # ========================================================================
    print("\n\n💼 PHASE 3: SALES PREPARATION")
    print("-" * 80)
    
    # Sales Agent prepares for launch
    print("\n[Sales Agent] Preparing sales enablement...")
    
    # Create sales playbook
    sales.create_proposal(
        opportunity_id="playbook-cloudsecure",
        customer_name="Sales Team",
        proposal_type="sales_playbook",
        value=0.0,
        products=[new_product.product_id],
    )
    print("  ✓ Sales playbook created")
    
    # Define target accounts
    print("\n[Sales Agent] Identifying target accounts...")
    
    target_accounts = [
        sales.create_lead(
            company_name="Acme Financial",
            industry="financial_services",
            employee_count=5000,
            annual_revenue=1000000000,
            location="New York, NY",
            source="target_account_list",
            status="new",
        ),
        sales.create_lead(
            company_name="TechCorp Industries",
            industry="technology",
            employee_count=2000,
            annual_revenue=500000000,
            location="San Francisco, CA",
            source="target_account_list",
            status="new",
        ),
        sales.create_lead(
            company_name="HealthSystem Inc",
            industry="healthcare",
            employee_count=10000,
            annual_revenue=2000000000,
            location="Boston, MA",
            source="target_account_list",
            status="new",
        ),
    ]
    print(f"  ✓ {len(target_accounts)} target accounts identified")
    
    # Create sales opportunities
    print("\n[Sales Agent] Creating early opportunities...")
    
    opportunities = [
        sales.create_opportunity(
            lead_id=target_accounts[0].lead_id,
            opportunity_name="Acme Financial - CloudSecure Pro",
            stage="prospecting",
            value=150000.0,
            close_date=launch_date + timedelta(days=90),
            probability=20,
            products=[new_product.product_id],
        ),
        sales.create_opportunity(
            lead_id=target_accounts[1].lead_id,
            opportunity_name="TechCorp - CloudSecure Pro",
            stage="qualification",
            value=100000.0,
            close_date=launch_date + timedelta(days=60),
            probability=30,
            products=[new_product.product_id],
        ),
    ]
    print(f"  ✓ {len(opportunities)} opportunities created")
    print(f"    - Total pipeline value: ${sum(o.value for o in opportunities):,.0f}")
    
    # Prepare pricing proposals
    print("\n[Sales Agent] Preparing pricing proposals...")
    
    sales.create_proposal(
        opportunity_id="enterprise-template",
        customer_name="Enterprise Template",
        proposal_type="pricing",
        value=999.0 * 12,  # Annual
        products=[new_product.product_id],
        terms={
            "annual_discount": "17%",
            "multi_year_discount": "25%",
            "enterprise_addons": ["SSO", "Advanced Analytics", "Premium Support"],
        },
    )
    print("  ✓ Enterprise pricing proposal created")
    
    # ========================================================================
    # PHASE 4: SUPPORT READINESS
    # ========================================================================
    print("\n\n🎧 PHASE 4: SUPPORT READINESS")
    print("-" * 80)
    
    # Support Agent prepares for launch
    print("\n[Support Agent] Preparing support infrastructure...")
    
    # Create support documentation
    print("\n[Support Agent] Creating documentation...")
    
    docs = [
        support.create_article(
            title="CloudSecure Pro - Getting Started Guide",
            category="getting_started",
            status="in_progress",
            author="docs-team@example.com",
        ),
        support.create_article(
            title="CloudSecure Pro - API Reference",
            category="api",
            status="in_progress",
            author="docs-team@example.com",
        ),
        support.create_article(
            title="CloudSecure Pro - Troubleshooting Guide",
            category="troubleshooting",
            status="planned",
            author="support-team@example.com",
        ),
        support.create_article(
            title="CloudSecure Pro - Security Best Practices",
            category="best_practices",
            status="planned",
            author="security-team@example.com",
        ),
    ]
    print(f"  ✓ {len(docs)} documentation articles planned")
    
    # Set up ticket routing
    print("\n[Support Agent] Configuring ticket routing...")
    
    routing_rules = [
        support.create_routing_rule(
            name="CloudSecure Pro - Technical Issues",
            condition="product:cloudsecure AND type:technical",
            assign_to="technical-support@example.com",
            priority="high",
            sla_hours=4,
        ),
        support.create_routing_rule(
            name="CloudSecure Pro - Billing Questions",
            condition="product:cloudsecure AND type:billing",
            assign_to="billing@example.com",
            priority="medium",
            sla_hours=24,
        ),
        support.create_routing_rule(
            name="CloudSecure Pro - Security Incidents",
            condition="product:cloudsecure AND type:security",
            assign_to="security-response@example.com",
            priority="critical",
            sla_hours=1,
        ),
    ]
    print(f"  ✓ {len(routing_rules)} ticket routing rules configured")
    
    # Plan training sessions
    print("\n[Support Agent] Scheduling training sessions...")
    
    training_sessions = [
        support.schedule_training(
            title="CloudSecure Pro - Support Team Training",
            training_type="internal",
            start_time=launch_date - timedelta(days=7),
            duration_minutes=120,
            attendees=["support-team@example.com"],
            trainer="product-team@example.com",
        ),
        support.schedule_training(
            title="CloudSecure Pro - Customer Onboarding",
            training_type="customer",
            start_time=launch_date + timedelta(days=14),
            duration_minutes=60,
            attendees=["customers"],
            trainer="support-team@example.com",
        ),
    ]
    print(f"  ✓ {len(training_sessions)} training sessions scheduled")
    
    # ========================================================================
    # PHASE 5: COMMUNICATIONS
    # ========================================================================
    print("\n\n📰 PHASE 5: COMMUNICATIONS")
    print("-" * 80)
    
    # Communications Agent handles PR
    print("\n[Communications Agent] Preparing press materials...")
    
    # Write press release
    press_release = comms.create_message_template(
        name="cloudsecure_press_release",
        template_type="press_release",
        subject="FOR IMMEDIATE RELEASE: Example Corp Launches CloudSecure Pro",
        body="""
FOR IMMEDIATE RELEASE

Example Corp Launches CloudSecure Pro: Enterprise Cloud Security Posture Management

[City, Date] - Example Corp today announced CloudSecure Pro, a comprehensive cloud security 
posture management (CSPM) platform designed for enterprise organizations managing multi-cloud 
infrastructure across AWS, GCP, and Azure.

CloudSecure Pro provides:
- Real-time security monitoring across all major cloud providers
- Automated compliance scoring for CIS, PCI-DSS, HIPAA, and SOC2
- AI-powered threat detection and automated remediation
- Executive dashboards for security posture visibility

"Cloud security is the top concern for CISOs managing multi-cloud environments," said 
Jane Smith, VP Product at Example Corp. "CloudSecure Pro gives enterprises the visibility 
and control they need to secure their cloud infrastructure at scale."

Key features include:
- Multi-cloud support (AWS, GCP, Azure)
- 200+ pre-built security policies
- Automated remediation of misconfigurations
- Integration with leading SIEM and ticketing systems

CloudSecure Pro is available immediately with pricing starting at $999/month.

About Example Corp
Example Corp provides enterprise security solutions for cloud-native organizations.

Contact:
press@example.com
        """,
    )
    print("  ✓ Press release template created")
    
    # Distribute press release
    print("\n[Communications Agent] Distributing press release...")
    
    comms.send_email(
        to=["press@techcrunch.com", "press@reuters.com", "press@bloomberg.com"],
        subject="FOR IMMEDIATE RELEASE: Example Corp Launches CloudSecure Pro",
        body=press_release.get('body', ''),
        priority="high",
    )
    print("  ✓ Press release distributed to media outlets")
    
    # Internal announcement
    print("\n[Communications Agent] Sending internal announcement...")
    
    comms.send_email(
        to=["all-company@example.com"],
        subject="🎉 Announcing CloudSecure Pro - Our Newest Product!",
        body=f"""
Team,

I'm excited to announce the launch of CloudSecure Pro, our enterprise cloud security 
posture management platform!

LAUNCH DATE: {format_date(launch_date)}

WHAT IT DOES:
CloudSecure Pro helps enterprises secure their multi-cloud infrastructure with:
- Real-time security monitoring
- Automated compliance scoring
- AI-powered threat detection

WHY IT MATTERS:
This represents a major expansion into the enterprise security market, with a 
TAM of $15B and growing.

THANK YOU:
Huge thanks to the Product, Engineering, Marketing, Sales, and Support teams 
who made this launch possible!

Join us for a launch celebration on {format_date(launch_date + timedelta(days=7))}.

Best,
CEO
        """,
        priority="normal",
    )
    print("  ✓ Internal announcement sent")
    
    # ========================================================================
    # PHASE 6: ANALYTICS & METRICS
    # ========================================================================
    print("\n\n📊 PHASE 6: ANALYTICS & METRICS")
    print("-" * 80)
    
    # DataAnalyst Agent sets up launch dashboards
    print("\n[DataAnalyst Agent] Creating launch dashboards...")
    
    # Define KPIs
    launch_kpis = {
        'marketing': {
            'website_visitors': {'target': 50000, 'unit': 'visitors'},
            'demo_requests': {'target': 100, 'unit': 'requests'},
            'mqls_generated': {'target': 500, 'unit': 'leads'},
            'social_engagement': {'target': 5000, 'unit': 'interactions'},
        },
        'sales': {
            'opportunities_created': {'target': 50, 'unit': 'opportunities'},
            'pipeline_value': {'target': 5000000, 'unit': 'USD'},
            'deals_closed': {'target': 10, 'unit': 'deals'},
            'avg_deal_size': {'target': 100000, 'unit': 'USD'},
        },
        'product': {
            'active_users': {'target': 1000, 'unit': 'users'},
            'feature_adoption': {'target': 60, 'unit': 'percent'},
            'nps_score': {'target': 50, 'unit': 'score'},
            'uptime': {'target': 99.9, 'unit': 'percent'},
        },
        'support': {
            'tickets_created': {'target': 200, 'unit': 'tickets'},
            'first_response_time': {'target': 2, 'unit': 'hours'},
            'csat_score': {'target': 4.5, 'unit': 'score'},
            'documentation_views': {'target': 10000, 'unit': 'views'},
        },
    }
    print(f"  ✓ {len(launch_kpis)} KPI categories defined")
    print(f"    - Total KPIs: {sum(len(v) for v in launch_kpis.values())}")
    
    # Create dashboard
    print("\n[DataAnalyst Agent] Building launch dashboard...")
    
    dashboard = data.create_dashboard(
        name="CloudSecure Pro Launch Dashboard",
        description="Real-time launch metrics across all teams",
        refresh_interval_minutes=15,
    )
    print(f"  ✓ Dashboard created: {dashboard.get('dashboard_id', 'launch-dash')}")
    
    # Add widgets
    widgets = [
        data.add_dashboard_widget(
            dashboard_id=dashboard.get('dashboard_id', 'launch-dash'),
            widget_type="metric",
            title="Demo Requests",
            metric="demo_requests_total",
            target=100,
        ),
        data.add_dashboard_widget(
            dashboard_id=dashboard.get('dashboard_id', 'launch-dash'),
            widget_type="metric",
            title="Pipeline Value",
            metric="pipeline_value_usd",
            target=5000000,
        ),
        data.add_dashboard_widget(
            dashboard_id=dashboard.get('dashboard_id', 'launch-dash'),
            widget_type="timeseries",
            title="Website Visitors (Daily)",
            metric="website_visitors_daily",
        ),
        data.add_dashboard_widget(
            dashboard_id=dashboard.get('dashboard_id', 'launch-dash'),
            widget_type="gauge",
            title="NPS Score",
            metric="nps_score",
            target=50,
        ),
    ]
    print(f"  ✓ {len(widgets)} dashboard widgets added")
    
    # Schedule reports
    print("\n[DataAnalyst Agent] Scheduling launch reports...")
    
    reports = [
        data.schedule_report(
            name="Daily Launch Metrics",
            report_type="metrics_summary",
            schedule="daily",
            recipients=["leadership@example.com"],
            dashboard_id=dashboard.get('dashboard_id', 'launch-dash'),
        ),
        data.schedule_report(
            name="Weekly Launch Performance",
            report_type="performance_analysis",
            schedule="weekly",
            recipients=["all-managers@example.com"],
            dashboard_id=dashboard.get('dashboard_id', 'launch-dash'),
        ),
    ]
    print(f"  ✓ {len(reports)} reports scheduled")
    
    # ========================================================================
    # SUMMARY
    # ========================================================================
    print("\n\n" + "=" * 80)
    print("PRODUCT LAUNCH SUMMARY")
    print("=" * 80)
    
    print(f"""
PRODUCT: {new_product.name}
LAUNCH DATE: {format_date(launch_date)}
CATEGORY: {new_product.category}
PRICE: ${new_product.price_usd}/{new_product.billing_cycle}

AGENTS INVOLVED:
  ✓ Product Agent - Product definition, milestones, features
  ✓ Marketing Agent - Campaign, content, social, events
  ✓ Sales Agent - Target accounts, opportunities, proposals
  ✓ Support Agent - Documentation, routing, training
  ✓ Communications Agent - Press release, announcements
  ✓ DataAnalyst Agent - KPIs, dashboards, reports

LAUNCH ASSETS CREATED:
  ✓ {len(launch_criteria)} product features
  ✓ {len(content_assets)} content assets
  ✓ {len(target_accounts)} target accounts
  ✓ {len(opportunities)} sales opportunities (${sum(o.value for o in opportunities):,.0f} pipeline)
  ✓ {len(docs)} documentation articles
  ✓ {len(routing_rules)} support routing rules
  ✓ {len(widgets)} dashboard widgets

MARKETING:
  ✓ Campaign budget: ${launch_campaign.budget:,.0f}
  ✓ Social posts scheduled: {len(social_posts)}
  ✓ Launch webinar: {format_date(launch_event.start_time)}

SUCCESS METRICS:
  ✓ {sum(len(v) for v in launch_kpis.values())} KPIs defined
  ✓ Launch dashboard created
  ✓ Daily & weekly reports scheduled
""")
    
    # Get final state from all agents
    print("\nAGENT STATES:")
    print(f"  Product Agent: {product.get_state()}")
    print(f"  Marketing Agent: {marketing.get_state()}")
    print(f"  Sales Agent: {sales.get_state()}")
    print(f"  Support Agent: {support.get_state()}")
    print(f"  Communications Agent: {comms.get_state()}")
    print(f"  DataAnalyst Agent: {data.get_state()}")
    
    print("\n" + "=" * 80)
    print("✅ PRODUCT LAUNCH WORKFLOW COMPLETE")
    print("=" * 80)
    
    return {
        'product': new_product,
        'launch_date': launch_date,
        'agents': {
            'product': product.get_state(),
            'marketing': marketing.get_state(),
            'sales': sales.get_state(),
            'support': support.get_state(),
            'comms': comms.get_state(),
            'data': data.get_state(),
        },
    }


if __name__ == "__main__":
    result = run_product_launch()
    print("\n📊 Workflow execution successful!")
