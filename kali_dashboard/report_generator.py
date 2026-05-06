"""
KaliAgent PDF Report Generator
===============================

High-fidelity professional security reports with charts, graphics,
and executive summaries.
"""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from reportlab.lib import colors  # noqa: F401
    from reportlab.lib.pagesizes import letter, A4  # noqa: F401
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle  # noqa: F401
    from reportlab.lib.units import inch, cm  # noqa: F401
    from reportlab.platypus import (  # noqa: F401
        SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle,
        PageBreak, KeepTogether, Image as PlatypusImage
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY  # noqa: F401
    from reportlab.pdfgen import canvas  # noqa: F401
    from reportlab.graphics.shapes import Drawing, Rect  # noqa: F401
    from reportlab.graphics.charts.piecharts import Pie  # noqa: F401
    from reportlab.graphics.charts.barcharts import VerticalBarChart  # noqa: F401
    from reportlab.graphics.charts.linecharts import HorizontalLineChart  # noqa: F401
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    print("Warning: reportlab not installed. Install with: pip install reportlab")

try:
    import matplotlib  # noqa: F401
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt  # noqa: F401
    import matplotlib.patches as mpatches  # noqa: F401
    from matplotlib.backends.backend_agg import FigureCanvasAgg  # noqa: F401
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    print("Warning: matplotlib not installed. Install with: pip install matplotlib")


class KaliReportGenerator:
    """
    Generate high-fidelity PDF security reports with professional graphics.
    """
    
    def __init__(self, output_dir: str = "/tmp/kali-reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Color scheme
        self.colors = {
            'primary': '#0f172a',
            'secondary': '#1e293b',
            'accent_blue': '#3b82f6',
            'accent_green': '#10b981',
            'accent_orange': '#f59e0b',
            'accent_red': '#ef4444',
            'accent_purple': '#8b5cf6',
            'accent_cyan': '#06b6d4',
        }
        
        # Severity colors
        self.severity_colors = {
            'critical': '#ef4444',
            'high': '#f59e0b',
            'medium': '#3b82f6',
            'low': '#10b981',
            'informational': '#6b7280',
        }
    
    def generate_pdf_report(
        self,
        engagement_name: str,
        engagement_type: str,
        execution_results: Dict[str, Any],
        findings: List[Dict[str, Any]],
        output_file: Optional[str] = None,
    ) -> str:
        """
        Generate a professional PDF report with charts and graphics.
        """
        if not REPORTLAB_AVAILABLE:
            raise ImportError("reportlab is required for PDF generation")
        
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        
        if output_file is None:
            output_file = self.output_dir / f"{engagement_name.replace(' ', '_')}_{timestamp}.pdf"
        else:
            output_file = Path(output_file)
        
        # Create PDF document
        doc = SimpleDocTemplate(
            str(output_file),
            pagesize=letter,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=0.75*inch,
            bottomMargin=0.75*inch,
        )
        
        # Build report elements
        elements = []
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=28,
            textColor=self.colors['primary'],
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold',
        )
        
        subtitle_style = ParagraphStyle(
            'Subtitle',
            parent=styles['Normal'],
            fontSize=14,
            textColor=self.colors['secondary'],
            spaceAfter=20,
            alignment=TA_CENTER,
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=18,
            textColor=self.colors['primary'],
            spaceAfter=12,
            spaceBefore=20,
            fontName='Helvetica-Bold',
        )
        
        ParagraphStyle(
            'SubHeading',
            parent=styles['Heading3'],
            fontSize=14,
            textColor=self.colors['accent_blue'],
            spaceAfter=10,
            spaceBefore=15,
            fontName='Helvetica-Bold',
        )
        
        # Title page
        elements.append(Paragraph("Security Assessment Report", title_style))
        elements.append(Paragraph(f"{engagement_name}", subtitle_style))
        elements.append(Paragraph(
            f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            styles['Normal']
        ))
        elements.append(Spacer(1, 0.5*inch))
        
        # Executive Summary
        elements.append(Paragraph("Executive Summary", heading_style))
        elements.append(self._create_executive_summary(execution_results, findings, styles))
        elements.append(Spacer(1, 0.3*inch))
        
        # Findings Chart
        if findings:
            elements.append(Paragraph("Findings Overview", heading_style))
            chart_path = self._create_findings_chart(findings)
            if chart_path:
                elements.append(PlatypusImage(str(chart_path), width=6*inch, height=4*inch))
                elements.append(Spacer(1, 0.3*inch))
        
        # Tools Executed
        elements.append(Paragraph("Tools Executed", heading_style))
        elements.append(self._create_tools_table(execution_results, styles))
        elements.append(Spacer(1, 0.3*inch))
        
        # Detailed Findings
        if findings:
            elements.append(PageBreak())
            elements.append(Paragraph("Detailed Findings", heading_style))
            elements.extend(self._create_findings_details(findings, styles))
        
        # Recommendations
        elements.append(PageBreak())
        elements.append(Paragraph("Recommendations", heading_style))
        elements.append(self._create_recommendations(findings, styles))
        
        # Appendix
        elements.append(PageBreak())
        elements.append(Paragraph("Appendix: Tool Output", heading_style))
        elements.append(self._create_tool_output_appendix(execution_results, styles))
        
        # Build PDF
        doc.build(elements)
        
        return str(output_file)
    
    def _create_executive_summary(
        self,
        execution_results: Dict[str, Any],
        findings: List[Dict[str, Any]],
        styles,
    ) -> Paragraph:
        """Create executive summary section."""
        total_tools = len(execution_results)
        successful = sum(1 for r in execution_results.values() 
                        if r.get('status') == 'completed')
        
        severity_counts = {
            'critical': sum(1 for f in findings if f.get('severity') == 'critical'),
            'high': sum(1 for f in findings if f.get('severity') == 'high'),
            'medium': sum(1 for f in findings if f.get('severity') == 'medium'),
            'low': sum(1 for f in findings if f.get('severity') == 'low'),
        }
        
        summary_text = f"""
        This security assessment was conducted using automated penetration testing tools.
        A total of <b>{total_tools} tools</b> were executed, with <b>{successful} completing successfully</b>.
        <br/><br/>
        
        <b>Key Findings:</b>
        <br/>
        • <font color="{self.severity_colors['critical']}">{severity_counts['critical']} Critical</font> findings requiring immediate attention
        <br/>
        • <font color="{self.severity_colors['high']}">{severity_counts['high']} High</font> severity vulnerabilities identified
        <br/>
        • <font color="{self.severity_colors['medium']}">{severity_counts['medium']} Medium</font> severity issues discovered
        <br/>
        • <font color="{self.severity_colors['low']}">{severity_counts['low']} Low</font> severity observations
        <br/><br/>
        
        <b>Overall Risk Level:</b> {'CRITICAL' if severity_counts['critical'] > 0 else 'HIGH' if severity_counts['high'] > 0 else 'MEDIUM' if severity_counts['medium'] > 0 else 'LOW'}
        <br/><br/>
        
        Immediate remediation is recommended for all critical and high severity findings.
        Detailed technical information and remediation steps are provided in subsequent sections.
        """
        
        return Paragraph(summary_text, styles['Normal'])
    
    def _create_findings_chart(self, findings: List[Dict[str, Any]]) -> Optional[Path]:
        """Create findings severity pie chart."""
        if not MATPLOTLIB_AVAILABLE:
            return None
        
        severity_counts = {}
        for finding in findings:
            severity = finding.get('severity', 'informational')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        if not severity_counts:
            return None
        
        # Create pie chart
        fig, ax = plt.subplots(figsize=(10, 8))
        
        labels = [s.capitalize() for s in severity_counts.keys()]
        sizes = list(severity_counts.values())
        colors_list = [self.severity_colors.get(s, '#6b7280') for s in severity_counts.keys()]
        
        wedges, texts, autotexts = ax.pie(
            sizes,
            labels=labels,
            colors=colors_list,
            autopct='%1.1f%%',
            startangle=90,
            textprops={'fontsize': 12, 'weight': 'bold'},
        )
        
        # Style the percentage texts
        for autotext in autotexts:
            autotext.set_color('white')
        
        ax.set_title('Findings by Severity', fontsize=16, fontweight='bold', pad=20)
        
        # Add legend
        ax.legend(
            wedges,
            labels,
            title="Severity",
            loc="center left",
            bbox_to_anchor=(1, 0, 0.5, 1)
        )
        
        plt.tight_layout()
        
        # Save chart
        chart_path = self.output_dir / 'findings_chart.png'
        plt.savefig(chart_path, dpi=150, bbox_inches='tight')
        plt.close()
        
        return chart_path
    
    def _create_tools_table(
        self,
        execution_results: Dict[str, Any],
        styles,
    ) -> Table:
        """Create tools execution summary table."""
        data = [['Tool', 'Status', 'Duration', 'Exit Code']]
        
        for tool_name, result in execution_results.items():
            status = result.get('status', 'unknown')
            duration = result.get('duration_seconds', 0)
            exit_code = result.get('exit_code', 'N/A')
            
            status_color = '✅' if status == 'completed' else '❌'
            
            data.append([
                tool_name,
                f"{status_color} {status}",
                f"{duration:.1f}s",
                str(exit_code),
            ])
        
        table = Table(data, colWidths=[2.5*inch, 1.5*inch, 1*inch, 1*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.colors['primary']),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
        ]))
        
        return table
    
    def _create_findings_details(
        self,
        findings: List[Dict[str, Any]],
        styles,
    ) -> list:
        """Create detailed findings section."""
        elements = []
        
        subheading_style = ParagraphStyle(
            'FindingTitle',
            parent=styles['Heading3'],
            fontSize=16,
            textColor=self.colors['primary'],
            spaceAfter=10,
            spaceBefore=20,
            fontName='Helvetica-Bold',
        )
        
        for i, finding in enumerate(findings, 1):
            severity = finding.get('severity', 'medium')
            severity_color = self.severity_colors.get(severity, '#6b7280')
            
            title = finding.get('title', f'Finding #{i}')
            description = finding.get('description', 'No description provided')
            remediation = finding.get('remediation', 'No remediation steps provided')
            
            # Finding header with severity badge
            elements.append(Paragraph(
                f"<b>Finding #{i}:</b> {title}",
                subheading_style
            ))
            
            # Severity badge
            elements.append(Paragraph(
                f"<b>Severity:</b> <font color='{severity_color}'>{severity.upper()}</font>",
                styles['Normal']
            ))
            
            elements.append(Spacer(1, 0.1*inch))
            
            # Description
            elements.append(Paragraph("<b>Description:</b>", styles['Normal']))
            elements.append(Paragraph(description, styles['Normal']))
            
            elements.append(Spacer(1, 0.15*inch))
            
            # Remediation
            elements.append(Paragraph("<b>Remediation:</b>", styles['Normal']))
            elements.append(Paragraph(remediation, styles['Normal']))
            
            elements.append(Spacer(1, 0.3*inch))
        
        return elements
    
    def _create_recommendations(
        self,
        findings: List[Dict[str, Any]],
        styles,
    ) -> Paragraph:
        """Create recommendations section."""
        critical_count = sum(1 for f in findings if f.get('severity') == 'critical')
        high_count = sum(1 for f in findings if f.get('severity') == 'high')
        
        recommendations = []
        
        if critical_count > 0:
            recommendations.append(
                "<b>1. IMMEDIATE ACTION REQUIRED:</b> Address all critical findings within 24-48 hours. "
                "These vulnerabilities pose an immediate threat to system security."
            )
        
        if high_count > 0:
            recommendations.append(
                "<b>2. HIGH PRIORITY:</b> Remediate high severity findings within 1-2 weeks. "
                "Schedule dedicated remediation sprints."
            )
        
        recommendations.append(
            "<b>3. REGULAR SCANNING:</b> Implement automated security scanning on a weekly basis "
            "to identify new vulnerabilities as they emerge."
        )
        
        recommendations.append(
            "<b>4. PATCH MANAGEMENT:</b> Establish a regular patch management cycle to ensure "
            "all systems are kept up-to-date with security patches."
        )
        
        recommendations.append(
            "<b>5. SECURITY TRAINING:</b> Conduct security awareness training for development "
            "and operations teams to prevent common vulnerabilities."
        )
        
        rec_text = "<br/><br/>".join(recommendations)
        
        return Paragraph(rec_text, styles['Normal'])
    
    def _create_tool_output_appendix(
        self,
        execution_results: Dict[str, Any],
        styles,
    ) -> Paragraph:
        """Create tool output appendix."""
        appendix_text = """
        The following tools were executed during this assessment. Full output logs are available
        in the engagement directory.
        <br/><br/>
        """
        
        tool_list = []
        for tool_name, result in execution_results.items():
            status = '✓' if result.get('status') == 'completed' else '✗'
            tool_list.append(f"• {status} {tool_name}")
        
        appendix_text += "<br/>".join(tool_list)
        
        return Paragraph(appendix_text, styles['Normal'])


def generate_sample_report():
    """Generate a sample report for testing."""
    generator = KaliReportGenerator()
    
    # Sample data
    execution_results = {
        'nmap': {'status': 'completed', 'duration_seconds': 45.3, 'exit_code': 0},
        'nikto': {'status': 'completed', 'duration_seconds': 120.7, 'exit_code': 0},
        'gobuster': {'status': 'completed', 'duration_seconds': 89.2, 'exit_code': 0},
        'sqlmap': {'status': 'failed', 'duration_seconds': 12.1, 'exit_code': 1},
    }
    
    findings = [
        {
            'title': 'SQL Injection Vulnerability',
            'severity': 'critical',
            'description': 'SQL injection vulnerability found in login form allowing authentication bypass.',
            'remediation': 'Use parameterized queries and input validation.',
        },
        {
            'title': 'Outdated SSL/TLS Configuration',
            'severity': 'high',
            'description': 'Server supports TLS 1.0 and weak cipher suites.',
            'remediation': 'Disable TLS 1.0/1.1 and configure strong cipher suites only.',
        },
        {
            'title': 'Directory Listing Enabled',
            'severity': 'medium',
            'description': 'Directory listing is enabled on web server exposing file structure.',
            'remediation': 'Disable directory listing in web server configuration.',
        },
        {
            'title': 'Missing Security Headers',
            'severity': 'low',
            'description': 'X-Frame-Options and CSP headers not configured.',
            'remediation': 'Add security headers to HTTP responses.',
        },
    ]
    
    output_file = generator.generate_pdf_report(
        engagement_name="Q2 2026 Security Assessment",
        engagement_type="web_audit",
        execution_results=execution_results,
        findings=findings,
    )
    
    print(f"✅ Report generated: {output_file}")
    return output_file


if __name__ == "__main__":
    generate_sample_report()
