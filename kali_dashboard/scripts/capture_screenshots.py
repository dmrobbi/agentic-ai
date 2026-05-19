#!/usr/bin/env python3
"""
KaliAgent Automated Screenshot Capture
=======================================
Captures all 15 required documentation screenshots using Playwright.

Requirements:
    pip install playwright
    playwright install firefox

Usage:
    python3 capture_screenshots.py

Output:
    screenshots/ directory with 15 PNG files
"""

import asyncio
from pathlib import Path
import sys

try:
    from playwright.async_api import async_playwright
except ImportError:
    print("❌ Playwright not installed. Install with:")
    print("   pip install playwright")
    print("   playwright install firefox")
    sys.exit(1)

# Configuration
DASHBOARD_URL = "http://localhost:5173"
OUTPUT_DIR = Path(__file__).parent / "screenshots"
VIEWPORT = {"width": 1920, "height": 1080}
LOAD_TIMEOUT = 5000  # 5 seconds

# Screenshot definitions
SCREENSHOTS = [
    {
        "file": "01-dashboard-overview.png",
        "description": "Dashboard Overview",
        "path": "/",
        "wait_for": "text=Quick Actions"
    },
    {
        "file": "02-engagements-page.png",
        "description": "Engagements Page",
        "path": "/engagements",
        "wait_for": "text=Engagements"
    },
    {
        "file": "03-playbooks-page.png",
        "description": "Playbooks Page",
        "path": "/playbooks",
        "wait_for": "text=Playbooks"
    },
    {
        "file": "04-tools-catalog.png",
        "description": "Tools Catalog",
        "path": "/tools",
        "wait_for": "text=52 Tools"
    },
    {
        "file": "05-settings-safety.png",
        "description": "Safety Settings",
        "path": "/settings",
        "wait_for": "text=Safety"
    },
    {
        "file": "06-live-monitor.png",
        "description": "Live Monitor",
        "path": "/live-monitor",
        "wait_for": "text=Live"
    },
    {
        "file": "07-create-engagement.png",
        "description": "Create Engagement",
        "path": "/engagements/new",
        "wait_for": "text=Create"
    },
    {
        "file": "08-execute-playbook.png",
        "description": "Execute Playbook",
        "path": "/playbooks/execute",
        "wait_for": "text=Execute"
    },
    {
        "file": "09-scan-results.png",
        "description": "Scan Results",
        "path": "/results",
        "wait_for": "text=Results"
    },
    {
        "file": "10-pdf-report-preview.png",
        "description": "PDF Report Preview",
        "path": "/reports/preview",
        "wait_for": "text=Report"
    },
    {
        "file": "11-tool-details.png",
        "description": "Tool Details (Nmap)",
        "path": "/tools/nmap",
        "wait_for": "text=Nmap"
    },
    {
        "file": "12-authorization-settings.png",
        "description": "Authorization Settings",
        "path": "/settings/auth",
        "wait_for": "text=Authorization"
    },
    {
        "file": "13-audit-logs.png",
        "description": "Audit Logs",
        "path": "/settings/audit",
        "wait_for": "text=Audit"
    },
    {
        "file": "14-test-coverage.png",
        "description": "Test Coverage",
        "path": "/reports/tests",
        "wait_for": "text=Coverage"
    },
    {
        "file": "15-mobile-view.png",
        "description": "Mobile View",
        "path": "/",
        "mobile": True,
        "wait_for": "text=Quick"
    }
]


def print_header():
    """Print colorful header"""
    print("\n" + "═" * 70)
    print("  📸 KaliAgent Screenshot Capture Script v1.0")
    print("  Capturing 15 documentation screenshots")
    print("═" * 70 + "\n")


def print_success(message):
    """Print success message"""
    print(f"✅ {message}")


def print_error(message):
    """Print error message"""
    print(f"❌ {message}")


def print_info(message):
    """Print info message"""
    print(f"ℹ️  {message}")


async def capture_screenshots():
    """Main screenshot capture function"""
    print_header()
    
    # Create output directory
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    print_success(f"Output directory: {OUTPUT_DIR}")
    
    # Check if dashboard is running
    import urllib.request
    try:
        urllib.request.urlopen(DASHBOARD_URL, timeout=5)
        print_success(f"Dashboard is running at {DASHBOARD_URL}")
    except Exception:
        print_error(f"Dashboard is NOT running at {DASHBOARD_URL}")
        print("\nPlease start the dashboard:")
        print("  cd kali_dashboard/frontend")
        print("  npm run dev\n")
        return False
    
    captured = 0
    failed = 0
    
    async with async_playwright() as p:
        for i, screenshot in enumerate(SCREENSHOTS, 1):
            print(f"\n{'─' * 70}")
            print(f"Screenshot {i} of {len(SCREENSHOTS)}")
            print(f"{'─' * 70}")
            print(f"📸 Capturing: {screenshot['description']}")
            print(f"   URL: {DASHBOARD_URL}{screenshot['path']}")
            print(f"   File: {screenshot['file']}")
            
            try:
                # Launch browser
                browser = await p.firefox.launch(headless=True)
                
                # Set viewport
                if screenshot.get('mobile'):
                    context = await browser.new_context(
                        viewport={"width": 375, "height": 667},
                        is_mobile=True
                    )
                else:
                    context = await browser.new_context(viewport=VIEWPORT)
                
                page = await context.new_page()
                
                # Navigate to page
                await page.goto(f"{DASHBOARD_URL}{screenshot['path']}", 
                              timeout=LOAD_TIMEOUT,
                              wait_until="networkidle")
                
                # Wait for specific element
                try:
                    await page.wait_for_selector(f"text={screenshot['wait_for']}", 
                                               timeout=3000)
                except Exception:
                    # Fallback: just wait a bit
                    await page.wait_for_timeout(2000)
                
                # Take screenshot
                output_file = OUTPUT_DIR / screenshot['file']
                await page.screenshot(path=str(output_file), full_page=True)
                
                # Close browser
                await browser.close()
                
                # Check file size
                file_size = output_file.stat().st_size
                file_size_kb = file_size / 1024
                
                print_success(f"Captured! ({file_size_kb:.1f} KB)")
                captured += 1
                
            except Exception as e:
                print_error(f"Failed: {str(e)}")
                failed += 1
            
            # Small delay between captures
            if i < len(SCREENSHOTS):
                await asyncio.sleep(1)
    
    # Summary
    print(f"\n{'═' * 70}")
    print("  Capture Complete")
    print(f"{'═' * 70}\n")
    print(f"Captured: {captured}/{len(SCREENSHOTS)}")
    print(f"Failed:   {failed}/{len(SCREENSHOTS)}\n")
    
    if captured == len(SCREENSHOTS):
        print_success("🎉 All screenshots captured successfully!")
        print(f"\nScreenshots saved to: {OUTPUT_DIR}")
        print("\nNext steps:")
        print("  1. Review screenshots")
        print("  2. Add annotations (red boxes, arrows, numbers)")
        print("  3. Update documentation with actual paths\n")
        return True
    else:
        print_error("⚠ Some screenshots failed. Check errors above.")
        return False


if __name__ == "__main__":
    success = asyncio.get_event_loop().run_until_complete(capture_screenshots())
    sys.exit(0 if success else 1)
