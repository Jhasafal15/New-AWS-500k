"""
Visual Dashboard Viewer for Student 1.
Run this script to immediately launch and view your interactive CSPM Security Dashboard in your web browser!

Usage:
  python view_dashboard.py
"""

import os
import sys
import webbrowser

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.visualization.generate_dashboard import generate_html_dashboard

def main():
    inv_file = os.path.join(PROJECT_ROOT, "data", "processed", "cloud_inventory.json")
    find_file = os.path.join(PROJECT_ROOT, "data", "processed", "rule_findings.json")
    out_html = os.path.join(PROJECT_ROOT, "data", "processed", "security_dashboard.html")

    if not os.path.exists(inv_file) or not os.path.exists(find_file):
        print("Processed files not found. Running run_pipeline.py first...")
        from run_pipeline import run_pipeline
        run_pipeline()

    dashboard_path = generate_html_dashboard(inv_file, find_file, out_html)
    print("=" * 60)
    print("AI-POWERED CSPM PLATFORM: SECURITY POSTURE DASHBOARD")
    print("=" * 60)
    print(f"Generated Dashboard: {dashboard_path}")
    print("Opening in your web browser...")
    webbrowser.open(f"file://{os.path.abspath(dashboard_path)}")
    print("Done! You can also double-click 'security_dashboard.html' in File Explorer at any time.")
    print("=" * 60)

if __name__ == "__main__":
    main()
