#!/usr/bin/env python3
"""
Demo script to showcase Aura-sec v3.0.0 interactive reporting capabilities
"""

import json
from aurasec import ScanResult, create_interactive_report, create_enhanced_text_report

# Create sample scan data to demonstrate reporting
def create_demo_data():
    """Create realistic demo scan data."""

    # Sample scan results
    scan_results = [
        ScanResult(
            port=22,
            status="open",
            service="SSH",
            version="OpenSSH_7.4",
            vulnerabilities=["CVE-2018-15473", "CVE-2016-6210"],
            confidence=0.95,
            response_time=0.123,
            threat_intel={"vulnerabilities": [{"cve_id": "CVE-2018-15473", "severity": "medium"}]}
        ),
        ScanResult(
            port=80,
            status="open",
            service="HTTP",
            version="nginx/1.18.0 [CloudFlare]",
            vulnerabilities=[],
            confidence=0.89,
            response_time=0.067,
            threat_intel={"vulnerabilities": []}
        ),
        ScanResult(
            port=443,
            status="open",
            service="HTTPS",
            version="TLS 1.3, CN: example.com",
            vulnerabilities=[],
            confidence=0.92,
            response_time=0.098,
            threat_intel={"vulnerabilities": []}
        ),
        ScanResult(
            port=3306,
            status="open",
            service="MySQL",
            version="MySQL 5.7.30",
            vulnerabilities=["CVE-2020-2922", "CVE-2020-2934"],
            confidence=0.88,
            response_time=0.156,
            threat_intel={"vulnerabilities": [{"cve_id": "CVE-2020-2922", "severity": "high"}]}
        ),
        ScanResult(
            port=6379,
            status="open",
            service="Redis",
            version="Redis 6.0.5",
            vulnerabilities=["CVE-2021-32626"],
            confidence=0.94,
            response_time=0.045,
            threat_intel={"vulnerabilities": [{"cve_id": "CVE-2021-32626", "severity": "high"}]}
        )
    ]

    # Complete scan data structure
    scan_data = {
        "scan_results": scan_results,
        "target_ip": "192.168.1.100",
        "timestamp": "2024-09-15T10:30:00Z",
        "scan_mode": "intelligence",
        "threat_intelligence": {
            "malicious": False,
            "reputation_score": 2,
            "sources": ["ThreatCrowd", "Local_DB"],
            "threats": []
        },
        "cloud_info": {
            "provider": "AWS",
            "metadata_accessible": False,
            "confidence": 0.75,
            "services": ["EC2"]
        },
        "kubernetes_info": {
            "detected": False,
            "api_accessible": False,
            "version": "unknown"
        }
    }

    return scan_data

def main():
    """Generate demo reports."""
    print("🚀 Aura-sec v3.0.0 - Demo Report Generator")
    print("=" * 50)

    # Create demo data
    print("📊 Creating demo scan data...")
    scan_data = create_demo_data()

    # Generate interactive HTML report
    print("🎨 Generating interactive HTML report...")
    try:
        create_interactive_report(scan_data, "demo_scan_report.html")
        print("✅ Interactive HTML report created: demo_scan_report.html")
    except Exception as e:
        print(f"❌ Error creating HTML report: {e}")

    # Generate enhanced text report
    print("📝 Generating enhanced text report...")
    try:
        create_enhanced_text_report(scan_data, "demo_scan_report.txt")
        print("✅ Enhanced text report created: demo_scan_report.txt")
    except Exception as e:
        print(f"❌ Error creating text report: {e}")

    # Generate JSON report
    print("📋 Generating JSON report...")
    try:
        with open("demo_scan_report.json", 'w', encoding='utf-8') as f:
            # Convert ScanResult objects to dict for JSON serialization
            json_data = scan_data.copy()
            json_data["scan_results"] = [
                {
                    "port": r.port,
                    "status": r.status,
                    "service": r.service,
                    "version": r.version,
                    "vulnerabilities": r.vulnerabilities,
                    "confidence": r.confidence,
                    "response_time": r.response_time
                } for r in json_data["scan_results"]
            ]
            json.dump(json_data, f, indent=2, default=str)
        print("✅ JSON report created: demo_scan_report.json")
    except Exception as e:
        print(f"❌ Error creating JSON report: {e}")

    print("\n🎯 Demo reports generated successfully!")
    print("📁 Files created:")
    print("   • demo_scan_report.html (Interactive)")
    print("   • demo_scan_report.txt (Enhanced Text)")
    print("   • demo_scan_report.json (Machine Readable)")
    print("\n🌟 Open the HTML file in your browser to see the interactive features!")


if __name__ == "__main__":
    main()
