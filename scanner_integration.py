#!/usr/bin/env python3
"""
Scanner Integration Module

Provides seamless integration between the vulnerability scanner and report generator,
enabling one-command scanning with comprehensive report generation for professional
security assessments.

Author: MohammedMiran J. Shaikh
Project: ML-Enhanced Web Vulnerability Detection Framework
"""

from scanner import EnhancedVulnerabilityScanner
from report_generator import VulnerabilityReportGenerator, ReportConfig
import typer
import os
import webbrowser
from pathlib import Path

app = typer.Typer()

@app.command()
def scan_and_report(
    url: str = typer.Argument(..., help="Target URL to scan"),
    max_pages: int = typer.Option(50, help="Maximum pages to crawl"),
    output_format: str = typer.Option("html", help="Report format (html/pdf)"),
    company_name: str = typer.Option("Security Team", help="Company name for report"),
    report_title: str = typer.Option("Vulnerability Assessment Report", help="Report title"),
    open_browser: bool = typer.Option(True, help="Open report in browser"),
    config_file: str = typer.Option("config.yaml", help="Scanner configuration file"),
    save_scan: bool = typer.Option(True, help="Save raw scan results")
):
    """
    Complete vulnerability scan with comprehensive report generation
    
    This command performs a full security assessment including:
    - Web crawling and endpoint discovery
    - Multi-scanner vulnerability detection (Nmap, Nikto, ZAP)
    - Machine learning analysis for false positive reduction
    - Professional HTML/PDF report generation with interactive charts
    """
    
    print(f"Starting comprehensive vulnerability assessment of {url}")
    print(f"Report format: {output_format.upper()}")
    print(f"Maximum pages to crawl: {max_pages}")
    print("-" * 60)
    
    # Initialize scanner
    scanner = EnhancedVulnerabilityScanner()
    
    # Run comprehensive scan
    print("Phase 1: Running vulnerability scan...")
    results = scanner.scan_with_tools(url, max_pages)
    
    # Save raw scan results if requested
    if save_scan:
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scan_file = f"scan_results_{timestamp}.json"
        
        import json
        with open(scan_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Raw scan results saved: {scan_file}")
    
    # Generate professional report
    print("Phase 2: Generating professional report...")
    
    config = ReportConfig(
        title=report_title,
        company_name=company_name,
        export_format=output_format,
        include_executive_summary=True,
        include_charts=True,
        include_detailed_findings=True,
        include_recommendations=True
    )
    
    generator = VulnerabilityReportGenerator(config)
    report_path = generator.generate_report(results)
    
    print("-" * 60)
    print("Vulnerability assessment completed successfully!")
    print(f"Report saved to: {report_path}")
    
    # Display summary statistics
    total_vulns = len(results.get('vulnerabilities', []))
    critical_vulns = len([v for v in results.get('vulnerabilities', []) 
                         if v.get('severity', '').lower() == 'critical'])
    high_vulns = len([v for v in results.get('vulnerabilities', []) 
                     if v.get('severity', '').lower() == 'high'])
    
    print(f"Total vulnerabilities found: {total_vulns}")
    print(f"Critical: {critical_vulns}, High: {high_vulns}")
    
    if open_browser:
        print("Opening report in browser...")
        webbrowser.open(f"file://{os.path.abspath(report_path)}")
    
    return report_path

@app.command()
def generate_report_only(
    scan_file: str = typer.Argument(..., help="Path to scan results JSON file"),
    output_format: str = typer.Option("html", help="Report format (html/pdf)"),
    company_name: str = typer.Option("Security Team", help="Company name for report"),
    report_title: str = typer.Option("Vulnerability Assessment Report", help="Report title"),
    output_filename: str = typer.Option(None, help="Custom output filename"),
    open_browser: bool = typer.Option(True, help="Open report in browser"),
    dark_mode: bool = typer.Option(False, help="Use dark mode theme")
):
    """
    Generate report from existing scan results
    
    Use this command to create professional reports from previously saved
    scan results without re-running the vulnerability assessment.
    """
    
    if not os.path.exists(scan_file):
        print(f"Error: Scan file not found: {scan_file}")
        return
    
    print(f"Generating report from: {scan_file}")
    print(f"Output format: {output_format.upper()}")
    
    # Create report configuration
    config = ReportConfig(
        title=report_title,
        company_name=company_name,
        export_format=output_format,
        dark_mode=dark_mode,
        include_executive_summary=True,
        include_charts=True,
        include_detailed_findings=True,
        include_recommendations=True
    )
    
    # Generate report
    generator = VulnerabilityReportGenerator(config)
    
    import json
    with open(scan_file, 'r') as f:
        scan_data = json.load(f)
    
    report_path = generator.generate_report(scan_data, output_filename)
    
    print(f"Report generated successfully: {report_path}")
    
    if open_browser:
        webbrowser.open(f"file://{os.path.abspath(report_path)}")

@app.command()
def batch_report(
    scan_directory: str = typer.Argument(..., help="Directory containing scan result files"),
    output_format: str = typer.Option("html", help="Report format (html/pdf)"),
    company_name: str = typer.Option("Security Team", help="Company name for reports"),
    merge_reports: bool = typer.Option(False, help="Merge all scans into single report")
):
    """
    Generate reports for multiple scan results in batch
    
    Process all JSON scan files in a directory and generate individual
    or merged professional reports for bulk analysis.
    """
    
    scan_dir = Path(scan_directory)
    if not scan_dir.exists():
        print(f"Error: Directory not found: {scan_directory}")
        return
    
    # Find all JSON scan files
    scan_files = list(scan_dir.glob("*.json"))
    if not scan_files:
        print(f"No JSON scan files found in: {scan_directory}")
        return
    
    print(f"Found {len(scan_files)} scan files")
    
    if merge_reports:
        print("Merging all scans into single report...")
        # Merge scan data (implementation would combine vulnerabilities)
        merged_data = {'vulnerabilities': [], 'scan_target': {}, 'scan_metadata': {}}
        
        import json
        for scan_file in scan_files:
            with open(scan_file, 'r') as f:
                data = json.load(f)
                merged_data['vulnerabilities'].extend(data.get('vulnerabilities', []))
        
        # Generate merged report
        config = ReportConfig(
            title="Consolidated Vulnerability Assessment Report",
            company_name=company_name,
            export_format=output_format
        )
        
        generator = VulnerabilityReportGenerator(config)
        report_path = generator.generate_report(merged_data, "consolidated_report.html")
        print(f"Consolidated report generated: {report_path}")
    
    else:
        print("Generating individual reports...")
        for scan_file in scan_files:
            print(f"Processing: {scan_file.name}")
            
            config = ReportConfig(
                title=f"Vulnerability Report - {scan_file.stem}",
                company_name=company_name,
                export_format=output_format
            )
            
            generator = VulnerabilityReportGenerator(config)
            
            import json
            with open(scan_file, 'r') as f:
                scan_data = json.load(f)
            
            output_name = f"report_{scan_file.stem}.html"
            report_path = generator.generate_report(scan_data, output_name)
            print(f"  Report generated: {report_path}")

@app.command()
def demo_report(
    sample_data: bool = typer.Option(False, help="Generate demo with sample data"),
    output_format: str = typer.Option("html", help="Report format"),
    open_browser: bool = typer.Option(True, help="Open demo in browser")
):
    """
    Generate a demonstration report with sample data
    
    Creates a professional report using sample vulnerability data to
    showcase the reporting capabilities and visual elements.
    """
    
    if sample_data:
        # Create sample vulnerability data for demonstration
        sample_scan_data = {
            'scan_target': {
                'base_url': 'https://demo.example.com',
                'scan_id': 'DEMO_20250810_001'
            },
            'scan_metadata': {
                'scan_duration': '00:15:30',
                'scanners_used': ['nmap', 'nikto', 'zap'],
                'total_endpoints': 25
            },
            'vulnerabilities': [
                {
                    'title': 'SQL Injection Vulnerability',
                    'severity': 'critical',
                    'confidence': 'high',
                    'source_scanner': 'zap',
                    'affected_url': 'https://demo.example.com/login',
                    'description': 'SQL injection vulnerability found in login form parameter',
                    'solution': 'Use parameterized queries and input validation',
                    'cve_id': 'CVE-2023-1234'
                },
                {
                    'title': 'Cross-Site Scripting (XSS)',
                    'severity': 'high',
                    'confidence': 'high',
                    'source_scanner': 'zap',
                    'affected_url': 'https://demo.example.com/search',
                    'description': 'Reflected XSS vulnerability in search parameter',
                    'solution': 'Implement proper output encoding and CSP headers'
                },
                {
                    'title': 'Information Disclosure',
                    'severity': 'medium',
                    'confidence': 'medium',
                    'source_scanner': 'nikto',
                    'affected_url': 'https://demo.example.com/admin',
                    'description': 'Sensitive information exposed in error messages',
                    'solution': 'Implement proper error handling'
                }
            ],
            'discovered_endpoints': [
                'https://demo.example.com/',
                'https://demo.example.com/login',
                'https://demo.example.com/search',
                'https://demo.example.com/admin'
            ],
            'ml_summary': {
                'ml_analysis_available': True,
                'vulnerabilities_analyzed': 3,
                'high_confidence_predictions': 2,
                'average_confidence': 0.85,
                'model_type': 'Random Forest + Isolation Forest'
            }
        }
        
        print("Generating demonstration report with sample data...")
        
        config = ReportConfig(
            title="Demonstration Vulnerability Assessment Report",
            company_name="Security Demo Team",
            export_format=output_format
        )
        
        generator = VulnerabilityReportGenerator(config)
        report_path = generator.generate_report(sample_scan_data, "demo_report.html")
        
        print(f"Demo report generated: {report_path}")
        
        if open_browser:
            webbrowser.open(f"file://{os.path.abspath(report_path)}")
    
    else:
        print("Use --sample-data flag to generate demo with sample vulnerability data")

if __name__ == "__main__":
    app()
