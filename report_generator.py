#!/usr/bin/env python3
"""
Enhanced Vulnerability Report Generator with Charts and Improved Sections
"""

import json
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

class VulnerabilityReportGenerator:
    """Enhanced HTML report generator with charts and improved deduplication"""
    
    def __init__(self, output_dir: str = "vulnerability-reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
    
    def generate_report(self, scan_data: Dict[str, Any], filename: str = None) -> str:
        """Generate comprehensive HTML vulnerability report"""
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_url = scan_data.get('target_url', 'unknown')
            domain = self._extract_domain(target_url)
            filename = f"{domain}-{timestamp}.html"
        elif not filename.endswith('.html'):
            filename += '.html'
        
        html_content = self._generate_enhanced_html_report(scan_data)
        
        report_path = self.output_dir / filename
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(report_path)
    
    def _generate_enhanced_html_report(self, data: Dict[str, Any]) -> str:
        """Generate enhanced HTML report with charts and improved sections"""
        
        # Extract data
        target_url = data.get('scan_target', {}).get('base_url', 'Unknown')
        scan_id = data.get('scan_target', {}).get('scan_id', 'Unknown')
        timestamp = data.get('scan_target', {}).get('timestamp', datetime.now().isoformat())
        
        vulnerabilities = data.get('vulnerabilities', [])
        ml_summary = data.get('ml_summary', {})
        scan_metadata = data.get('scan_metadata', {})
        
        # Calculate statistics
        vuln_stats = self._calculate_vulnerability_stats(vulnerabilities, scan_metadata)
        chart_data = self._prepare_chart_data(vulnerabilities, scan_metadata)
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Assessment Report - {self._extract_domain(target_url)}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        {self._get_midnight_blue_css()}
    </style>
</head>
<body>
    <div class="theme-toggle">
        <button onclick="toggleTheme()" id="theme-btn">🌙 Dark Mode</button>
    </div>
    
    <div class="container">
        <header class="report-header">
            <h1>Web Application Vulnerability Assessment Report</h1>
            <div class="target-info">
                <div class="info-grid">
                    <div><strong>Target:</strong> {target_url}</div>
                    <div><strong>Scan ID:</strong> {scan_id}</div>
                    <div><strong>Date:</strong> {timestamp.split('T')[0]}</div>
                    <div><strong>Total Vulnerabilities:</strong> <span class="vuln-count">{vuln_stats['total']}</span></div>
                    <div><strong>Unique CVEs:</strong> {vuln_stats['unique_cves']}</div>
                    <div><strong>Scanners Used:</strong> {', '.join(vuln_stats['scanners'])}</div>
                </div>
            </div>
        </header>

        <!-- Executive Summary -->
        <section class="summary-section">
            <h2>🎯 Executive Summary</h2>
            <div class="summary-cards">
                <div class="summary-card critical">
                    <h3>{vuln_stats['by_severity'].get('critical', 0)}</h3>
                    <p>Critical Issues</p>
                    <span class="confidence">Avg Confidence: {vuln_stats['avg_confidence_by_severity'].get('critical', 0):.1%}</span>
                </div>
                <div class="summary-card high">
                    <h3>{vuln_stats['by_severity'].get('high', 0)}</h3>
                    <p>High Issues</p>
                    <span class="confidence">Avg Confidence: {vuln_stats['avg_confidence_by_severity'].get('high', 0):.1%}</span>
                </div>
                <div class="summary-card medium">
                    <h3>{vuln_stats['by_severity'].get('medium', 0)}</h3>
                    <p>Medium Issues</p>
                    <span class="confidence">Avg Confidence: {vuln_stats['avg_confidence_by_severity'].get('medium', 0):.1%}</span>
                </div>
                <div class="summary-card low">
                    <h3>{vuln_stats['by_severity'].get('low', 0)}</h3>
                    <p>Low Issues</p>
                    <span class="confidence">Avg Confidence: {vuln_stats['avg_confidence_by_severity'].get('low', 0):.1%}</span>
                </div>
            </div>
        </section>

        <!-- Charts Section -->
        <section class="charts-section">
            <h2>📊 Security Analysis Charts</h2>
            <div class="charts-grid">
                <div class="chart-container">
                    <h3>Severity Distribution</h3>
                    <canvas id="severityChart"></canvas>
                </div>
                <div class="chart-container">
                    <h3>Scanner Performance</h3>
                    <canvas id="scannerChart"></canvas>
                </div>
                <div class="chart-container">
                    <h3>Finding Types</h3>
                    <canvas id="findingTypesChart"></canvas>
                </div>
                <div class="chart-container">
                    <h3>Confidence Distribution</h3>
                    <canvas id="confidenceChart"></canvas>
                </div>
            </div>
        </section>

        {self._generate_ml_analysis_section(ml_summary)}
        {self._generate_detailed_findings_section(vulnerabilities)}
        {self._generate_technical_appendix_section(scan_metadata, vulnerabilities)}
        
        <footer class="report-footer">
            <p>Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | 
            ML-Enhanced Vulnerability Scanner v3.2.0</p>
        </footer>
    </div>

    <script>
        {self._get_chart_scripts(chart_data)}
        {self._get_theme_toggle_script()}
    </script>
</body>
</html>"""
        
        return html
    
    def _get_midnight_blue_css(self) -> str:
        """Enhanced midnight blue CSS theme"""
        return """
        :root {
            --primary-color: #191970;
            --secondary-color: #4169E1;
            --accent-color: #00BFFF;
            --background-color: #0F0F23;
            --surface-color: #1E1E3F;
            --text-color: #FFFFFF;
            --text-secondary: #FFFFFF;
            --border-color: #2F2F5F;
            --success-color: #32CD32;
            --warning-color: #FFD700;
            --error-color: #FF6347;
            --critical-color: #DC143C;
        }
        
        [data-theme="light"] {
            --primary-color: #191970;
            --secondary-color: #4169E1;
            --accent-color: #00BFFF;
            --background-color: #F8F9FA;
            --surface-color: #FFFFFF;
            --text-color: #000000;
            --text-secondary: #000000;
            --border-color: #DEE2E6;
            --success-color: #28A745;
            --warning-color: #FFC107;
            --error-color: #DC3545;
            --critical-color: #721C24;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: var(--background-color);
            color: var(--text-color);
            line-height: 1.6;
            transition: all 0.3s ease;
        }
        
        /* Ensure all text elements use the correct text color */
        * {
            color: inherit;
        }
        
        div, section, p, span, h1, h2, h3, h4, h5, h6, button, label, td, th, li, a {
            color: var(--text-color);
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .theme-toggle {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 1000;
        }
        
        .theme-toggle button {
            background: var(--primary-color);
            color: white;
            border: 1px solid var(--border-color);
            padding: 10px 15px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.3s ease;
        }
        
        .theme-toggle button:hover {
            background: var(--secondary-color);
            transform: translateY(-2px);
        }
        
        .report-header {
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            padding: 40px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        }
        
        .report-header h1 {
            color: white;
            font-size: 2.5em;
            margin-bottom: 20px;
            text-align: center;
        }
        
        .target-info {
            background: rgba(255, 255, 255, 0.1);
            padding: 20px;
            border-radius: 8px;
            backdrop-filter: blur(10px);
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            color: white;
        }
        
        .info-grid div {
            padding: 10px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 6px;
        }
        
        .vuln-count {
            background: var(--error-color);
            color: white;
            padding: 2px 8px;
            border-radius: 12px;
            font-weight: bold;
        }
        
        section {
            background: var(--surface-color);
            margin: 30px 0;
            padding: 30px;
            border-radius: 12px;
            border: 1px solid var(--border-color);
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.1);
        }
        
        h2 {
            color: var(--text-color);
            font-size: 1.8em;
            margin-bottom: 20px;
            border-bottom: 2px solid var(--accent-color);
            padding-bottom: 10px;
        }
        
        h3 {
            color: var(--text-color);
            margin: 20px 0 10px 0;
        }
        
        h4 {
            color: var(--text-color);
        }
        
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .summary-card {
            padding: 25px;
            border-radius: 12px;
            text-align: center;
            color: white;
            position: relative;
            overflow: hidden;
        }
        
        .summary-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(135deg, transparent, rgba(255, 255, 255, 0.1));
            z-index: 1;
        }
        
        .summary-card > * {
            position: relative;
            z-index: 2;
        }
        
        .summary-card.critical {
            background: linear-gradient(135deg, var(--critical-color), #B71C1C);
        }
        
        .summary-card.high {
            background: linear-gradient(135deg, var(--error-color), #D32F2F);
        }
        
        .summary-card.medium {
            background: linear-gradient(135deg, var(--warning-color), #F57C00);
        }
        
        .summary-card.low {
            background: linear-gradient(135deg, var(--accent-color), #0288D1);
        }
        
        .summary-card h3 {
            font-size: 2.5em;
            margin: 0;
            color: white;
        }
        
        .summary-card p {
            margin: 10px 0;
            font-size: 1.1em;
        }
        
        .confidence {
            font-size: 0.9em;
            opacity: 0.9;
            background: rgba(255, 255, 255, 0.2);
            padding: 4px 8px;
            border-radius: 4px;
            display: inline-block;
        }
        
        .charts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 30px;
            margin-top: 20px;
        }
        
        .chart-container {
            background: var(--surface-color);
            padding: 25px;
            border-radius: 12px;
            border: 1px solid var(--border-color);
            position: relative;
        }
        
        .chart-container h3 {
            text-align: center;
            margin-bottom: 20px;
            color: var(--text-color);
        }
        
        .chart-container canvas {
            max-height: 300px;
        }
        
        .vulnerability-item {
            background: var(--surface-color);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin: 15px 0;
            overflow: hidden;
            transition: all 0.3s ease;
        }
        
        .vulnerability-item:hover {
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.15);
            transform: translateY(-2px);
        }
        
        .vulnerability-header {
            padding: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
        }
        
        .vulnerability-title {
            font-weight: bold;
            font-size: 1.1em;
            color: var(--text-color);
        }
        
        .severity-badge {
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .severity-critical {
            background: var(--critical-color);
            color: white;
        }
        
        .severity-high {
            background: var(--error-color);
            color: white;
        }
        
        .severity-medium {
            background: var(--warning-color);
            color: #333;
        }
        
        .severity-low {
            background: var(--accent-color);
            color: white;
        }
        
        .vulnerability-details {
            padding: 0 20px 20px;
            border-top: 1px solid var(--border-color);
            background: rgba(0, 0, 0, 0.02);
        }
        
        .vulnerability-meta {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 15px 0;
        }
        
        .meta-item {
            background: var(--background-color);
            padding: 10px;
            border-radius: 6px;
            border-left: 4px solid var(--accent-color);
        }
        
        .meta-label {
            font-weight: bold;
            color: var(--text-secondary);
            font-size: 0.9em;
            margin-bottom: 5px;
        }
        
        .meta-value {
            color: var(--text-color);
        }
        
        .confidence-indicator {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: var(--surface-color);
            padding: 6px 12px;
            border-radius: 6px;
            border: 1px solid var(--border-color);
        }
        
        .confidence-bar {
            width: 60px;
            height: 8px;
            background: var(--border-color);
            border-radius: 4px;
            overflow: hidden;
        }
        
        .confidence-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--error-color), var(--warning-color), var(--success-color));
            border-radius: 4px;
            transition: width 0.3s ease;
        }
        
        .grouped-indicator {
            background: var(--accent-color);
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            margin-left: 10px;
        }
        
        .report-footer {
            text-align: center;
            padding: 30px 0;
            color: var(--text-secondary);
            border-top: 1px solid var(--border-color);
            margin-top: 40px;
        }
        
        .appendix-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .appendix-card {
            background: var(--background-color);
            padding: 20px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }
        
        .appendix-card h4 {
            color: var(--text-color);
            margin-bottom: 10px;
        }
        
        .tech-details {
            font-family: 'Courier New', monospace;
            background: var(--background-color);
            padding: 15px;
            border-radius: 6px;
            border-left: 4px solid var(--accent-color);
            margin: 10px 0;
            overflow-x: auto;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .charts-grid {
                grid-template-columns: 1fr;
            }
            
            .chart-container {
                min-width: unset;
            }
            
            .info-grid {
                grid-template-columns: 1fr;
            }
            
            .summary-cards {
                grid-template-columns: repeat(2, 1fr);
            }
            
            .vulnerability-meta {
                grid-template-columns: 1fr;
            }
        }
        """
    
    def _generate_detailed_findings_section(self, vulnerabilities: List[Dict]) -> str:
        """Generate detailed security findings section with confidence ratings"""
        
        if not vulnerabilities:
            return """
            <section class="findings-section">
                <h2>🔍 Detailed Security Findings</h2>
                <p>No vulnerabilities detected during the assessment.</p>
            </section>
            """
        
        # Group vulnerabilities by severity
        by_severity = {'critical': [], 'high': [], 'medium': [], 'low': []}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low').lower()
            if severity in by_severity:
                by_severity[severity].append(vuln)
        
        findings_html = '<section class="findings-section"><h2>🔍 Detailed Security Findings</h2>'
        
        for severity in ['critical', 'high', 'medium', 'low']:
            if not by_severity[severity]:
                continue
                
            findings_html += f'<h3>{severity.title()} Risk Findings ({len(by_severity[severity])} issues)</h3>'
            
            for i, vuln in enumerate(by_severity[severity], 1):
                confidence = self._get_confidence_value(vuln)
                confidence_class = 'high' if confidence > 0.7 else 'medium' if confidence > 0.4 else 'low'
                
                grouped_text = ""
                if vuln.get('is_grouped'):
                    grouped_text = f'<span class="grouped-indicator">Affects {vuln.get("affected_count", 1)} URLs</span>'
                
                findings_html += f"""
                <div class="vulnerability-item">
                    <div class="vulnerability-header" onclick="toggleDetails('vuln-{severity}-{i}')">
                        <div class="vulnerability-title">
                            {vuln.get('title', 'Unknown Vulnerability')}
                            {grouped_text}
                        </div>
                        <div style="display: flex; align-items: center; gap: 15px;">
                            <div class="confidence-indicator">
                                <span style="font-size: 0.9em;">Confidence:</span>
                                <div class="confidence-bar">
                                    <div class="confidence-fill" style="width: {confidence*100}%"></div>
                                </div>
                                <span style="font-size: 0.9em;">{confidence:.1%}</span>
                            </div>
                            <span class="severity-badge severity-{severity}">{severity}</span>
                        </div>
                    </div>
                    <div class="vulnerability-details" id="vuln-{severity}-{i}" style="display: none;">
                        <div class="vulnerability-meta">
                            <div class="meta-item">
                                <div class="meta-label">Scanner Source</div>
                                <div class="meta-value">{vuln.get('source_scanner', 'unknown').upper()}</div>
                            </div>
                            <div class="meta-item">
                                <div class="meta-label">Affected URL</div>
                                <div class="meta-value">{vuln.get('affected_url', 'N/A')}</div>
                            </div>
                            <div class="meta-item">
                                <div class="meta-label">Vulnerability Type</div>
                                <div class="meta-value">{vuln.get('type', 'web_application').replace('_', ' ').title()}</div>
                            </div>
                            <div class="meta-item">
                                <div class="meta-label">Confidence Level</div>
                                <div class="meta-value">{confidence_class.title()} ({confidence:.1%})</div>
                            </div>
                        </div>
                        
                        <div style="margin: 15px 0;">
                            <div class="meta-label">Description</div>
                            <div style="margin-top: 8px; line-height: 1.6;">
                                {vuln.get('description', 'No description available.')}
                            </div>
                        </div>
                        
                        {self._format_additional_vuln_details(vuln)}
                    </div>
                </div>
                """
        
        findings_html += '</section>'
        return findings_html
    
    def _generate_technical_appendix_section(self, scan_metadata: Dict, vulnerabilities: List[Dict]) -> str:
        """Generate technical appendix section"""
        
        scanner_stats = scan_metadata.get('vulnerabilities_by_scanner', {})
        pipeline_stats = scan_metadata.get('pipeline_statistics', {})
        
        appendix_html = f"""
        <section class="appendix-section">
            <h2>📋 Technical Appendix</h2>
            
            <h3>Scan Configuration</h3>
            <div class="appendix-grid">
                <div class="appendix-card">
                    <h4>Target Information</h4>
                    <div class="tech-details">
                        Total Endpoints Discovered: {scan_metadata.get('total_endpoints', 0)}<br>
                        High Priority Targets: {scan_metadata.get('high_priority_targets', 0)}<br>
                        Endpoints with Forms: {scan_metadata.get('endpoints_with_forms', 0)}
                    </div>
                </div>
                
                <div class="appendix-card">
                    <h4>Scanner Performance</h4>
                    <div class="tech-details">
                        {self._format_scanner_performance(scanner_stats)}
                    </div>
                </div>
                
                <div class="appendix-card">
                    <h4>Vulnerability Statistics</h4>
                    <div class="tech-details">
                        Total Raw Findings: {scan_metadata.get('total_raw_findings', 0)}<br>
                        Total Filtered Vulnerabilities: {scan_metadata.get('total_vulnerabilities_found', 0)}<br>
                        False Positives Filtered: {scan_metadata.get('false_positives_filtered', 0)}<br>
                        Deduplication Effectiveness: {scan_metadata.get('filtering_effectiveness', 'N/A')}
                    </div>
                </div>
                
                <div class="appendix-card">
                    <h4>Processing Pipeline</h4>
                    <div class="tech-details">
                        {self._format_pipeline_stats(pipeline_stats)}
                    </div>
                </div>
            </div>
            
            <h3>Methodology</h3>
            <div class="tech-details">
                <strong>Scanning Approach:</strong><br>
                1. Web Application Discovery - Aggressive crawling with SPA support<br>
                2. Network Security Assessment - Nmap vulnerability scripts<br>
                3. Web Application Security Testing - Nikto and ZAP analysis<br>
                4. Machine Learning Analysis - Random Forest + Isolation Forest classification<br>
                5. Intelligent Deduplication - Pattern-based vulnerability grouping<br>
                6. Risk Assessment - CVSS-based severity classification with confidence scoring
            </div>
            
            <h3>Tool Versions</h3>
            <div class="tech-details">
                Scanner Framework: ML-Enhanced Vulnerability Scanner v3.2.0<br>
                ML Model: Hybrid Random Forest + Isolation Forest<br>
                Crawling Engine: AggressiveVulnCrawler with Selenium WebDriver<br>
                Report Generator: Enhanced HTML5 with Chart.js integration
            </div>
        </section>
        """
        
        return appendix_html
    
    def _calculate_vulnerability_stats(self, vulnerabilities: List[Dict], scan_metadata: Dict) -> Dict:
        """Calculate comprehensive vulnerability statistics"""
        
        stats = {
            'total': len(vulnerabilities),
            'unique_cves': len(set(v.get('cve_id', '') for v in vulnerabilities if v.get('cve_id'))),
            'scanners': list(set(v.get('source_scanner', 'unknown') for v in vulnerabilities)),
            'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'by_scanner': {},
            'by_type': {},
            'avg_confidence_by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'confidence_distribution': {'high': 0, 'medium': 0, 'low': 0}
        }
        
        # Count by severity and calculate confidence
        severity_confidence_sums = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low').lower()
            scanner = vuln.get('source_scanner', 'unknown')
            vuln_type = vuln.get('type', 'web_application')
            confidence = self._get_confidence_value(vuln)
            
            if severity in stats['by_severity']:
                stats['by_severity'][severity] += 1
                severity_confidence_sums[severity] += confidence
                severity_counts[severity] += 1
            
            stats['by_scanner'][scanner] = stats['by_scanner'].get(scanner, 0) + 1
            stats['by_type'][vuln_type] = stats['by_type'].get(vuln_type, 0) + 1
            
            # Confidence distribution
            if confidence > 0.7:
                stats['confidence_distribution']['high'] += 1
            elif confidence > 0.4:
                stats['confidence_distribution']['medium'] += 1
            else:
                stats['confidence_distribution']['low'] += 1
        
        # Calculate average confidence by severity
        for severity in severity_counts:
            if severity_counts[severity] > 0:
                stats['avg_confidence_by_severity'][severity] = severity_confidence_sums[severity] / severity_counts[severity]
        
        return stats
    
    def _prepare_chart_data(self, vulnerabilities: List[Dict], scan_metadata: Dict) -> Dict:
        """Prepare data for charts"""
        
        vuln_stats = self._calculate_vulnerability_stats(vulnerabilities, scan_metadata)
        
        return {
            'severity': {
                'labels': ['Critical', 'High', 'Medium', 'Low'],
                'data': [
                    vuln_stats['by_severity']['critical'],
                    vuln_stats['by_severity']['high'],
                    vuln_stats['by_severity']['medium'],
                    vuln_stats['by_severity']['low']
                ],
                'colors': ['#DC143C', '#FF6347', '#FFD700', '#00BFFF']
            },
            'scanner': {
                'labels': list(vuln_stats['by_scanner'].keys()),
                'data': list(vuln_stats['by_scanner'].values()),
                'colors': ['#191970', '#4169E1', '#00BFFF', '#32CD32', '#FFD700']
            },
            'types': {
                'labels': list(vuln_stats['by_type'].keys()),
                'data': list(vuln_stats['by_type'].values()),
                'colors': ['#191970', '#4169E1', '#00BFFF', '#32CD32']
            },
            'confidence': {
                'labels': ['High Confidence', 'Medium Confidence', 'Low Confidence'],
                'data': [
                    vuln_stats['confidence_distribution']['high'],
                    vuln_stats['confidence_distribution']['medium'],
                    vuln_stats['confidence_distribution']['low']
                ],
                'colors': ['#32CD32', '#FFD700', '#FF6347']
            }
        }
    
    def _get_chart_scripts(self, chart_data: Dict) -> str:
        """Generate Chart.js scripts"""
        
        return f"""
        // Chart.js Configuration
        const chartOptions = {{
            responsive: true,
            maintainAspectRatio: false,
            plugins: {{
                legend: {{
                    labels: {{
                        color: getComputedStyle(document.documentElement).getPropertyValue('--text-color'),
                        font: {{
                            size: 12
                        }}
                    }}
                }}
            }},
            scales: {{
                y: {{
                    ticks: {{
                        color: getComputedStyle(document.documentElement).getPropertyValue('--text-secondary')
                    }},
                    grid: {{
                        color: getComputedStyle(document.documentElement).getPropertyValue('--border-color')
                    }}
                }},
                x: {{
                    ticks: {{
                        color: getComputedStyle(document.documentElement).getPropertyValue('--text-secondary')
                    }},
                    grid: {{
                        color: getComputedStyle(document.documentElement).getPropertyValue('--border-color')
                    }}
                }}
            }}
        }};
        
        // Severity Distribution Chart
        const severityCtx = document.getElementById('severityChart').getContext('2d');
        new Chart(severityCtx, {{
            type: 'doughnut',
            data: {{
                labels: {chart_data['severity']['labels']},
                datasets: [{{
                    data: {chart_data['severity']['data']},
                    backgroundColor: {chart_data['severity']['colors']},
                    borderWidth: 2,
                    borderColor: '#fff'
                }}]
            }},
            options: {{
                ...chartOptions,
                cutout: '40%'
            }}
        }});
        
        // Scanner Performance Chart
        const scannerCtx = document.getElementById('scannerChart').getContext('2d');
        new Chart(scannerCtx, {{
            type: 'bar',
            data: {{
                labels: {chart_data['scanner']['labels']},
                datasets: [{{
                    label: 'Vulnerabilities Found',
                    data: {chart_data['scanner']['data']},
                    backgroundColor: {chart_data['scanner']['colors'][:len(chart_data['scanner']['labels'])]},
                    borderWidth: 1
                }}]
            }},
            options: chartOptions
        }});
        
        // Finding Types Chart
        const typesCtx = document.getElementById('findingTypesChart').getContext('2d');
        new Chart(typesCtx, {{
            type: 'pie',
            data: {{
                labels: {chart_data['types']['labels']},
                datasets: [{{
                    data: {chart_data['types']['data']},
                    backgroundColor: {chart_data['types']['colors'][:len(chart_data['types']['labels'])]},
                    borderWidth: 2,
                    borderColor: '#fff'
                }}]
            }},
            options: chartOptions
        }});
        
        // Confidence Distribution Chart
        const confidenceCtx = document.getElementById('confidenceChart').getContext('2d');
        new Chart(confidenceCtx, {{
            type: 'bar',
            data: {{
                labels: {chart_data['confidence']['labels']},
                datasets: [{{
                    label: 'Number of Findings',
                    data: {chart_data['confidence']['data']},
                    backgroundColor: {chart_data['confidence']['colors']},
                    borderWidth: 1
                }}]
            }},
            options: chartOptions
        }});
        
        // Toggle vulnerability details
        function toggleDetails(elementId) {{
            const element = document.getElementById(elementId);
            element.style.display = element.style.display === 'none' ? 'block' : 'none';
        }}
        """
    
    def _get_theme_toggle_script(self) -> str:
        """Theme toggle functionality"""
        return """
        function toggleTheme() {
            const body = document.body;
            const btn = document.getElementById('theme-btn');
            
            if (body.getAttribute('data-theme') === 'light') {
                body.removeAttribute('data-theme');
                btn.textContent = '🌙 Dark Mode';
                localStorage.setItem('theme', 'dark');
            } else {
                body.setAttribute('data-theme', 'light');
                btn.textContent = '☀️ Light Mode';
                localStorage.setItem('theme', 'light');
            }
        }
        
        // Load saved theme
        const savedTheme = localStorage.getItem('theme');
        if (savedTheme === 'light') {
            document.body.setAttribute('data-theme', 'light');
            document.getElementById('theme-btn').textContent = '☀️ Light Mode';
        }
        """
    
    def _get_confidence_value(self, vuln: Dict) -> float:
        """Extract confidence value from vulnerability"""
        confidence = vuln.get('confidence', vuln.get('ml_confidence', 0.5))
        
        if isinstance(confidence, str):
            confidence_map = {'high': 0.9, 'medium': 0.6, 'low': 0.3}
            return confidence_map.get(confidence.lower(), 0.5)
        
        return float(confidence) if confidence else 0.5
    
    def _format_additional_vuln_details(self, vuln: Dict) -> str:
        """Format additional vulnerability details"""
        details = []
        
        if vuln.get('cve_id'):
            details.append(f"<strong>CVE ID:</strong> {vuln['cve_id']}")
        
        if vuln.get('solution'):
            details.append(f"<strong>Recommended Solution:</strong> {vuln['solution']}")
        
        if vuln.get('parameter'):
            details.append(f"<strong>Vulnerable Parameter:</strong> {vuln['parameter']}")
        
        if vuln.get('is_grouped') and vuln.get('affected_urls_list'):
            urls_list = '<br>'.join(f"• {url}" for url in vuln['affected_urls_list'][:5])
            if len(vuln['affected_urls_list']) > 5:
                urls_list += f"<br>• ... and {len(vuln['affected_urls_list']) - 5} more URLs"
            details.append(f"<strong>Affected URLs:</strong><br>{urls_list}")
        
        return '<div style="margin-top: 15px;">' + '<br><br>'.join(details) + '</div>' if details else ''
    
    def _format_scanner_performance(self, scanner_stats: Dict) -> str:
        """Format scanner performance details"""
        if not scanner_stats:
            return "No scanner performance data available"
        
        lines = []
        for scanner, count in scanner_stats.items():
            lines.append(f"{scanner.upper()}: {count} findings")
        
        return '<br>'.join(lines)
    
    def _format_pipeline_stats(self, pipeline_stats: Dict) -> str:
        """Format pipeline statistics"""
        if not pipeline_stats:
            return "No pipeline statistics available"
        
        lines = []
        for scanner, stats in pipeline_stats.items():
            raw = stats.get('raw_findings', 0)
            final = stats.get('final_findings', 0)
            lines.append(f"{scanner.upper()}: {raw} raw → {final} final")
        
        return '<br>'.join(lines)
    
    def _generate_ml_analysis_section(self, ml_summary: Dict) -> str:
        """Generate ML analysis section"""
        if not ml_summary.get('ml_analysis_available'):
            return """
            <section class="ml-section">
                <h2>🤖 Machine Learning Analysis</h2>
                <p>ML analysis was not available for this scan. Train an ML model using 'python scanner.py train-ml' to enable intelligent vulnerability classification.</p>
            </section>
            """
        
        return f"""
        <section class="ml-section">
            <h2>🤖 Machine Learning Analysis</h2>
            <div class="appendix-grid">
                <div class="appendix-card">
                    <h4>ML Model Performance</h4>
                    <div class="tech-details">
                        Model Type: {ml_summary.get('model_type', 'Unknown')}<br>
                        Vulnerabilities Analyzed: {ml_summary.get('vulnerabilities_analyzed', 0)}<br>
                        High Confidence Predictions: {ml_summary.get('high_confidence_predictions', 0)}<br>
                        Average Confidence: {ml_summary.get('average_confidence', 0):.1%}
                    </div>
                </div>
                
                <div class="appendix-card">
                    <h4>ML Enhancement Benefits</h4>
                    <div class="tech-details">
                        • Reduced false positive rate through intelligent classification<br>
                        • Enhanced severity assessment using CVE database training<br>
                        • Confidence scoring for vulnerability reliability<br>
                        • Anomaly detection for unknown vulnerability patterns
                    </div>
                </div>
            </div>
        </section>
        """
    
    def _extract_domain(self, url: str) -> str:
        """Extract clean domain name from URL"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            domain = domain.replace('www.', '').replace('.', '-')
            return domain if domain else 'unknown'
        except:
            return 'unknown'


def main():
    """Demo function for testing the enhanced report generator"""
    # Sample data for testing
    sample_data = {
        'scan_target': {
            'base_url': 'https://testphp.vulnweb.com',
            'scan_id': 'DEMO_20250813_001',
            'timestamp': datetime.now().isoformat()
        },
        'scan_metadata': {
            'total_endpoints': 25,
            'high_priority_targets': 5,
            'endpoints_with_forms': 3,
            'total_raw_findings': 150,
            'total_vulnerabilities_found': 45,
            'false_positives_filtered': 105,
            'vulnerabilities_by_scanner': {
                'nmap': 5,
                'nikto': 8,
                'zap': 32
            }
        },
        'vulnerabilities': [
            {
                'title': 'Cross Site Scripting (Reflected)',
                'severity': 'high',
                'confidence': 0.85,
                'source_scanner': 'zap',
                'affected_url': 'https://testphp.vulnweb.com/search',
                'description': 'Multiple reflected XSS vulnerabilities found across various parameters and pages',
                'type': 'web_application',
                'is_grouped': True,
                'affected_count': 15,
                'affected_urls_list': [
                    'https://testphp.vulnweb.com/search?q=test',
                    'https://testphp.vulnweb.com/comment?text=test',
                    'https://testphp.vulnweb.com/feedback?msg=test'
                ]
            },
            {
                'title': 'SQL Injection Vulnerability',
                'severity': 'critical',
                'confidence': 0.92,
                'source_scanner': 'zap',
                'affected_url': 'https://testphp.vulnweb.com/login',
                'description': 'SQL injection vulnerability found in login form parameter',
                'type': 'web_application',
                'cve_id': 'CVE-2023-1234',
                'solution': 'Use parameterized queries and input validation'
            }
        ],
        'ml_summary': {
            'ml_analysis_available': True,
            'model_type': 'Random Forest + Isolation Forest',
            'vulnerabilities_analyzed': 45,
            'high_confidence_predictions': 32,
            'average_confidence': 0.78
        }
    }
    
    generator = VulnerabilityReportGenerator()
    report_path = generator.generate_report(sample_data, 'enhanced_demo_report')
    print(f"Enhanced demo report generated: {report_path}")


if __name__ == "__main__":
    main()
