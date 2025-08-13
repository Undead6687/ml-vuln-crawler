#!/usr/bin/env python3
"""
Web Vulnerability Detection Framework
Author: MohammedMiran J. Shaikh
Project: ML-Driven Web Vulnerability Detection with Dynamic Crawling
Institution: Master of Engineering in Cyber Security - LK473

Description: Main vulnerability scanner module with ML integration.
             Combines web crawling with multiple security scanners and ML classification.
Dependencies: typer, requests, subprocess, crawler, ml_handler, json, pathlib
"""

import os
import sys
import json
import time
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import warnings
import logging
import platform
import hashlib
import uuid
import yaml
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set, Union
from datetime import datetime
from urllib.parse import urlparse, urljoin
import requests
import typer

# Import ALL functionality from crawler without modification
from crawler import AggressiveVulnCrawler

def normalize_url(url: str) -> str:
    """
    Normalize URL by adding scheme if missing.
    
    Args:
        url: Target URL to normalize
        
    Returns:
        str: Normalized URL with https scheme if none provided
    """
    if not url.startswith(('http://', 'https://')):
        # Default to https for security scanning
        url = 'https://' + url
    return url

def create_security_scan_report(crawl_results: List[Dict], target_url: str, scan_id: str) -> Dict:
    """
    Create a security scan report from crawl results.
    
    Args:
        crawl_results: List of crawled page data
        target_url: Original target URL
        scan_id: Unique scan identifier
        
    Returns:
        Dict: Structured security scan report with endpoints and targets
    """
    # Normalize URL first
    normalized_url = normalize_url(target_url)
    
    # Parse target URL
    parsed_url = urlparse(normalized_url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    # Process endpoints
    discovered_endpoints = []
    endpoints_with_forms = 0
    high_priority_targets = 0
    
    for page in crawl_results:
        endpoint = {
            'url': page['url'],
            'final_url': page.get('final_url', page['url']),
            'status_code': page['status_code'],
            'title': page.get('title', ''),
            'has_forms': page['has_forms'],
            'forms': page.get('forms', []),
            'links_found': len(page.get('links', [])),
            'security_issues': page.get('security_issues', []),
            'scanner_priority': 'high' if page['has_forms'] else 'medium'
        }
        
        discovered_endpoints.append(endpoint)
        
        if page['has_forms']:
            endpoints_with_forms += 1
            high_priority_targets += 1
    
    # Create scanner targets
    nmap_targets = [{'host': parsed_url.netloc, 'ports': 'default'}]
    nikto_targets = [base_url]
    
    # Technology fingerprinting (basic)
    tech_stack = {
        'web_servers': [],
        'frameworks': [],
        'databases': []
    }
    
    report = {
        'scan_target': {
            'base_url': base_url,
            'scan_id': scan_id,
            'timestamp': datetime.now().isoformat()
        },
        'discovered_endpoints': discovered_endpoints,
        'scanner_targets': {
            'nmap_targets': nmap_targets,
            'nikto_targets': nikto_targets
        },
        'scan_summary': {
            'total_endpoints': len(discovered_endpoints),
            'endpoints_with_forms': endpoints_with_forms,
            'high_priority_targets': high_priority_targets,
            'technology_fingerprint': tech_stack
        }
    }
    
    return report

# Create typer app
app = typer.Typer(
    name="ML Vulnerability Scanner",
    help="Vulnerability scanner with CPU-based ML capabilities"
)

class EnhancedVulnerabilityScanner:
    """Vulnerability scanner with CPU-based ML integration"""
    
    def __init__(self, config_file: str = "config.yaml"):
        """
        Initialize vulnerability scanner with configuration and tools.
        
        Args:
            config_file: Path to YAML configuration file containing scanner settings
            
        Raises:
            FileNotFoundError: If configuration file is not found
            PermissionError: If cannot create results directory
        """
        self.config_file = config_file
        self.config = self.load_config(config_file)
        self.available_scanners = self.check_scanner_availability()
        
        # Results directory
        self.results_dir = Path("vuln-scanner-results")
        self.results_dir.mkdir(exist_ok=True)
        
        # Tracking
        self.scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.vulnerabilities_by_scanner = {
            'crawler': 0,
            'nmap': 0,
            'nikto': 0,
            'zap': 0
        }
        self.total_vulnerabilities_found = 0
        
        # Crawler instance (will be initialized per scan)
        self.crawler = None
    
    def load_config(self, config_file: str) -> Dict:
        """Load scanner configuration with Windows defaults"""
        default_config = {
            'nmap': {
                'enabled': True,
                'path': 'nmap',
                'timeout': 1000,
                'timing': 'T3',
                'scripts': True
            },
            'nikto': {
                'enabled': True,
                'path': 'perl',
                'nikto_script': './nikto-master/program/nikto.pl',
                'timeout': 800,
                'max_scan_time': 800
            },
            'zap': {
                'enabled': True,
                'host': 'localhost',
                'port': 8080,
                'api_key': '',
                'timeout': 1800,
                'zap_path': 'C:\\Program Files\\ZAP\\Zed Attack Proxy\\zap.bat'
            }
        }
        
        try:
            import yaml
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    loaded_config = yaml.safe_load(f)
                    default_config.update(loaded_config)
        except FileNotFoundError:
            pass
        except ImportError:
            pass
        
        return default_config
    
    def check_scanner_availability(self) -> Dict[str, bool]:
        """Check which scanners are available on Windows"""
        available: Dict[str, bool] = {}

        # Check Nmap
        try:
            result = subprocess.run(['nmap', '--version'], capture_output=True, text=True, timeout=10)
            available['nmap'] = result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            available['nmap'] = False

        # Check Nikto (via Perl)
        try:
            result = subprocess.run([
                self.config['nikto']['path'],
                self.config['nikto']['nikto_script'],
                '-Version'
            ], capture_output=True, text=True, timeout=10, shell=True)
            available['nikto'] = result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            available['nikto'] = False

        # Check ZAP
        if self.config['zap']['enabled']:
            available['zap'] = self._check_zap_running()
        else:
            available['zap'] = False

        return available

    def initialize_crawler(self, max_pages: int = 100, delay: float = 0.3, 
                          use_selenium: bool = True, aggressive: bool = False,
                          ignore_robots: bool = False, enable_dedup: bool = True):
        """Initialize the crawler with specified parameters"""
        self.crawler = AggressiveVulnCrawler(
            max_pages=max_pages,
            delay=delay,
            timeout=10,
            use_selenium=use_selenium,
            aggressive=aggressive,
            ignore_robots=ignore_robots,
            enable_dedup=enable_dedup
        )
    
    def apply_ml_enhancement(self, final_report: Dict) -> Dict:
        """Apply ML enhancement to scan results using CPU-based Random Forest + Isolation Forest"""
        try:
            from ml_handler import MLVulnerabilityEngine

            print("\n[ML ENHANCEMENT] Analyzing vulnerabilities with hybrid RF+IF model...")

            ml_handler = MLVulnerabilityEngine(cve_base_path="./cves")

            # Try to load existing model
            model_files = list(ml_handler.models_path.glob("hybrid_rf_isolation_*.pkl"))
            if not model_files:
                print("[ML] No pre-trained model found, skipping ML enhancement")
                print("[ML] Run 'python scanner.py train-ml' to train a model first")
                return final_report

            # Load the most recent model
            latest_model = max(model_files, key=lambda x: x.stat().st_mtime)
            fe_file = latest_model.parent / latest_model.name.replace("hybrid_rf_isolation_", "feature_engineer_")
            metadata_file = latest_model.parent / latest_model.name.replace("hybrid_rf_isolation_", "metadata_").replace(".pkl", ".json")

            if not ml_handler.load_model(str(latest_model), str(fe_file), str(metadata_file)):
                print("[ML] Failed to load model files, skipping ML enhancement")
                return final_report

            print(f"[ML] Using pre-trained hybrid model: {latest_model.name}")

            # Apply ML to each vulnerability if we have any
            vulnerabilities = final_report.get('vulnerabilities', [])
            enhanced_vulnerabilities: List[Dict] = []
            ml_predictions: List[Dict] = []

            for vuln in vulnerabilities:
                description = vuln.get('description', '')
                if description:
                    try:
                        ml_result = ml_handler.predict_vulnerability(description)

                        # Store original severity for comparison
                        original_severity = vuln.get('severity', 'unknown')

                        # Update vulnerability with ML predictions
                        enhanced_vuln = vuln.copy()
                        enhanced_vuln.update({
                            'ml_predicted_severity': ml_result.get('predicted_severity'),
                            'ml_confidence': ml_result.get('confidence'),
                            'ml_is_reliable': ml_result.get('is_reliable'),
                            'original_severity': original_severity
                        })

                        # Use ML prediction if it's reliable and confident
                        if ml_result.get('is_reliable') and float(ml_result.get('confidence', 0)) > 0.7:
                            enhanced_vuln['severity'] = ml_result.get('predicted_severity', original_severity)
                            enhanced_vuln['confidence_source'] = 'ml_enhanced'
                        else:
                            enhanced_vuln['confidence_source'] = 'scanner_original'

                        enhanced_vulnerabilities.append(enhanced_vuln)
                        ml_predictions.append(ml_result)
                    except Exception as e:
                        print(f"[!] ML prediction failed for vulnerability: {e}")
                        enhanced_vulnerabilities.append(vuln)
                else:
                    enhanced_vulnerabilities.append(vuln)

            # Update the report
            final_report['vulnerabilities'] = enhanced_vulnerabilities

            # Add ML summary
            if ml_predictions:
                high_confidence_predictions = sum(1 for p in ml_predictions if float(p.get('confidence', 0)) > 0.7)
                average_confidence = (
                    sum(float(p.get('confidence', 0)) for p in ml_predictions) / max(len(ml_predictions), 1)
                )

                final_report['ml_summary'] = {
                    'ml_analysis_available': True,
                    'vulnerabilities_analyzed': len(ml_predictions),
                    'high_confidence_predictions': high_confidence_predictions,
                    'average_confidence': float(average_confidence),
                    'model_type': 'HybridRF-IsolationForest'
                }

                print(f"[ML] Analyzed {len(ml_predictions)} vulnerabilities")
                print(f"[ML] High confidence predictions: {high_confidence_predictions}")
                print(f"[ML] Average confidence: {average_confidence:.2f}")

            return final_report

        except ImportError:
            print("[!] ml_handler.py not available, skipping ML enhancement")
            return final_report
        except Exception as e:
            print(f"[!] ML enhancement failed: {e}")
            return final_report
    
    def crawl_only(self, target_url: str, save_file: str = None, include_all: bool = False) -> Dict:
        """
        Run web application discovery without security scanners.
        
        Performs comprehensive web crawling with form detection and 
        ML-powered vulnerability classification on discovered endpoints.
        
        Args:
            target_url: Target URL to crawl
            save_file: Optional filename to save results
            include_all: Include pages without forms in results
            
        Returns:
            Dict containing crawl results and ML analysis
        """
        print(f"Starting web application discovery of {target_url}")
        print(f"Scan ID: {self.scan_id}")
        
        if not self.crawler:
            self.initialize_crawler()
        
        crawl_results = self.crawler.crawl(target_url)
        crawler_report = create_security_scan_report(crawl_results, target_url, self.scan_id)
        
        # Apply ML enhancement to crawl results
        enhanced_report = self.apply_ml_enhancement(crawler_report)
        
        # Save results if requested
        if save_file:
            json_path, html_path = self.save_results_with_report(enhanced_report, save_file, target_url)
            print(f"JSON report saved to: {json_path}")
            print(f"HTML report saved to: {html_path}")
        
        return enhanced_report
    
    def scan_with_tools(self, target_url: str, max_pages: int = 50, save_file: str = None) -> Dict:
        """
        Comprehensive vulnerability scan with multiple security tools.
        
        Orchestrates web crawling, network scanning (Nmap), web application
        scanning (Nikto), and ML-powered vulnerability classification.
        
        Args:
            target_url: Target URL to scan
            max_pages: Maximum pages to crawl
            save_file: Optional filename to save results
            
        Returns:
            Dict containing comprehensive scan results from all tools
        """
        print(f"Starting comprehensive vulnerability scan of {target_url}")
        print(f"Scan ID: {self.scan_id}")
        
        # Step 1: Crawl target
        print("\n" + "="*60)
        print("[PHASE 1] Web Application Discovery")
        print("="*60)
        
        if not self.crawler:
            self.initialize_crawler(max_pages=max_pages)
        
        crawl_results = self.crawler.crawl(target_url)
        crawler_report = create_security_scan_report(crawl_results, target_url, self.scan_id)
        
        # Count crawler vulnerabilities
        crawler_vulns = 0
        for endpoint in crawler_report['discovered_endpoints']:
            if 'security_issues' in endpoint:
                crawler_vulns += len(endpoint['security_issues'])
        
        self.vulnerabilities_by_scanner['crawler'] = crawler_vulns
        self.total_vulnerabilities_found += crawler_vulns
        
        print(f"Discovered {len(crawl_results)} endpoints")
        print(f"Found {len([p for p in crawl_results if p['has_forms']])} pages with forms")
        if crawler_vulns > 0:
            print(f"Crawler found {crawler_vulns} potential configuration issues")
        
        # Step 2: Run security scanners
        print("\n" + "="*60)
        print("[PHASE 2] Vulnerability Scanning")
        print("="*60)
        print(f"Running scanners on {len(crawler_report['scanner_targets']['nmap_targets'])} network targets")
        print(f"Running scanners on {len(crawler_report['scanner_targets']['nikto_targets'])} web targets")
        
        scan_results = {}
        
        if self.available_scanners.get('nmap') and self.config['nmap']['enabled']:
            scan_results['nmap'] = self.run_nmap_scan_enhanced(crawler_report['scanner_targets']['nmap_targets'])
        
        if self.available_scanners.get('nikto') and self.config['nikto']['enabled']:
            scan_results['nikto'] = self.run_nikto_scan_enhanced(crawler_report['scanner_targets']['nikto_targets'])
        
        if self.available_scanners.get('zap') and self.config['zap']['enabled']:
            scan_results['zap'] = self.run_zap_scan(crawler_report['scanner_targets']['nikto_targets'])
        
        # Step 3: Apply ML Enhancement
        print("\n" + "="*60)
        print("[PHASE 3] ML-Powered Analysis")
        print("="*60)
        
        # Apply ML enhancement to scan results
        enhanced_report = self.apply_ml_enhancement(crawler_report)
        
        # Step 4: Aggregate results
        print("\n" + "="*60)
        print("[PHASE 4] Results & Analysis")
        print("="*60)
        final_report = self.aggregate_results(enhanced_report, scan_results)
        
        # Step 5: Save results and show detailed analysis
        json_path, html_path = self.save_results_with_report(final_report, save_file, target_url)
        print(f"JSON report saved to: {json_path}")
        print(f"HTML report saved to: {html_path}")
        self.display_detailed_analysis(final_report)
        
        return final_report
    
    def run_nmap_scan_enhanced(self, nmap_targets: List[Dict]) -> Dict:
        """Execute Nmap with real-time vulnerability feedback"""
        nmap_results = {
            'scanner': 'nmap',
            'version': self.get_nmap_version(),
            'vulnerabilities': [],
            'scan_metadata': {},
            'errors': []
        }
        
        for target in nmap_targets:
            host = target['host']
            ports = target.get('ports', 'default')
            
            # Handle port configuration properly
            if ports == 'default':
                port_args = ['-p', '80,443,8080,8443']
            else:
                port_args = ['-p', ','.join(map(str, ports)) if isinstance(ports, list) else str(ports)]
            
            print(f"  [NMAP] Scanning {host} on ports {ports}...")
            
            try:
                with tempfile.NamedTemporaryFile(suffix='.xml', delete=False) as temp_file:
                    temp_path = temp_file.name
                
                # Platform-specific nmap commands for better Windows compatibility
                if platform.system() == 'Windows':
                    cmd = [
                        'nmap',
                        '-sS', '-sV', '--script', 'vuln',  # Use your working manual command
                        '-p-',  # Scan all ports like your manual command
                        '-oX', temp_path, host
                    ]
                else:
                    cmd = [
                        'nmap',
                        '-sV', '-sC', '--script', 'vuln',  # Full scripts on Linux/Mac
                        *port_args,
                        '-oX', temp_path, host
                    ]
                
                result = subprocess.run(cmd, capture_output=True, text=True,
                                      timeout=self.config['nmap']['timeout'],
                                      shell=True)
                
                if result.returncode == 0:
                    vulnerabilities = self.parse_nmap_xml(temp_path, host)
                    nmap_results['vulnerabilities'].extend(vulnerabilities)
                    
                    vuln_count = len(vulnerabilities)
                    self.vulnerabilities_by_scanner['nmap'] += vuln_count
                    self.total_vulnerabilities_found += vuln_count
                    
                    print(f"  [NMAP] ✓ Found {vuln_count} vulnerabilities on {host}")
                else:
                    error_msg = f"Nmap scan failed for {host}: {result.stderr}"
                    nmap_results['errors'].append(error_msg)
                    print(f"  [NMAP] ✗ Scan failed for {host}")
                    
            except subprocess.TimeoutExpired:
                error_msg = f"Nmap scan timeout for {host}"
                nmap_results['errors'].append(error_msg)
                print(f"  [NMAP] ⏱ Timeout scanning {host}")
            except Exception as e:
                error_msg = f"Nmap error for {host}: {str(e)}"
                nmap_results['errors'].append(error_msg)
                print(f"  [NMAP] ✗ Error scanning {host}: {e}")
            finally:
                try:
                    os.unlink(temp_path)
                except:
                    pass

        # Track raw/deduplicated findings for pipeline stats (no dedup for NMAP)
        nmap_results['scan_metadata']['raw_findings'] = len(nmap_results['vulnerabilities'])
        nmap_results['scan_metadata']['deduplicated_findings'] = len(nmap_results['vulnerabilities'])

        print(f"[NMAP] Complete: {self.vulnerabilities_by_scanner['nmap']} total vulnerabilities found")
        return nmap_results

    def run_nikto_scan_enhanced(self, nikto_targets: List[str]) -> Dict:
        """Execute Nikto with real-time vulnerability feedback"""
        nikto_results = {
            'scanner': 'nikto',
            'version': self.get_nikto_version(),
            'vulnerabilities': [],
            'scan_metadata': {},
            'errors': []
        }
        
        print(f"[NIKTO] Scanning {len(nikto_targets)} web targets...")
        target_count = 0
        
        for target in nikto_targets:
            target_count += 1
            print(f"  [NIKTO] ({target_count}/{len(nikto_targets)}) Scanning {target}")
            
            try:
                with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as temp_file:
                    temp_path = temp_file.name
                
                cmd = [
                    self.config['nikto']['path'],
                    self.config['nikto']['nikto_script'],
                    '-h', target, 
                    '-output', temp_path, 
                    '-Format', 'txt',
                    '-timeout', '10'
                ]
                
                print(f"    Running: {' '.join(cmd)}")
                result = subprocess.run(cmd, capture_output=True, text=True,
                                      timeout=self.config['nikto']['timeout'], 
                                      shell=True)
                
                vuln_count = 0
                if os.path.exists(temp_path) and os.path.getsize(temp_path) > 0:
                    with open(temp_path, 'r', encoding='utf-8', errors='ignore') as f:
                        nikto_output = f.read()
                    vulnerabilities = self.parse_nikto_text_output(nikto_output, target)
                    nikto_results['vulnerabilities'].extend(vulnerabilities)
                    vuln_count = len(vulnerabilities)
                    
                    self.vulnerabilities_by_scanner['nikto'] += vuln_count
                    self.total_vulnerabilities_found += vuln_count
                
                if vuln_count > 0:
                    print(f"  [NIKTO] ✓ Found {vuln_count} issues")
                else:
                    print(f"  [NIKTO] ✓ No issues detected")
                    
            except subprocess.TimeoutExpired:
                nikto_results['errors'].append(f"Nikto scan timeout for {target}")
                print(f"  [NIKTO] ⏱ Timeout scanning {target}")
            except Exception as e:
                nikto_results['errors'].append(f"Nikto error for {target}: {str(e)}")
                print(f"  [NIKTO] ✗ Error scanning {target}: {e}")
            finally:
                try:
                    if os.path.exists(temp_path):
                        os.unlink(temp_path)
                except:
                    pass

        # Track raw/deduplicated findings for pipeline stats (no dedup for NIKTO)
        nikto_results['scan_metadata']['raw_findings'] = self.vulnerabilities_by_scanner['nikto']
        nikto_results['scan_metadata']['deduplicated_findings'] = self.vulnerabilities_by_scanner['nikto']

        print(f"[NIKTO] Complete: {self.vulnerabilities_by_scanner['nikto']} total vulnerabilities found")
        return nikto_results

    def run_zap_scan(self, zap_targets: List[str]) -> Dict:
        """Execute OWASP ZAP scan with intelligent deduplication"""
        zap_results = {
            'scanner': 'zap',
            'version': self.get_zap_version(),
            'vulnerabilities': [],
            'scan_metadata': {},
            'errors': []
        }
        
        # Check if ZAP is running before starting scan
        if not self._check_zap_running():
            print(f"[!] ZAP is not running - attempting to start ZAP...")
            self._auto_start_zap()
            print(f"[*] Waiting 30 seconds for ZAP to initialize...")
            time.sleep(30)
            
            # Check again after starting
            if not self._check_zap_running():
                error_msg = "ZAP failed to start or is not accessible"
                zap_results['errors'].append(error_msg)
                print(f"[!] {error_msg}")
                return zap_results
        
        print(f"[ZAP] Scanning {len(zap_targets)} web targets...")
        
        # After collecting all alerts, apply intelligent deduplication
        all_raw_vulnerabilities = []
        
        for target in zap_targets:
            print(f"  [ZAP] Scanning {target}")
            
            try:
                # Step 1: Spider the target
                spider_id = self._zap_spider(target)
                if spider_id:
                    print(f"  [ZAP] Spidering target (ID: {spider_id})...")
                    self._wait_for_zap_spider(spider_id)
                
                # Step 2: Run active scan
                scan_id = self._zap_active_scan(target)
                if scan_id:
                    print(f"  [ZAP] Active scanning (ID: {scan_id})...")
                    self._wait_for_zap_scan(scan_id)
                
                # Step 3: Get alerts
                alerts = self._get_zap_alerts(target)
                raw_vulnerabilities = self.parse_zap_alerts(alerts, target)
                all_raw_vulnerabilities.extend(raw_vulnerabilities)
                
            except Exception as e:
                error_msg = f"ZAP error for {target}: {str(e)}"
                zap_results['errors'].append(error_msg)
                print(f"  [ZAP] ✗ Error scanning {target}: {e}")
        
        # FIXED: Apply intelligent deduplication
        deduplicated_vulnerabilities = self.deduplicate_zap_results(all_raw_vulnerabilities)
        zap_results['vulnerabilities'] = deduplicated_vulnerabilities
        
        # Update counts
        original_count = len(all_raw_vulnerabilities)
        deduplicated_count = len(deduplicated_vulnerabilities)
        
        # ENHANCED: Track raw & dedup for pipeline stats (retain legacy fields)
        zap_results['scan_metadata']['raw_findings'] = original_count
        zap_results['scan_metadata']['original_findings'] = original_count
        zap_results['scan_metadata']['deduplicated_findings'] = deduplicated_count
        zap_results['scan_metadata']['reduction_percentage'] = round(
            (1 - deduplicated_count / max(original_count, 1)) * 100, 1
        )

        self.vulnerabilities_by_scanner['zap'] = deduplicated_count
        # FIXED: Don't recalculate total here - it will be properly set in aggregate_results()

        print(f"[ZAP] Complete: {original_count} raw findings → {deduplicated_count} deduplicated ({zap_results['scan_metadata']['reduction_percentage']}% reduction)")

        return zap_results

    def parse_nmap_xml(self, xml_path: str, host: str) -> List[Dict]:
        """Parse Nmap XML output for vulnerabilities - FIXED VERSION"""
        vulnerabilities = []
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            
            for host_elem in root.findall('host'):
                for port_elem in host_elem.findall('.//port'):
                    port_num = port_elem.get('portid')
                    service = port_elem.find('service')
                    service_name = service.get('name', 'unknown') if service is not None else 'unknown'
                    service_version = service.get('version', '') if service is not None else ''
                    
                    for script in port_elem.findall('.//script'):
                        script_id = script.get('id', '')
                        script_output = script.get('output', '')
                        
                        # FIXED: Proper negative finding detection
                        negative_indicators = [
                            "couldn't find any",
                            "no vulnerabilities found",
                            "not vulnerable",
                            "not affected",
                            "no issues detected",
                            "scan completed successfully with no",
                            "no security issues"
                        ]
                        
                        # Skip if this is explicitly a negative finding
                        is_negative_finding = any(indicator in script_output.lower() 
                                                for indicator in negative_indicators)
                        
                        if is_negative_finding:
                            continue  # Skip negative findings completely
                        
                        # FIXED: Only flag actual positive vulnerability detections
                        is_vulnerability = any([
                            # Explicit vulnerability confirmations
                            'VULNERABLE' in script_output.upper() and 'CVE-' in script_output,
                            'CONFIRMED VULNERABLE' in script_output.upper(),
                            'EXPLOITATION CONFIRMED' in script_output.upper(),
                            
                            # Specific vulnerability types with positive indicators
                            script_id == 'http-csrf' and 'CSRF vulnerabilities:' in script_output and 'Path:' in script_output,
                            script_id in ['http-stored-xss', 'http-reflected-xss'] and 'XSS found' in script_output,
                            
                            # Security misconfigurations (not vulnerabilities)
                            script_id == 'http-enum' and any(word in script_output.lower() 
                                                           for word in ['admin panel', 'management interface', 'backup files']),
                            
                            # Actual exploitable conditions
                            'remote code execution' in script_output.lower(),
                            'privilege escalation' in script_output.lower(),
                            'authentication bypass' in script_output.lower()
                        ])
                        
                        if is_vulnerability:
                            # FIXED: Categorize findings properly
                            if any(word in script_output.lower() for word in ['admin', 'management', 'backup']):
                                finding_type = 'configuration_issue'
                                severity = 'medium'
                            elif 'CVE-' in script_output:
                                finding_type = 'vulnerability'
                                severity = self.determine_nmap_severity(script_output, script_id)
                            else:
                                finding_type = 'security_misconfiguration'
                                severity = 'low'
                            
                            vuln = {
                                'title': f"Security finding: {script_id}",
                                'description': script_output.strip(),
                                'severity': severity,
                                'type': 'network',
                                'finding_category': finding_type,  # NEW: Categorize findings
                                'affected_url': f"{host}:{port_num}",
                                'affected_port': int(port_num),
                                'service': f"{service_name} {service_version}".strip(),
                                'scanner_source': 'nmap',
                                'confidence': 'high'
                            }
                            
                            # Extract CVE if present
                            import re
                            cve_match = re.search(r'CVE-\d{4}-\d{4,}', script_output)
                            if cve_match:
                                vuln['cve_id'] = cve_match.group()
                            
                            vulnerabilities.append(vuln)
                            
        except Exception as e:
            print(f"[!] Error parsing Nmap XML: {e}")
        
        return vulnerabilities

    def parse_nikto_text_output(self, text_output: str, target: str) -> List[Dict]:
        """Parse Nikto text output into vulnerabilities"""
        vulnerabilities = []
        
        try:
            lines = text_output.split('\n')
            for line in lines:
                line = line.strip()
                
                if (line.startswith('+') and len(line) > 10 and 
                    any(keyword in line.lower() for keyword in [
                        'found', 'detected', 'vulnerable', 'error', 'exposed',
                        'directory', 'file', 'script', 'cgi', 'admin', 'login'
                    ])):
                    
                    osvdb_id = None
                    if 'OSVDB-' in line:
                        import re
                        osvdb_match = re.search(r'OSVDB-(\d+)', line)
                        if osvdb_match:
                            osvdb_id = f"OSVDB-{osvdb_match.group(1)}"
                    
                    severity = self.determine_nikto_severity_from_text(line)
                    
                    vuln = {
                        'title': f"Nikto finding: {line[:100]}...",
                        'description': line,
                        'severity': severity,
                        'type': 'web_application',
                        'affected_url': target,
                        'scanner_source': 'nikto',
                        'confidence': 'medium'
                    }
                    
                    if osvdb_id:
                        vuln['osvdb_id'] = osvdb_id
                    
                    vulnerabilities.append(vuln)
        
        except Exception as e:
            print(f"[!] Error parsing Nikto output: {e}")
        
        return vulnerabilities

    def deduplicate_zap_results(self, zap_vulnerabilities: List[Dict]) -> List[Dict]:
        """Enhanced deduplication with better grouping"""
        
        # Define grouping patterns for better clustering
        grouping_patterns = {
            'charset_mismatch': {
                'pattern': ['charset mismatch', 'content-type charset'],
                'title': 'Charset Mismatch Between HTTP Header and Meta Tag',
                'description': 'Multiple pages have charset mismatches between HTTP headers and meta content-type declarations'
            },
            'xss_reflected': {
                'pattern': ['cross site scripting', 'reflected', 'xss'],
                'title': 'Cross Site Scripting (Reflected)',
                'description': 'Multiple reflected XSS vulnerabilities found across various parameters and pages'
            },
            'sql_injection': {
                'pattern': ['sql injection'],
                'title': 'SQL Injection Vulnerabilities',
                'description': 'SQL injection vulnerabilities detected in multiple parameters and endpoints'
            },
            'modern_web_app': {
                'pattern': ['modern web application'],
                'title': 'Modern Web Application Detection',
                'description': 'Application identified as modern web application requiring specialized testing approaches'
            },
            'server_disclosure': {
                'pattern': ['server technology disclosure', 'x-powered-by', 'x-aspnet-version'],
                'title': 'Server Technology Information Disclosure',
                'description': 'Server reveals technology stack information through HTTP headers'
            },
            'csrf_protection': {
                'pattern': ['csrf', 'cross-site request forgery'],
                'title': 'Missing CSRF Protection',
                'description': 'Forms lack proper Cross-Site Request Forgery protection mechanisms'
            }
        }
        
        # Group vulnerabilities by pattern
        grouped_vulns = {}
        ungrouped_vulns = []
        
        for vuln in zap_vulnerabilities:
            title_lower = vuln.get('title', '').lower()
            desc_lower = vuln.get('description', '').lower()
            
            grouped = False
            for group_key, group_info in grouping_patterns.items():
                if any(pattern in title_lower or pattern in desc_lower for pattern in group_info['pattern']):
                    if group_key not in grouped_vulns:
                        grouped_vulns[group_key] = {
                            'representative': vuln.copy(),
                            'count': 0,
                            'urls': set(),
                            'group_info': group_info
                        }
                    
                    grouped_vulns[group_key]['count'] += 1
                    grouped_vulns[group_key]['urls'].add(vuln.get('affected_url', ''))
                    grouped = True
                    break
            
            if not grouped:
                ungrouped_vulns.append(vuln)
        
        # Create final deduplicated list
        deduplicated = []
        
        # Add grouped vulnerabilities
        for group_key, group_data in grouped_vulns.items():
            vuln = group_data['representative']
            group_info = group_data['group_info']
            
            vuln.update({
                'title': group_info['title'],
                'description': group_info['description'],
                'is_grouped': True,
                'affected_count': group_data['count'],
                'affected_urls_list': list(group_data['urls'])[:10],
                'confidence': 'high'  # Add confidence rating
            })
            
            if group_data['count'] > 10:
                vuln['affected_urls_list'].append(f"... and {group_data['count'] - 10} more URLs")
                
            deduplicated.append(vuln)
        
        # Add ungrouped vulnerabilities
        deduplicated.extend(ungrouped_vulns)
        
        return deduplicated

    def is_false_positive(self, vuln: Dict) -> bool:
        """Enhanced false positive detection"""
        title = vuln.get('title', '').lower()
        description = vuln.get('description', '').lower()
        
        # Informational only (not vulnerabilities)
        informational_patterns = [
            'session management response identified',
            'authentication request identified', 
            'user agent fuzzer',
            'informational alert rather than a vulnerability',
            'retrieved from cache',  # Usually not a vulnerability
            'x-aspnet-version response header',  # Information disclosure, not critical
            "couldn't find any",
            "no vulnerabilities found",
            "scan completed successfully"
        ]
        
        # Low-value findings that should be grouped/minimized
        return any(pattern in title or pattern in description for pattern in informational_patterns)
    
    def reclassify_severity(self, vuln: Dict) -> str:
        """More accurate severity classification"""
        title = vuln.get('title', '').lower()
        
        # Downgrade information disclosure to informational
        if any(keyword in title for keyword in ['x-powered-by', 'x-aspnet-version', 'server leaks']):
            return 'informational'
        
        # Downgrade missing headers to low/informational  
        if any(keyword in title for keyword in ['header not set', 'header missing']):
            return 'low'
            
        return vuln.get('severity', 'low')
    
    def categorize_finding_type(self, vuln: Dict) -> str:
        """Properly categorize findings"""
        title = vuln.get('title', '').lower()
        
        # These are configuration issues, not vulnerabilities
        config_patterns = [
            'header not set', 'header missing', 'cache-control',
            'x-powered-by', 'x-aspnet-version', 'content-type-options'
        ]
        
        if any(pattern in title for pattern in config_patterns):
            return 'configuration_issue'
        
        # These are informational
        info_patterns = [
            'session management response', 'user agent fuzzer',
            'retrieved from cache'
        ]
        
        if any(pattern in title for pattern in info_patterns):
            return 'informational'
            
        return 'vulnerability'

    def filter_and_categorize_results(self, all_vulnerabilities: List[Dict]) -> Dict:
        """Filter and categorize vulnerabilities by severity and type"""
        
        categorized_results = {
            'critical_vulnerabilities': [],
            'high_vulnerabilities': [],
            'medium_vulnerabilities': [],
            'low_vulnerabilities': [],
            'configuration_issues': [],
            'informational': [],
            'false_positives': []
        }
        
        # Define what constitutes each category
        for vuln in all_vulnerabilities:
            # Apply enhanced false positive detection
            if self.is_false_positive(vuln):
                categorized_results['false_positives'].append(vuln)
                continue
            
            # Reclassify severity more accurately
            vuln['severity'] = self.reclassify_severity(vuln)
            severity = vuln['severity'].lower()
            
            # Categorize by finding type
            finding_type = self.categorize_finding_type(vuln)
            
            if finding_type == 'configuration_issue':
                categorized_results['configuration_issues'].append(vuln)
                continue
            elif finding_type == 'informational':
                categorized_results['informational'].append(vuln)
                continue
            
            # Categorize by severity
            if severity == 'critical':
                categorized_results['critical_vulnerabilities'].append(vuln)
            elif severity == 'high':
                categorized_results['high_vulnerabilities'].append(vuln)
            elif severity == 'medium':
                categorized_results['medium_vulnerabilities'].append(vuln)
            elif severity == 'low':
                # Further filter low severity
                title = vuln.get('title', '').lower()
                if any(word in title for word in ['information', 'disclosure', 'version']):
                    categorized_results['informational'].append(vuln)
                else:
                    categorized_results['low_vulnerabilities'].append(vuln)
        
        return categorized_results

    def parse_zap_alerts(self, alerts: List[Dict], target: str) -> List[Dict]:
        """Parse ZAP alerts into vulnerability format"""
        vulnerabilities = []
        
        try:
            for alert in alerts:
                vuln = {
                    'title': alert.get('name', 'Unknown ZAP Alert'),
                    'description': alert.get('description', ''),
                    'severity': self.map_zap_risk_to_severity(alert.get('riskdesc', 'Low')),
                    'type': 'web_application',
                    'affected_url': alert.get('url', target),
                    'scanner_source': 'zap',
                    'confidence': alert.get('confidence', 'Medium').lower(),
                    'cwe_id': alert.get('cweid'),
                    'wascid': alert.get('wascid'),
                    'solution': alert.get('solution', '')
                }
                
                if alert.get('param'):
                    vuln['parameter'] = alert.get('param')
                
                vulnerabilities.append(vuln)
        
        except Exception as e:
            print(f"[!] Error parsing ZAP alerts: {e}")
        
        return vulnerabilities

    def aggregate_results(self, crawler_report: Dict, scan_results: Dict) -> Dict:
        """Enhanced result aggregation with intelligent filtering"""
        final_report = crawler_report.copy()
        
        # Ensure scan_metadata exists
        if 'scan_metadata' not in final_report:
            final_report['scan_metadata'] = {}
        
        # Add scanner results
        final_report['scan_results'] = scan_results
        
        # Aggregate all vulnerabilities
        all_vulnerabilities = []
        raw_vulnerability_count = 0
        
        # Add crawler vulnerabilities
        for endpoint in crawler_report.get('discovered_endpoints', []):
            if 'security_issues' in endpoint:
                for vuln in endpoint['security_issues']:
                    vuln['source_scanner'] = 'crawler'
                all_vulnerabilities.extend(endpoint['security_issues'])
                raw_vulnerability_count += len(endpoint.get('security_issues', []))
        
        # Add scanner vulnerabilities
        for scanner_name, results in scan_results.items():
            if 'vulnerabilities' in results:
                vulns = results['vulnerabilities']
                # Add scanner source to each vulnerability
                for vuln in vulns:
                    vuln['source_scanner'] = scanner_name
                all_vulnerabilities.extend(vulns)
                raw_vulnerability_count += len(vulns)
        
        # Apply intelligent filtering and categorization
        print(f"\n🧠 APPLYING INTELLIGENT ANALYSIS...")
        print(f"   Raw findings before filtering: {raw_vulnerability_count}")
        
        categorized_results = self.filter_and_categorize_results(all_vulnerabilities)
        
        # Calculate filtered counts
        filtered_vulns = (categorized_results['critical_vulnerabilities'] + 
                         categorized_results['high_vulnerabilities'] + 
                         categorized_results['medium_vulnerabilities'] + 
                         categorized_results['low_vulnerabilities'])
        
        config_issues = categorized_results['configuration_issues']
        false_positives = categorized_results['false_positives']
        
        print(f"   Real vulnerabilities identified: {len(filtered_vulns)}")
        print(f"   Configuration issues: {len(config_issues)}")
        print(f"   False positives filtered out: {len(false_positives)}")
        
        # Update vulnerability counts by scanner
        vulnerabilities_by_scanner = {}
        for scanner_name in ['crawler', 'nmap', 'nikto', 'zap']:
            scanner_vulns = [v for v in filtered_vulns if v.get('source_scanner') == scanner_name]
            if scanner_vulns:
                vulnerabilities_by_scanner[scanner_name] = len(scanner_vulns)
        
        # Build comprehensive final report
        final_report['vulnerabilities'] = filtered_vulns
        final_report['configuration_issues'] = config_issues
        final_report['total_vulnerabilities'] = len(filtered_vulns)
        final_report['total_configuration_issues'] = len(config_issues)
        final_report['false_positives_filtered'] = len(false_positives)

        # FIXED: Update the tracking variable with filtered count instead of raw count
        self.total_vulnerabilities_found = len(filtered_vulns)

        # ENHANCED: Track complete processing pipeline
        pipeline_stats = {}
        for scanner_name in ['nmap', 'nikto', 'zap']:
            if scanner_name in scan_results:
                scanner_meta = scan_results[scanner_name].get('scan_metadata', {})
                scanner_vulns = [v for v in filtered_vulns if v.get('source_scanner') == scanner_name]

                pipeline_stats[scanner_name] = {
                    'raw_findings': scanner_meta.get('raw_findings', 0),
                    'deduplicated_findings': scanner_meta.get('deduplicated_findings', 0),
                    'final_findings': len(scanner_vulns),
                    'has_deduplication': scanner_meta.get('reduction_percentage', 0) > 0
                }

        # Enhanced metadata
        final_report['scan_metadata'].update({
            'total_vulnerabilities_found': len(filtered_vulns),
            'vulnerabilities_by_scanner': vulnerabilities_by_scanner,
            'total_raw_findings': raw_vulnerability_count,
            'pipeline_statistics': pipeline_stats,
            'filtering_effectiveness': f"{len(false_positives)}/{raw_vulnerability_count} false positives removed",
            'vulnerability_categories': {
                'critical': len(categorized_results['critical_vulnerabilities']),
                'high': len(categorized_results['high_vulnerabilities']),
                'medium': len(categorized_results['medium_vulnerabilities']),
                'low': len(categorized_results['low_vulnerabilities'])
            }
        })

        return final_report

    def display_detailed_analysis(self, final_report: Dict):
        """Display vulnerability analysis with proper categorization"""
        
        all_vulnerabilities = final_report.get('vulnerabilities', [])
        categorized = self.filter_and_categorize_results(all_vulnerabilities)
        
        print(f"\nSCAN COMPLETED - ANALYSIS RESULTS")
        print(f"=" * 60)
        
        # Summary by category
        critical_count = len(categorized['critical_vulnerabilities'])
        high_count = len(categorized['high_vulnerabilities'])
        medium_count = len(categorized['medium_vulnerabilities'])
        low_count = len(categorized['low_vulnerabilities'])
        config_count = len(categorized['configuration_issues'])
        info_count = len(categorized['informational'])
        false_positive_count = len(categorized['false_positives'])
        
        total_real_vulns = critical_count + high_count + medium_count + low_count
        
        print(f"VULNERABILITY BREAKDOWN:")
        print(f"   Critical Vulnerabilities: {critical_count}")
        print(f"   High Vulnerabilities: {high_count}")
        print(f"   Medium Vulnerabilities: {medium_count}")
        print(f"   Low Vulnerabilities: {low_count}")
        print(f"   Configuration Issues: {config_count}")
        print(f"   Informational: {info_count}")
        print(f"   False Positives Filtered: {false_positive_count}")
        
        print(f"\nREAL SECURITY ISSUES: {total_real_vulns}")
        print(f"CONFIGURATION IMPROVEMENTS: {config_count}")
        
        # Priority recommendations
        if critical_count > 0 or high_count > 0:
            print(f"\nIMMEDIATE ACTION REQUIRED:")
            for vuln in categorized['critical_vulnerabilities'] + categorized['high_vulnerabilities']:
                print(f"   • {vuln['title']}")
                if vuln.get('cve_id'):
                    print(f"     CVE: {vuln['cve_id']}")
        
        # Show scanner breakdown
        vuln_breakdown = final_report.get('scan_metadata', {}).get('vulnerabilities_by_scanner', {})
        print(f"\nSCANNER PERFORMANCE:")
        for scanner, count in vuln_breakdown.items():
            if count > 0:
                print(f"   {scanner.upper()}: {count} findings")
        
        # Deduplication stats
        if 'scan_results' in final_report and 'zap' in final_report['scan_results']:
            zap_meta = final_report['scan_results']['zap'].get('scan_metadata', {})
            if 'reduction_percentage' in zap_meta:
                print(f"\nDEDUPLICATION EFFECTIVENESS:")
                print(f"   ZAP: {zap_meta['original_findings']} → {zap_meta['deduplicated_findings']} "
                      f"({zap_meta['reduction_percentage']}% reduction)")

    def determine_nmap_severity(self, output: str, script_id: str = '') -> str:
        """Determine severity based on Nmap output"""
        output_lower = output.lower()
        
        if any(word in output_lower for word in ['critical', 'remote code execution', 'rce']):
            return 'critical'
        elif any(word in output_lower for word in ['high', 'dangerous', 'exploit']):
            return 'high'
        elif any(word in output_lower for word in ['medium', 'moderate', 'warning']):
            return 'medium'
        else:
            return 'low'

    def determine_nikto_severity_from_text(self, line: str) -> str:
        """Determine severity from Nikto output line"""
        line_lower = line.lower()
        
        if any(word in line_lower for word in ['admin', 'password', 'login', 'auth', 'upload']):
            return 'high'
        elif any(word in line_lower for word in ['backup', 'config', 'debug', 'test']):
            return 'medium'
        else:
            return 'low'

    def map_zap_risk_to_severity(self, risk_desc: str) -> str:
        """Map ZAP risk levels to our severity levels"""
        risk_lower = risk_desc.lower()
        
        if 'high' in risk_lower:
            return 'high'
        elif 'medium' in risk_lower:
            return 'medium'
        elif 'low' in risk_lower:
            return 'low'
        else:
            return 'low'

    def _check_zap_running(self) -> bool:
        """Check if ZAP is running"""
        try:
            response = requests.get(f"http://{self.config['zap']['host']}:{self.config['zap']['port']}/JSON/core/view/version/",
                                  timeout=5)
            return response.status_code == 200
        except:
            return False

    def _auto_start_zap(self):
        """Attempt to start ZAP automatically"""
        try:
            zap_path = self.config['zap']['zap_path']
            if os.path.exists(zap_path):
                subprocess.Popen([zap_path, '-daemon'])
        except Exception as e:
            print(f"[!] Failed to start ZAP: {e}")

    def _zap_spider(self, target: str) -> Optional[str]:
        """Start ZAP spider"""
        try:
            response = requests.get(f"http://{self.config['zap']['host']}:{self.config['zap']['port']}/JSON/spider/action/scan/",
                                  params={'url': target, 'apikey': self.config['zap']['api_key']})
            if response.status_code == 200:
                return response.json().get('scan')
        except Exception as e:
            print(f"[!] ZAP spider error: {e}")
        return None

    def _wait_for_zap_spider(self, spider_id: str):
        """Wait for ZAP spider to complete"""
        try:
            while True:
                response = requests.get(f"http://{self.config['zap']['host']}:{self.config['zap']['port']}/JSON/spider/view/status/",
                                      params={'scanId': spider_id, 'apikey': self.config['zap']['api_key']})
                if response.status_code == 200:
                    status = response.json().get('status')
                    if status == '100':
                        break
                time.sleep(2)
        except Exception as e:
            print(f"[!] ZAP spider wait error: {e}")

    def _zap_active_scan(self, target: str) -> Optional[str]:
        """Start ZAP active scan"""
        try:
            response = requests.get(f"http://{self.config['zap']['host']}:{self.config['zap']['port']}/JSON/ascan/action/scan/",
                                  params={'url': target, 'apikey': self.config['zap']['api_key']})
            if response.status_code == 200:
                return response.json().get('scan')
        except Exception as e:
            print(f"[!] ZAP active scan error: {e}")
        return None

    def _wait_for_zap_scan(self, scan_id: str):
        """Wait for ZAP active scan to complete"""
        try:
            while True:
                response = requests.get(f"http://{self.config['zap']['host']}:{self.config['zap']['port']}/JSON/ascan/view/status/",
                                      params={'scanId': scan_id, 'apikey': self.config['zap']['api_key']})
                if response.status_code == 200:
                    status = response.json().get('status')
                    if status == '100':
                        break
                time.sleep(5)
        except Exception as e:
            print(f"[!] ZAP scan wait error: {e}")

    def _get_zap_alerts(self, target: str) -> List[Dict]:
        """Get ZAP alerts for target"""
        try:
            response = requests.get(f"http://{self.config['zap']['host']}:{self.config['zap']['port']}/JSON/core/view/alerts/",
                                  params={'baseurl': target, 'apikey': self.config['zap']['api_key']})
            if response.status_code == 200:
                return response.json().get('alerts', [])
        except Exception as e:
            print(f"[!] ZAP alerts error: {e}")
        return []

    def get_nmap_version(self) -> str:
        """Get Nmap version"""
        try:
            result = subprocess.run(['nmap', '--version'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'Nmap version' in line:
                        return line.split('version')[1].strip()
        except:
            pass
        return "unknown"
    
    def get_nikto_version(self) -> str:
        """Get Nikto version"""
        try:
            result = subprocess.run([
                self.config['nikto']['path'], 
                self.config['nikto']['nikto_script'], 
                '-Version'
            ], capture_output=True, text=True, timeout=10, shell=True)
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'Nikto' in line and ('v' in line or 'version' in line):
                        return line.strip()
            return "Nikto (local installation)"
        except:
            return "unknown"
    
    def get_zap_version(self) -> str:
        """Get ZAP version"""
        try:
            zap_url = f"http://{self.config['zap']['host']}:{self.config['zap']['port']}"
            response = requests.get(f"{zap_url}/JSON/core/view/version/", params={
                'apikey': self.config['zap']['api_key']
            })
            if response.status_code == 200:
                return response.json().get('version', 'unknown')
            return "unknown"
        except:
            return "unknown"

    def save_results(self, final_report: Dict, custom_filename: str = None) -> str:
        """Save scan results to JSON file"""
        if custom_filename:
            filename = custom_filename
        else:
            filename = f"vuln_scan_{self.scan_id}.json"
        
        report_path = self.results_dir / filename
        
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(final_report, f, indent=2, ensure_ascii=False)
        
        return str(report_path)

    def save_results_with_report(self, final_report: Dict, save_file: str, target_url: str) -> Tuple[str, str]:
        """Save scan results and automatically generate HTML report with matching names"""
        from report_generator import VulnerabilityReportGenerator
        
        # Determine base filename
        if save_file and save_file != "auto":
            # Use custom filename (remove extension if provided)
            base_filename = save_file.replace('.json', '')
        else:
            # Extract domain and create timestamp for auto naming
            parsed_url = urlparse(normalize_url(target_url))
            domain = parsed_url.netloc.lower().replace('www.', '').replace('.', '-')
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_filename = f"{domain}-{timestamp}"
        
        # Save JSON results
        json_filename = f"{base_filename}.json"
        json_path = self.results_dir / json_filename
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(final_report, f, indent=2, ensure_ascii=False)
        
        # Generate HTML report
        generator = VulnerabilityReportGenerator()
        html_filename = f"{base_filename}.html"
        
        # Set the output filename explicitly
        html_path_str = generator.generate_report(final_report, html_filename)
        
        return str(json_path), html_path_str

# CLI Commands
@app.command()
def scan(
    url: str = typer.Argument(..., help="Target URL to scan"),
    max_pages: int = typer.Option(50, help="Maximum pages to crawl"),
    delay: float = typer.Option(0.3, help="Delay between requests (seconds)"),
    save: bool = typer.Option(False, "--save", help="Save results to file"),
    include_all: bool = typer.Option(False, help="Include pages without forms in results"),
    no_selenium: bool = typer.Option(False, help="Disable Selenium (requests only)"),
    aggressive: bool = typer.Option(False, help="Enable aggressive mode (bypass some protections)"),
    ignore_robots: bool = typer.Option(False, help="Ignore robots.txt (for security testing)"),
    no_dedup: bool = typer.Option(False, help="Disable content deduplication"),
    config: str = typer.Option("config.yaml", help="Configuration file path"),
    crawl_only: bool = typer.Option(False, help="Only crawl, don't run security scanners")
):
    """
    Complete vulnerability scan with ML enhancement
    
    This tool combines web crawling with multiple security scanners:
    - Nmap for network vulnerabilities
    - Nikto for web server vulnerabilities  
    - Custom analysis for configuration issues
    - ML-powered vulnerability classification
    - Full crawler.py functionality integrated
    """
    
    # Initialize scanner with config
    scanner = EnhancedVulnerabilityScanner(config)
    
    # Normalize URL
    normalized_url = normalize_url(url)
    
    # Initialize crawler with all options
    scanner.initialize_crawler(
        max_pages=max_pages,
        delay=delay,
        use_selenium=not no_selenium,
        aggressive=aggressive,
        ignore_robots=ignore_robots,
        enable_dedup=not no_dedup
    )
    
    print("="*80)
    print("ML-POWERED VULNERABILITY SCANNER")
    print("="*80)
    print(f"Target: {url} → {normalized_url}")
    print(f"Max pages to crawl: {max_pages}")
    print(f"Crawl delay: {delay}s")
    print(f"Selenium: {'Disabled' if no_selenium else 'Enabled'}")
    print(f"Aggressive mode: {'Enabled' if aggressive else 'Disabled'}")
    print(f"Robots.txt: {'Ignored' if ignore_robots else 'Respected'}")
    print(f"Content deduplication: {'Disabled' if no_dedup else 'Enabled'}")
    print(f"Available scanners: {[k for k, v in scanner.available_scanners.items() if v]}")
    print(f"Results folder: vuln-scanner-results/")
    
    if ignore_robots or aggressive:
        print("\n[!] Running in security testing mode")
        print("[!] Ensure you have permission to test this target")
    
    try:
        if crawl_only:
            print("\n[*] Running CRAWL-ONLY mode (no security scanners)")
            # Enable auto report generation if save is enabled
            save_filename = "auto" if save else None
            if save:
                print("[+] Auto-generating JSON and HTML reports with domain-timestamp naming")
            
            results = scanner.crawl_only(normalized_url, save_filename, include_all)
            
            # Display crawler results
            print(f"\n{'='*60}")
            print("SECURITY CRAWL RESULTS")
            print(f"{'='*60}")
            print(f"Scan ID: {results['scan_target']['scan_id']}")
            print(f"Total Endpoints: {results['scan_summary']['total_endpoints']}")
            print(f"Endpoints with Forms: {results['scan_summary']['endpoints_with_forms']}")
            print(f"High Priority Targets: {results['scan_summary']['high_priority_targets']}")
            
            for i, endpoint in enumerate(results['discovered_endpoints'], 1):
                print(f"\n{i}. URL: {endpoint['url']}")
                if endpoint.get('final_url') != endpoint['url']:
                    print(f"   Final URL: {endpoint['final_url']}")
                print(f"   Status: {endpoint['status_code']}")
                print(f"   Priority: {endpoint.get('scanner_priority', 'unknown')}")
                
                if endpoint['forms']:
                    print(f"   Forms found: {len(endpoint['forms'])}")
                    for j, form in enumerate(endpoint['forms'], 1):
                        print(f"   Form {j}: {form['method']} → {form['action'] or 'same page'}")
                        print(f"   Inputs: {[inp['name'] for inp in form['inputs']]}")
            
        else:
            print("\n[*] Running FULL VULNERABILITY SCAN mode with ML enhancement")
            # Enable auto report generation if save is enabled
            save_filename = "auto" if save else None
            if save:
                print("[+] Auto-generating JSON and HTML reports with domain-timestamp naming")
                
            results = scanner.scan_with_tools(normalized_url, max_pages, save_filename)
            print(f"\nSCAN COMPLETED SUCCESSFULLY!")
            # FIXED: Use filtered count from report instead of raw tracking variable
            total_filtered = results.get('total_vulnerabilities', 0) if 'total_vulnerabilities' in results else 0
            print(f"Total vulnerabilities found: {total_filtered}")
        
    except KeyboardInterrupt:
        print(f"\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"\n[!] Scan failed: {e}")

@app.command()
def crawl(
    url: str = typer.Argument(..., help="Target URL to crawl"),
    max_pages: int = typer.Option(100, help="Maximum pages to crawl"),
    delay: float = typer.Option(0.3, help="Delay between requests (seconds)"),
    save: Optional[str] = typer.Option(None, help="Save results to file. Use --save for auto-naming or --save filename.json for custom name"),
    include_all: bool = typer.Option(False, help="Include pages without forms in results"),
    no_selenium: bool = typer.Option(False, help="Disable Selenium (requests only)"),
    aggressive: bool = typer.Option(False, help="Enable aggressive mode (bypass some protections)"),
    ignore_robots: bool = typer.Option(False, help="Ignore robots.txt (for security testing)"),
    no_dedup: bool = typer.Option(False, help="Disable content deduplication")
):
    """
    Pure crawling functionality - identical to crawler.py
    
    Aggressive vulnerability-focused web crawler for security testing.
    Features: SPA support, aggressive link discovery, robots.txt bypassing,
    content deduplication, stealth user-agent rotation, enhanced form detection.
    """
    # This is essentially the same as scan with crawl_only=True
    return scan(
        url=url, max_pages=max_pages, delay=delay, save=save,
        include_all=include_all, no_selenium=no_selenium, 
        aggressive=aggressive, ignore_robots=ignore_robots, 
        no_dedup=no_dedup, crawl_only=True, config="config.yaml"
    )

@app.command()
def check():
    """Check scanner availability and configuration"""
    scanner = EnhancedVulnerabilityScanner()
    
    print("Scanner Availability Check:")
    print("-" * 30)
    
    for scanner_name, available in scanner.available_scanners.items():
        status = "✓ Available" if available else "✗ Not Available"
        enabled = "Enabled" if scanner.config[scanner_name]['enabled'] else "Disabled"
        print(f"{scanner_name.upper():8} | {status:12} | {enabled}")
    
    print(f"\nResults will be saved to: vuln-scanner-results/")

@app.command()
def train_ml():
    """Train ML model for vulnerability classification using CVE data"""
    try:
        from ml_handler import MLVulnerabilityEngine
        
        print("ML Model Training")
        print("=" * 50)
        
        # Initialize ML handler
        ml_handler = MLVulnerabilityEngine(cve_base_path="./cves")
        
        # Check CVE data availability
        cve_files = ml_handler.data_processor.discover_cve_files()
        # FIXED: Extract years correctly from nested directory structure
        available_years = []
        for cve_file in cve_files:
            # Extract year from path structure: cves/YYYY/xxxx/CVE-YYYY-*.json
            parts = cve_file.parts
            for part in parts:
                if part.isdigit() and len(part) == 4 and 1999 <= int(part) <= 2030:
                    available_years.append(int(part))
                    break
        available_years = sorted(set(available_years))
        
        print(f"CVE Data Path: {ml_handler.cve_base_path}")
        print(f"Available Years: {available_years}")
        print(f"Total CVE Files: {len(cve_files):,}")
        
        if not cve_files:
            print("No CVE data available. Please ensure CVE files are in the correct directory structure.")
            print("   Expected structure: ./cves/2023/CVE-2023-*.json")
            print("                      ./cves/2024/CVE-2024-*.json")
            return
        
        # Train model using the unified train_model method
        print(f"\nStarting ML Model Training...")
        print(f"   Using {len(cve_files):,} CVE files from {len(available_years)} years")
        
        success = ml_handler.train_model(
            max_files=None,  # Use all available files
            use_validation=True,
            train_size=0.6,
            val_size=0.2,
            test_size=0.2,
            save_model=True,
            early_stopping_patience=10,
            max_iterations=50
        )
        
        if success:
            print("ML model training completed successfully!")
            print(f"Model saved in: {ml_handler.models_path}")
            
            # Display final evaluation
            try:
                evaluation = ml_handler.evaluate_model_comprehensive()
                if 'error' not in evaluation:
                    print(f"\nModel Information:")
                    print(f"   • Model Type: {evaluation.get('model_type', 'Unknown')}")
                    print(f"   • Test Accuracy: {evaluation.get('test_accuracy', 0):.3f}")
                    print(f"   • Training Samples: {evaluation.get('training_samples', 0):,}")
                    print(f"   • Feature Count: {evaluation.get('feature_count', 0):,}")
                    
                    if evaluation.get('validation_samples', 0) > 0:
                        print(f"   • Best Val Accuracy: {evaluation.get('best_val_accuracy', 0):.3f}")
                        print(f"   • Total Iterations: {evaluation.get('total_iterations_trained', 0)}")
                else:
                    print(f"Model evaluation error: {evaluation['error']}")
            except Exception as e:
                print(f"Could not evaluate model: {e}")
        else:
            print("Failed to train model")
            
    except ImportError:
        print("ML dependencies not available. Install with:")
        print("   pip install scikit-learn pandas numpy")
    except KeyboardInterrupt:
        print(f"\nTraining interrupted by user")
    except Exception as e:
        print(f"Training failed: {e}")

@app.command()
def ml_status():
    """Check ML model status and CVE data availability"""
    try:
        from ml_handler import MLVulnerabilityEngine
        
        print("ML System Status")
        print("=" * 40)
        
        ml_handler = MLVulnerabilityEngine(cve_base_path="./cves")
        
        # Check CVE data availability
        cve_files = ml_handler.data_processor.discover_cve_files()
        # FIXED: Extract years correctly from nested directory structure
        available_years = []
        for cve_file in cve_files:
            # Extract year from path structure: cves/YYYY/xxxx/CVE-YYYY-*.json
            parts = cve_file.parts
            for part in parts:
                if part.isdigit() and len(part) == 4 and 1999 <= int(part) <= 2030:
                    available_years.append(int(part))
                    break
        available_years = sorted(set(available_years))
        
        print(f"CVE Data Path: {ml_handler.cve_base_path}")
        print(f"Available CVE Years: {available_years}")
        print(f"Total CVE Files: {len(cve_files):,}")
        
        # Check for trained models
        model_files = list(ml_handler.models_path.glob("hybrid_rf_isolation_*.pkl"))
        metadata_files = list(ml_handler.models_path.glob("metadata_*.json"))
        
        print(f"Model Files Exist: {'Yes' if model_files else 'No'}")
        print(f"Metadata Files: {len(metadata_files)}")
        
        if model_files:
            latest_model = max(model_files, key=lambda x: x.stat().st_mtime)
            print(f"Latest Model: {latest_model.name}")
            
            # Try to load and evaluate the latest model
            try:
                # Find corresponding feature engineer and metadata files
                timestamp = latest_model.name.replace('hybrid_rf_isolation_', '').replace('.pkl', '')
                fe_file = ml_handler.models_path / f"feature_engineer_{timestamp}.pkl"
                metadata_file = ml_handler.models_path / f"metadata_{timestamp}.json"
                
                if fe_file.exists():
                    # Load the model for evaluation
                    success = ml_handler.load_model(str(latest_model), str(fe_file), str(metadata_file))
                    if success:
                        evaluation = ml_handler.evaluate_model_comprehensive()
                        if 'error' not in evaluation:
                            print(f"\nModel Information:")
                            print(f"   • Model Type: {evaluation.get('model_type', 'Unknown')}")
                            print(f"   • Model Version: {evaluation.get('model_version', 'Unknown')}")
                            print(f"   • Test Accuracy: {evaluation.get('test_accuracy', 0):.3f}")
                            print(f"   • Training Samples: {evaluation.get('training_samples', 0):,}")
                            print(f"   • Feature Count: {evaluation.get('feature_count', 0):,}")
                            
                            if evaluation.get('validation_samples', 0) > 0:
                                print(f"   • Best Val Accuracy: {evaluation.get('best_val_accuracy', 0):.3f}")
                                print(f"   • Total Iterations: {evaluation.get('total_iterations_trained', 0)}")
                        else:
                            print(f"Model evaluation error: {evaluation['error']}")
                    else:
                        print(f"Failed to load model for evaluation")
                else:
                    print(f"Feature engineer file not found: {fe_file.name}")
                    print(f"Model exists but cannot be fully evaluated without feature engineer")
            except Exception as e:
                print(f"Could not evaluate model: {e}")
        else:
            print(f"\nNo trained model available. Run: python scanner.py train-ml")
            
    except ImportError:
        print("ML dependencies not available. Install with:")
        print("   pip install scikit-learn pandas numpy")
    except Exception as e:
        print(f"Error checking ML status: {e}")

if __name__ == "__main__":
    app()
