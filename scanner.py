#!/usr/bin/env python3
# scanner.py - Enhanced Vulnerability Scanner with Full Crawler Integration

import subprocess
import json
import time
import xml.etree.ElementTree as ET
import tempfile
import os
import requests
import hashlib
import warnings
import logging
import platform
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
from datetime import datetime
import uuid
from urllib.parse import urlparse, urljoin
import yaml
import typer

# Import ALL functionality from crawler without modification
from crawler import AggressiveVulnCrawler

def create_security_scan_report(crawl_results: List[Dict], target_url: str, scan_id: str) -> Dict:
    """Create a security scan report from crawl results"""
    # Parse target URL
    parsed_url = urlparse(target_url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    # Process endpoints
    discovered_endpoints = []
    endpoints_with_forms = 0
    high_priority_targets = 0
    
    for page in crawl_results:
        endpoint = {
            'url': page['url'],
            'title': page.get('title', 'Unknown'),
            'status_code': page.get('status_code', 200),
            'has_forms': page.get('has_forms', False),
            'forms': page.get('forms', []),
            'security_issues': []
        }
        
        if endpoint['has_forms']:
            endpoints_with_forms += 1
            high_priority_targets += 1
            
        # Add basic security checks
        if page.get('has_forms'):
            for form in page.get('forms', []):
                if form.get('method', '').upper() == 'POST':
                    endpoint['security_issues'].append({
                        'type': 'form_security',
                        'description': 'POST form found - potential for security testing'
                    })
        
        discovered_endpoints.append(endpoint)
    
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
            'base_url': target_url,
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
    name="Enhanced ML Vulnerability Scanner",
    help="Advanced vulnerability scanner with integrated web crawling capabilities"
)

class EnhancedVulnerabilityScanner:
    """Enhanced vulnerability scanner with full crawler integration and real-time feedback"""
    
    def __init__(self, config_file: str = "config.yaml"):
        self.config_file = config_file  # Store config file path for ML enhancement
        self.config = self.load_config(config_file)
        self.scan_id = str(uuid.uuid4())
        self.results_dir = Path("vuln-scanner-results")
        self.results_dir.mkdir(exist_ok=True)
        
        # Scanner availability
        self.available_scanners = self.check_scanner_availability()
        
        # Real-time vulnerability tracking
        self.total_vulnerabilities_found = 0
        self.vulnerabilities_by_scanner = {
            'crawler': 0,
            'nmap': 0, 
            'nikto': 0,
            'zap': 0
        }
        
        # Crawler instance (will be initialized per scan)
        self.crawler = None
    
    def load_config(self, config_file: str) -> Dict:
        """Load scanner configuration with Windows defaults"""
        default_config = {
            'nmap': {
                'enabled': True,
                'path': 'nmap',
                'timeout': 1000,  # Increased to 1000 seconds for comprehensive scans
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
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    user_config = yaml.safe_load(f) or {}
                    # Merge with defaults
                    for section in default_config:
                        if section in user_config:
                            default_config[section].update(user_config[section])
            return default_config
        except FileNotFoundError:
            print(f"[!] Config file {config_file} not found, using defaults")
            return default_config
    
    def check_scanner_availability(self) -> Dict[str, bool]:
        """Check which scanners are available on Windows"""
        available = {}
        
        # Check Nmap
        try:
            result = subprocess.run([self.config['nmap']['path'], '--version'], 
                                  capture_output=True, timeout=10, shell=True)
            available['nmap'] = result.returncode == 0
            if available['nmap']:
                print(f"[+] Nmap found: {self.config['nmap']['path']}")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            available['nmap'] = False
            print(f"[!] Nmap not found at: {self.config['nmap']['path']}")
        
        # Check Nikto (via Perl)
        try:
            nikto_path = self.config['nikto']['nikto_script']
            if os.path.exists(nikto_path):
                result = subprocess.run([
                    self.config['nikto']['path'], 
                    nikto_path, 
                    '-Version'
                ], capture_output=True, timeout=10, shell=True)
                available['nikto'] = result.returncode == 0
                if available['nikto']:
                    print(f"[+] Nikto found: {nikto_path}")
            else:
                available['nikto'] = False
                print(f"[!] Nikto script not found at: {nikto_path}")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            available['nikto'] = False
            print(f"[!] Perl or Nikto not accessible")
        
        # Check ZAP
        if self.config['zap']['enabled']:
            try:
                zap_url = f"http://{self.config['zap']['host']}:{self.config['zap']['port']}"
                response = requests.get(f"{zap_url}/JSON/core/view/version/", 
                                      timeout=5)
                available['zap'] = response.status_code == 200
                if available['zap']:
                    print(f"[+] ZAP found running at: {zap_url}")
                else:
                    print(f"[!] ZAP not responding at: {zap_url}")
                    # Try to start ZAP automatically
                    self._auto_start_zap()
            except:
                available['zap'] = False
                print(f"[!] ZAP not running - attempting to start ZAP automatically...")
                # Try to start ZAP automatically
                self._auto_start_zap()
        else:
            available['zap'] = False
        
        return available

    def _auto_start_zap(self):
        """Automatically start ZAP in a new terminal if start_zap.bat exists"""
        try:
            zap_start_script = "start_zap.bat"
            if os.path.exists(zap_start_script):
                print(f"[*] Found {zap_start_script} - starting ZAP in new terminal...")
                
                # Start ZAP in a new terminal window (Windows)
                if platform.system() == 'Windows':
                    subprocess.Popen([
                        'cmd', '/c', 'start', 'cmd', '/k', zap_start_script
                    ], creationflags=subprocess.CREATE_NEW_CONSOLE)
                    print(f"[+] ZAP starting in new terminal - please wait 30-60 seconds for ZAP to initialize")
                    print(f"[+] You can continue with the scan - ZAP will be checked again when needed")
                else:
                    # For Linux/Mac - open in new terminal
                    subprocess.Popen(['gnome-terminal', '--', 'bash', '-c', f'./{zap_start_script}; read'])
                    print(f"[+] ZAP starting in new terminal - please wait for ZAP to initialize")
                
                # Give ZAP a moment to start
                time.sleep(2)
                
            else:
                print(f"[!] {zap_start_script} not found in current directory")
                print(f"[!] Please start ZAP manually or ensure {zap_start_script} exists")
                
        except Exception as e:
            print(f"[!] Failed to auto-start ZAP: {e}")
            print(f"[!] Please start ZAP manually using start_zap.bat")

    def _check_zap_running(self) -> bool:
        """Check if ZAP is currently running and accessible"""
        try:
            zap_url = f"http://{self.config['zap']['host']}:{self.config['zap']['port']}"
            response = requests.get(f"{zap_url}/JSON/core/view/version/", timeout=5)
            return response.status_code == 200
        except:
            return False

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
    
    def crawl_only(self, target_url: str, save_filename: Optional[str] = None, 
                   include_all: bool = False) -> Dict:
        """Run crawl-only operation with full crawler functionality"""
        print(f"🕷️  Starting security-focused crawl of {target_url}")
        print(f"📝 Scan ID: {self.scan_id}")
        
        if not self.crawler:
            raise RuntimeError("Crawler not initialized. Call initialize_crawler() first.")
        
        # Run the crawl
        crawl_results = self.crawler.crawl(target_url)
        
        # Create security scan report
        crawler_report = create_security_scan_report(crawl_results, target_url, self.scan_id)
        
        # Count crawler vulnerabilities
        crawler_vulns = 0
        for endpoint in crawler_report['discovered_endpoints']:
            if 'security_issues' in endpoint:
                crawler_vulns += len(endpoint['security_issues'])
        
        self.vulnerabilities_by_scanner['crawler'] = crawler_vulns
        self.total_vulnerabilities_found += crawler_vulns
        
        print(f"✅ Discovered {len(crawl_results)} endpoints")
        print(f"📝 Found {len([p for p in crawl_results if p['has_forms']])} pages with forms")
        print(f"🔍 Crawler found {crawler_vulns} potential configuration issues")
        
        # Save results
        if save_filename:
            filepath = self.save_crawl_results(crawler_report, save_filename)
        else:
            filepath = self.save_crawl_results(crawler_report, f"crawl_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        
        return crawler_report
    
    def scan_with_tools(self, target_url: str, max_pages: int = 50) -> Dict:
        """Main scanning orchestration method with real-time feedback"""
        print(f"🎯 Starting comprehensive vulnerability scan of {target_url}")
        print(f"📝 Scan ID: {self.scan_id}")
        
        # Step 1: Crawl target
        print("\n" + "="*60)
        print("🕷️  [PHASE 1] Web Application Discovery")
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
        
        print(f"✅ Discovered {len(crawl_results)} endpoints")
        print(f"📝 Found {len([p for p in crawl_results if p['has_forms']])} pages with forms")
        print(f"🔍 Crawler found {crawler_vulns} potential configuration issues")
        
        # Step 2: Run security scanners
        print("\n" + "="*60)
        print("🛡️  [PHASE 2] Vulnerability Scanning")
        print("="*60)
        print(f"🌐 Running scanners on {len(crawler_report['scanner_targets']['nmap_targets'])} network targets")
        print(f"🕸️  Running scanners on {len(crawler_report['scanner_targets']['nikto_targets'])} web targets")
        
        scan_results = {}
        
        if self.available_scanners.get('nmap') and self.config['nmap']['enabled']:
            scan_results['nmap'] = self.run_nmap_scan_enhanced(crawler_report['scanner_targets']['nmap_targets'])
        
        if self.available_scanners.get('nikto') and self.config['nikto']['enabled']:
            scan_results['nikto'] = self.run_nikto_scan_enhanced(crawler_report['scanner_targets']['nikto_targets'])
        
        if self.available_scanners.get('zap') and self.config['zap']['enabled']:
            scan_results['zap'] = self.run_zap_scan(crawler_report['scanner_targets']['nikto_targets'])
        
        # Step 3: Aggregate results
        print("\n" + "="*60)
        print("📊 [PHASE 3] Result Aggregation & Analysis")
        print("="*60)
        final_report = self.aggregate_results(crawler_report, scan_results)
        
        # Step 4: Save results and show detailed analysis
        report_path = self.save_results(final_report)
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
        
        print(f"[NIKTO] Complete: {self.vulnerabilities_by_scanner['nikto']} total vulnerabilities found")
        return nikto_results

    def parse_nmap_xml(self, xml_path: str, host: str) -> List[Dict]:
        """Parse Nmap XML output for vulnerabilities - ENHANCED VERSION"""
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
                        
                        # EXPANDED: Check for more vulnerability indicators
                        is_vulnerability = any([
                            'vuln' in script_id and ('VULNERABLE' in script_output.upper() or 'CVE-' in script_output),
                            script_id == 'http-csrf' and 'CSRF vulnerabilities' in script_output,
                            script_id == 'http-enum' and ('backup' in script_output.lower() or 'admin' in script_output.lower()),
                            script_id == 'http-stored-xss' and 'XSS' in script_output,
                            script_id == 'http-dombased-xss' and 'XSS' in script_output,
                            'possible vulnerability' in script_output.lower(),
                            'security issue' in script_output.lower()
                        ])
                        
                        if is_vulnerability:
                            severity = self.determine_nmap_severity(script_output, script_id)
                            
                            vuln = {
                                'title': f"Security issue detected by {script_id}",
                                'description': script_output.strip(),
                                'severity': severity,
                                'type': 'network',
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
                        'confidence': 'high',
                        'osvdb_id': osvdb_id
                    }
                    
                    if 'CVE-' in line:
                        import re
                        cve_match = re.search(r'CVE-\d{4}-\d{4,}', line)
                        if cve_match:
                            vuln['cve_id'] = cve_match.group()
                    
                    vulnerabilities.append(vuln)
        
        except Exception as e:
            print(f"[!] Error parsing Nikto output: {e}")
        
        return vulnerabilities

    def determine_nmap_severity(self, output: str, script_id: str = '') -> str:
        """Enhanced severity determination"""
        output_lower = output.lower()
        
        # CSRF vulnerabilities are typically high severity
        if 'csrf' in script_id.lower() and 'vulnerabilities' in output_lower:
            return 'high'
        
        # Backup files and admin directories are medium-high
        if 'backup' in output_lower or 'admin' in output_lower:
            return 'medium'
        
        # Original logic
        if any(word in output_lower for word in ['critical', 'remote code execution', 'rce']):
            return 'critical'
        elif any(word in output_lower for word in ['high', 'privilege escalation', 'csrf']):
            return 'high'
        elif any(word in output_lower for word in ['medium', 'information disclosure', 'backup']):
            return 'medium'
        else:
            return 'low'

    def determine_nikto_severity_from_text(self, line: str) -> str:
        """Determine severity from Nikto text output"""
        line_lower = line.lower()
        
        if any(keyword in line_lower for keyword in [
            'remote code execution', 'rce', 'sql injection', 'command injection',
            'file inclusion', 'directory traversal', 'arbitrary file'
        ]):
            return 'critical'
        elif any(keyword in line_lower for keyword in [
            'xss', 'cross-site scripting', 'csrf', 'authentication bypass',
            'admin', 'login', 'password', 'configuration file'
        ]):
            return 'high'
        elif any(keyword in line_lower for keyword in [
            'information disclosure', 'directory', 'backup', 'debug',
            'error', 'server status'
        ]):
            return 'medium'
        elif any(keyword in line_lower for keyword in [
            'version', 'banner', 'server information', 'robots.txt'
        ]):
            return 'low'
        else:
            return 'info'
    
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
    
    def run_zap_scan(self, zap_targets: List[str]) -> Dict:
        """Execute OWASP ZAP scan with real functionality"""
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
                vulnerabilities = self._get_zap_alerts()
                zap_results['vulnerabilities'].extend(vulnerabilities)
                
                vuln_count = len(vulnerabilities)
                self.vulnerabilities_by_scanner['zap'] += vuln_count
                self.total_vulnerabilities_found += vuln_count
                
                print(f"  [ZAP] ✓ Found {vuln_count} vulnerabilities")
                
            except Exception as e:
                error_msg = f"ZAP scan failed for {target}: {str(e)}"
                zap_results['errors'].append(error_msg)
                print(f"  [ZAP] ✗ Error scanning {target}: {e}")
        
        print(f"[ZAP] Complete: {self.vulnerabilities_by_scanner['zap']} total vulnerabilities found")
        return zap_results
    
    def _zap_spider(self, target: str) -> Optional[str]:
        """Start ZAP spider scan"""
        try:
            zap_url = f"http://{self.config['zap']['host']}:{self.config['zap']['port']}"
            response = requests.get(f"{zap_url}/JSON/spider/action/scan/", params={
                'apikey': self.config['zap']['api_key'],
                'url': target
            })
            if response.status_code == 200:
                return response.json().get('scan')
            return None
        except:
            return None

    def _wait_for_zap_spider(self, scan_id: str, max_wait: int = 300):
        """Wait for ZAP spider to complete"""
        zap_url = f"http://{self.config['zap']['host']}:{self.config['zap']['port']}"
        wait_time = 0
        
        while wait_time < max_wait:
            try:
                response = requests.get(f"{zap_url}/JSON/spider/view/status/", params={
                    'apikey': self.config['zap']['api_key'],
                    'scanId': scan_id
                })
                if response.status_code == 200:
                    status = response.json().get('status', '0')
                    if status == '100':  # Complete
                        break
            except:
                break
            
            time.sleep(5)
            wait_time += 5

    def _zap_active_scan(self, target: str) -> Optional[str]:
        """Start ZAP active scan"""
        try:
            zap_url = f"http://{self.config['zap']['host']}:{self.config['zap']['port']}"
            response = requests.get(f"{zap_url}/JSON/ascan/action/scan/", params={
                'apikey': self.config['zap']['api_key'],
                'url': target
            })
            if response.status_code == 200:
                return response.json().get('scan')
            return None
        except:
            return None

    def _wait_for_zap_scan(self, scan_id: str, max_wait: int = 600):
        """Wait for ZAP active scan to complete"""
        zap_url = f"http://{self.config['zap']['host']}:{self.config['zap']['port']}"
        wait_time = 0
        
        while wait_time < max_wait:
            try:
                response = requests.get(f"{zap_url}/JSON/ascan/view/status/", params={
                    'apikey': self.config['zap']['api_key'],
                    'scanId': scan_id
                })
                if response.status_code == 200:
                    status = response.json().get('status', '0')
                    if status == '100':  # Complete
                        break
            except:
                break
            
            time.sleep(10)
            wait_time += 10

    def _get_zap_alerts(self) -> List[Dict]:
        """Get vulnerabilities from ZAP"""
        try:
            zap_url = f"http://{self.config['zap']['host']}:{self.config['zap']['port']}"
            response = requests.get(f"{zap_url}/JSON/core/view/alerts/", params={
                'apikey': self.config['zap']['api_key']
            })
            
            if response.status_code == 200:
                alerts = response.json().get('alerts', [])
                vulnerabilities = []
                
                for alert in alerts:
                    vuln = {
                        'title': alert.get('name', 'ZAP Alert'),
                        'description': alert.get('description', ''),
                        'severity': self._map_zap_risk(alert.get('risk', 'Low')),
                        'type': 'web_application',
                        'affected_url': alert.get('url', ''),
                        'scanner_source': 'zap',
                        'confidence': alert.get('confidence', 'Medium').lower()
                    }
                    vulnerabilities.append(vuln)
                
                return vulnerabilities
            return []
        except:
            return []

    def _map_zap_risk(self, risk: str) -> str:
        """Map ZAP risk levels to severity"""
        risk_mapping = {
            'High': 'high',
            'Medium': 'medium',
            'Low': 'low',
            'Informational': 'info'
        }
        return risk_mapping.get(risk, 'info')
    
    def aggregate_results(self, crawler_report: Dict, scan_results: Dict) -> Dict:
        """Aggregate all scan results into final report"""
        final_report = crawler_report.copy()
        final_report['scanner_results'] = scan_results
        
        all_vulnerabilities = []
        
        # Add crawler-discovered vulnerabilities from security_issues
        for endpoint in crawler_report['discovered_endpoints']:
            security_issues = endpoint.get('security_issues', [])
            for issue in security_issues:
                vuln = {
                    'title': f"Configuration issue: {issue.get('type', 'Unknown').replace('_', ' ').title()}",
                    'description': issue.get('description', 'Security configuration issue detected'),
                    'severity': self.map_crawler_severity(issue.get('type', ''), issue.get('description', '')),
                    'type': 'configuration',
                    'affected_url': endpoint['url'],
                    'scanner_source': 'crawler',
                    'confidence': 'medium'
                }
                all_vulnerabilities.append(vuln)
                
            # Also check for forms as potential vulnerabilities
            if endpoint.get('has_forms'):
                for form in endpoint.get('forms', []):
                    if form.get('method', '').upper() == 'POST':
                        vuln = {
                            'title': 'POST Form Detected',
                            'description': f"POST form found at {endpoint['url']} - potential injection point",
                            'severity': 'medium',
                            'type': 'web_application',
                            'affected_url': endpoint['url'],
                            'scanner_source': 'crawler',
                            'confidence': 'high'
                        }
                        all_vulnerabilities.append(vuln)
        
        # Add scanner vulnerabilities
        for scanner_name, scanner_result in scan_results.items():
            all_vulnerabilities.extend(scanner_result.get('vulnerabilities', []))
        
        # Deduplicate vulnerabilities
        deduplicated_vulns = self.deduplicate_vulnerabilities(all_vulnerabilities)
        
        # Add vulnerability summary
        final_report['vulnerability_summary'] = {
            'total_vulnerabilities': len(deduplicated_vulns),
            'critical': len([v for v in deduplicated_vulns if v['severity'] == 'critical']),
            'high': len([v for v in deduplicated_vulns if v['severity'] == 'high']),
            'medium': len([v for v in deduplicated_vulns if v['severity'] == 'medium']),
            'low': len([v for v in deduplicated_vulns if v['severity'] == 'low']),
            'info': len([v for v in deduplicated_vulns if v['severity'] == 'info'])
        }
        
        final_report['vulnerabilities'] = deduplicated_vulns
        
        # Update metadata
        final_report['scan_metadata'] = {
            'scan_id': self.scan_id,
            'timestamp': datetime.now().isoformat() + 'Z',
            'scanner_version': '2.0',
            'scanners_used': list(scan_results.keys()),
            'total_scan_time': sum(sr.get('scan_duration', 0) for sr in scan_results.values())
        }
        
        # Apply ML enhancement before returning
        return self.apply_ml_enhancement(final_report)
    
    def map_crawler_severity(self, vuln_type: str, issue: str) -> str:
        """Map crawler findings to severity levels"""
        issue_lower = issue.lower() if issue else ''
        vuln_type_lower = vuln_type.lower() if vuln_type else ''
        
        # High severity issues
        if any(keyword in issue_lower for keyword in ['post form', 'login', 'admin', 'password', 'csrf']):
            return 'high'
        elif any(keyword in vuln_type_lower for keyword in ['form_security', 'authentication']):
            return 'high'
            
        # Medium severity issues
        if any(keyword in issue_lower for keyword in ['form found', 'security testing', 'configuration']):
            return 'medium'
        elif any(keyword in vuln_type_lower for keyword in ['security_headers', 'cookie_issues']):
            return 'medium'
            
        # Low severity issues
        if any(keyword in issue_lower for keyword in ['information', 'disclosure', 'version']):
            return 'low'
            
        # Default to medium for security-related findings
        return 'medium'
    
    def deduplicate_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Remove duplicate vulnerabilities"""
        seen_vulns = set()
        unique_vulns = []
        
        for vuln in vulnerabilities:
            dedup_key = (
                vuln['title'].lower().strip(),
                vuln.get('affected_url', ''),
                vuln['severity']
            )
            
            if dedup_key not in seen_vulns:
                seen_vulns.add(dedup_key)
                unique_vulns.append(vuln)
        
        # Sort by severity
        severity_order = {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1}
        return sorted(unique_vulns, 
                     key=lambda v: (severity_order.get(v['severity'], 0), v['title']), 
                     reverse=True)

    def display_detailed_analysis(self, report: Dict):
        """Display comprehensive scan analysis automatically"""
        print("\n" + "="*80)
        print("COMPREHENSIVE VULNERABILITY ANALYSIS")
        print("="*80)
        
        # Basic scan info
        print(f"Target: {report['scan_target']['base_url']}")
        print(f"Scan ID: {report['scan_target']['scan_id']}")
        print(f"Completed: {report['scan_metadata']['timestamp']}")
        print(f"Scanners Used: {', '.join(report['scan_metadata']['scanners_used'])}")
        
        # Discovery summary
        print(f"\n📊 DISCOVERY SUMMARY:")
        print(f"  • Endpoints Discovered: {len(report['discovered_endpoints'])}")
        print(f"  • Forms Found: {report['scan_summary']['endpoints_with_forms']}")
        print(f"  • High Priority Targets: {report['scan_summary']['high_priority_targets']}")
        
        # Technology stack
        tech_stack = report['scan_summary']['technology_fingerprint']
        print(f"\n🔧 TECHNOLOGY STACK:")
        if tech_stack['web_servers']:
            print(f"  • Web Servers: {', '.join(tech_stack['web_servers'])}")
        if tech_stack['frameworks']:
            print(f"  • Frameworks: {', '.join(tech_stack['frameworks'])}")
        if tech_stack['databases']:
            print(f"  • Databases: {', '.join(tech_stack['databases'])}")
        
        # Vulnerability breakdown by scanner
        print(f"\n🔍 VULNERABILITY BREAKDOWN BY SCANNER:")
        print(f"  • Crawler (Configuration Issues): {self.vulnerabilities_by_scanner['crawler']}")
        print(f"  • Nmap (Network Security): {self.vulnerabilities_by_scanner['nmap']}")
        print(f"  • Nikto (Web Application): {self.vulnerabilities_by_scanner['nikto']}")
        print(f"  • ZAP (Dynamic Analysis): {self.vulnerabilities_by_scanner['zap']}")
        print(f"  • TOTAL VULNERABILITIES: {self.total_vulnerabilities_found}")
        
        # Severity distribution
        vuln_summary = report['vulnerability_summary']
        print(f"\n🚨 SEVERITY DISTRIBUTION:")
        print(f"  • 🔴 Critical: {vuln_summary['critical']}")
        print(f"  • 🟠 High: {vuln_summary['high']}")
        print(f"  • 🟡 Medium: {vuln_summary['medium']}")
        print(f"  • 🔵 Low: {vuln_summary['low']}")
        print(f"  • ⚪ Info: {vuln_summary['info']}")
        
        # Top vulnerabilities by severity
        print(f"\n🎯 TOP CRITICAL & HIGH SEVERITY ISSUES:")
        critical_high = [v for v in report['vulnerabilities'] if v['severity'] in ['critical', 'high']]
        
        if critical_high:
            for i, vuln in enumerate(critical_high[:10], 1):
                severity_icon = "🔴" if vuln['severity'] == 'critical' else "🟠"
                print(f"  {i}. {severity_icon} [{vuln['severity'].upper()}] {vuln['title'][:70]}...")
                print(f"     🌐 URL: {vuln.get('affected_url', 'N/A')[:80]}")
                print(f"     🔍 Source: {vuln['scanner_source']} | Confidence: {vuln.get('confidence', 'medium')}")
                if vuln.get('cve_id'):
                    print(f"     🆔 CVE: {vuln['cve_id']}")
                print()
        else:
            print("  ✅ No critical or high severity vulnerabilities found!")
        
        print(f"\n📁 Detailed results saved to: vuln-scanner-results/")

    def save_results(self, report: Dict) -> str:
        """Save scan results to JSON file in vuln-scanner-results folder"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"vuln_scan_{timestamp}.json"
        filepath = self.results_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Complete scan report saved to {filepath}")
        return str(filepath)

    def save_crawl_results(self, report: Dict, filename: str) -> str:
        """Save crawl-only results"""
        if not filename.endswith('.json'):
            filename = f"{filename}.json"
        
        filepath = self.results_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Crawl results saved to {filepath}")
        return str(filepath)
    
    def apply_ml_enhancement(self, final_report: Dict) -> Dict:
        """Apply ML enhancement to scan results"""
        try:
            from ml_handler import MLVulnerabilityHandler
            
            print(f"\n🤖 [ML ENHANCEMENT] Analyzing vulnerabilities with trained model...")
            
            ml_handler = MLVulnerabilityHandler(self.config_file)
            enhanced_report = ml_handler.enhance_vulnerability_analysis(final_report)
            
            # Update vulnerability counts if ML made changes
            ml_summary = enhanced_report.get('ml_summary', {})
            if ml_summary.get('ml_analysis_available'):
                print(f"🤖 [ML] Analyzed {ml_summary['vulnerabilities_analyzed']} vulnerabilities")
                print(f"🤖 [ML] Average confidence: {ml_summary['average_confidence']:.2f}")
                print(f"🤖 [ML] High confidence predictions: {ml_summary['high_confidence_predictions']}")
                print(f"🤖 [ML] Severity adjustments: {ml_summary['severity_adjustments']}")
            
            return enhanced_report
            
        except ImportError:
            print(f"[!] ml_handler.py not available, skipping ML enhancement")
            return final_report
        except Exception as e:
            print(f"[!] ML enhancement failed: {e}")
            return final_report

# CLI Commands with ALL crawler.py functionality
@app.command()
def scan(
    url: str = typer.Argument(..., help="Target URL to scan"),
    max_pages: int = typer.Option(50, help="Maximum pages to crawl"),
    delay: float = typer.Option(0.3, help="Delay between requests (seconds)"),
    save: str = typer.Option(None, help="Filename to save results (auto-timestamped if not provided)"),
    include_all: bool = typer.Option(False, help="Include pages without forms in results"),
    no_selenium: bool = typer.Option(False, help="Disable Selenium (requests only)"),
    aggressive: bool = typer.Option(False, help="Enable aggressive mode (bypass some protections)"),
    ignore_robots: bool = typer.Option(False, help="Ignore robots.txt (for security testing)"),
    no_dedup: bool = typer.Option(False, help="Disable content deduplication"),
    config: str = typer.Option("config.yaml", help="Configuration file path"),
    crawl_only: bool = typer.Option(False, help="Only crawl, don't run security scanners")
):
    """
    Complete vulnerability scan: crawl + security scanning
    
    This tool combines web crawling with multiple security scanners:
    - Nmap for network vulnerabilities
    - Nikto for web server vulnerabilities  
    - Custom analysis for configuration issues
    - Full crawler.py functionality integrated
    """
    
    # Initialize scanner
    scanner = EnhancedVulnerabilityScanner(config)
    
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
    print("ENHANCED ML VULNERABILITY SCANNER")
    print("="*80)
    print(f"Target: {url}")
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
    
    # Run scan
    try:
        if crawl_only:
            print("\n[*] Running CRAWL-ONLY mode (no security scanners)")
            results = scanner.crawl_only(url, save, include_all)
            
            # Display crawler results like crawler.py does
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
            print("\n[*] Running FULL VULNERABILITY SCAN mode")
            results = scanner.scan_with_tools(url, max_pages)
            print(f"\n🎉 SCAN COMPLETED SUCCESSFULLY!")
            print(f"📊 Total vulnerabilities found: {scanner.total_vulnerabilities_found}")
        
    except KeyboardInterrupt:
        print(f"\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"\n[!] Scan failed: {e}")

@app.command()
def crawl(
    url: str = typer.Argument(..., help="Target URL to crawl"),
    max_pages: int = typer.Option(100, help="Maximum pages to crawl"),
    delay: float = typer.Option(0.3, help="Delay between requests (seconds)"),
    save: str = typer.Option(None, help="Filename to save results (auto-timestamped if not provided)"),
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
        from ml_handler import MLVulnerabilityHandler
        
        print("🤖 ML Model Training")
        print("=" * 50)
        
        # Initialize ML handler
        ml_handler = MLVulnerabilityHandler()
        
        # Check status
        status = ml_handler.get_model_status()
        print(f"📁 CVE Data Path: {status['cve_data_path']}")
        print(f"📅 Available Years: {status['available_cve_years']}")
        print(f"📊 Model Files Exist: {status['model_files_exist']}")
        
        if not status['available_cve_years']:
            print("❌ No CVE data available. Please ensure CVE files are in the correct directory structure.")
            print("   Expected structure: ./cves/2023/CVE-2023-*.json")
            print("                      ./cves/2024/CVE-2024-*.json")
            return
        
        # Step 1: Collect and process CVE data
        print(f"\n[1/4] Collecting CVE data...")
        if not ml_handler.collect_and_process_cve_data():
            print("❌ Failed to collect CVE data")
            return
        
        # Step 2: Prepare training data
        print(f"\n[2/4] Preparing training data...")
        if not ml_handler.prepare_training_data():
            print("❌ Failed to prepare training data")
            return
        
        # Step 3: Train model
        print(f"\n[3/4] Training vulnerability classifier...")
        if not ml_handler.train_vulnerability_classifier():
            print("❌ Failed to train model")
            return
        
        # Step 4: Save model
        print(f"\n[4/4] Saving trained model...")
        if ml_handler.save_trained_model():
            print("✅ ML model training completed successfully!")
            print(f"📁 Model saved in: {ml_handler.models_path}")
            
            # Display final status
            final_status = ml_handler.get_model_status()
            if 'model_info' in final_status:
                info = final_status['model_info']
                print(f"\n📊 Model Information:")
                print(f"   • Training Date: {info['training_date']}")
                print(f"   • Test Accuracy: {info['test_accuracy']:.3f}")
                print(f"   • Training Samples: {info['training_samples']:,}")
                print(f"   • CVE Sources: {', '.join(info['cve_sources'])}")
        else:
            print("❌ Failed to save model")
            
    except ImportError:
        print("❌ ML dependencies not available. Install with:")
        print("   pip install scikit-learn pandas numpy")
    except KeyboardInterrupt:
        print(f"\n⚠️ Training interrupted by user")
    except Exception as e:
        print(f"❌ Training failed: {e}")

@app.command()
def train_gpu(
    dataset_limit: int = typer.Option(None, help="Limit dataset size for faster GPU training"),
    force: bool = typer.Option(False, help="Force GPU training even if GPU not available")
):
    """🚀 Train ML model using GPU acceleration for faster performance"""
    try:
        from ml_handler import MLVulnerabilityHandler
        
        print("🚀 GPU-Accelerated ML Model Training")
        print("=" * 60)
        
        # Initialize ML handler
        ml_handler = MLVulnerabilityHandler()
        
        # Check GPU availability
        try:
            import torch
            gpu_available = torch.cuda.is_available()
            if gpu_available:
                gpu_name = torch.cuda.get_device_name(0)
                print(f"🎯 GPU Detected: {gpu_name}")
                print(f"🔥 CUDA Version: {torch.version.cuda}")
            else:
                print("⚠️  No GPU detected - will use CPU fallback")
                if not force:
                    print("💡 Use --force to train on CPU anyway")
                    return
        except ImportError:
            print("❌ PyTorch not installed - GPU training unavailable")
            print("📦 Install with: pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118")
            return
        
        # Check CVE data status
        status = ml_handler.get_model_status()
        print(f"\n📁 CVE Data Path: {status['cve_data_path']}")
        print(f"📅 Available Years: {status['available_cve_years']}")
        
        if not status['available_cve_years']:
            print("❌ No CVE data available. Please ensure CVE files are in the correct directory structure.")
            return
        
        if dataset_limit:
            print(f"📊 Dataset limited to: {dataset_limit:,} samples")
        
        # Step 1: Collect and process CVE data
        print(f"\n[1/4] 📥 Collecting CVE data...")
        if not ml_handler.collect_and_process_cve_data():
            print("❌ Failed to collect CVE data")
            return
        
        # Step 2: Prepare training data
        print(f"\n[2/4] 🔧 Preparing training data...")
        if not ml_handler.prepare_training_data():
            print("❌ Failed to prepare training data")
            return
        
        # Step 3: Train GPU model
        print(f"\n[3/4] 🧠 Training GPU neural network...")
        if not ml_handler.train_gpu_accelerated_classifier(dataset_size_limit=dataset_limit):
            print("❌ GPU training failed - trying CPU fallback...")
            if not ml_handler.train_vulnerability_classifier():
                print("❌ CPU training also failed")
                return
        
        # Step 4: Save model
        print(f"\n[4/4] 💾 Saving trained model...")
        if ml_handler.save_trained_model():
            print("✅ GPU model training completed successfully!")
            print(f"📁 Model saved in: {ml_handler.models_path}")
            
            # Display final status
            final_status = ml_handler.get_model_status()
            if 'model_info' in final_status:
                info = final_status['model_info']
                print(f"\n📊 Model Information:")
                print(f"   • Model Type: {info.get('model_type', 'GPU Neural Network')}")
                print(f"   • Training Date: {info['training_date']}")
                print(f"   • Test Accuracy: {info['test_accuracy']:.3f}")
                print(f"   • Training Samples: {info['training_samples']:,}")
                print(f"   • CVE Sources: {', '.join(info['cve_sources'])}")
        else:
            print("❌ Failed to save model")
            
    except ImportError:
        print("❌ ML dependencies not available. Install with:")
        print("   pip install scikit-learn pandas numpy torch")
    except KeyboardInterrupt:
        print(f"\n⚠️ GPU training interrupted by user")
    except Exception as e:
        print(f"❌ GPU training failed: {e}")

@app.command()
def ml_status():
    """Check ML model status and CVE data availability"""
    try:
        from ml_handler import MLVulnerabilityHandler
        
        print("🤖 ML System Status")
        print("=" * 40)
        
        ml_handler = MLVulnerabilityHandler()
        status = ml_handler.get_model_status()
        
        print(f"📁 CVE Data Path: {status['cve_data_path']}")
        print(f"📅 Available CVE Years: {status['available_cve_years']}")
        print(f"📊 Processed Data Exists: {'✓' if status['processed_data_exists'] else '✗'}")
        print(f"🤖 Model Files Exist: {'✓' if status['model_files_exist'] else '✗'}")
        print(f"🔄 Model Loaded: {'✓' if status['model_loaded'] else '✗'}")
        
        if 'model_info' in status:
            info = status['model_info']
            print(f"\n📊 Model Information:")
            print(f"   • Training Date: {info['training_date']}")
            print(f"   • Test Accuracy: {info['test_accuracy']:.3f}")
            print(f"   • Training Samples: {info['training_samples']:,}")
            print(f"   • CVE Sources: {', '.join(info['cve_sources'])}")
        else:
            print(f"\n⚠️ No trained model available. Run: python scanner.py train-ml")
            
    except ImportError:
        print("❌ ML dependencies not available. Install with:")
        print("   pip install scikit-learn pandas numpy")
    except Exception as e:
        print(f"❌ Error checking ML status: {e}")

if __name__ == "__main__":
    app()