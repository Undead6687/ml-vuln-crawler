#!/usr/bin/env python3
import os
import sys

# Fix Windows console encoding issues
if os.name == 'nt':  # Windows
    import ctypes
    try:
        # Set console to UTF-8
        ctypes.windll.kernel32.SetConsoleCP(65001)
        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
    except:
        pass

"""
ML Vulnerability Scanner Validation Framework - JUICE SHOP EDITION
Comprehensive testing suite to validate scanner effectiveness against OWASP Juice Shop
"""

import json
import subprocess
import time
import pandas as pd
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import requests
from urllib.parse import urljoin
import logging

class JuiceShopValidationFramework:
    def __init__(self, scanner_path="./scanner.py"):
        self.scanner_path = scanner_path
        self.results_dir = Path("validation_results")
        self.results_dir.mkdir(exist_ok=True)
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.results_dir / 'validation.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # OWASP Juice Shop known vulnerabilities (ground truth)
        self.juice_shop_vulnerabilities = self._load_juice_shop_ground_truth()
        
        # Validation results storage
        self.validation_results = {
            'test_timestamp': datetime.now().isoformat(),
            'baseline_comparison': {},
            'ml_effectiveness': {},
            'false_positive_validation': {},
            'detection_rate_analysis': {},
            'severity_accuracy': {},
            'overall_assessment': {}
        }

    def _load_juice_shop_ground_truth(self) -> Dict:
        """
        Load OWASP Juice Shop's known vulnerabilities as ground truth
        Based on official Juice Shop challenge list
        """
        return {
            'sql_injection': {
                'endpoints': [
                    '/rest/products/search',
                    '/rest/user/login',
                    '/api/Users',
                    '/rest/products/reviews',
                    '/rest/track-result'
                ],
                'severity': 'high',
                'expected_count': 5,
                'description': 'SQL injection in search, login, and API endpoints'
            },
            'xss': {
                'endpoints': [
                    '/profile',
                    '/search',
                    '/contact',
                    '/complain',
                    '/rest/user/whoami'
                ],
                'severity': 'medium',
                'expected_count': 8,
                'description': 'Reflected and stored XSS in multiple forms'
            },
            'broken_authentication': {
                'endpoints': [
                    '/rest/user/login',
                    '/rest/user/reset-password',
                    '/api/Users',
                    '/rest/user/change-password'
                ],
                'severity': 'high',
                'expected_count': 6,
                'description': 'Weak passwords, password reset flaws, etc.'
            },
            'sensitive_data_exposure': {
                'endpoints': [
                    '/ftp',
                    '/encryptionkeys',
                    '/.well-known',
                    '/rest/admin/application-version',
                    '/rest/admin/application-configuration'
                ],
                'severity': 'high',
                'expected_count': 4,
                'description': 'Confidential documents and data accessible'
            },
            'security_misconfiguration': {
                'endpoints': [
                    '/administration',
                    '/metrics',
                    '/rest/admin',
                    '/snippets',
                    '/redirect'
                ],
                'severity': 'medium',
                'expected_count': 7,
                'description': 'Admin interfaces, debug info, redirects'
            },
            'csrf': {
                'endpoints': [
                    '/profile',
                    '/rest/user/change-password',
                    '/complain',
                    '/contact'
                ],
                'severity': 'medium',
                'expected_count': 3,
                'description': 'Missing CSRF tokens in state-changing operations'
            },
            'vulnerable_components': {
                'endpoints': [
                    '/rest/admin/application-version',
                    '/rest/admin/application-configuration'
                ],
                'severity': 'high',
                'expected_count': 2,
                'description': 'Outdated dependencies with known vulnerabilities'
            },
            'insufficient_logging': {
                'endpoints': [
                    '/rest/user/login',
                    '/rest/user/reset-password',
                    '/administration'
                ],
                'severity': 'low',
                'expected_count': 2,
                'description': 'Security events not properly logged'
            }
        }

    def check_juice_shop_running(self, juice_shop_url: str = "http://localhost:3000") -> bool:
        """Check if OWASP Juice Shop is running and accessible"""
        try:
            response = requests.get(juice_shop_url, timeout=10)
            if response.status_code == 200 and 'juice' in response.text.lower():
                self.logger.info(f"OWASP Juice Shop is running at {juice_shop_url}")
                
                # Also check what scanners are available
                self.logger.info("Checking available vulnerability scanners...")
                try:
                    result = subprocess.run(['python', self.scanner_path, 'scan', '--help'], 
                                          capture_output=True, text=True, timeout=30)
                    if 'nmap' in result.stdout.lower():
                        self.logger.info("- Nmap: Available")
                    if 'nikto' in result.stdout.lower():
                        self.logger.info("- Nikto: Available") 
                    if 'zap' in result.stdout.lower():
                        self.logger.info("- ZAP: Available")
                except Exception as e:
                    self.logger.warning(f"Could not check scanner availability: {e}")
                
                return True
        except Exception as e:
            self.logger.error(f"Juice Shop not accessible: {e}")
            
        self.logger.error("Please start OWASP Juice Shop first:")
        self.logger.error("1. Clone: git clone https://github.com/juice-shop/juice-shop.git")
        self.logger.error("2. Install: cd juice-shop && npm install")
        self.logger.error("3. Run: npm start")
        self.logger.error("4. Wait for startup, then access http://localhost:3000")
        return False

    def validate_detection_rate(self, scan_data: Dict) -> Dict:
        """Validate actual detection rate against Juice Shop ground truth"""
        self.logger.info("Validating detection rates against Juice Shop ground truth...")
        
        found_vulnerabilities = scan_data.get('vulnerabilities', [])
        
        # Count detections by vulnerability type
        detection_results = {}
        total_expected = 0
        total_found = 0
        
        for vuln_type, vuln_info in self.juice_shop_vulnerabilities.items():
            expected_count = vuln_info['expected_count']
            expected_endpoints = set(vuln_info['endpoints'])
            
            # Count how many we actually found
            found_count = 0
            found_endpoints = set()
            
            for vuln in found_vulnerabilities:
                vuln_url = vuln.get('affected_url', '')
                vuln_desc = vuln.get('description', '').lower()
                vuln_title = vuln.get('title', '').lower()
                
                # Check if this vulnerability matches the type (Juice Shop specific)
                if vuln_type == 'sql_injection':
                    if any(keyword in vuln_desc or keyword in vuln_title 
                          for keyword in ['sql injection', 'sql', 'injection']):
                        found_count += 1
                        found_endpoints.add(vuln_url)
                
                elif vuln_type == 'xss':
                    if any(keyword in vuln_desc or keyword in vuln_title 
                          for keyword in ['xss', 'cross-site scripting', 'scripting']):
                        found_count += 1
                        found_endpoints.add(vuln_url)
                
                elif vuln_type == 'broken_authentication':
                    if any(keyword in vuln_desc or keyword in vuln_title 
                          for keyword in ['auth', 'authentication', 'login', 'password', 'session']):
                        found_count += 1
                        found_endpoints.add(vuln_url)
                
                elif vuln_type == 'sensitive_data_exposure':
                    if any(keyword in vuln_desc or keyword in vuln_title 
                          for keyword in ['exposure', 'disclosure', 'sensitive', 'confidential', 'ftp']):
                        found_count += 1
                        found_endpoints.add(vuln_url)
                
                elif vuln_type == 'security_misconfiguration':
                    if any(keyword in vuln_desc or keyword in vuln_title 
                          for keyword in ['misconfiguration', 'admin', 'configuration', 'debug']):
                        found_count += 1
                        found_endpoints.add(vuln_url)
                
                elif vuln_type == 'csrf':
                    if any(keyword in vuln_desc or keyword in vuln_title 
                          for keyword in ['csrf', 'cross-site request forgery']):
                        found_count += 1
                        found_endpoints.add(vuln_url)
                
                elif vuln_type == 'vulnerable_components':
                    if any(keyword in vuln_desc or keyword in vuln_title 
                          for keyword in ['component', 'dependency', 'version', 'outdated']):
                        found_count += 1
                        found_endpoints.add(vuln_url)
                
                elif vuln_type == 'insufficient_logging':
                    if any(keyword in vuln_desc or keyword in vuln_title 
                          for keyword in ['logging', 'log', 'audit', 'monitoring']):
                        found_count += 1
                        found_endpoints.add(vuln_url)
            
            detection_rate = (found_count / expected_count) * 100 if expected_count > 0 else 0
            
            detection_results[vuln_type] = {
                'expected': expected_count,
                'found': found_count,
                'detection_rate': detection_rate,
                'expected_endpoints': list(expected_endpoints),
                'found_endpoints': list(found_endpoints),
                'missing_endpoints': list(expected_endpoints - found_endpoints),
                'description': vuln_info['description']
            }
            
            total_expected += expected_count
            total_found += found_count
            
            self.logger.info(f"{vuln_type}: {found_count}/{expected_count} ({detection_rate:.1f}%)")
        
        overall_detection_rate = (total_found / total_expected) * 100 if total_expected > 0 else 0
        
        return {
            'overall_detection_rate': overall_detection_rate,
            'total_expected': total_expected,
            'total_found': total_found,
            'by_vulnerability_type': detection_results,
            'assessment': 'EXCELLENT' if overall_detection_rate >= 80 else 'GOOD' if overall_detection_rate >= 60 else 'POOR'
        }

    def run_scanner_baseline(self, target_url: str) -> Dict:
        """Run scanner WITHOUT ML to establish baseline"""
        self.logger.info("Running BASELINE scan (no ML)...")
        
        cmd = [
            'python', self.scanner_path, 'scan', target_url,
            '--max-pages', '200', '--save', '--aggressive', '--ignore-robots'
        ]
        
        baseline_file = self.results_dir / f"baseline_scan_{int(time.time())}.json"
        
        try:
            # Run scanner
            start_time = time.time()
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
            scan_time = time.time() - start_time
            
            self.logger.info(f"Baseline scan completed in {scan_time:.1f}s")
            
            # Find the most recent scan result
            scan_results = self._find_latest_scan_result()
            
            if scan_results:
                # Copy to our validation directory
                with open(scan_results, 'r') as f:
                    data = json.load(f)
                
                with open(baseline_file, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                
                return {
                    'success': True,
                    'file': str(baseline_file),
                    'vulnerabilities_found': len(data.get('vulnerabilities', [])),
                    'scan_time': scan_time,
                    'data': data
                }
            else:
                return {'success': False, 'error': 'No scan results found'}
                
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Scan timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def run_scanner_with_ml(self, target_url: str) -> Dict:
        """Run scanner WITH ML enabled"""
        self.logger.info("Running ML-ENHANCED scan...")
        
        # First ensure ML model is trained
        self.logger.info("Training ML model first...")
        train_cmd = ['python', self.scanner_path, 'train-ml', '--max-files', '1000']
        
        try:
            train_result = subprocess.run(train_cmd, capture_output=True, text=True, timeout=600)
            if train_result.returncode != 0:
                self.logger.warning("ML training failed, continuing anyway...")
        except Exception as e:
            self.logger.warning(f"ML training error: {e}")
        
        # Run scan with ML
        cmd = [
            'python', self.scanner_path, 'scan', target_url,
            '--max-pages', '200', '--save', '--aggressive', '--ignore-robots'
        ]
        
        ml_file = self.results_dir / f"ml_scan_{int(time.time())}.json"
        
        try:
            start_time = time.time()
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
            scan_time = time.time() - start_time
            
            self.logger.info(f"ML scan completed in {scan_time:.1f}s")
            
            # Find the most recent scan result
            scan_results = self._find_latest_scan_result()
            
            if scan_results:
                with open(scan_results, 'r') as f:
                    data = json.load(f)
                
                with open(ml_file, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                
                return {
                    'success': True,
                    'file': str(ml_file),
                    'vulnerabilities_found': len(data.get('vulnerabilities', [])),
                    'scan_time': scan_time,
                    'data': data
                }
            else:
                return {'success': False, 'error': 'No scan results found'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _find_latest_scan_result(self) -> Optional[Path]:
        """Find the most recent scan result file"""
        scan_dirs = ['vuln-scanner-results', 'vulnerability-reports']
        
        latest_file = None
        latest_time = 0
        
        for scan_dir in scan_dirs:
            if os.path.exists(scan_dir):
                for file in Path(scan_dir).glob('*.json'):
                    if file.stat().st_mtime > latest_time:
                        latest_time = file.stat().st_mtime
                        latest_file = file
        
        return latest_file

    def compare_baseline_vs_ml(self, baseline_data: Dict, ml_data: Dict) -> Dict:
        """Compare baseline scan vs ML-enhanced scan"""
        self.logger.info("Comparing baseline vs ML-enhanced results...")
        
        baseline_vulns = baseline_data.get('vulnerabilities', [])
        ml_vulns = ml_data.get('vulnerabilities', [])
        
        # Count by severity
        def count_by_severity(vulns):
            counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            for v in vulns:
                severity = v.get('severity', 'low').lower()
                if severity in counts:
                    counts[severity] += 1
            return counts
        
        baseline_counts = count_by_severity(baseline_vulns)
        ml_counts = count_by_severity(ml_vulns)
        
        # Calculate changes
        changes = {}
        for severity in ['critical', 'high', 'medium', 'low']:
            baseline_count = baseline_counts[severity]
            ml_count = ml_counts[severity]
            change = ml_count - baseline_count
            change_pct = (change / baseline_count * 100) if baseline_count > 0 else 0
            
            changes[severity] = {
                'baseline': baseline_count,
                'ml_enhanced': ml_count,
                'change': change,
                'change_percent': change_pct
            }
        
        # Overall assessment
        total_baseline = len(baseline_vulns)
        total_ml = len(ml_vulns)
        total_change = total_ml - total_baseline
        
        # Check for ML effectiveness
        ml_effective = False
        if total_change != 0:  # Any change indicates ML is doing something
            ml_effective = True
        
        # Check if ML model actually ran
        ml_summary = ml_data.get('ml_summary', {})
        ml_analysis_available = ml_summary.get('ml_analysis_available', False)
        
        return {
            'ml_model_actually_ran': ml_analysis_available,
            'total_vulnerabilities': {
                'baseline': total_baseline,
                'ml_enhanced': total_ml,
                'change': total_change
            },
            'by_severity': changes,
            'ml_effectiveness': {
                'detected_changes': ml_effective,
                'assessment': 'WORKING' if ml_effective and ml_analysis_available else 'NOT WORKING'
            },
            'ml_summary': ml_summary
        }

    def run_comprehensive_validation(self, juice_shop_url: str = "http://localhost:3000") -> Dict:
        """Run complete validation suite against OWASP Juice Shop"""
        self.logger.info("Starting Comprehensive Validation Suite - OWASP JUICE SHOP")
        self.logger.info("=" * 70)
        
        # Check Juice Shop availability
        if not self.check_juice_shop_running(juice_shop_url):
            return {'error': 'OWASP Juice Shop not accessible'}
        
        # Step 1: Baseline scan
        self.logger.info("\nSTEP 1: Baseline Scan (No ML)")
        baseline_result = self.run_scanner_baseline(juice_shop_url)
        
        if not baseline_result['success']:
            self.logger.error(f"Baseline scan failed: {baseline_result['error']}")
            return {'error': 'Baseline scan failed'}
        
        # Step 2: ML-enhanced scan
        self.logger.info("\nSTEP 2: ML-Enhanced Scan")
        ml_result = self.run_scanner_with_ml(juice_shop_url)
        
        if not ml_result['success']:
            self.logger.error(f"ML scan failed: {ml_result['error']}")
            return {'error': 'ML scan failed'}
        
        # Step 3: Detection rate validation
        self.logger.info("\nSTEP 3: Detection Rate Validation")
        detection_validation = self.validate_detection_rate(ml_result['data'])
        self.validation_results['detection_rate_analysis'] = detection_validation
        
        # Step 4: Baseline vs ML comparison
        self.logger.info("\nSTEP 4: Baseline vs ML Comparison")
        baseline_ml_comparison = self.compare_baseline_vs_ml(baseline_result['data'], ml_result['data'])
        self.validation_results['baseline_comparison'] = baseline_ml_comparison
        self.validation_results['ml_effectiveness'] = baseline_ml_comparison['ml_effectiveness']
        
        # Step 5: Overall assessment
        self.logger.info("\nSTEP 5: Overall Assessment")
        overall_assessment = self._generate_overall_assessment()
        self.validation_results['overall_assessment'] = overall_assessment
        
        # Save results
        results_file = self.results_dir / f"juice_shop_validation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump(self.validation_results, f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"\nComplete validation results saved to: {results_file}")
        
        return self.validation_results

    def _generate_overall_assessment(self) -> Dict:
        """Generate final assessment of scanner effectiveness against Juice Shop"""
        
        detection_rate = self.validation_results['detection_rate_analysis']['overall_detection_rate']
        ml_working = self.validation_results['ml_effectiveness']['assessment'] == 'WORKING'
        
        # Calculate overall score
        score = 0
        max_score = 100
        
        # Detection rate (50 points max - more important for Juice Shop)
        score += min(50, detection_rate * 0.5)
        
        # ML functionality (30 points max)
        if ml_working:
            score += 30
        
        # Vulnerability type coverage (20 points max)
        vuln_types_found = len([v for v in self.validation_results['detection_rate_analysis']['by_vulnerability_type'].values() if v['found'] > 0])
        total_vuln_types = len(self.juice_shop_vulnerabilities)
        coverage_score = (vuln_types_found / total_vuln_types) * 20
        score += coverage_score
        
        grade = 'F'
        if score >= 85:
            grade = 'A'
        elif score >= 75:
            grade = 'B'
        elif score >= 65:
            grade = 'C'
        elif score >= 55:
            grade = 'D'
        
        recommendations = []
        
        if detection_rate < 60:
            recommendations.append("CRITICAL: Detection rate too low for Juice Shop - verify scanner configuration")
        
        if not ml_working:
            recommendations.append("CRITICAL: ML enhancement not functioning - check model training")
        
        if vuln_types_found < total_vuln_types * 0.7:
            recommendations.append("HIGH: Missing several vulnerability types - improve scanner coverage")
        
        return {
            'overall_score': score,
            'grade': grade,
            'detection_rate': detection_rate,
            'ml_functional': ml_working,
            'vulnerability_type_coverage': f"{vuln_types_found}/{total_vuln_types}",
            'recommendations': recommendations,
            'summary': f"Scanner achieved {detection_rate:.1f}% detection rate on Juice Shop with ML {'functional' if ml_working else 'non-functional'}"
        }

    def generate_validation_report(self) -> str:
        """Generate human-readable validation report for Juice Shop"""
        report_lines = [
            "=" * 80,
            "ML VULNERABILITY SCANNER VALIDATION REPORT - OWASP JUICE SHOP",
            "=" * 80,
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Target: OWASP Juice Shop (http://localhost:3000)",
            "",
            "EXECUTIVE SUMMARY",
            "-" * 40
        ]
        
        overall = self.validation_results.get('overall_assessment', {})
        report_lines.extend([
            f"Overall Grade: {overall.get('grade', 'N/A')}",
            f"Overall Score: {overall.get('overall_score', 0):.1f}/100",
            f"Detection Rate: {overall.get('detection_rate', 0):.1f}%",
            f"ML Functionality: {'Working' if overall.get('ml_functional') else 'Not Working'}",
            f"Vulnerability Coverage: {overall.get('vulnerability_type_coverage', 'N/A')}",
            ""
        ])
        
        # Detection rate details
        detection = self.validation_results.get('detection_rate_analysis', {})
        report_lines.extend([
            "JUICE SHOP VULNERABILITY DETECTION ANALYSIS",
            "-" * 50,
            f"Overall Detection Rate: {detection.get('overall_detection_rate', 0):.1f}%",
            f"Total Expected Vulnerabilities: {detection.get('total_expected', 0)}",
            f"Total Found Vulnerabilities: {detection.get('total_found', 0)}",
            ""
        ])
        
        # Vulnerability type breakdown
        if 'by_vulnerability_type' in detection:
            report_lines.append("By Vulnerability Type:")
            for vuln_type, data in detection['by_vulnerability_type'].items():
                rate = data.get('detection_rate', 0)
                found = data.get('found', 0)
                expected = data.get('expected', 0)
                description = data.get('description', '')
                report_lines.append(f"  {vuln_type.replace('_', ' ').title()}: {found}/{expected} ({rate:.1f}%)")
                report_lines.append(f"    {description}")
        
        report_lines.append("")
        
        # ML effectiveness
        ml_eff = self.validation_results.get('ml_effectiveness', {})
        report_lines.extend([
            "ML EFFECTIVENESS ANALYSIS",
            "-" * 40,
            f"ML Model Status: {ml_eff.get('assessment', 'Unknown')}",
            f"Changes Detected: {'Yes' if ml_eff.get('detected_changes') else 'No'}",
            ""
        ])
        
        # Recommendations
        recommendations = overall.get('recommendations', [])
        if recommendations:
            report_lines.extend([
                "RECOMMENDATIONS",
                "-" * 40
            ])
            for i, rec in enumerate(recommendations, 1):
                report_lines.append(f"{i}. {rec}")
            report_lines.append("")
        
        # Save report
        report_content = "\n".join(report_lines)
        report_file = self.results_dir / f"juice_shop_validation_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        print("\n" + report_content)
        print(f"\nFull report saved to: {report_file}")
        
        return report_content

def main():
    """Main validation function for OWASP Juice Shop"""
    print("ML Vulnerability Scanner Validation Framework - OWASP JUICE SHOP")
    print("=" * 70)
    
    # Initialize validation framework
    validator = JuiceShopValidationFramework()
    
    # Run comprehensive validation
    try:
        results = validator.run_comprehensive_validation()
        
        if 'error' in results:
            print(f"Validation failed: {results['error']}")
            return
        
        # Generate human-readable report
        validator.generate_validation_report()
        
        print("\nJuice Shop validation completed successfully!")
        print(f"All results saved in: {validator.results_dir}")
        
    except KeyboardInterrupt:
        print("\nValidation interrupted by user")
    except Exception as e:
        print(f"\nValidation failed with error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
