# crawler.py - Security-focused SPA-aware web crawler
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from collections import deque
from tqdm import tqdm
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
import typer
import time
import re
import json
import warnings
import logging
import hashlib
import random
from typing import Set, List, Dict, Optional, Tuple

# Suppress warnings for aggressive crawling
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", module="urllib3")
warnings.filterwarnings("ignore", module="selenium")

# Configure logging to reduce noise
logging.getLogger('selenium').setLevel(logging.ERROR)
logging.getLogger('urllib3').setLevel(logging.ERROR)
logging.getLogger('webdriver_manager').setLevel(logging.ERROR)

app = typer.Typer()

class AggressiveVulnCrawler:
    def __init__(self, max_pages=100, delay=0.3, timeout=10, use_selenium=True, aggressive=False, ignore_robots=False, enable_dedup=True):
        self.max_pages = max_pages
        self.delay = delay
        self.timeout = timeout
        self.use_selenium = use_selenium
        self.aggressive = aggressive
        self.ignore_robots = ignore_robots
        self.enable_dedup = enable_dedup
        
        # URL and content tracking
        self.visited: Set[str] = set()
        self.to_visit: deque = deque()
        self.discovered_pages: List[Dict] = []
        
        # Content deduplication
        self.content_hashes: Set[str] = set()
        self.url_content_map: Dict[str, str] = {}  # URL -> content hash
        self.duplicate_urls: List[Dict] = []  # Track duplicates for reporting
        
        # URL pattern tracking
        self.url_patterns: Set[str] = set()
        
        # SPA detection - detect if we're dealing with hash-based routing
        self.is_spa_mode: bool = False
        self.spa_base_url: str = ""
        
        self.session = requests.Session()
        self.driver = None
        
        # User agents for bypassing basic filters
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0'
        ]
        
        # Setup session with settings
        self.setup_session()
        
        # Initialize Selenium if needed
        if self.use_selenium:
            self.setup_selenium()
    
    def setup_session(self):
        """Setup requests session with aggressive settings"""
        import random
        self.session.headers.update({
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        
        # Disable SSL verification for aggressive mode
        if self.aggressive:
            self.session.verify = False
            requests.packages.urllib3.disable_warnings()
    
    def setup_selenium(self):
        """Setup Selenium WebDriver with stealth options"""
        try:
            chrome_options = Options()
            
            if not self.aggressive:
                chrome_options.add_argument('--headless')
            
            # Stealth options
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--disable-web-security')
            chrome_options.add_argument('--allow-running-insecure-content')
            chrome_options.add_argument('--disable-features=VizDisplayCompositor')
            chrome_options.add_argument('--window-size=1920,1080')
            
            # Bypass bot detection
            chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
            chrome_options.add_experimental_option('useAutomationExtension', False)
            
            import random
            chrome_options.add_argument(f'--user-agent={random.choice(self.user_agents)}')
            
            self.driver = webdriver.Chrome(
                service=webdriver.chrome.service.Service(ChromeDriverManager().install()),
                options=chrome_options
            )
            
            # Execute script to avoid detection
            self.driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
            self.driver.set_page_load_timeout(self.timeout)
            
            if not self.aggressive:
                print("[+] Stealth WebDriver initialized")
            
        except Exception as e:
            if not self.aggressive:
                print(f"[!] Selenium setup failed: {e}")
            self.use_selenium = False
            self.driver = None
    
    def normalize_url(self, url: str) -> str:
        """Normalize URL for consistent processing"""
        parsed = urlparse(url)
        # Normalize path but preserve trailing slash for root path
        path = parsed.path.rstrip('/') if parsed.path != '/' else parsed.path
        normalized = f"{parsed.scheme}://{parsed.netloc}{path}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        # Keep hash for SPA routing - preserve exact fragment
        if parsed.fragment and parsed.fragment.startswith('/'):
            normalized += f"#{parsed.fragment}"
        return normalized
    
    def detect_spa_mode(self, url: str) -> bool:
        """Detect if the URL indicates SPA hash-based routing"""
        parsed = urlparse(url)
        # Check if URL has hash fragment that looks like a route
        if parsed.fragment and parsed.fragment.startswith('/'):
            return True
        return False
    
    def convert_to_spa_url(self, path: str) -> str:
        """Convert a regular path to SPA hash-based URL"""
        if not self.is_spa_mode or not self.spa_base_url:
            return path
        
        parsed_path = urlparse(path)
        parsed_base = urlparse(self.spa_base_url)
        
        # If it's already a hash-based URL, return as is
        if parsed_path.fragment and parsed_path.fragment.startswith('/'):
            return path
        
        # If it's a regular path, convert to hash-based
        if parsed_path.path and parsed_path.path != '/':
            return f"{parsed_base.scheme}://{parsed_base.netloc}/#//{parsed_path.path.lstrip('/')}"
        
        return path
    
    def ensure_consistent_url_format(self, url: str, base_url: str = None) -> str:
        """Ensure URL follows the detected SPA pattern if applicable"""
        if not self.is_spa_mode:
            return self.normalize_url(url)
        
        parsed = urlparse(url)
        
        # If URL already has hash routing, normalize and return
        if parsed.fragment and parsed.fragment.startswith('/'):
            return self.normalize_url(url)
        
        # If it's a regular path but we're in SPA mode, convert it
        if parsed.path and parsed.path != '/' and not parsed.fragment:
            spa_base = urlparse(self.spa_base_url)
            converted_url = f"{spa_base.scheme}://{spa_base.netloc}/#{parsed.path}"
            return self.normalize_url(converted_url)
        
        return self.normalize_url(url)
    
    def is_valid_url(self, url: str) -> bool:
        """Check if URL is valid and crawlable"""
        parsed = urlparse(url)
        
        if parsed.scheme not in ['http', 'https']:
            return False
        
        # More permissive file filtering in aggressive mode
        if self.aggressive:
            skip_extensions = ['.pdf', '.zip', '.exe', '.dmg', '.iso']
        else:
            skip_extensions = ['.pdf', '.jpg', '.jpeg', '.png', '.gif', '.css', '.js', 
                              '.ico', '.svg', '.woff', '.woff2', '.ttf', '.zip', '.exe']
        
        return not any(parsed.path.lower().endswith(ext) for ext in skip_extensions)
    
    def is_internal_link(self, base_url: str, link: str) -> bool:
        """Check if link is internal to the target domain"""
        base_domain = urlparse(base_url).netloc.lower()
        link_domain = urlparse(link).netloc.lower()
        
        if not link_domain:
            return True
        
        return (link_domain == base_domain or 
                link_domain.endswith('.' + base_domain) or
                base_domain.endswith('.' + link_domain))
    
    def check_robots_txt(self, base_url: str) -> bool:
        """Check robots.txt - can be bypassed in aggressive mode"""
        if self.ignore_robots:
            return True
            
        try:
            robots_url = urljoin(base_url, '/robots.txt')
            response = self.session.get(robots_url, timeout=5)
            if response.status_code == 200:
                # Simple check - in aggressive mode, we bypass this
                return self.aggressive
        except:
            pass
        
        return True
    
    def extract_aggressive_routes(self, base_url: str, html: str) -> Set[str]:
        """Aggressively extract potential routes and endpoints"""
        routes = set()
        
        try:
            # Common vulnerability testing paths
            vuln_paths = [
                '/admin', '/administrator', '/login', '/wp-admin', '/wp-login.php',
                '/dashboard', '/panel', '/control', '/manager', '/console',
                '/api', '/api/v1', '/api/v2', '/rest', '/graphql',
                '/test', '/testing', '/dev', '/development', '/debug',
                '/config', '/configuration', '/settings', '/setup',
                '/backup', '/backups', '/db', '/database', '/sql',
                '/upload', '/uploads', '/files', '/file', '/download',
                '/user', '/users', '/account', '/accounts', '/profile',
                '/search', '/help', '/support', '/contact', '/about'
            ]
            
            # Add vuln paths to base URL - respect SPA mode
            parsed_base = urlparse(base_url)
            base_domain = f"{parsed_base.scheme}://{parsed_base.netloc}"
            
            for path in vuln_paths:
                if self.is_spa_mode:
                    # Convert to hash-based URL for SPA
                    full_url = f"{base_domain}/#{path}"
                else:
                    # Regular URL
                    full_url = urljoin(base_domain, path)
                
                normalized = self.ensure_consistent_url_format(full_url)
                if self.is_valid_url(normalized):
                    routes.add(normalized)
            
            # Extract from JavaScript and HTML
            route_patterns = [
                r'["\'](?:https?://[^/]+)?(/[^"\'?\s]+)["\']',  # Any path
                r'href\s*=\s*["\']([^"\']+)["\']',  # Href attributes
                r'action\s*=\s*["\']([^"\']+)["\']',  # Form actions
                r'src\s*=\s*["\']([^"\']+)["\']',  # Source attributes
                r'url\s*:\s*["\']([^"\']+)["\']',  # URL in JS objects
                r'endpoint\s*:\s*["\']([^"\']+)["\']',  # API endpoints
            ]
            
            for pattern in route_patterns:
                matches = re.findall(pattern, html, re.IGNORECASE)
                for match in matches:
                    if match and len(match) > 1 and not match.startswith('data:'):
                        if match.startswith('/'):
                            if self.is_spa_mode and not match.startswith('/#'):
                                # Convert regular path to SPA hash-based URL
                                full_url = f"{base_domain}/#{match}"
                            else:
                                full_url = urljoin(base_domain, match)
                        elif match.startswith('http'):
                            full_url = match
                        else:
                            continue
                            
                        normalized = self.ensure_consistent_url_format(full_url)
                        if (self.is_valid_url(normalized) and 
                            self.is_internal_link(base_url, normalized)):
                            routes.add(normalized)
            
            # Extract from script tags more aggressively
            soup = BeautifulSoup(html, 'html.parser')
            for script in soup.find_all('script'):
                if script.string:
                    # Look for more patterns in scripts
                    script_patterns = [
                        r'["\']([^"\']*(?:login|admin|api|user|search|upload)[^"\']*)["\']',
                        r'route[s]?\s*:\s*["\']([^"\']+)["\']',
                        r'path[s]?\s*:\s*["\']([^"\']+)["\']',
                    ]
                    
                    for pattern in script_patterns:
                        matches = re.findall(pattern, script.string, re.IGNORECASE)
                        for match in matches:
                            if match and len(match) > 1:
                                if self.is_spa_mode and match.startswith('/') and not match.startswith('/#'):
                                    # Convert to SPA format
                                    full_url = f"{base_domain}/#{match}"
                                else:
                                    full_url = urljoin(base_domain, match)
                                
                                normalized = self.ensure_consistent_url_format(full_url)
                                if (self.is_valid_url(normalized) and 
                                    self.is_internal_link(base_url, normalized)):
                                    routes.add(normalized)
            
        except Exception:
            pass  # Silently continue on errors
        
        return routes
    
    def extract_links_selenium(self, url: str) -> Set[str]:
        """Extract links using Selenium"""
        try:
            self.driver.get(url)
            WebDriverWait(self.driver, 5).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            time.sleep(0.5)  # Further reduced wait time for speed
            
            html = self.driver.page_source
            links = self.extract_links(url, html)
            
            # Extract aggressive routes
            aggressive_routes = self.extract_aggressive_routes(url, html)
            links.update(aggressive_routes)
            
            # Find clickable elements
            try:
                elements = self.driver.find_elements(By.CSS_SELECTOR, 
                    "a, button, [ng-click], [onclick], [data-target], [data-href]")
                
                for element in elements:
                    try:
                        href = element.get_attribute('href') or element.get_attribute('data-href')
                        if href and self.is_internal_link(url, href):
                            normalized = self.ensure_consistent_url_format(href)
                            if self.is_valid_url(normalized):
                                links.add(normalized)
                    except:
                        continue
            except:
                pass
            
            return links
            
        except Exception:
            return set()
    
    def extract_links(self, base_url: str, html: str) -> Set[str]:
        """Extract all internal links from HTML"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            links = set()
            
            # Extract from multiple sources
            for tag in soup.find_all(['a', 'form', 'iframe', 'frame']):
                url_attrs = ['href', 'action', 'src']
                for attr in url_attrs:
                    href = tag.get(attr, '').strip()
                    if href and not href.startswith('javascript:') and not href.startswith('mailto:'):
                        full_url = urljoin(base_url, href)
                        normalized = self.ensure_consistent_url_format(full_url)
                        
                        if (self.is_valid_url(normalized) and 
                            self.is_internal_link(base_url, normalized)):
                            links.add(normalized)
            
            return links
            
        except Exception:
            return set()
    
    def extract_forms_selenium(self, url: str) -> List[Dict]:
        """Extract forms using Selenium with modern framework support"""
        try:
            # Store current URL path for form action detection
            self._current_url_path = urlparse(url).path
            
            html = self.driver.page_source
            forms = self.extract_forms(html)
            
            # Always try to find dynamic forms with Selenium
            try:
                # Look for any input fields with meaningful IDs or names
                input_selectors = [
                    "input[id]:not([id=''])",
                    "textarea[id]:not([id=''])", 
                    "input[name]:not([name=''])",
                    "textarea[name]:not([name=''])"
                ]
                
                all_inputs = []
                for selector in input_selectors:
                    elements = self.driver.find_elements(By.CSS_SELECTOR, selector)
                    all_inputs.extend(elements)
                
                # Add mat-select elements
                mat_selects = self.driver.find_elements(By.CSS_SELECTOR, "mat-select")
                all_inputs.extend(mat_selects)
                
                # Look for submit buttons
                submit_buttons = self.driver.find_elements(By.CSS_SELECTOR, 
                    "button[type='submit'], button[id*='login'], button[id*='register'], button[id*='submit'], button[id*='Button']")
                
                if all_inputs:
                    # Create a dynamic form entry
                    dynamic_inputs = []
                    seen_names = set()
                    
                    for inp in all_inputs:
                        try:
                            name = inp.get_attribute('name') or inp.get_attribute('id') or ''
                            input_type = inp.get_attribute('type') or inp.tag_name or 'text'
                            required = inp.get_attribute('required') is not None or inp.get_attribute('aria-required') == 'true'
                            
                            # Skip navigation and non-form inputs
                            if (name and name not in seen_names and 
                                not any(skip in name.lower() for skip in ['navbar', 'menu', 'language', 'slide-toggle'])):
                                
                                dynamic_inputs.append({
                                    'name': name,
                                    'type': input_type,
                                    'required': required
                                })
                                seen_names.add(name)
                        except:
                            continue
                    
                    # Find relevant submit buttons
                    dynamic_buttons = []
                    for btn in submit_buttons:
                        try:
                            btn_id = btn.get_attribute('id') or ''
                            btn_text = btn.text.strip()
                            
                            # Only include buttons that seem form-related
                            if (btn_id and any(keyword in btn_id.lower() for keyword in ['login', 'register', 'submit', 'button']) and
                                not any(skip in btn_id.lower() for skip in ['navbar', 'language', 'menu'])):
                                
                                dynamic_buttons.append({
                                    'id': btn_id,
                                    'text': btn_text,
                                    'type': 'submit'
                                })
                        except:
                            continue
                    
                    # Only create form if we have meaningful inputs
                    if dynamic_inputs and len(dynamic_inputs) >= 2:  # At least 2 inputs to be considered a form
                        form_action = self.detect_form_action_dynamic(url, dynamic_inputs)
                        
                        dynamic_form = {
                            'action': form_action,
                            'method': 'post',
                            'inputs': dynamic_inputs,
                            'input_names': [inp['name'] for inp in dynamic_inputs],
                            'buttons': dynamic_buttons,
                            'form_type': 'selenium_dynamic'
                        }
                        
                        # Check if this form is already in the list (avoid duplicates)
                        if not any(existing_form['input_names'] == dynamic_form['input_names'] for existing_form in forms):
                            forms.append(dynamic_form)
                        
            except Exception as e:
                if not self.aggressive:
                    print(f"[!] Error extracting dynamic forms: {e}")
            
            return forms
            
        except Exception:
            return self.extract_forms(self.driver.page_source if self.driver else "")
    
    def extract_forms(self, html: str) -> List[Dict]:
        """Extract all forms from HTML, including modern framework components"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            forms = []
            
            # Traditional HTML forms
            for form in soup.find_all('form'):
                action = form.get('action', '').strip() or ''
                method = form.get('method', 'get').lower()
                
                inputs = []
                for inp in form.find_all(['input', 'textarea', 'select']):
                    name = inp.get('name', '').strip()
                    input_type = inp.get('type', 'text').lower()
                    
                    if name:
                        inputs.append({
                            'name': name,
                            'type': input_type,
                            'required': inp.has_attr('required')
                        })
                
                if inputs:
                    forms.append({
                        'action': action,
                        'method': method,
                        'inputs': inputs,
                        'input_names': [inp['name'] for inp in inputs],
                        'form_type': 'traditional'
                    })
            
            # Modern framework forms (Angular Material, React, etc.)
            modern_form = self.extract_modern_form_components(soup)
            if modern_form:
                forms.append(modern_form)
            
            return forms
            
        except Exception:
            return []

    def extract_modern_form_components(self, soup) -> Dict:
        """Extract form components from modern frameworks like Angular Material"""
        inputs = []
        buttons = []
        
        # Angular Material input fields
        mat_inputs = soup.find_all(['input', 'textarea'], attrs={'matinput': True})
        for inp in mat_inputs:
            name = inp.get('name') or inp.get('id', '')
            input_type = inp.get('type', 'text').lower()
            required = inp.has_attr('required') or inp.has_attr('aria-required')
            
            if name:
                inputs.append({
                    'name': name,
                    'type': input_type,
                    'required': required
                })
        
        # Regular input fields with IDs (common in SPAs)
        regular_inputs = soup.find_all(['input', 'textarea'], id=True)
        for inp in regular_inputs:
            name = inp.get('name') or inp.get('id', '')
            input_type = inp.get('type', 'text').lower()
            required = inp.has_attr('required') or inp.has_attr('aria-required')
            
            # Skip if already found as mat-input
            if name and not any(existing['name'] == name for existing in inputs):
                inputs.append({
                    'name': name,
                    'type': input_type,
                    'required': required
                })
        
        # Angular Material selects
        mat_selects = soup.find_all('mat-select')
        for select in mat_selects:
            name = select.get('name') or select.get('id', '')
            if name:
                inputs.append({
                    'name': name,
                    'type': 'select',
                    'required': select.has_attr('required') or select.has_attr('aria-required')
                })
        
        # Submit buttons (various types)
        submit_selectors = [
            'button[type="submit"]',
            'button[id*="login"]',
            'button[id*="register"]', 
            'button[id*="submit"]',
            'button[aria-label*="Login"]',
            'button[aria-label*="Register"]',
            'input[type="submit"]'
        ]
        
        for selector in submit_selectors:
            elements = soup.select(selector)
            for btn in elements:
                btn_id = btn.get('id', '')
                btn_text = btn.get_text(strip=True)
                if btn_id or btn_text:
                    buttons.append({
                        'id': btn_id,
                        'text': btn_text,
                        'type': 'submit'
                    })
        
        # If we found inputs or buttons, consider this a form
        if inputs or buttons:
            form_action = self.detect_form_action(soup, inputs, buttons)
            
            return {
                'action': form_action,
                'method': 'post',  # Default for modern forms
                'inputs': inputs,
                'input_names': [inp['name'] for inp in inputs],
                'buttons': buttons,
                'form_type': 'modern_spa'
            }
        
        return None

    def detect_form_action(self, soup, inputs, buttons) -> str:
        """Try to detect the form action from context"""
        # Check for common patterns in the URL or page
        current_path = getattr(self, '_current_url_path', '')
        
        if 'login' in current_path.lower():
            return '/api/Sessions'  # Common login endpoint
        elif 'register' in current_path.lower():
            return '/api/Users'  # Common registration endpoint
        elif 'forgot' in current_path.lower():
            return '/api/forgot-password'
        
        # Look for API calls in script tags
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string:
                # Look for API endpoint patterns
                api_patterns = [
                    r'["\'](/api/[^"\']+)["\']',
                    r'["\']([^"\']*(?:login|register|auth)[^"\']*)["\']'
                ]
                for pattern in api_patterns:
                    matches = re.findall(pattern, script.string, re.IGNORECASE)
                    if matches:
                        return matches[0]
        
        return ''  # Default to current page

    def detect_form_action_dynamic(self, url: str, inputs: List[Dict]) -> str:
        """Detect form action for dynamically found forms"""
        parsed_url = urlparse(url)
        path = parsed_url.path.lower()
        
        # Determine likely API endpoint based on page and inputs
        input_names = [inp['name'].lower() for inp in inputs]
        
        has_email = any('email' in name for name in input_names)
        has_password = any('password' in name for name in input_names)
        has_repeat_password = any('repeat' in name or 'confirm' in name for name in input_names)
        
        if 'login' in path and has_email and has_password:
            return '/api/Sessions'
        elif 'register' in path and has_email and has_password:
            return '/api/Users'
        elif 'forgot' in path and has_email:
            return '/rest/user/reset-password'
        elif has_email and has_password and has_repeat_password:
            return '/api/Users'  # Likely registration
        elif has_email and has_password and not has_repeat_password:
            return '/api/Sessions'  # Likely login
        
        return '/api/form-submit'  # Generic fallback
    
    def safe_get(self, url: str, retries: int = 2) -> Optional[requests.Response]:
        """Safely fetch URL with minimal retries"""
        import random
        
        for attempt in range(retries):
            try:
                # Rotate user agent
                self.session.headers['User-Agent'] = random.choice(self.user_agents)
                
                response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                
                # Handle rate limiting
                if response.status_code == 429:
                    if attempt < retries - 1:
                        time.sleep(self.delay * 2)
                        continue
                
                # Accept more status codes in aggressive mode
                if self.aggressive:
                    if response.status_code < 500:
                        return response
                else:
                    response.raise_for_status()
                    return response
                
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
                if attempt < retries - 1:
                    time.sleep(self.delay)
            except requests.exceptions.HTTPError as e:
                if e.response.status_code in [403, 404] and not self.aggressive:
                    break
            except Exception:
                if attempt < retries - 1:
                    time.sleep(self.delay)
        
        return None
    
    def crawl(self, start_url: str) -> List[Dict]:
        """Two-phase security crawling: hard links first, then speculative probing"""
        if not self.aggressive:
            print(f"[*] Starting two-phase security crawl from: {start_url}")
            print(f"[*] Selenium: {self.use_selenium} | Robots: {'IGNORED' if self.ignore_robots else 'RESPECTED'}")
            if self.enable_dedup:
                print("[*] Content deduplication: ENABLED")
        
        start_url_normalized = self.normalize_url(start_url)
        
        # Detect SPA mode from the starting URL
        if self.detect_spa_mode(start_url_normalized):
            self.is_spa_mode = True
            self.spa_base_url = start_url_normalized
            if not self.aggressive:
                print(f"[*] SPA hash-based routing detected!")
                print(f"[*] All routes will use hash-based format")
        
        # PHASE 1: Hard Links Discovery
        if not self.aggressive:
            print(f"\n[PHASE 1] Discovering hard links and organic navigation...")
        
        self.to_visit.append(start_url_normalized)
        hard_links_discovered = self.crawl_hard_links()
        
        # PHASE 2: Speculative Path Probing
        if not self.aggressive:
            print(f"\n[PHASE 2] Speculative probing for hidden endpoints...")
        
        speculative_findings = self.probe_speculative_paths(start_url_normalized)
        
        # Combine results
        all_findings = hard_links_discovered + speculative_findings
        
        # Final report
        pages_with_forms = [p for p in all_findings if p['has_forms']]
        total_forms = sum(len(p['forms']) for p in pages_with_forms)
        
        if not self.aggressive:
            print(f"\n[+] Two-phase crawl completed!")
            print(f"[+] Phase 1 (Hard Links): {len(hard_links_discovered)} pages")
            print(f"[+] Phase 2 (Speculative): {len(speculative_findings)} pages")
            print(f"[+] Total unique pages: {len(all_findings)}")
            print(f"[+] Pages with forms: {len(pages_with_forms)}")
            print(f"[+] Total forms found: {total_forms}")
            
            if self.duplicate_urls:
                print(f"\n[!] Found {len(self.duplicate_urls)} duplicate URLs:")
                for dup in self.duplicate_urls[:5]:  # Show first 5
                    print(f"    {dup['url']} -> duplicate of {dup['original_url']}")
                if len(self.duplicate_urls) > 5:
                    print(f"    ... and {len(self.duplicate_urls) - 5} more")
        
        return all_findings

    def crawl_hard_links(self) -> List[Dict]:
        """Phase 1: Crawl only hard links found organically in the application"""
        hard_links_pages = []
        pbar = tqdm(total=min(self.max_pages // 2, 50), desc="Hard Links", unit="page", 
                   disable=self.aggressive)
        
        visited_in_phase = set()
        pages_crawled = 0
        max_phase_pages = min(self.max_pages // 2, 50)  # Reserve half for speculative
        
        try:
            while self.to_visit and pages_crawled < max_phase_pages:
                current_url = self.to_visit.popleft()
                
                if current_url in visited_in_phase or current_url in self.visited:
                    continue
                
                if not self.aggressive:
                    print(f"[HARD] {current_url}")
                
                try:
                    visited_in_phase.add(current_url)
                    self.visited.add(current_url)
                    
                    # Fetch page content
                    if self.use_selenium and self.driver:
                        forms = self.extract_forms_selenium(current_url)
                        new_links = self.extract_links_selenium(current_url)
                        final_url = self.driver.current_url
                        status_code = 200
                        content_type = "text/html"
                        html = self.driver.page_source
                    else:
                        response = self.safe_get(current_url)
                        if not response:
                            continue
                        
                        html = response.text
                        forms = self.extract_forms(html)
                        new_links = self.extract_links(current_url, html)
                        
                        final_url = response.url
                        status_code = response.status_code
                        content_type = response.headers.get('content-type', '')
                    
                    # Check for content duplication
                    is_duplicate, content_hash = self.is_content_duplicate(current_url, html)
                    
                    if is_duplicate:
                        if not self.aggressive:
                            print(f"[!] Duplicate content detected")
                        continue
                    
                    page_data = {
                        'url': current_url,
                        'final_url': final_url,
                        'forms': forms,
                        'status_code': status_code,
                        'content_type': content_type,
                        'content_hash': content_hash,
                        'has_forms': len(forms) > 0,
                        'discovery_method': 'hard_link',
                        'phase': 1
                    }
                    
                    hard_links_pages.append(page_data)
                    pages_crawled += 1
                    
                    if forms and not self.aggressive:
                        print(f"[+] Found {len(forms)} forms")
                    
                    # Queue ONLY hard links (no speculative paths in this phase)
                    hard_links_only = self.filter_hard_links_only(new_links)
                    new_count = 0
                    for link in hard_links_only:
                        if link not in visited_in_phase and link not in self.visited and link not in self.to_visit:
                            self.to_visit.append(link)
                            new_count += 1
                    
                    if new_count > 0 and not self.aggressive:
                        print(f"[+] Found {new_count} new hard links")
                    
                    pbar.update(1)
                    pbar.set_postfix({
                        'crawled': pages_crawled,
                        'queued': len(self.to_visit),
                        'forms': sum(1 for p in hard_links_pages if p['has_forms'])
                    })
                    
                    if self.delay > 0:
                        time.sleep(self.delay)
                        
                except Exception as e:
                    if not self.aggressive:
                        print(f"[!] Error crawling {current_url}: {e}")
                    continue
                    
        except KeyboardInterrupt:
            if not self.aggressive:
                print(f"\n[!] Phase 1 interrupted by user")
        
        finally:
            pbar.close()
        
        if not self.aggressive:
            print(f"[+] Phase 1 complete: {len(hard_links_pages)} unique pages discovered")
        
        return hard_links_pages

    def filter_hard_links_only(self, links: Set[str]) -> Set[str]:
        """Filter to include only genuine hard links, not speculative paths"""
        hard_links = set()
        
        # Common speculative/vulnerability paths to exclude from hard link phase
        speculative_indicators = [
            '/admin', '/administrator', '/wp-admin', '/wp-login.php',
            '/dashboard', '/panel', '/control', '/manager', '/console',
            '/api', '/api/v1', '/api/v2', '/rest', '/graphql',
            '/test', '/testing', '/dev', '/development', '/debug',
            '/config', '/configuration', '/settings', '/setup',
            '/backup', '/backups', '/db', '/database', '/sql',
            '/upload', '/uploads', '/files', '/file', '/download',
            '/user', '/users', '/account', '/accounts', '/profile'
        ]
        
        for link in links:
            parsed = urlparse(link)
            path = parsed.path.lower()
            
            # For SPA mode, check the hash fragment
            if self.is_spa_mode and parsed.fragment:
                path = parsed.fragment.lower()
            
            # Skip if it looks like a speculative vulnerability path
            is_speculative = any(spec_path in path for spec_path in speculative_indicators)
            
            # Skip external resources
            if any(ext in path for ext in ['.css', '.js', '.ico', '.svg', '.woff', '.ttf']):
                continue
                
            if not is_speculative:
                hard_links.add(link)
        
        return hard_links

    def probe_speculative_paths(self, base_url: str) -> List[Dict]:
        """Phase 2: Probe for hidden/undocumented endpoints using informed guessing"""
        speculative_pages = []
        
        # Generate speculative paths based on discovered context + common vulnerability paths
        speculative_urls = self.generate_speculative_paths(base_url)
        
        pbar = tqdm(total=min(len(speculative_urls), self.max_pages // 2), 
                   desc="Speculative", unit="probe", disable=self.aggressive)
        
        probed_count = 0
        max_speculative = self.max_pages // 2  # Use remaining budget
        
        try:
            for url in speculative_urls:
                if probed_count >= max_speculative:
                    break
                    
                if url in self.visited:  # Skip if already discovered in Phase 1
                    continue
                
                if not self.aggressive:
                    print(f"[PROBE] {url}")
                
                try:
                    # Quick HEAD/GET check first
                    if self.use_selenium and self.driver:
                        try:
                            self.driver.get(url)
                            status_code = 200  # Selenium doesn't give us direct status
                            final_url = self.driver.current_url
                            html = self.driver.page_source
                            content_type = "text/html"
                        except Exception:
                            continue
                    else:
                        response = self.safe_get(url)
                        if not response:
                            continue
                        
                        status_code = response.status_code
                        final_url = response.url
                        html = response.text
                        content_type = response.headers.get('content-type', '')
                    
                    # Skip obvious 404s or redirect loops
                    if status_code in [404, 410] or self.is_404_content(html):
                        continue
                    
                    # Check for content duplication against Phase 1 findings
                    is_duplicate, content_hash = self.is_content_duplicate(url, html)
                    
                    if is_duplicate:
                        if not self.aggressive:
                            print(f"[!] Duplicate of existing content")
                        continue
                    
                    # This is a valid, unique speculative finding!
                    self.visited.add(url)
                    
                    forms = self.extract_forms(html) if not self.use_selenium else self.extract_forms_selenium(url)
                    
                    page_data = {
                        'url': url,
                        'final_url': final_url,
                        'forms': forms,
                        'status_code': status_code,
                        'content_type': content_type,
                        'content_hash': content_hash,
                        'has_forms': len(forms) > 0,
                        'discovery_method': 'speculative_probe',
                        'phase': 2
                    }
                    
                    speculative_pages.append(page_data)
                    probed_count += 1
                    
                    if not self.aggressive:
                        if forms:
                            print(f"[+] SPECULATIVE HIT! Found {len(forms)} forms at {url}")
                        else:
                            print(f"[+] Speculative hit: {url}")
                    
                    # If we found something interesting, do a quick follow-up crawl
                    if forms or any(keyword in html.lower() for keyword in ['login', 'admin', 'password', 'dashboard']):
                        self.quick_follow_up_crawl(url, html)
                    
                    pbar.update(1)
                    pbar.set_postfix({
                        'probed': probed_count,
                        'hits': len(speculative_pages),
                        'forms': sum(1 for p in speculative_pages if p['has_forms'])
                    })
                    
                    if self.delay > 0:
                        time.sleep(self.delay)
                        
                except Exception as e:
                    if not self.aggressive:
                        print(f"[!] Error probing {url}: {e}")
                    continue
                    
        except KeyboardInterrupt:
            if not self.aggressive:
                print(f"\n[!] Phase 2 interrupted by user")
        
        finally:
            pbar.close()
            if self.driver:
                self.driver.quit()
        
        if not self.aggressive:
            print(f"[+] Phase 2 complete: {len(speculative_pages)} hidden endpoints discovered")
        
        return speculative_pages

    def generate_speculative_paths(self, base_url: str) -> List[str]:
        """Generate educated guesses for hidden endpoints"""
        parsed_base = urlparse(base_url)
        base_domain = f"{parsed_base.scheme}://{parsed_base.netloc}"
        
        # Core vulnerability assessment paths
        vuln_paths = [
            # Authentication & Admin
            '/login', '/signin', '/sign-in', '/auth', '/authenticate',
            '/register', '/signup', '/sign-up', '/create-account',
            '/admin', '/administrator', '/admin/login', '/admin/dashboard',
            '/dashboard', '/panel', '/control', '/manager', '/console',
            
            # APIs & Services
            '/api', '/api/v1', '/api/v2', '/api/v3', '/rest', '/graphql',
            '/api/users', '/api/admin', '/api/auth', '/api/login',
            '/api/config', '/api/debug', '/api/status', '/api/health',
            
            # Development & Debug
            '/debug', '/test', '/testing', '/dev', '/development',
            '/staging', '/beta', '/alpha', '/demo',
            '/health', '/status', '/info', '/version',
            '/phpinfo', '/info.php', '/phpinfo.php',
            
            # Configuration & Setup
            '/config', '/configuration', '/settings', '/setup', '/install',
            '/wp-config.php', '/web.config', '/.env', '/env',
            
            # Backup & Files
            '/backup', '/backups', '/backup.zip', '/backup.sql',
            '/uploads', '/upload', '/files', '/file', '/documents',
            '/downloads', '/download', '/assets',
            
            # Database & Storage
            '/db', '/database', '/sql', '/mysql', '/postgres',
            '/phpmyadmin', '/pma', '/db_admin',
            
            # CMS Specific
            '/wp-admin', '/wp-login.php', '/wp-content',
            '/drupal', '/joomla', '/magento',
            
            # Security Testing
            '/robots.txt', '/sitemap.xml', '/.git/', '/.svn/',
            '/crossdomain.xml', '/clientaccesspolicy.xml'
        ]
        
        # Generate URLs
        speculative_urls = []
        
        for path in vuln_paths:
            if self.is_spa_mode:
                # Convert to hash-based URL for SPA
                if path.startswith('/'):
                    full_url = f"{base_domain}/#{path}"
                else:
                    full_url = f"{base_domain}/#{path}"
            else:
                # Regular URL
                full_url = urljoin(base_domain, path)
            
            normalized = self.ensure_consistent_url_format(full_url)
            if self.is_valid_url(normalized):
                speculative_urls.append(normalized)
        
        # Add contextual paths based on what we found in Phase 1
        contextual_paths = self.generate_contextual_paths(base_domain)
        speculative_urls.extend(contextual_paths)
        
        # Remove duplicates and already visited
        unique_urls = []
        for url in speculative_urls:
            if url not in self.visited and url not in unique_urls:
                unique_urls.append(url)
        
        return unique_urls

    def generate_contextual_paths(self, base_domain: str) -> List[str]:
        """Generate contextual paths based on discovered content"""
        contextual = []
        
        # Use the discovered_pages from current crawl session
        pages_to_analyze = getattr(self, 'discovered_pages', [])
        
        # If we found /products, try /products/admin, etc.
        for page in pages_to_analyze:
            parsed = urlparse(page['url'])
            path = parsed.path
            
            if self.is_spa_mode and parsed.fragment:
                path = parsed.fragment
            
            if path and path != '/':
                # Add admin variants
                admin_variants = [f"{path}/admin", f"{path}/manage", f"{path}/edit"]
                for variant in admin_variants:
                    if self.is_spa_mode:
                        full_url = f"{base_domain}/#{variant}"
                    else:
                        full_url = urljoin(base_domain, variant)
                    
                    normalized = self.ensure_consistent_url_format(full_url)
                    if self.is_valid_url(normalized):
                        contextual.append(normalized)
        
        return contextual

    def is_404_content(self, html: str) -> bool:
        """Detect if content is actually a 404 page despite 200 status"""
        html_lower = html.lower()
        not_found_indicators = [
            'not found', '404', 'page not found', 'file not found',
            'does not exist', 'cannot be found', 'page cannot be displayed',
            'requested url was not found', 'the page you are looking for'
        ]
        
        return any(indicator in html_lower for indicator in not_found_indicators)

    def quick_follow_up_crawl(self, url: str, html: str):
        """Quick follow-up crawl for interesting speculative findings"""
        try:
            # Extract any immediate links from this interesting page
            soup = BeautifulSoup(html, 'html.parser')
            immediate_links = set()
            
            for tag in soup.find_all(['a'], href=True):
                href = tag.get('href', '').strip()
                if href and not href.startswith('javascript:') and not href.startswith('mailto:'):
                    full_url = urljoin(url, href)
                    normalized = self.ensure_consistent_url_format(full_url)
                    
                    if (self.is_valid_url(normalized) and 
                        self.is_internal_link(url, normalized) and
                        normalized not in self.visited):
                        immediate_links.add(normalized)
            
            # Limit follow-up to 3 immediate links to avoid scope creep
            for link in list(immediate_links)[:3]:
                if not self.aggressive:
                    print(f"[FOLLOW-UP] {link}")
                
                try:
                    response = self.safe_get(link)
                    if response and response.status_code == 200:
                        self.visited.add(link)
                        
                except Exception:
                    continue
                    
        except Exception:
            pass  # Silently continue on errors

    def get_url_pattern(self, url: str) -> str:
        """Extract URL pattern for duplicate detection"""
        parsed = urlparse(url)
        path = parsed.path.rstrip('/')
        
        # For SPA mode, include the hash fragment in the pattern
        if self.is_spa_mode and parsed.fragment and parsed.fragment.startswith('/'):
            # Use the hash fragment as the main path for pattern detection
            hash_path = parsed.fragment.rstrip('/')
            
            # Replace numeric IDs with placeholder in hash path
            hash_path = re.sub(r'/\d+(?=/|$)', '/[ID]', hash_path)
            
            # Replace UUIDs with placeholder in hash path
            hash_path = re.sub(r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=/|$)', '/[UUID]', hash_path, flags=re.IGNORECASE)
            
            # Create pattern using hash path (this makes each SPA route unique)
            pattern = f"{parsed.netloc}#{hash_path}"
        else:
            # Regular URL pattern detection
            # Replace numeric IDs with placeholder
            path = re.sub(r'/\d+(?=/|$)', '/[ID]', path)
            
            # Replace UUIDs with placeholder
            path = re.sub(r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=/|$)', '/[UUID]', path, flags=re.IGNORECASE)
            
            # Create pattern
            pattern = f"{parsed.netloc}{path}"
        
        # Handle query parameters - keep structure but generalize values
        if parsed.query:
            query_dict = parse_qs(parsed.query)
            # Sort keys for consistent pattern
            sorted_params = sorted(query_dict.keys())
            pattern += f"?{','.join(sorted_params)}"
        
        return pattern
    
    def get_content_hash(self, html: str) -> str:
        """Generate content hash for deduplication"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Remove dynamic content that changes between requests
            for element in soup.find_all(['script', 'noscript', 'style']):
                element.decompose()
            
            # Remove elements that commonly have timestamps or session data
            for element in soup.find_all(attrs={'class': re.compile(r'timestamp|session|time|date', re.I)}):
                element.decompose()
            
            for element in soup.find_all(attrs={'id': re.compile(r'timestamp|session|time|date', re.I)}):
                element.decompose()
            
            # Get main content
            main_content = soup.get_text(strip=True)
            
            # Remove extra whitespace
            main_content = re.sub(r'\s+', ' ', main_content)
            
            # Generate hash
            return hashlib.md5(main_content.encode('utf-8')).hexdigest()
            
        except Exception:
            # Fallback to simple text hash
            text = re.sub(r'\s+', ' ', html)
            return hashlib.md5(text.encode('utf-8')).hexdigest()
    
    def is_content_duplicate(self, url: str, html: str) -> Tuple[bool, str]:
        """Check if content is duplicate and return (is_duplicate, content_hash)"""
        if not self.enable_dedup:
            return False, ""
        
        content_hash = self.get_content_hash(html)
        
        if content_hash in self.content_hashes:
            # Find the original URL with this content
            original_url = None
            for orig_url, orig_hash in self.url_content_map.items():
                if orig_hash == content_hash:
                    original_url = orig_url
                    break
            
            self.duplicate_urls.append({
                'url': url,
                'original_url': original_url,
                'content_hash': content_hash
            })
            return True, content_hash
        
        self.content_hashes.add(content_hash)
        self.url_content_map[url] = content_hash
        return False, content_hash
    
    def should_skip_url_pattern(self, url: str) -> bool:
        """Check if URL pattern suggests it might be a duplicate"""
        pattern = self.get_url_pattern(url)
        
        if pattern in self.url_patterns:
            # We've seen this pattern before, might be duplicate
            return True
        
        self.url_patterns.add(pattern)
        return False
    
# Backward compatibility functions
def crawl(start_url: str, max_pages: int = 50) -> List[Dict]:
    """Enhanced crawl function with aggressive capabilities"""
    crawler = AggressiveVulnCrawler(max_pages=max_pages, delay=0.3, use_selenium=True, aggressive=True)
    all_pages = crawler.crawl(start_url)
    
    # Return only pages with forms for backward compatibility
    pages_with_forms = [page for page in all_pages if page['has_forms']]
    
    # Convert to old format for compatibility
    compatible_format = []
    for page in pages_with_forms:
        old_forms = []
        for form in page['forms']:
            old_forms.append({
                'action': form['action'],
                'method': form['method'],
                'inputs': form['input_names']
            })
        
        compatible_format.append({
            'url': page['url'],
            'forms': old_forms
        })
    
    return compatible_format

@app.command()
def run(
    url: str = typer.Argument(..., help="Starting URL"),
    max_pages: int = typer.Option(100, help="Max number of pages to crawl"),
    delay: float = typer.Option(0.3, help="Delay between requests (seconds)"),
    save: str = typer.Option(None, help="Path to save results as JSON"),
    include_all: bool = typer.Option(False, help="Include pages without forms in results"),
    no_selenium: bool = typer.Option(False, help="Disable Selenium (requests only)"),
    aggressive: bool = typer.Option(False, help="Enable aggressive mode (bypass some protections)"),
    ignore_robots: bool = typer.Option(False, help="Ignore robots.txt (for security testing)"),
    no_dedup: bool = typer.Option(False, help="Disable content deduplication")
):
    """
    Aggressive vulnerability-focused web crawler for security testing.
    
    Features:
    - SPA support with Selenium
    - Aggressive link discovery  
    - robots.txt bypassing capabilities
    - Content deduplication to avoid duplicate pages
    - URL pattern detection to skip similar pages
    - Stealth user-agent rotation
    - Enhanced form detection
    """
    if ignore_robots or aggressive:
        print("[!] Running in security testing mode")
        print("[!] Ensure you have permission to test this target")
    
    crawler = AggressiveVulnCrawler(
        max_pages=max_pages, 
        delay=delay, 
        use_selenium=not no_selenium,
        aggressive=aggressive,
        ignore_robots=ignore_robots,
        enable_dedup=not no_dedup
    )
    results = crawler.crawl(url)
    
    # Filter results
    if not include_all:
        results = [page for page in results if page['has_forms']]
    
    # Display results
    print(f"\n{'='*60}")
    print("SECURITY CRAWL RESULTS")
    print(f"{'='*60}")
    
    for i, page in enumerate(results, 1):
        print(f"\n{i}. URL: {page['url']}")
        if page.get('final_url') != page['url']:
            print(f"   Final URL: {page['final_url']}")
        print(f"   Status: {page['status_code']}")
        
        if page['forms']:
            print(f"   Forms found: {len(page['forms'])}")
            for j, form in enumerate(page['forms'], 1):
                print(f"     Form {j}: {form['method'].upper()} -> {form['action'] or 'same page'}")
                print(f"              Inputs: {[inp['name'] for inp in form['inputs']]}")
    
    # Show deduplication statistics
    if crawler.duplicate_urls:
        print(f"\n{'='*60}")
        print("DEDUPLICATION REPORT")
        print(f"{'='*60}")
        print(f"Duplicate URLs found: {len(crawler.duplicate_urls)}")
        
        # Group by original URL
        duplicates_by_original = {}
        for dup in crawler.duplicate_urls:
            original = dup['original_url']
            if original not in duplicates_by_original:
                duplicates_by_original[original] = []
            duplicates_by_original[original].append(dup['url'])
        
        for original, duplicates in duplicates_by_original.items():
            print(f"\nOriginal: {original}")
            for dup_url in duplicates:
                print(f"  -> {dup_url}")
    
    if save:
        # Include deduplication data in saved results
        save_data = {
            'unique_pages': results,
            'duplicate_urls': crawler.duplicate_urls,
            'crawl_stats': {
                'total_visited': len(crawler.visited),
                'unique_pages': len(results),
                'duplicate_count': len(crawler.duplicate_urls),
                'pages_with_forms': len([p for p in results if p['has_forms']]),
                'total_forms': sum(len(p['forms']) for p in results if p['has_forms'])
            }
        }
        
        with open(save, 'w') as f:
            json.dump(save_data, f, indent=2)
        print(f"\n[+] Results saved to {save}")

if __name__ == "__main__":
    app()