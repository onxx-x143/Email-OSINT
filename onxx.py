#!/usr/bin/env python3
"""
EmailCrawl - Professional Email Extraction Crawler (Enterprise Edition)
Advanced OSINT tool with bulletproof error handling and tabular output
Author: Security Research
Project: Email Intelligence Gathering
Version: 3.0 - Enterprise Stable
"""

import os
import re
import argparse
import requests
import time
import urllib.parse
import tldextract
from datetime import datetime
from bs4 import BeautifulSoup
import json
from tabulate import tabulate
from collections import deque
import sys
import textwrap
from urllib3.exceptions import InsecureRequestWarning
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Suppress ALL warnings
import warnings
warnings.filterwarnings("ignore")
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# Suppress Qt debug output before importing colorama
os.environ['QT_LOGGING_RULES'] = '*.debug=false;qt.*.debug=false'
os.environ['QT_MESSAGE_PATTERN'] = ''
os.environ['COLORAMA_SHELL'] = 'false'

# Now import colorama
from colorama import Fore, Style, init, just_fix_windows_console

# Initialize colorama with minimal configuration
just_fix_windows_console()  # Only on Windows
init(autoreset=True, strip=False, convert=False)

class ColorOutput:
    @staticmethod
    def info(msg):
        print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def success(msg):
        print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def warning(msg):
        print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def error(msg):
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def email(msg):
        print(f"{Fore.GREEN}[EMAIL]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def crawling(msg):
        print(f"{Fore.BLUE}[CRAWLING]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def stats(msg):
        print(f"{Fore.MAGENTA}[STATS]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def table(msg):
        print(f"{Fore.BLUE}[TABLE]{Style.RESET_ALL} {msg}")

class Config:
    def __init__(self, verify_ssl=True):
        # Request Configuration
        self.USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        self.TIMEOUT = 15
        self.MAX_RETRIES = 2
        self.VERIFY_SSL = verify_ssl
        self.ALLOW_REDIRECTS = True
        self.MAX_REDIRECTS = 5
        
        # Crawler Configuration
        self.MAX_PAGES = 200
        self.MAX_DEPTH = 3
        self.CRAWL_DELAY = 0.5
        
        # Error Handling Configuration
        self.IGNORE_HTTP_ERRORS = [400, 401, 403, 404, 405, 408, 429, 500, 502, 503, 504]
        self.VALID_CONTENT_TYPES = ['text/html', 'application/xhtml+xml', 'text/plain']
        
        # Output Configuration
        self.OUTPUT_DIR = "emailcrawl_output"
        
        # Proxy Configuration
        self.HTTP_PROXY = os.getenv('HTTP_PROXY')
        self.SOCKS_PROXY = os.getenv('SOCKS_PROXY')
        
        # Table Configuration
        self.TABLE_FORMAT = "grid"
        self.URL_COLUMN_WIDTH = 60

class URLUtils:
    @staticmethod
    def is_valid_url(url):
        """Validate URL format"""
        if not url or not isinstance(url, str):
            return False
            
        try:
            result = urllib.parse.urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    @staticmethod
    def get_domain(url):
        """Extract domain from URL"""
        try:
            extracted = tldextract.extract(url)
            return f"{extracted.domain}.{extracted.suffix}"
        except:
            return "unknown"
    
    @staticmethod
    def normalize_url(url):
        """Normalize URL for consistent comparison"""
        if not url:
            return ""
            
        try:
            parsed = urllib.parse.urlparse(url)
            path = parsed.path if parsed.path else ''
            normalized = urllib.parse.urlunparse((
                parsed.scheme,
                parsed.netloc.lower(),
                path.rstrip('/'),
                '',  # params
                '',  # query
                ''   # fragment
            ))
            return normalized
        except:
            return url
    
    @staticmethod
    def should_skip_url(url):
        """Check if URL should be skipped"""
        if not url:
            return True
            
        skip_patterns = [
            r'cdn-cgi/l/email-protection',
            r'mailto:', r'tel:', r'javascript:', r'data:',
            r'^#', r'^javascript:', r'^mailto:', r'^tel:',
            r'\.pdf$', r'\.jpg$|\.jpeg$|\.png$|\.gif$|\.svg$|\.ico$|\.bmp$|\.webp$',
            r'\.css$', r'\.js$', r'\.woff$|\.woff2$|\.ttf$|\.eot$',
            r'\.zip$|\.tar$|\.gz$|\.rar$|\.7z$',
            r'\.mp4$|\.mp3$|\.avi$|\.mov$|\.wmv$|\.flv$',
            r'\.doc$|\.docx$|\.xls$|\.xlsx$|\.ppt$|\.pptx$',
            r'\.xml$|\.json$|\.txt$|\.csv$',
            r'wp-json', r'xmlrpc.php', r'wp-admin', r'wp-includes',
            r'feed', r'rss', r'atom',
        ]
        
        url_lower = url.lower()
        return any(re.search(pattern, url_lower) for pattern in skip_patterns)
    
    @staticmethod
    def is_wp_endpoint(url):
        """Check if URL is a WordPress endpoint"""
        wp_patterns = [
            'wp-json', 'xmlrpc.php', 'wp-admin', 'wp-includes',
            'wp-content', 'wp-login.php',
        ]
        url_lower = url.lower()
        return any(pattern in url_lower for pattern in wp_patterns)

class AdvancedEmailValidator:
    def __init__(self, target_domain=None):
        self.target_domain = target_domain
        self.false_positive_domains = [
            'example.com', 'domain.com', 'email.com', 'test.com',
            'yourdomain.com', 'sentry.io', 'wixpress.com', 
            'localhost', '127.0.0.1', 'your-email.com', 'company.com',
            'placeholder.com', 'fake.com', 'test.org', 'example.org',
            'email.fake', 'test.email', 'example.email', 'domain.test',
        ]
        
        self.system_patterns = [
            r'noreply@', r'no-reply@', r'support@.*\.test', 
            r'info@.*\.local', r'admin@.*\.local', r'root@', 
            r'postmaster@', r'webmaster@', r'mailer@',
            r'^[a-f0-9]{32}@',
            r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}@',
            r'^[0-9]+@',
            r'@sentry\.',
            r'@.*\.local$',
            r'@.*\.test$',
            r'@.*\.example$',
        ]

    def is_valid_email(self, email):
        """Comprehensive email validation"""
        if not email or not isinstance(email, str):
            return False
            
        email_lower = email.lower().strip()
        
        # Basic structural validation
        if (len(email_lower) < 6 or 
            '..' in email_lower or 
            email_lower.count('@') != 1 or
            email_lower.startswith('.') or 
            email_lower.endswith('.') or
            email_lower.count('.') < 1):
            return False
        
        # Check for false positive domains
        if any(domain in email_lower for domain in self.false_positive_domains):
            return False
        
        # Check for system/automated email patterns
        if any(re.search(pattern, email_lower) for pattern in self.system_patterns):
            return False
        
        # Enhanced regex pattern for email validation
        email_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9._%+-]{0,64}@[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email_lower):
            return False
        
        # Check if email looks like it belongs to a real person/organization
        return self._is_likely_real_email(email_lower)
    
    def _is_likely_real_email(self, email):
        """Determine if email appears to be from a real person/organization"""
        username = email.split('@')[0].lower()
        
        # Common real email patterns
        real_patterns = [
            r'^[a-z]+\.[a-z]+$',
            r'^[a-z]+$',
            r'^[a-z]+[0-9]*$',
            r'^[a-z][a-z0-9._-]{2,}$',
        ]
        
        # Common fake/automated patterns
        fake_patterns = [
            r'^[a-f0-9]+$',
            r'^[0-9]+$',
            r'^[a-z0-9]{32}$',
            r'^admin$', r'^root$', r'^test$', r'^demo$', r'^user$',
        ]
        
        # Must match at least one real pattern
        if not any(re.search(pattern, username) for pattern in real_patterns):
            return False
        
        # Must NOT match any fake patterns
        if any(re.search(pattern, username) for pattern in fake_patterns):
            return False
        
        return True

class SmartTextWrapper:
    """Intelligent text wrapping for URLs and long text in tables"""
    
    @staticmethod
    def wrap_url(url, width=60):
        """Wrap long URLs intelligently"""
        if not url:
            return ""
            
        if len(url) <= width:
            return url
        
        # Try to wrap at natural breakpoints
        parts = []
        current = url
        
        while len(current) > width:
            # Find the last separator before width limit
            break_point = width
            
            # Look for natural breakpoints
            for separator in ['/', '?', '&', '=', '-', '_', '.']:
                pos = current[:width].rfind(separator)
                if pos > width * 0.7:  # Only break if we find a good spot
                    break_point = pos + 1
                    break
            
            parts.append(current[:break_point])
            current = current[break_point:]
        
        if current:
            parts.append(current)
        
        return "\n".join(parts)
    
    @staticmethod
    def wrap_text(text, width=40):
        """Wrap regular text"""
        if not text:
            return ""
            
        if len(text) <= width:
            return text
        
        # Use textwrap for regular text
        return "\n".join(textwrap.wrap(text, width=width))

class EnhancedTableFormatter:
    """Enhanced table formatter with smart text wrapping"""
    
    def __init__(self, config):
        self.config = config
        self.wrapper = SmartTextWrapper()
    
    def create_email_table(self, emails_data):
        """Create enhanced email table with wrapped URLs"""
        table_data = []
        
        for idx, email_info in enumerate(emails_data, 1):
            email = email_info.get('email', 'N/A')
            source = email_info.get('source', 'Unknown')
            username = email_info.get('username', 'N/A')
            domain = email_info.get('domain', 'N/A')
            pattern_type = email_info.get('pattern_type', 'Unknown')
            
            # Wrap long URLs and text
            wrapped_source = self.wrapper.wrap_url(source, self.config.URL_COLUMN_WIDTH)
            wrapped_email = self.wrapper.wrap_text(email, 30)
            wrapped_username = self.wrapper.wrap_text(username, 20)
            wrapped_domain = self.wrapper.wrap_text(domain, 25)
            wrapped_pattern = self.wrapper.wrap_text(pattern_type, 20)
            
            table_data.append([
                idx,
                wrapped_email,
                wrapped_username,
                wrapped_domain,
                wrapped_pattern,
                wrapped_source
            ])
        
        headers = ["#", "Email Address", "Username", "Domain", "Pattern Type", "Source URL"]
        
        # Create table with adjusted column widths
        table = tabulate(
            table_data, 
            headers=headers, 
            tablefmt=self.config.TABLE_FORMAT,
            stralign="left",
            numalign="left"
        )
        
        return table
    
    def create_compact_email_table(self, emails_data, max_emails=20):
        """Create a compact table for quick viewing"""
        table_data = []
        
        for idx, email_info in enumerate(emails_data[:max_emails], 1):
            email = email_info.get('email', 'N/A')
            source = email_info.get('source', 'Unknown')
            
            # Truncate source for compact view
            if len(source) > 40:
                source_display = source[:20] + "..." + source[-15:]
            else:
                source_display = source
            
            table_data.append([
                idx,
                email,
                source_display
            ])
        
        headers = ["#", "Email", "Source"]
        
        table = tabulate(
            table_data,
            headers=headers,
            tablefmt="simple",
            stralign="left",
            numalign="left"
        )
        
        return table
    
    def create_domain_table(self, domain_stats):
        """Create domain statistics table"""
        table_data = []
        total_emails = sum(domain_stats.values())
        
        for idx, (domain, count) in enumerate(domain_stats.items(), 1):
            percentage = (count / total_emails) * 100 if total_emails > 0 else 0
            
            # Wrap long domain names
            wrapped_domain = self.wrapper.wrap_text(domain, 40)
            
            table_data.append([
                idx,
                wrapped_domain,
                count,
                f"{percentage:.1f}%"
            ])
        
        headers = ["#", "Domain", "Count", "Percentage"]
        
        table = tabulate(
            table_data,
            headers=headers,
            tablefmt=self.config.TABLE_FORMAT,
            stralign="left",
            numalign="left"
        )
        
        return table
    
    def create_pattern_table(self, pattern_stats):
        """Create pattern statistics table"""
        table_data = []
        
        for idx, (pattern, count) in enumerate(pattern_stats.items(), 1):
            # Wrap long pattern names
            wrapped_pattern = self.wrapper.wrap_text(pattern, 30)
            
            table_data.append([
                idx,
                wrapped_pattern,
                count
            ])
        
        headers = ["#", "Pattern Type", "Count"]
        
        table = tabulate(
            table_data,
            headers=headers,
            tablefmt=self.config.TABLE_FORMAT,
            stralign="left",
            numalign="left"
        )
        
        return table
    
    def create_source_url_table(self, emails_data):
        """Create table showing emails grouped by source URL"""
        # Group emails by source URL
        source_map = {}
        for email_info in emails_data:
            source = email_info.get('source', 'Unknown')
            email = email_info.get('email', 'N/A')
            
            if source not in source_map:
                source_map[source] = []
            source_map[source].append(email)
        
        # Create table data
        table_data = []
        for idx, (source, emails) in enumerate(source_map.items(), 1):
            # Wrap source URL
            wrapped_source = self.wrapper.wrap_url(source, 50)
            
            # Combine emails
            email_list = ", ".join(emails[:3])  # Show first 3 emails
            if len(emails) > 3:
                email_list += f" (+{len(emails) - 3} more)"
            
            table_data.append([
                idx,
                wrapped_source,
                len(emails),
                email_list
            ])
        
        headers = ["#", "Source URL", "Email Count", "Emails Found"]
        
        table = tabulate(
            table_data,
            headers=headers,
            tablefmt=self.config.TABLE_FORMAT,
            stralign="left",
            numalign="left"
        )
        
        return table

class EmailExtractor:
    def __init__(self, base_url):
        self.base_url = base_url
        self.base_domain = URLUtils.get_domain(base_url) if base_url else None
        self.validator = AdvancedEmailValidator(self.base_domain)
        self.email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        self.username_patterns = [
            (r'^([a-z]+)\.([a-z]+)$', 'first.last'),
            (r'^([a-z]+)$', 'firstname'),
            (r'^([a-z]+)(\d+)$', 'firstname_digits'),
            (r'^([a-z]+)\.(\d+)$', 'first.digits'),
            (r'^([a-z]+)([a-z]+)$', 'first_last'),
            (r'^([a-z])([a-z]+)$', 'initial_last'),
            (r'^([a-z]+)_([a-z]+)$', 'first_last_underscore'),
            (r'^([a-z]+)-([a-z]+)$', 'first_last_hyphen'),
        ]
    
    def extract_emails_with_metadata(self, text, source_url=None):
        """Extract emails with comprehensive metadata"""
        if not text:
            return []
            
        email_data = []
        
        # Method 1: Regex extraction
        raw_emails = set(re.findall(self.email_pattern, text, re.IGNORECASE))
        
        # Method 2: Look for email-like patterns
        email_like_patterns = [
            r'[\w\.-]+@[\w\.-]+\.\w+',
            r'[\w\.-]+\[at\][\w\.-]+\.\w+',
            r'[\w\.-]+\(at\)[\w\.-]+\.\w+',
            r'[\w\.-]+\s*@\s*[\w\.-]+\.\w+',
        ]
        
        for pattern in email_like_patterns:
            found = re.findall(pattern, text, re.IGNORECASE)
            for email in found:
                # Normalize [at] and (at) to @
                email = email.replace('[at]', '@').replace('(at)', '@').replace(' ', '')
                raw_emails.add(email)
        
        for email in raw_emails:
            email = email.strip()
            if self.validator.is_valid_email(email):
                username, domain = email.split('@')
                pattern_type = self.analyze_username_pattern(username)
                
                email_info = {
                    'email': email,
                    'username': username,
                    'domain': domain,
                    'pattern_type': pattern_type,
                    'source': source_url or 'Unknown',
                    'timestamp': datetime.now().isoformat(),
                    'valid': True
                }
                
                email_data.append(email_info)
                
                # Display found email
                if source_url:
                    ColorOutput.email(f"Found: {email} (Pattern: {pattern_type})")
                else:
                    ColorOutput.email(f"Found: {email} (Pattern: {pattern_type})")
        
        return email_data
    
    def analyze_username_pattern(self, username):
        """Analyze username pattern for classification"""
        if not username:
            return 'unknown'
            
        username_lower = username.lower()
        
        for pattern, pattern_name in self.username_patterns:
            if re.match(pattern, username_lower):
                return pattern_name
        
        # Check for special patterns
        if re.match(r'^[a-z]+\.[a-z]+\.[a-z]+$', username_lower):
            return 'first.middle.last'
        elif re.match(r'^[a-z]+[0-9]{2,}$', username_lower):
            return 'name_with_year'
        elif re.match(r'^[0-9]+[a-z]+$', username_lower):
            return 'year_name'
        elif username_lower.count('_') >= 2:
            return 'multiple_underscores'
        elif username_lower.count('-') >= 2:
            return 'multiple_hyphens'
        elif username_lower.count('.') >= 2:
            return 'multiple_dots'
        else:
            return 'unknown'
    
    def extract_emails_from_html(self, html_content, source_url=None):
        """Specialized email extraction from HTML content"""
        email_data = []
        
        if not html_content:
            return email_data
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Extract from visible text
            visible_text = soup.get_text()
            email_data.extend(self.extract_emails_with_metadata(visible_text, source_url))
            
            # Extract from meta tags
            for meta in soup.find_all('meta'):
                content = meta.get('content', '')
                if content:
                    email_data.extend(self.extract_emails_with_metadata(content, source_url))
            
            # Extract from link hrefs (mailto links)
            for link in soup.find_all('a', href=True):
                href = link['href']
                if href.startswith('mailto:'):
                    email = href[7:].split('?')[0].strip()
                    if email and self.validator.is_valid_email(email):
                        username, domain = email.split('@')
                        pattern_type = self.analyze_username_pattern(username)
                        
                        email_info = {
                            'email': email,
                            'username': username,
                            'domain': domain,
                            'pattern_type': pattern_type,
                            'source': source_url or 'Unknown',
                            'timestamp': datetime.now().isoformat(),
                            'valid': True,
                            'type': 'mailto_link'
                        }
                        
                        email_data.append(email_info)
                        ColorOutput.email(f"Found: {email} (mailto link, Pattern: {pattern_type})")
            
            # Remove duplicates while preserving metadata
            unique_emails = {}
            for email_info in email_data:
                email = email_info['email']
                if email not in unique_emails:
                    unique_emails[email] = email_info
                else:
                    # Keep the one with more complete metadata
                    existing = unique_emails[email]
                    current_source = email_info.get('source', '')
                    existing_source = existing.get('source', '')
                    
                    if len(str(current_source)) > len(str(existing_source)):
                        unique_emails[email] = email_info
            
            return list(unique_emails.values())
            
        except Exception:
            return email_data

class RobustWebCrawler:
    def __init__(self, config, proxy=None):
        self.config = config
        self.proxy = proxy
        self.visited_urls = set()
        self.all_emails = []
        self.email_map = {}
        self.url_status = {}
        self.session = self._create_robust_session()
        self.crawl_stats = {
            'pages_crawled': 0,
            'emails_found': 0,
            'unique_domains': 0,
            'valid_urls': 0,
            'skipped_urls': 0,
            'start_time': None,
            'end_time': None
        }
    
    def _create_robust_session(self):
        """Create a robust HTTP session with advanced error handling"""
        session = requests.Session()
        session.headers.update({
            'User-Agent': self.config.USER_AGENT,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        })
        
        if self.proxy:
            if self.proxy.startswith('socks'):
                session.proxies = {'http': self.proxy, 'https': self.proxy}
            else:
                session.proxies = {'http': self.proxy, 'https': self.proxy}
        
        # Advanced retry strategy
        retry_strategy = Retry(
            total=self.config.MAX_RETRIES,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD"],
            raise_on_status=False
        )
        
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=10,
            pool_maxsize=10
        )
        
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session
    
    def fetch_url(self, url):
        """Fetch URL content with bulletproof error handling"""
        if not url or URLUtils.should_skip_url(url):
            self.url_status[url] = 'skipped'
            self.crawl_stats['skipped_urls'] += 1
            return None
        
        # Skip WordPress endpoints by default
        if URLUtils.is_wp_endpoint(url):
            self.url_status[url] = 'skipped_wp'
            self.crawl_stats['skipped_urls'] += 1
            return None
        
        try:
            ColorOutput.crawling(f"Fetching: {url[:80]}..." if len(url) > 80 else f"Fetching: {url}")
            
            response = self.session.get(
                url,
                timeout=self.config.TIMEOUT,
                verify=self.config.VERIFY_SSL,
                allow_redirects=self.config.ALLOW_REDIRECTS,
                stream=False
            )
            
            # Check HTTP status code - silently skip errors
            if response.status_code in self.config.IGNORE_HTTP_ERRORS:
                self.url_status[url] = f'skipped_http_{response.status_code}'
                self.crawl_stats['skipped_urls'] += 1
                return None
            
            response.raise_for_status()
            
            # Check content type
            content_type = response.headers.get('content-type', '').lower()
            is_valid_content = any(ct in content_type for ct in self.config.VALID_CONTENT_TYPES)
            
            if not is_valid_content:
                self.url_status[url] = 'invalid_content_type'
                self.crawl_stats['skipped_urls'] += 1
                return None
            
            self.url_status[url] = 'success'
            self.crawl_stats['valid_urls'] += 1
            return response.text
            
        except requests.exceptions.SSLError:
            self.url_status[url] = 'ssl_error'
            return None
            
        except requests.exceptions.Timeout:
            self.url_status[url] = 'timeout'
            return None
            
        except requests.exceptions.ConnectionError:
            self.url_status[url] = 'connection_error'
            return None
            
        except requests.exceptions.TooManyRedirects:
            self.url_status[url] = 'too_many_redirects'
            return None
            
        except requests.exceptions.HTTPError:
            self.url_status[url] = 'http_error'
            return None
            
        except Exception:
            self.url_status[url] = 'unknown_error'
            return None
    
    def crawl(self, start_url, max_pages=None, max_depth=None):
        """Main crawling function with bulletproof error handling"""
        if max_pages is None:
            max_pages = self.config.MAX_PAGES
        if max_depth is None:
            max_depth = self.config.MAX_DEPTH
        
        self.crawl_stats['start_time'] = datetime.now().isoformat()
        
        queue = deque([(start_url, 0)])
        email_extractor = EmailExtractor(start_url)
        
        ColorOutput.info("=" * 80)
        ColorOutput.info(f"Starting Enterprise Crawl: {start_url}")
        ColorOutput.info(f"Max pages: {max_pages}, Max depth: {max_depth}")
        ColorOutput.info(f"SSL verification: {'ENABLED' if self.config.VERIFY_SSL else 'DISABLED (INSECURE)'}")
        ColorOutput.info("=" * 80)
        
        processed_count = 0
        successful_crawls = 0
        
        while queue and len(self.visited_urls) < max_pages:
            url, depth = queue.popleft()
            
            if not url:
                continue
                
            normalized_url = URLUtils.normalize_url(url)
            
            if (normalized_url in self.visited_urls or 
                depth > max_depth or 
                URLUtils.should_skip_url(url)):
                continue
            
            # Progress display
            progress_pct = (len(self.visited_urls) / max_pages) * 100
            if processed_count % 10 == 0:
                ColorOutput.stats(f"Progress: {len(self.visited_urls)}/{max_pages} pages ({progress_pct:.1f}%) | Emails: {len(self.all_emails)}")
            
            ColorOutput.crawling(f"Crawling [{processed_count + 1}/{max_pages}]: Depth {depth} - {url[:80]}..." if len(url) > 80 else f"Crawling [{processed_count + 1}/{max_pages}]: Depth {depth} - {url}")
            
            content = self.fetch_url(url)
            if content:
                self.visited_urls.add(normalized_url)
                processed_count += 1
                successful_crawls += 1
                self.crawl_stats['pages_crawled'] += 1
                
                # Extract emails with metadata
                email_data = email_extractor.extract_emails_from_html(content, url)
                
                for email_info in email_data:
                    email = email_info['email']
                    if email not in self.email_map:
                        self.email_map[email] = email_info
                        self.all_emails.append(email_info)
                        self.crawl_stats['emails_found'] += 1
                
                # Display progress every 10 emails
                if len(self.all_emails) > 0 and len(self.all_emails) % 10 == 0:
                    ColorOutput.success(f"Found {len(self.all_emails)} emails so far...")
                
                # Discover new URLs if we haven't reached depth limit
                if depth < max_depth:
                    new_urls = self._extract_urls_from_page(content, url)
                    for new_url in new_urls:
                        normalized_new = URLUtils.normalize_url(new_url)
                        if (normalized_new and 
                            normalized_new not in self.visited_urls and 
                            normalized_new not in [URLUtils.normalize_url(u) for u, d in queue]):
                            queue.append((new_url, depth + 1))
                
                # Adaptive delay
                time.sleep(self.config.CRAWL_DELAY)
            else:
                processed_count += 1
        
        self.crawl_stats['end_time'] = datetime.now().isoformat()
        
        # Calculate statistics
        domains = set()
        for email_info in self.all_emails:
            domains.add(email_info['domain'])
        self.crawl_stats['unique_domains'] = len(domains)
        
        # Calculate duration
        start_dt = datetime.fromisoformat(self.crawl_stats['start_time'])
        end_dt = datetime.fromisoformat(self.crawl_stats['end_time'])
        self.crawl_stats['duration_seconds'] = (end_dt - start_dt).total_seconds()
        
        # Display final summary
        self._display_final_summary(successful_crawls)
        
        return {
            'emails': self.all_emails,
            'stats': self.crawl_stats,
            'crawled_urls': list(self.visited_urls),
            'target_domain': URLUtils.get_domain(start_url) if start_url else 'Unknown',
            'crawl_completed': datetime.now().isoformat(),
            'url_status': self.url_status
        }
    
    def _extract_urls_from_page(self, html_content, base_url):
        """Enhanced URL extraction with proper resolution and filtering"""
        urls = set()
        
        if not html_content or not base_url:
            return urls
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            base_domain = URLUtils.get_domain(base_url)
            
            # Extract from all href attributes
            for tag in soup.find_all(['a'], href=True):
                href = tag['href'].strip()
                
                if not href or href == '':
                    continue
                
                # Skip problematic hrefs
                if URLUtils.should_skip_url(href):
                    continue
                
                # Skip anchors that are only fragments
                if href.startswith('#'):
                    continue
                
                # Skip data URLs
                if href.startswith('data:'):
                    continue
                
                # Resolve relative URLs
                try:
                    full_url = urllib.parse.urljoin(base_url, href)
                    
                    # Remove fragments
                    full_url = full_url.split('#')[0]
                    
                    parsed = urllib.parse.urlparse(full_url)
                    
                    # Validate URL
                    if not parsed.scheme or not parsed.netloc:
                        continue
                    
                    # Ensure it's HTTP or HTTPS
                    if parsed.scheme not in ['http', 'https']:
                        continue
                    
                    # Normalize URL
                    normalized_url = URLUtils.normalize_url(full_url)
                    
                    # Stay on same domain
                    if URLUtils.get_domain(normalized_url) != base_domain:
                        continue
                    
                    # Skip already visited
                    if normalized_url in self.visited_urls:
                        continue
                    
                    # Skip WordPress endpoints
                    if URLUtils.is_wp_endpoint(normalized_url):
                        continue
                    
                    # Add to set
                    urls.add(normalized_url)
                    
                except Exception:
                    continue
            
        except Exception:
            return urls
        
        return urls
    
    def _display_final_summary(self, successful_crawls):
        """Display final crawl summary"""
        ColorOutput.info("\n" + "=" * 80)
        ColorOutput.success("CRAWLING COMPLETED")
        ColorOutput.info("=" * 80)
        
        ColorOutput.stats(f"Total pages attempted: {self.crawl_stats['pages_crawled'] + self.crawl_stats['skipped_urls']}")
        ColorOutput.stats(f"Successfully crawled: {self.crawl_stats['pages_crawled']}")
        ColorOutput.stats(f"Skipped URLs: {self.crawl_stats['skipped_urls']}")
        ColorOutput.stats(f"Total emails found: {self.crawl_stats['emails_found']}")
        ColorOutput.stats(f"Unique domains: {self.crawl_stats['unique_domains']}")
        
        if self.crawl_stats.get('duration_seconds'):
            duration = self.crawl_stats['duration_seconds']
            mins, secs = divmod(duration, 60)
            ColorOutput.stats(f"Crawl duration: {int(mins)}m {secs:.1f}s")
            
            if self.crawl_stats['pages_crawled'] > 0:
                pages_per_sec = self.crawl_stats['pages_crawled'] / duration
                ColorOutput.stats(f"Success rate: {(successful_crawls/self.crawl_stats['pages_crawled'])*100:.1f}%")
                ColorOutput.stats(f"Pages per second: {pages_per_sec:.2f}")
            
            if self.crawl_stats['emails_found'] > 0:
                emails_per_sec = self.crawl_stats['emails_found'] / duration
                ColorOutput.stats(f"Emails per second: {emails_per_sec:.2f}")
        
        ColorOutput.info("=" * 80)

class EnterpriseEmailCrawl:
    def __init__(self, config):
        self.config = config
        self.results = {}
        self.table_formatter = EnhancedTableFormatter(config)
    
    def run_email_crawl(self, start_url, max_pages=None, max_depth=None, output_file=None, proxy=None):
        """Main email crawling execution - Enterprise Edition"""
        ColorOutput.info("=" * 80)
        ColorOutput.info("EMAILCRAWL ENTERPRISE EDITION v3.0")
        ColorOutput.info("=" * 80)
        ColorOutput.info(f"Target: {start_url}")
        ColorOutput.info(f"Started: {datetime.now().isoformat()}")
        ColorOutput.info("=" * 80)
        
        # Validate URL
        if not URLUtils.is_valid_url(start_url):
            ColorOutput.error(f"Invalid URL provided: {start_url}")
            return
        
        # Create output directory
        os.makedirs(self.config.OUTPUT_DIR, exist_ok=True)
        
        # Use provided proxy or config proxy
        use_proxy = proxy or self.config.HTTP_PROXY or self.config.SOCKS_PROXY
        
        try:
            # Initialize crawler
            crawler = RobustWebCrawler(self.config, proxy=use_proxy)
            
            # Perform crawling
            ColorOutput.info("Starting enterprise-grade web crawl...")
            crawl_results = crawler.crawl(start_url, max_pages, max_depth)
            self.results.update(crawl_results)
            
            # Generate report with tables
            self._generate_report(output_file, start_url)
            
            ColorOutput.success("Email crawling completed successfully!")
            
        except KeyboardInterrupt:
            ColorOutput.warning("\nCrawling interrupted by user")
            self._generate_report(output_file, start_url, interrupted=True)
            
        except Exception as e:
            ColorOutput.error(f"Crawling failed: {str(e)[:200]}")
    
    def _generate_report(self, output_file=None, domain=None, interrupted=False):
        """Generate comprehensive email report with enhanced tables"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_domain = "crawl_results"
            if domain:
                safe_domain = "".join(c for c in domain if c.isalnum() or c in ('-', '_')).rstrip()
            output_file = f"{self.config.OUTPUT_DIR}/emailcrawl_{safe_domain}_{timestamp}.json"
        
        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        # Save JSON report
        try:
            serializable_results = self._make_serializable(self.results)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(serializable_results, f, indent=2, ensure_ascii=False, default=str)
            
            # Generate and display tables
            self._generate_enhanced_tables()
            
            # Print summary
            self._print_enhanced_summary(interrupted)
            
            ColorOutput.success(f"Full report saved to: {output_file}")
            
            # Also save tables to text files
            self._save_enhanced_tables_to_files(output_file)
            
        except Exception as e:
            ColorOutput.error(f"Failed to save report: {e}")
            self._print_enhanced_summary(interrupted)
    
    def _generate_enhanced_tables(self):
        """Generate and display enhanced analysis tables"""
        emails = self.results.get('emails', [])
        
        if not emails:
            ColorOutput.warning("No emails found to display in tables")
            return
        
        ColorOutput.info("\n" + "=" * 80)
        ColorOutput.info("ENTERPRISE ANALYSIS REPORT")
        ColorOutput.info("=" * 80)
        
        # 1. Main Enhanced Email Table (with wrapped URLs)
        ColorOutput.table("\n1. EMAIL ADDRESSES FOUND (with source URLs):")
        email_table = self.table_formatter.create_email_table(emails)
        print(f"\n{email_table}")
        
        # 2. Compact Email Table for quick view
        if len(emails) > 20:
            ColorOutput.table("\n2. COMPACT EMAIL VIEW (first 20):")
            compact_table = self.table_formatter.create_compact_email_table(emails)
            print(f"\n{compact_table}")
        
        # 3. Domain Distribution Table
        ColorOutput.table("\n3. DOMAIN DISTRIBUTION ANALYSIS:")
        domain_stats = self._calculate_domain_stats(emails)
        domain_table = self.table_formatter.create_domain_table(domain_stats)
        print(f"\n{domain_table}")
        
        # 4. Username Pattern Analysis
        ColorOutput.table("\n4. USERNAME PATTERN ANALYSIS:")
        pattern_stats = self._calculate_pattern_stats(emails)
        pattern_table = self.table_formatter.create_pattern_table(pattern_stats)
        print(f"\n{pattern_table}")
        
        # 5. Source URL Analysis
        ColorOutput.table("\n5. SOURCE URL ANALYSIS (where emails were found):")
        source_table = self.table_formatter.create_source_url_table(emails)
        print(f"\n{source_table}")
    
    def _calculate_domain_stats(self, emails):
        """Calculate domain distribution statistics"""
        domain_counts = {}
        for email_info in emails:
            domain = email_info.get('domain', 'unknown')
            domain_counts[domain] = domain_counts.get(domain, 0) + 1
        
        # Sort by count descending
        sorted_domains = dict(sorted(domain_counts.items(), key=lambda x: x[1], reverse=True))
        return sorted_domains
    
    def _calculate_pattern_stats(self, emails):
        """Calculate username pattern statistics"""
        pattern_counts = {}
        for email_info in emails:
            pattern = email_info.get('pattern_type', 'unknown')
            pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1
        
        # Sort by count descending
        sorted_patterns = dict(sorted(pattern_counts.items(), key=lambda x: x[1], reverse=True))
        return sorted_patterns
    
    def _make_serializable(self, obj):
        """Convert non-serializable objects to serializable formats"""
        if isinstance(obj, dict):
            return {k: self._make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._make_serializable(item) for item in obj]
        elif isinstance(obj, (datetime)):
            return obj.isoformat()
        elif hasattr(obj, 'isoformat'):
            return obj.isoformat()
        else:
            return obj
    
    def _save_enhanced_tables_to_files(self, json_file):
        """Save enhanced tables to separate text files"""
        base_name = json_file.replace('.json', '')
        emails = self.results.get('emails', [])
        
        if not emails:
            return
        
        try:
            # Save full table report
            table_file = f"{base_name}_tables.txt"
            with open(table_file, 'w', encoding='utf-8') as f:
                f.write("# EmailCrawl Enterprise Edition - Tabular Report\n")
                f.write("#" * 80 + "\n\n")
                f.write(f"Target: {self.results.get('target_domain', 'Unknown')}\n")
                f.write(f"Date: {datetime.now().isoformat()}\n")
                f.write(f"Total Emails Found: {len(emails)}\n")
                f.write(f"Pages Crawled: {self.results.get('stats', {}).get('pages_crawled', 0)}\n")
                f.write("#" * 80 + "\n\n")
                
                # Email table
                f.write("EMAIL ADDRESSES FOUND:\n")
                f.write("=" * 80 + "\n")
                f.write(self.table_formatter.create_email_table(emails))
                f.write("\n\n")
                
                # Domain stats
                f.write("DOMAIN DISTRIBUTION:\n")
                f.write("=" * 80 + "\n")
                f.write(self.table_formatter.create_domain_table(self._calculate_domain_stats(emails)))
                f.write("\n\n")
                
                # Pattern stats
                f.write("USERNAME PATTERNS:\n")
                f.write("=" * 80 + "\n")
                f.write(self.table_formatter.create_pattern_table(self._calculate_pattern_stats(emails)))
                f.write("\n\n")
                
                # Source URL analysis
                f.write("SOURCE URL ANALYSIS:\n")
                f.write("=" * 80 + "\n")
                f.write(self.table_formatter.create_source_url_table(emails))
            
            ColorOutput.success(f"Enterprise table report saved to: {table_file}")
            
            # Save email list (simple format)
            list_file = f"{base_name}_emails.txt"
            with open(list_file, 'w', encoding='utf-8') as f:
                f.write("# EmailCrawl Enterprise - Extracted Email Addresses\n")
                f.write("#" * 80 + "\n\n")
                for idx, email_info in enumerate(emails, 1):
                    email = email_info.get('email', '')
                    source = email_info.get('source', 'Unknown')
                    f.write(f"{idx}. {email}\n")
                    f.write(f"   Source: {source}\n")
                    f.write(f"   Domain: {email_info.get('domain', '')}\n")
                    f.write(f"   Pattern: {email_info.get('pattern_type', '')}\n")
                    f.write("-" * 80 + "\n")
            
            ColorOutput.success(f"Email list saved to: {list_file}")
            
        except Exception:
            pass
    
    def _print_enhanced_summary(self, interrupted=False):
        """Print enhanced crawling summary"""
        stats = self.results.get('stats', {})
        emails = self.results.get('emails', [])
        
        ColorOutput.info("\n" + "=" * 80)
        if interrupted:
            ColorOutput.warning("ENTERPRISE CRAWL - INTERRUPTED SUMMARY")
        else:
            ColorOutput.success("ENTERPRISE CRAWL - COMPLETED SUCCESSFULLY")
        ColorOutput.info("=" * 80)
        
        # Basic stats
        ColorOutput.stats(f"Pages Crawled: {stats.get('pages_crawled', 0)}")
        ColorOutput.stats(f"Unique Emails Found: {len(emails)}")
        ColorOutput.stats(f"Unique Domains: {stats.get('unique_domains', 0)}")
        ColorOutput.stats(f"Valid URLs: {stats.get('valid_urls', 0)}")
        ColorOutput.stats(f"Skipped URLs: {stats.get('skipped_urls', 0)}")
        
        # Performance stats
        if stats.get('duration_seconds'):
            duration = stats['duration_seconds']
            mins, secs = divmod(duration, 60)
            ColorOutput.stats(f"Crawl Duration: {int(mins)}m {secs:.1f}s")
            
            if stats.get('pages_crawled', 0) > 0:
                pages_per_sec = stats['pages_crawled'] / duration
                ColorOutput.stats(f"Pages per second: {pages_per_sec:.2f}")
            
            if len(emails) > 0:
                emails_per_sec = len(emails) / duration
                ColorOutput.stats(f"Emails per second: {emails_per_sec:.2f}")
        
        # Pattern analysis
        if emails:
            patterns = self._calculate_pattern_stats(emails)
            if patterns:
                most_common = list(patterns.items())[0]
                ColorOutput.stats(f"Most Common Pattern: {most_common[0]} ({most_common[1]} emails)")
            
            # Domain analysis
            domains = self._calculate_domain_stats(emails)
            if domains:
                top_domain = list(domains.items())[0]
                ColorOutput.stats(f"Most Common Domain: {top_domain[0]} ({top_domain[1]} emails)")
        
        ColorOutput.info("=" * 80)
        
        if interrupted:
            ColorOutput.warning("Note: Crawling was interrupted. Results may be incomplete.")
        
        if emails:
            ColorOutput.success(f"Successfully extracted {len(emails)} email addresses!")
            ColorOutput.info(f"Check the output directory for complete reports.")
                      
def display_banner():
    banner = f"""
{Fore.GREEN}
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⡆⠀⠀⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣼⣿⣇⣀⡀⣿⣷⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⠀⠀⠀⠶⣦⣄⡀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⠀⠀⠀⢀⣠⣴⡶⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⠀⠀⠀⠀⠀⠀
⠰⠶⠶⠿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠿⠿⣷⣶⣾⣿⣿⣶⣄⣿⣿⣿⣿⣿⣿⣿⣿⣡⣿⣿⡇⠀⢠⣶⣿⣿⣷⣶⣾⠿⠿⠿⠿⣿⣿⣿⣿⣿⣿⣿⡿⠷⠶⠦
⠀⠀⠀⠀⠀⠈⠉⠛⢿⣿⣻⣿⣶⣦⣤⣤⣀⣨⣿⣿⣿⡏⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⢸⣿⣿⣿⣏⣤⣤⣤⣴⣶⣿⡟⣽⡿⠛⠉⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⢳⣿⣿⣿⣿⡿⠟⢋⣽⣿⣿⣧⠘⣿⣿⣿⣿⣿⣿⣿⣼⣿⣿⣿⠀⣸⣿⣿⣯⡙⠻⢿⣿⣿⣿⣿⣶⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⣿⣋⣠⣴⣾⡟⠁⠹⣿⣶⣾⢿⣿⣿⣿⣿⣿⣿⣿⣿⠿⢠⣿⠏⠈⢙⣿⣦⣤⣙⣻⣿⣿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⡿⠟⠛⢻⣿⣿⣿⣿⣷⣄⣹⣿⣿⣷⣿⣿⣿⣿⣿⣿⣿⠏⣠⣿⣯⢠⣾⣿⣿⣿⣿⡟⠛⠻⢿⣿⣧⡀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠿⠋⠁⠀⠀⠀⣸⣿⣿⠟⠀⠙⣿⣿⣿⣿⣿⣿⣿⣇⠉⣿⣿⣯⣾⣿⣿⣿⣿⠋⠀⠻⣿⣿⣇⠀⠀⠀⠈⠙⠿⠆⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡿⠋⠀⠀⠀⠘⣿⣿⣿⣿⡿⣿⣿⣿⣰⣿⣿⣿⡿⣿⣿⣿⣿⠃⠀⠀⠀⠙⢿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠀⠀⠀⠀⢿⣿⣿⣿⠀⠸⣿⣿⣿⣿⣿⠟⠁⣿⣿⣿⣿⠀⠀⠀⠀⠀⠈⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠇⠀⠀⠘⢿⣿⣿⠇⠀⠀⠸⣿⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⡟⠀⠀⠀⠀⠸⣿⠃⠀⠀⠀⠀⢹⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⡟⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⢻⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
{Fore.CYAN}                    Professional Email Extraction Crawler
{Fore.YELLOW}                         Advanced OSINT Intelligence Tool
{Fore.MAGENTA}                          by onxx-x143 v3.0
{Style.RESET_ALL}
    """
    print(banner)

def display_usage():
    """Display enterprise usage information"""
    print(f"""
{Fore.GREEN}EmailCrawl Enterprise Edition v3.0{Style.RESET_ALL}

{Fore.CYAN}Usage:{Style.RESET_ALL}
  python3 onxx.py https://example.com [options]

{Fore.CYAN}Enterprise Features:{Style.RESET_ALL}
  • Professional error handling - All errors managed internally
  • Advanced HTTP error filtering (400, 401, 403, 404, 405, 408, 429, 500, 502, 503, 504)
  • WordPress endpoint auto-skipping (wp-json, xmlrpc.php, etc.)
  • Intelligent URL filtering and validation
  • Robust session management with retry logic
  • Enterprise-grade error handling
  • Clean, professional output only

{Fore.CYAN}Options:{Style.RESET_ALL}
  --max-pages NUM        Maximum pages to crawl (default: 200)
  --max-depth NUM        Maximum crawl depth (default: 3)
  --output FILE          Custom output file path
  --proxy URL            HTTP/SOCKS proxy URL
  --delay SECONDS        Delay between requests (default: 0.5)
  --table-format FORMAT  Table format: grid, fancy_grid, plain, simple, github (default: grid)
  --no-verify-ssl        Disable SSL certificate verification (INSECURE - not recommended)

{Fore.CYAN}Examples:{Style.RESET_ALL}
  {Fore.YELLOW}# Enterprise-grade email extraction{Style.RESET_ALL}
  python3 onxx.py https://example.com

  {Fore.YELLOW}# Deep crawl with enterprise error handling{Style.RESET_ALL}
  python3 hari.py https://example.com --max-pages 500 --max-depth 4

  {Fore.YELLOW}# With proxy and custom output{Style.RESET_ALL}
  python3 harry.py https://example.com --proxy http://proxy:8080 --output results.json

  {Fore.YELLOW}# Faster enterprise crawling{Style.RESET_ALL}
  python3 vasu.py https://example.com --delay 0.3

{Fore.CYAN}Error Handling:{Style.RESET_ALL}
  • HTTP 405 (Method Not Allowed): Auto-skipped, not displayed
  • HTTP 503 (Service Unavailable): Auto-skipped, not displayed
  • HTTP 404 (Not Found): Auto-skipped, not displayed
  • Connection errors: Handled internally
  • Timeout errors: Handled internally
  • SSL errors: Handled based on configuration

{Fore.CYAN}Output:{Style.RESET_ALL}
  • Clean, professional output
  • JSON file with complete metadata
  • TXT file with formatted tables
  • TXT file with simple email list
  • Real-time progress
  • Comprehensive statistics and domain analysis
    """)

def main():
    display_banner()
    
    parser = argparse.ArgumentParser(
        description='EmailCrawl Enterprise Edition v3.0',
        add_help=False
    )
    
    # Required arguments
    parser.add_argument('url', nargs='?', help='Target URL for email extraction')
    
    # Optional arguments
    parser.add_argument('--max-pages', type=int, default=200, help='Maximum pages to crawl (default: 200)')
    parser.add_argument('--max-depth', type=int, default=3, help='Maximum crawl depth (default: 3)')
    parser.add_argument('--output', help='Output file path')
    parser.add_argument('--proxy', help='HTTP/SOCKS proxy URL')
    parser.add_argument('--delay', type=float, default=0.5, help='Delay between requests in seconds (default: 0.5)')
    parser.add_argument('--table-format', default='grid', help='Table format: grid, fancy_grid, plain, simple, github (default: grid)')
    parser.add_argument('--no-verify-ssl', action='store_true', help='Disable SSL certificate verification (INSECURE - not recommended)')
    parser.add_argument('-h', '--help', action='store_true', help='Show this help message and exit')
    
    args = parser.parse_args()
    
    # Show help if requested or no URL provided
    if args.help or not args.url:
        display_usage()
        return
    
    # Update config with command line arguments
    config = Config(verify_ssl=not args.no_verify_ssl)
    if args.proxy:
        config.HTTP_PROXY = args.proxy
    config.MAX_PAGES = args.max_pages
    config.MAX_DEPTH = args.max_depth
    config.CRAWL_DELAY = args.delay
    config.TABLE_FORMAT = args.table_format
    
    # Initialize and run email crawling
    email_crawl = EnterpriseEmailCrawl(config)
    email_crawl.run_email_crawl(
        start_url=args.url,
        max_pages=args.max_pages,
        max_depth=args.max_depth,
        output_file=args.output,
        proxy=args.proxy
    )

if __name__ == '__main__':
    main()