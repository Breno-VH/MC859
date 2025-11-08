import os
import networkx as nx
from typing import List, Dict, Any, Tuple
from collections import Counter
import re
import math
import aiohttp
import asyncio
from datetime import datetime, timezone
import json

# CWE Mapping (keeping your original mapping)
CWE_MAPPING = {
    "CWE-77": "Command and Argument Injection",
    "CWE-78": "OS Command Injection",
    "CWE-89": "SQL Injection",
    "CWE-94": "Code Injection",
    "CWE-116": "Improper Encoding or Escaping",
    "CWE-434": "Unrestricted Upload of File with Dangerous Type",
    "CWE-502": "Deserialization of Untrusted Data (RCE)",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-20": "Improper Input Validation",
    "CWE-79": "Cross-Site Scripting (XSS)",
    "CWE-134": "Use of Externally-Controlled Format String",
    "CWE-601": "URL Redirection to Untrusted Site (Open Redirect)",
    "CWE-611": "Improper Restriction of XML External Entity Reference (XXE)",
    "CWE-119": "Improper Restriction of Memory Buffer Operations",
    "CWE-120": "Buffer Overflow",
    "CWE-125": "Out-of-bounds Read",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-416": "Use After Free",
    "CWE-787": "Out-of-bounds Write",
    "CWE-287": "Improper Authentication",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-862": "Missing Authorization",
    "CWE-22": "Path Traversal",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-269": "Improper Privilege Management",
    "CWE-732": "Incorrect Permission Assignment for Critical Resource",
    "CWE-200": "Information Exposure",
    "CWE-312": "Cleartext Storage of Sensitive Information",
    "CWE-522": "Missing Protection for Sensitive Data (e.g., Password)",
    "CWE-532": "Information Exposure (Secrets/Logs)",
    "CWE-668": "Exposure of Resource to Wrong Sphere",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-362": "Race Condition",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-754": "Improper Check for Unusual or Exceptional Conditions",
}

def get_cwe_category(cwe_id: str) -> str:
    """Returns readable category for a CWE ID or 'Other' if not mapped."""
    return CWE_MAPPING.get(cwe_id, "Outras (Não mapeado)")


def analyze_risk_classification(vulnerability_report: List[Dict[str, Any]]) -> List[Tuple[str, int]]:
    """
    Classifies vulnerabilities by mapped CWE category.
    Returns ordered list of (CWE Category, Count of Affected Packages).
    """
    category_counts: Dict[str, int] = {}
    package_categorized: Dict[str, set] = {}

    for item in vulnerability_report:
        package_name = item['package_name']
        
        if package_name not in package_categorized:
            package_categorized[package_name] = set()
            
        for cwe_id in item.get('cwe_ids', []):
            cwe_clean = cwe_id.upper().replace('CWE-', 'CWE-')
            
            category = next((
                cat for prefix, cat in CWE_MAPPING.items() if cwe_clean.startswith(prefix)
            ), "Outras Vulnerabilidades (CWE)")
            
            if category not in package_categorized[package_name]:
                category_counts[category] = category_counts.get(category, 0) + 1
                package_categorized[package_name].add(category)

    sorted_classification = sorted(category_counts.items(), key=lambda item: item[1], reverse=True)
    return sorted_classification


def get_maturity_score(dev_status: str) -> float:
    """
    Assigns score based on development status (0 to 5).
    5.0: Production (most stable, highest impact risk)
    3.0: Beta/Alpha
    1.0: Pre-Alpha/Planning
    """
    if "Development Status :: 5 - Production/Stable" in dev_status:
        return 5.0
    elif "Development Status :: 4 - Beta" in dev_status:
        return 4.0
    elif "Development Status :: 3 - Alpha" in dev_status:
        return 3.0
    else:
        return 1.0


def calculate_days_since(date_string: str) -> int:
    """Calculate days since a given ISO date string"""
    if not date_string or date_string == 'N/A':
        return -1
    
    try:
        date = datetime.fromisoformat(date_string.replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        return (now - date).days
    except:
        return -1


def calculate_maintenance_health_score(repo_data: Dict[str, Any]) -> float:
    """
    Calculate a comprehensive maintenance health score (0-100).
    Higher is better (healthier project).
    
    Considers:
    - Recent activity (commits, releases)
    - Issue responsiveness
    - Community size
    - Project maturity
    """
    score = 50.0  # Base score
    
    # Recent activity (+30 points max)
    days_since_push = repo_data.get('days_since_last_push', -1)
    if days_since_push >= 0:
        if days_since_push < 30:
            score += 30
        elif days_since_push < 90:
            score += 20
        elif days_since_push < 180:
            score += 10
        elif days_since_push < 365:
            score += 5
        # else: no points for old projects
    
    # Issue responsiveness (+20 points max)
    open_issues = repo_data.get('open_issues', 0)
    watchers = repo_data.get('watchers', 0)
    if watchers > 0:
        issue_ratio = open_issues / max(watchers, 1)
        if issue_ratio < 0.1:
            score += 20
        elif issue_ratio < 0.5:
            score += 10
        elif issue_ratio < 1.0:
            score += 5
    
    # Community size (+20 points max)
    stars = repo_data.get('repo_stars', 0)
    contributors = repo_data.get('repo_contributors', 0)
    if stars > 10000 or contributors > 100:
        score += 20
    elif stars > 1000 or contributors > 50:
        score += 15
    elif stars > 100 or contributors > 10:
        score += 10
    elif stars > 10 or contributors > 5:
        score += 5
    
    # Security features (+10 points)
    if repo_data.get('has_security_policy', False):
        score += 5
    if repo_data.get('has_vulnerability_alerts', False):
        score += 5
    
    # Penalties
    if repo_data.get('archived', False):
        score -= 50
    if repo_data.get('disabled', False):
        score -= 100
    
    return max(0, min(100, score))


# --- ENHANCED GITHUB API IMPLEMENTATION ---

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
MAX_RETRIES = 3
INITIAL_DELAY = 1.0

class GitHubAPIClient:
    """Enhanced GitHub API client with comprehensive metrics collection"""
    
    def __init__(self, token: str = None):
        self.token = token or GITHUB_TOKEN
        self.rate_limit_remaining = None
        self.rate_limit_reset = None
        
    def _get_headers(self) -> Dict[str, str]:
        """Generate request headers with authentication if available"""
        headers = {"Accept": "application/vnd.github.v3+json"}
        if self.token:
            headers["Authorization"] = f"token {self.token}"
        return headers
    
    def _parse_repo_url(self, repo_url: str) -> Tuple[str, str] | None:
        """Parse GitHub URL to extract owner and repo name."""
        if not repo_url or 'github.com' not in repo_url.lower():
            return None
        
        cleaned = (repo_url
                   .replace('https://', '')
                   .replace('http://', '')
                   .replace('www.', '')
                   .replace('.git', '')
                   .strip('/'))
        
        match = re.search(r'github\.com/([^/]+)/([^/]+)', cleaned, re.IGNORECASE)
        if match:
            owner, repo = match.groups()
            repo = repo.split('?')[0].split('#')[0]
            return owner, repo
        
        return None
    
    async def _fetch_with_retry(self, session: aiohttp.ClientSession, url: str, 
                                package_name: str = None) -> Dict[str, Any] | None:
        """Fetch URL with exponential backoff retry logic."""
        delay = INITIAL_DELAY
        
        for attempt in range(MAX_RETRIES):
            try:
                async with session.get(url, headers=self._get_headers(), timeout=aiohttp.ClientTimeout(total=15)) as response:
                    
                    self.rate_limit_remaining = response.headers.get('X-RateLimit-Remaining')
                    self.rate_limit_reset = response.headers.get('X-RateLimit-Reset')
                    
                    if response.status == 200:
                        return await response.json()
                    
                    elif response.status == 404:
                        if package_name:
                            print(f"    ⚠️  [{package_name}] Repository not found (404): {url}")
                        return None
                    
                    elif response.status == 403:
                        if self.rate_limit_remaining == '0':
                            print(f"    ⚠️  Rate limit exceeded. Reset at: {self.rate_limit_reset}")
                            if attempt < MAX_RETRIES - 1:
                                wait_time = min(delay * (2 ** attempt), 60)
                                print(f"    ⏳ Waiting {wait_time}s before retry...")
                                await asyncio.sleep(wait_time)
                                continue
                        return None
                    
                    elif response.status == 401:
                        print(f"    ❌ Unauthorized (401). Check your GITHUB_TOKEN")
                        return None
                    
                    else:
                        if attempt < MAX_RETRIES - 1:
                            await asyncio.sleep(delay)
                            delay *= 2
                        else:
                            return None
                        
            except asyncio.TimeoutError:
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(delay)
                    delay *= 2
                else:
                    return None
                    
            except aiohttp.ClientError as e:
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(delay)
                    delay *= 2
                else:
                    return None
            
            except Exception as e:
                return None
        
        return None
    
    async def fetch_repo_metrics(self, session: aiohttp.ClientSession, 
                                 repo_url: str, package_name: str) -> Dict[str, Any]:
        """
        Fetch comprehensive repository metrics from GitHub API.
        
        Returns dict with:
        - Basic metrics: stars, forks, contributors, watchers
        - Activity metrics: last push, last release, open issues
        - Health indicators: archived, disabled, security features
        - Maintenance score: calculated health metric
        """
        parsed = self._parse_repo_url(repo_url)
        
        if not parsed:
            print(f"    ⚠️  [{package_name}] Invalid or non-GitHub URL: {repo_url}")
            return self._empty_metrics()
        
        owner, repo = parsed
        repo_endpoint = f"https://api.github.com/repos/{owner}/{repo}"
        
        print(f"    🔍 [{package_name}] Fetching: {owner}/{repo}")
        
        # Fetch main repo data
        repo_data = await self._fetch_with_retry(session, repo_endpoint, package_name)
        
        if not repo_data:
            return self._empty_metrics()
        
        # Basic metrics
        stars = repo_data.get('stargazers_count', 0)
        forks = repo_data.get('forks_count', 0)
        watchers = repo_data.get('watchers_count', 0)
        open_issues = repo_data.get('open_issues_count', 0)
        
        # Activity metrics
        pushed_at = repo_data.get('pushed_at', 'N/A')
        created_at = repo_data.get('created_at', 'N/A')
        updated_at = repo_data.get('updated_at', 'N/A')
        
        days_since_push = calculate_days_since(pushed_at)
        days_since_created = calculate_days_since(created_at)
        
        # Health indicators
        archived = repo_data.get('archived', False)
        disabled = repo_data.get('disabled', False)
        has_issues = repo_data.get('has_issues', False)
        has_wiki = repo_data.get('has_wiki', False)
        has_pages = repo_data.get('has_pages', False)
        
        # License
        license_info = repo_data.get('license')
        license_name = license_info.get('name', 'N/A') if license_info else 'N/A'
        
        # Fetch contributors
        contributors_endpoint = f"{repo_endpoint}/contributors?per_page=100"
        contributors_data = await self._fetch_with_retry(session, contributors_endpoint, package_name)
        
        contributors_count = 0
        if contributors_data and isinstance(contributors_data, list):
            contributors_count = len(contributors_data)
        
        # Fetch latest release (if any)
        releases_endpoint = f"{repo_endpoint}/releases/latest"
        release_data = await self._fetch_with_retry(session, releases_endpoint, package_name)
        
        latest_release_date = 'N/A'
        days_since_release = -1
        if release_data and not isinstance(release_data, list):
            latest_release_date = release_data.get('published_at', 'N/A')
            days_since_release = calculate_days_since(latest_release_date)
        
        # Check for security policy (community standards)
        security_endpoint = f"{repo_endpoint}/community/profile"
        security_data = await self._fetch_with_retry(session, security_endpoint, package_name)
        
        has_security_policy = False
        if security_data and 'files' in security_data:
            has_security_policy = security_data['files'].get('security', None) is not None
        
        # Build comprehensive metrics dict
        metrics = {
            'repo_stars': stars,
            'repo_contributors': contributors_count,
            'repo_forks': forks,
            'watchers': watchers,
            'open_issues': open_issues,
            'archived': archived,
            'disabled': disabled,
            'pushed_at': pushed_at,
            'created_at': created_at,
            'updated_at': updated_at,
            'days_since_last_push': days_since_push,
            'days_since_created': days_since_created,
            'days_since_release': days_since_release,
            'latest_release_date': latest_release_date,
            'license': license_name,
            'has_issues': has_issues,
            'has_wiki': has_wiki,
            'has_pages': has_pages,
            'has_security_policy': has_security_policy,
            'has_vulnerability_alerts': has_issues,  # Proxy metric
        }
        
        # Calculate maintenance health score
        metrics['maintenance_health_score'] = calculate_maintenance_health_score(metrics)
        
        # Display summary
        status_icons = []
        if archived:
            status_icons.append("📦 ARCHIVED")
        if disabled:
            status_icons.append("🚫 DISABLED")
        if days_since_push < 30:
            status_icons.append("✅ Active")
        elif days_since_push < 180:
            status_icons.append("⚠️  Slow")
        else:
            status_icons.append("❌ Stale")
        
        status = " | ".join(status_icons) if status_icons else ""
        
        print(f"    ✅ [{package_name}] ⭐ {stars} | 🍴 {forks} | 👥 {contributors_count} | 🏥 {metrics['maintenance_health_score']:.0f}/100 | {status}")
        
        return metrics
    
    def _empty_metrics(self) -> Dict[str, Any]:
        """Return empty metrics dict with default values"""
        return {
            'repo_stars': 0,
            'repo_contributors': 0,
            'repo_forks': 0,
            'watchers': 0,
            'open_issues': 0,
            'archived': False,
            'disabled': False,
            'pushed_at': 'N/A',
            'created_at': 'N/A',
            'updated_at': 'N/A',
            'days_since_last_push': -1,
            'days_since_created': -1,
            'days_since_release': -1,
            'latest_release_date': 'N/A',
            'license': 'N/A',
            'has_issues': False,
            'has_wiki': False,
            'has_pages': False,
            'has_security_policy': False,
            'has_vulnerability_alerts': False,
            'maintenance_health_score': 0,
        }


async def extract_project_risk_data(G: nx.DiGraph, 
                                   top_vulnerable_packages: List[Dict[str, Any]], 
                                   count: int = 10) -> List[Dict[str, Any]]:
    """
    Orchestrates fetching of comprehensive repository metrics
    and calculates enhanced Project Risk (Maintenance) score.
    """
    
    print(f"\n{'='*80}")
    print(f"🔍 GITHUB API: Fetching comprehensive repository metrics for top {count} packages")
    print(f"{'='*80}\n")
    
    token_status = "✅ Authenticated" if GITHUB_TOKEN else "⚠️  Unauthenticated (60 req/hour limit)"
    print(f"Token Status: {token_status}\n")
    
    # Prepare unique packages
    unique_packages = {}
    for pkg in top_vulnerable_packages:
        name = pkg['package_name']
        if name not in unique_packages:
            node_data = G.nodes.get(name, {})
            repo_url = node_data.get('repo_url', '')
            dev_status = node_data.get('dev_status', 'Não Classificado')

            unique_packages[name] = {
                'package_name': name,
                'repo_url': repo_url,
                'in_degree': pkg.get('in_degree_dependents', 0),
                'dev_status': dev_status,
                'max_security_risk': pkg.get('max_risk_score', 0),
                'weighted_risk_score': pkg.get('weighted_risk_score', 0),
                'risk_level': pkg.get('risk_level', 'UNKNOWN'),
            }

    packages_list = list(unique_packages.values())[:count]
    
    # Asynchronous GitHub API calls
    client = GitHubAPIClient()
    
    async with aiohttp.ClientSession() as session:
        tasks = []
        for pkg_data in packages_list:
            if pkg_data['repo_url'] and pkg_data['repo_url'] != 'N/A':
                task = client.fetch_repo_metrics(session, pkg_data['repo_url'], pkg_data['package_name'])
                tasks.append((pkg_data, task))
            else:
                print(f"    ⚠️  [{pkg_data['package_name']}] No repository URL available")
                tasks.append((pkg_data, None))
        
        # Execute all tasks
        results = []
        for pkg_data, task in tasks:
            if task:
                result = await task
                results.append((pkg_data, result))
            else:
                results.append((pkg_data, client._empty_metrics()))
        
        await asyncio.sleep(0.5)
    
    # Process results and calculate final risk
    final_project_risk_data = []
    
    print(f"\n{'='*80}")
    print("📊 Calculating Enhanced Project Risk Scores")
    print(f"{'='*80}\n")
    
    for pkg_data, api_data in results:
        
        # Update package data with all metrics
        pkg_data.update(api_data)
        
        # Extract key metrics
        in_degree = pkg_data['in_degree']
        max_security_risk = pkg_data['max_security_risk']
        dev_status = pkg_data['dev_status']
        maintenance_health = pkg_data['maintenance_health_score']
        
        # --- ENHANCED PROJECT RISK SCORE CALCULATION ---
        
        # Maturity Factor
        maturity_score = get_maturity_score(dev_status)
        
        # Influence Factor
        influence_factor = math.log(in_degree + 2)
        
        # Health Factor (now using comprehensive health score)
        # Convert 0-100 health score to a factor (higher health = lower risk)
        health_factor = math.log((maintenance_health / 10) + 10)
        
        # Additional penalty factors
        penalty_multiplier = 1.0
        if pkg_data.get('archived', False):
            penalty_multiplier *= 2.0  # Double risk if archived
        if pkg_data.get('days_since_last_push', 0) > 365:
            penalty_multiplier *= 1.5  # 50% more risk if no activity in a year
        
        # Final Formula: (Security * Maturity * Influence * Penalties) / Health
        weighted_score = (max_security_risk * maturity_score * influence_factor * penalty_multiplier) / health_factor
        
        pkg_data['weighted_score'] = weighted_score
        
        final_project_risk_data.append(pkg_data)
    
    # Sort by final score
    final_project_risk_data.sort(key=lambda x: x['weighted_score'], reverse=True)
    
    print(f"\n✅ Successfully analyzed {len(final_project_risk_data)} packages with enhanced metrics\n")
    
    return final_project_risk_data[:count]


def export_visualization_data(vulnerability_report: List[Dict[str, Any]], 
                              project_risk_data: List[Dict[str, Any]],
                              output_file: str = "visualization_data.json"):
    """
    Export data in a format optimized for visualization.
    Creates a JSON file with all metrics needed for charts.
    """
    export_data = {
        'vulnerability_summary': [],
        'project_risk_summary': [],
        'health_vs_risk': [],
        'severity_distribution': {'CRITICAL': 0, 'HIGH': 0, 'MODERATE': 0, 'LOW': 0},
        'metadata': {
            'total_vulnerable_packages': len(vulnerability_report),
            'total_analyzed_repos': len(project_risk_data),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
    }
    
    # Vulnerability summary
    for item in vulnerability_report[:20]:  # Top 20
        export_data['vulnerability_summary'].append({
            'package': item['package_name'],
            'risk_level': item['risk_level'],
            'risk_score': item['weighted_risk_score'],
            'dependents': item['in_degree_dependents'],
            'depth': item.get('min_dependency_depth', -1)
        })
        
        # Count severities
        export_data['severity_distribution'][item['risk_level']] += 1
    
    # Project risk summary with health metrics
    for item in project_risk_data:
        export_data['project_risk_summary'].append({
            'package': item['package_name'],
            'risk_score': item['weighted_score'],
            'health_score': item.get('maintenance_health_score', 0),
            'stars': item.get('repo_stars', 0),
            'contributors': item.get('repo_contributors', 0),
            'days_since_push': item.get('days_since_last_push', -1),
            'open_issues': item.get('open_issues', 0),
            'archived': item.get('archived', False),
            'severity': item.get('risk_level', 'UNKNOWN')
        })
        
        # Health vs Risk correlation data
        export_data['health_vs_risk'].append({
            'package': item['package_name'],
            'health': item.get('maintenance_health_score', 0),
            'risk': item['weighted_score'],
            'severity': item.get('risk_level', 'UNKNOWN')
        })
    
    # Write to JSON file
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(export_data, f, indent=2, ensure_ascii=False)
    
    print(f"\n📊 Visualization data exported to: {output_file}")
    return export_data