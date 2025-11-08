import os
import networkx as nx
from typing import List, Dict, Any, Tuple
from collections import Counter
import re
import math
import aiohttp
import asyncio

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


# --- ENHANCED GITHUB API IMPLEMENTATION ---

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
MAX_RETRIES = 3
INITIAL_DELAY = 1.0

class GitHubAPIClient:
    """Enhanced GitHub API client with robust error handling and rate limiting"""
    
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
        """
        Parse GitHub URL to extract owner and repo name.
        Handles various URL formats.
        """
        if not repo_url or 'github.com' not in repo_url.lower():
            return None
        
        # Clean URL
        cleaned = (repo_url
                   .replace('https://', '')
                   .replace('http://', '')
                   .replace('www.', '')
                   .replace('.git', '')
                   .strip('/'))
        
        # Extract owner and repo using regex
        match = re.search(r'github\.com/([^/]+)/([^/]+)', cleaned, re.IGNORECASE)
        if match:
            owner, repo = match.groups()
            # Remove any trailing parameters or fragments
            repo = repo.split('?')[0].split('#')[0]
            return owner, repo
        
        return None
    
    async def _fetch_with_retry(self, session: aiohttp.ClientSession, url: str, 
                                package_name: str = None) -> Dict[str, Any] | None:
        """
        Fetch URL with exponential backoff retry logic.
        """
        delay = INITIAL_DELAY
        
        for attempt in range(MAX_RETRIES):
            try:
                async with session.get(url, headers=self._get_headers(), timeout=aiohttp.ClientTimeout(total=15)) as response:
                    
                    # Update rate limit info
                    self.rate_limit_remaining = response.headers.get('X-RateLimit-Remaining')
                    self.rate_limit_reset = response.headers.get('X-RateLimit-Reset')
                    
                    if response.status == 200:
                        return await response.json()
                    
                    elif response.status == 404:
                        if package_name:
                            print(f"    ⚠️  [{package_name}] Repository not found (404): {url}")
                        return None
                    
                    elif response.status == 403:
                        # Rate limit hit
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
                        error_text = await response.text()
                        print(f"    ⚠️  HTTP {response.status} for {url}: {error_text[:100]}")
                        
                        if attempt < MAX_RETRIES - 1:
                            await asyncio.sleep(delay)
                            delay *= 2
                        else:
                            return None
                        
            except asyncio.TimeoutError:
                print(f"    ⏱️  Timeout for {url} (attempt {attempt + 1}/{MAX_RETRIES})")
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(delay)
                    delay *= 2
                else:
                    return None
                    
            except aiohttp.ClientError as e:
                print(f"    ⚠️  Connection error for {url}: {e}")
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(delay)
                    delay *= 2
                else:
                    return None
            
            except Exception as e:
                print(f"    ❌ Unexpected error for {url}: {e}")
                return None
        
        return None
    
    async def fetch_repo_metrics(self, session: aiohttp.ClientSession, 
                                 repo_url: str, package_name: str) -> Dict[str, Any]:
        """
        Fetch repository metrics (stars, forks, contributors) from GitHub API.
        Returns dict with metrics or zeros if fetch fails.
        """
        parsed = self._parse_repo_url(repo_url)
        
        if not parsed:
            print(f"    ⚠️  [{package_name}] Invalid or non-GitHub URL: {repo_url}")
            return {'repo_stars': 0, 'repo_contributors': 0, 'repo_forks': 0}
        
        owner, repo = parsed
        repo_endpoint = f"https://api.github.com/repos/{owner}/{repo}"
        
        print(f"    🔍 [{package_name}] Fetching: {owner}/{repo}")
        
        # Fetch main repo data
        repo_data = await self._fetch_with_retry(session, repo_endpoint, package_name)
        
        if not repo_data:
            return {'repo_stars': 0, 'repo_contributors': 0, 'repo_forks': 0}
        
        stars = repo_data.get('stargazers_count', 0)
        forks = repo_data.get('forks_count', 0)
        
        # Fetch contributors (separate endpoint)
        contributors_endpoint = f"{repo_endpoint}/contributors?per_page=100"
        contributors_data = await self._fetch_with_retry(session, contributors_endpoint, package_name)
        
        contributors_count = 0
        if contributors_data and isinstance(contributors_data, list):
            contributors_count = len(contributors_data)
            # If there are exactly 100, there might be more (pagination needed)
            if contributors_count == 100:
                print(f"    ℹ️  [{package_name}] May have 100+ contributors (pagination limit)")
        
        print(f"    ✅ [{package_name}] ⭐ {stars} | 🍴 {forks} | 👥 {contributors_count}")
        
        return {
            'repo_stars': stars,
            'repo_contributors': contributors_count,
            'repo_forks': forks,
            'archived': repo_data.get('archived', False),
            'disabled': repo_data.get('disabled', False),
            'pushed_at': repo_data.get('pushed_at', 'N/A')
        }


async def extract_project_risk_data(G: nx.DiGraph, 
                                   top_vulnerable_packages: List[Dict[str, Any]], 
                                   count: int = 10) -> List[Dict[str, Any]]:
    """
    Orchestrates fetching of repository maintenance metrics (Stars, Contributors)
    and calculates weighted Project Risk (Maintenance) score.
    """
    
    print(f"\n{'='*80}")
    print(f"🔍 GITHUB API: Fetching repository metrics for top {count} packages")
    print(f"{'='*80}\n")
    
    # Check for GitHub token
    token_status = "✅ Authenticated" if GITHUB_TOKEN else "⚠️  Unauthenticated (60 req/hour limit)"
    print(f"Token Status: {token_status}\n")
    
    # 1. Prepare unique packages
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
                'repo_stars': 0,
                'repo_contributors': 0,
                'repo_forks': 0,
            }

    packages_list = list(unique_packages.values())[:count]
    
    # 2. Asynchronous GitHub API calls
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
                results.append((pkg_data, {'repo_stars': 0, 'repo_contributors': 0, 'repo_forks': 0}))
        
        # Small delay between batches to be respectful to API
        await asyncio.sleep(0.5)
    
    # 3. Process results and calculate final risk
    final_project_risk_data = []
    
    print(f"\n{'='*80}")
    print("📊 Calculating Project Risk Scores")
    print(f"{'='*80}\n")
    
    for pkg_data, api_data in results:
        
        # Update package data with real metrics
        pkg_data.update(api_data)
        
        stars = pkg_data['repo_stars']
        contributors = pkg_data['repo_contributors']
        
        # --- PROJECT RISK SCORE CALCULATION ---
        
        in_degree = pkg_data['in_degree']
        max_security_risk = pkg_data['max_security_risk']
        dev_status = pkg_data['dev_status']
        
        # Maturity Factor (higher maturity = higher potential impact)
        maturity_score = get_maturity_score(dev_status)
        
        # Influence Factor (higher in_degree = wider impact reach)
        influence_factor = math.log(in_degree + 2)
        
        # Health/Maintenance Factor (higher health = lower risk of slow fixes)
        health_index = stars + contributors
        health_factor = math.log(health_index + 10) if health_index > 0 else 1.0
        
        # Final Formula: (Security Risk * Maturity * Influence) / Health
        weighted_score = (max_security_risk * maturity_score * influence_factor) / health_factor
        
        pkg_data['weighted_score'] = weighted_score
        
        final_project_risk_data.append(pkg_data)
    
    # 4. Sort by final score
    final_project_risk_data.sort(key=lambda x: x['weighted_score'], reverse=True)
    
    print(f"\n✅ Successfully analyzed {len(final_project_risk_data)} packages\n")
    
    return final_project_risk_data[:count]