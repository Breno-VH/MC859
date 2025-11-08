import aiohttp
import asyncio
import networkx as nx
import time
import re
import os
import pandas as pd
import json
from typing import Dict, Any, List

# --- ENHANCED REPOSITORY URL EXTRACTION ---

def extract_repo_url(info: Dict[str, Any]) -> str:
    """
    Enhanced function to find repository URL (GitHub, GitLab, etc.) in PyPI metadata.
    Prioritizes actual repository URLs over generic homepages.
    """
    project_urls = info.get('project_urls', {})
    
    if not project_urls:
        project_urls = {}
    
    # Priority order for finding repository URLs
    priority_keys = [
        'Source Code',
        'Source',
        'Repository',
        'Code',
        'GitHub',
        'GitLab',
        'Homepage',
    ]
    
    # 1. Try explicit repository URL keys
    for key in priority_keys:
        url = project_urls.get(key)
        if url and ('github.com' in url.lower() or 'gitlab.com' in url.lower()):
            return url
    
    # 2. Search all project_urls for repository patterns
    for key, url in project_urls.items():
        if url and ('github.com' in url.lower() or 'gitlab.com' in url.lower()):
            # Avoid documentation or issues URLs
            if not any(x in url.lower() for x in ['/issues', '/wiki', '/docs', 'readthedocs']):
                return url
    
    # 3. Try main homepage
    home_page = info.get('home_page')
    if home_page and ('github.com' in home_page.lower() or 'gitlab.com' in home_page.lower()):
        if not any(x in home_page.lower() for x in ['/issues', '/wiki', '/docs']):
            return home_page
    
    # 4. Try package_url (sometimes contains GitHub)
    package_url = info.get('package_url')
    if package_url and 'github.com' in package_url.lower():
        return package_url
        
    return ""


def extract_repo_url_from_vulnerabilities(vulnerabilities: List[Dict[str, Any]]) -> str:
    """
    Fallback: Extract repository URL from vulnerability references.
    Useful when PyPI metadata doesn't have the repo URL.
    """
    if not vulnerabilities:
        return ""
    
    for vuln in vulnerabilities:
        references = vuln.get('references', [])
        for ref in references:
            ref_type = ref.get('type', '').upper()
            ref_url = ref.get('url', '')
            
            # Prioritize PACKAGE or REPOSITORY type references
            if 'github.com' in ref_url and ref_type in ['PACKAGE', 'REPOSITORY', 'WEB']:
                # Clean up the URL (remove /issues, /security, etc.)
                base_url_match = re.match(r'(https?://github\.com/[^/]+/[^/]+)', ref_url)
                if base_url_match:
                    return base_url_match.group(1)
    
    return ""


async def get_repo_data(session: aiohttp.ClientSession, repo_url: str, package_name: str = None) -> Dict[str, Any]:
    """
    Fetch repository metrics from GitHub/GitLab.
    This is now a PLACEHOLDER that returns empty dict - 
    actual implementation is in analysis_utils.py
    
    Keep this function for compatibility with the graph building process,
    but don't use it for the final analysis (use analysis_utils instead).
    """
    # Return empty dict - we'll fetch this data later during analysis
    # This prevents duplicate API calls during graph building
    return {}


async def get_package_data(session: aiohttp.ClientSession, package_name: str) -> Dict[str, Any] | None:
    """
    Fetch package data from PyPI asynchronously.
    Adds delay to avoid overwhelming the API.
    """
    url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        async with session.get(url, timeout=20) as response:
            response.raise_for_status()
            await asyncio.sleep(0.05) 
            data = await response.json()
            return data
    except aiohttp.ClientError as e:
        print(f"Error accessing API for package {package_name}: {e}")
        return None


async def get_osv_vulnerabilities(session: aiohttp.ClientSession, package_name: str, version: str) -> List[Dict[str, Any]]:
    """
    Fetch vulnerabilities for a package and version from OSV API.
    """
    url = "https://api.osv.dev/v1/query"
    payload = {
        "package": {
            "name": package_name,
            "ecosystem": "PyPI"
        },
        "version": version
    }
    try:
        async with session.post(url, json=payload, timeout=10) as response:
            response.raise_for_status()
            await asyncio.sleep(0.05)
            data = await response.json()
            return data.get('vulns', [])
    except aiohttp.ClientError as e:
        print(f"Error accessing OSV API for {package_name}@{version}: {e}")
        return []


def extract_clean_dependencies(dependencies_list: List[str] | None) -> List[str]:
    """
    Extract only package name from a dependencies list.
    Handles versions, metadata and extras.
    """
    if dependencies_list is None:
        return []

    clean_deps = set()
    for dep_string in dependencies_list:
        # Get first sequence of characters that isn't a version operator
        match = re.match(r'([a-zA-Z0-9-._]+)', dep_string)
        if match:
            clean_deps.add(match.group(1))
    return list(clean_deps)


async def build_dependency_graph(initial_packages: List[str], graph: nx.DiGraph, 
                                visited_packages: set, max_depth: int):
    """
    Build dependency graph with depth limit asynchronously.
    Now includes ENHANCED repository URL extraction from multiple sources.
    
    NOTE: We don't fetch GitHub metrics here to avoid rate limiting.
    That will be done separately in analysis_utils.py for only the vulnerable packages.
    """
    if not initial_packages:
        return

    queue = [(pkg, 0) for pkg in initial_packages]
    batch_size = 50 

    async with aiohttp.ClientSession() as session:
        while queue:
            current_batch = []
            tasks_pypi = []
            
            for _ in range(min(len(queue), batch_size)):
                package_name, current_depth = queue.pop(0)
                if package_name not in visited_packages and current_depth <= max_depth:
                    visited_packages.add(package_name)
                    current_batch.append((package_name, current_depth))
                    tasks_pypi.append(get_package_data(session, package_name))
            
            if not tasks_pypi:
                continue

            responses_pypi = await asyncio.gather(*tasks_pypi, return_exceptions=True)

            osv_tasks = []
            valid_packages_for_osv = []
            
            for i, response_data in enumerate(responses_pypi):
                package_name, current_depth = current_batch[i]
                print(f"Collecting data for: {package_name} (Depth: {current_depth})")

                if isinstance(response_data, Exception) or not response_data or 'info' not in response_data:
                    print(f"Incomplete data for {package_name}. Skipping.")
                    continue
                
                info = response_data['info']
                version = info.get('version', '')
                
                # Schedule OSV vulnerability check
                osv_tasks.append(get_osv_vulnerabilities(session, package_name, version))
                valid_packages_for_osv.append(package_name)
            
            # Execute OSV searches
            osv_responses = await asyncio.gather(*osv_tasks, return_exceptions=True)

            # --- Process Results and Build Node ---
            for i, (package_name, current_depth) in enumerate(current_batch):
                response_data = responses_pypi[i]
                if isinstance(response_data, Exception) or not response_data or 'info' not in response_data:
                    continue
                
                info = response_data['info']
                version = info.get('version', '')
                
                # Collect and normalize PyPI vulnerability data
                all_vulnerabilities = []
                vulnerabilities_data = response_data.get('vulnerabilities', [])
                for vuln in vulnerabilities_data:
                    vulnerability_info = {
                        'id': vuln.get('id'),
                        'summary': vuln.get('summary', 'No summary provided.'),
                        'fixed_in': vuln.get('fixed_in', []),
                        'withdrawn': vuln.get('withdrawn')
                    }
                    all_vulnerabilities.append(vulnerability_info)

                last_updated = info.get('upload_time_iso_8601', 'N/A')
                classifiers_info = info.get('classifiers', [])
                
                try:
                    latest_release = response_data['releases'].get(info.get('version', ''))
                    size = latest_release[0]['size'] if latest_release and latest_release[0] else 0
                except (IndexError, KeyError, TypeError):
                    size = 0

                dev_status = next((c for c in info.get('classifiers', []) if 'Development Status' in c), '')
                
                # --- ENHANCED Repository URL Extraction ---
                # Try primary method
                repo_url = extract_repo_url(info)
                
                # If not found, try OSV vulnerabilities
                osv_vulns = osv_responses[i] if i < len(osv_responses) else []
                if not repo_url and isinstance(osv_vulns, list):
                    repo_url = extract_repo_url_from_vulnerabilities(osv_vulns)
                
                # Final fallback
                if not repo_url:
                    repo_url = 'N/A'
                
                # Log successful URL extraction
                if repo_url != 'N/A' and 'github.com' in repo_url:
                    print(f"  ✅ Found repository URL: {repo_url}")

                # --- Add OSV vulnerability data ---
                if isinstance(osv_vulns, list):
                    osv_vulns_data = osv_vulns
                else:
                    osv_vulns_data = []

                # Prepare final node attributes
                # NOTE: repo_stars and repo_contributors are set to 0 here
                # They will be populated later during risk analysis
                node_attributes = {
                    'size': size,
                    'vulnerabilities': all_vulnerabilities,
                    'osv_vulnerabilities': osv_vulns_data,
                    'version': version,
                    'dev_status': dev_status,
                    'last_updated': last_updated,
                    'classifiers': classifiers_info,
                    'repo_url': repo_url,
                    'repo_stars': 0,  # Will be populated during analysis
                    'repo_contributors': 0,  # Will be populated during analysis
                }
                
                # Ensure all None values are empty strings or default values
                for key, value in node_attributes.items():
                    if value is None:
                        node_attributes[key] = '' 

                graph.add_node(package_name, **node_attributes)

                # --- Process Dependencies and Queue ---
                dependencies = info.get('requires_dist', [])
                clean_dependencies = extract_clean_dependencies(dependencies)

                for dep in clean_dependencies:
                    # Add edge: dependency -> package
                    graph.add_edge(dep, package_name)
                    if dep not in visited_packages and current_depth + 1 <= max_depth:
                        queue.append((dep, current_depth + 1))