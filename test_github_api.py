"""
Integration test script for GitHub API functionality.
Run this before your main analysis to verify everything works.
"""

import asyncio
import os
import sys
from typing import List, Dict, Any
import networkx as nx

# Try to import your modules
try:
    from analysis_utils import GitHubAPIClient, extract_project_risk_data
    print("✅ Successfully imported analysis_utils")
except ImportError as e:
    print(f"❌ Failed to import analysis_utils: {e}")
    sys.exit(1)

# --- TEST CONFIGURATION ---
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

# Sample test data - popular packages with known GitHub repos
TEST_PACKAGES = [
    {
        'package_name': 'requests',
        'repo_url': 'https://github.com/psf/requests',
        'max_risk_score': 4.0,
        'in_degree_dependents': 100,
        'weighted_risk_score': 40.0,
    },
    {
        'package_name': 'flask',
        'repo_url': 'https://github.com/pallets/flask',
        'max_risk_score': 3.0,
        'in_degree_dependents': 50,
        'weighted_risk_score': 21.2,
    },
    {
        'package_name': 'django',
        'repo_url': 'https://github.com/django/django',
        'max_risk_score': 5.0,
        'in_degree_dependents': 80,
        'weighted_risk_score': 44.7,
    },
]

# Test URLs with various formats
TEST_URL_FORMATS = [
    "https://github.com/psf/requests",
    "http://github.com/psf/requests",
    "github.com/psf/requests",
    "https://www.github.com/psf/requests",
    "https://github.com/psf/requests.git",
    "https://github.com/psf/requests/",
    "not-a-github-url.com/test",
    "https://gitlab.com/some/project",  # Should be filtered
]


async def test_url_parsing():
    """Test URL parsing functionality"""
    print("\n" + "="*80)
    print("TEST 1: URL Parsing")
    print("="*80 + "\n")
    
    client = GitHubAPIClient()
    
    for url in TEST_URL_FORMATS:
        result = client._parse_repo_url(url)
        status = "✅" if result else "❌"
        
        if result:
            owner, repo = result
            print(f"{status} '{url}' -> {owner}/{repo}")
        else:
            print(f"{status} '{url}' -> None (as expected)")
    
    return True


async def test_github_api_connectivity():
    """Test basic GitHub API connection"""
    print("\n" + "="*80)
    print("TEST 2: GitHub API Connectivity")
    print("="*80 + "\n")
    
    if not GITHUB_TOKEN:
        print("⚠️  WARNING: No GITHUB_TOKEN found!")
        print("   You'll be limited to 60 requests/hour")
        print("   Set token with: export GITHUB_TOKEN='your_token_here'")
        print()
    else:
        print(f"✅ GitHub token found: {GITHUB_TOKEN[:10]}...")
        print()
    
    client = GitHubAPIClient()
    
    # Test with a simple well-known repository
    test_url = "https://github.com/python/cpython"
    
    import aiohttp
    async with aiohttp.ClientSession() as session:
        result = await client.fetch_repo_metrics(session, test_url, "test-package")
        
        if result and result.get('repo_stars', 0) > 0:
            print(f"✅ Successfully connected to GitHub API")
            print(f"   Test repository stats: ⭐ {result['repo_stars']} stars")
            return True
        else:
            print(f"❌ Failed to connect to GitHub API")
            print(f"   Result: {result}")
            return False


async def test_multiple_packages():
    """Test fetching data for multiple packages"""
    print("\n" + "="*80)
    print("TEST 3: Multiple Package Fetching")
    print("="*80 + "\n")
    
    client = GitHubAPIClient()
    
    import aiohttp
    async with aiohttp.ClientSession() as session:
        results = []
        
        for pkg in TEST_PACKAGES[:3]:  # Test first 3 packages
            result = await client.fetch_repo_metrics(
                session, 
                pkg['repo_url'], 
                pkg['package_name']
            )
            results.append((pkg['package_name'], result))
            
            # Small delay between requests
            await asyncio.sleep(0.5)
        
        # Summary
        print("\n" + "-"*80)
        print("RESULTS SUMMARY:")
        print("-"*80)
        
        successful = 0
        for name, result in results:
            stars = result.get('repo_stars', 0)
            contributors = result.get('repo_contributors', 0)
            
            if stars > 0:
                successful += 1
                print(f"✅ {name:<20} | ⭐ {stars:>6} | 👥 {contributors:>4}")
            else:
                print(f"❌ {name:<20} | Failed to fetch")
        
        print(f"\nSuccess rate: {successful}/{len(results)}")
        return successful == len(results)


async def test_with_mock_graph():
    """Test with a mock NetworkX graph (simulating real usage)"""
    print("\n" + "="*80)
    print("TEST 4: Integration with NetworkX Graph")
    print("="*80 + "\n")
    
    # Create mock graph
    G = nx.DiGraph()
    
    for pkg in TEST_PACKAGES:
        G.add_node(
            pkg['package_name'],
            repo_url=pkg['repo_url'],
            dev_status='Development Status :: 5 - Production/Stable',
            vulnerabilities=[]
        )
    
    print(f"Created mock graph with {G.number_of_nodes()} nodes\n")
    
    # Test the actual function you'll use in main.py
    try:
        project_risk_data = await extract_project_risk_data(
            G, 
            TEST_PACKAGES, 
            count=3
        )
        
        print("\n" + "-"*80)
        print("PROJECT RISK DATA:")
        print("-"*80)
        
        for item in project_risk_data:
            print(f"\n📦 {item['package_name']}")
            print(f"   ⭐ Stars: {item['repo_stars']}")
            print(f"   👥 Contributors: {item['repo_contributors']}")
            print(f"   📊 Weighted Score: {item['weighted_score']:.2f}")
        
        return len(project_risk_data) > 0
        
    except Exception as e:
        print(f"❌ Error during integration test: {e}")
        import traceback
        traceback.print_exc()
        return False


async def run_all_tests():
    """Run all tests in sequence"""
    print("\n" + "="*80)
    print("🧪 GITHUB API INTEGRATION TEST SUITE")
    print("="*80)
    
    tests = [
        ("URL Parsing", test_url_parsing),
        ("API Connectivity", test_github_api_connectivity),
        ("Multiple Packages", test_multiple_packages),
        ("Graph Integration", test_with_mock_graph),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = await test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n❌ Test '{test_name}' failed with exception: {e}")
            import traceback
            traceback.print_exc()
            results.append((test_name, False))
    
    # Final summary
    print("\n" + "="*80)
    print("📊 FINAL TEST RESULTS")
    print("="*80 + "\n")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"{status} - {test_name}")
    
    print(f"\n{'='*80}")
    print(f"Overall: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    print(f"{'='*80}\n")
    
    if passed == total:
        print("🎉 All tests passed! Your GitHub API integration is ready.")
        print("\nNext steps:")
        print("1. Make sure your GITHUB_TOKEN is set")
        print("2. Run your main.py script")
        print("3. Check the output for repository metrics")
    else:
        print("⚠️  Some tests failed. Please review the errors above.")
        print("\nCommon issues:")
        print("- Missing GITHUB_TOKEN (set with: export GITHUB_TOKEN='your_token')")
        print("- Network connectivity issues")
        print("- Rate limiting (wait an hour or use a token)")


if __name__ == "__main__":
    # Check Python version
    if sys.version_info < (3, 10):
        print("⚠️  Warning: This code is designed for Python 3.10+")
        print(f"   You're running Python {sys.version}")
        print()
    
    # Run tests
    asyncio.run(run_all_tests())
