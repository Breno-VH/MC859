import aiohttp
import asyncio
import networkx as nx
import time
import re
import os
import pandas as pd
import json

async def get_package_data(session, package_name):
    """
    Busca dados de um pacote no PyPI de forma assíncrona.
    Adiciona um delay para evitar sobrecarregar a API.
    """
    url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        async with session.get(url, timeout=10) as response:
            response.raise_for_status()
            await asyncio.sleep(0.05) 
            data = await response.json()
            return data
    except aiohttp.ClientError as e:
        print(f"Erro ao acessar a API para o pacote {package_name}: {e}")
        return None

async def get_osv_vulnerabilities(session, package_name, version):
    """
    Busca vulnerabilidades para um pacote e versão na API OSV.
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
            # Retorna apenas a lista de vulnerabilidades se o campo 'vulns' existir
            return data.get('vulns', [])
    except aiohttp.ClientError as e:
        print(f"Erro ao acessar a API OSV para {package_name}@{version}: {e}")
        return []

def extract_clean_dependencies(dependencies_list):
    """
    Extrai apenas o nome do pacote de uma lista de dependências.
    Lida com versões, metadados e extras.
    """
    if dependencies_list is None:
        return []

    clean_deps = set()
    for dep_string in dependencies_list:
        match = re.match(r'([a-zA-Z0-9-._]+)', dep_string)
        if match:
            clean_deps.add(match.group(1))
    return list(clean_deps)

async def build_dependency_graph(initial_packages, graph, visited_packages, max_depth):
    """
    Construção do grafo de dependências com limite de profundidade de forma assíncrona.
    """
    if not initial_packages:
        return

    queue = [(pkg, 0) for pkg in initial_packages]
    batch_size = 50 

    async with aiohttp.ClientSession() as session:
        while queue:
            current_batch = []
            tasks = []
            
            for _ in range(min(len(queue), batch_size)):
                package_name, current_depth = queue.pop(0)
                if package_name not in visited_packages and current_depth <= max_depth:
                    visited_packages.add(package_name)
                    current_batch.append((package_name, current_depth))
                    tasks.append(get_package_data(session, package_name))
            
            if not tasks:
                continue

            responses = await asyncio.gather(*tasks, return_exceptions=True)

            osv_tasks = []
            valid_packages_for_osv = []
            for i, response_data in enumerate(responses):
                package_name, current_depth = current_batch[i]
                print(f"Coletando dados para: {package_name} (Profundidade: {current_depth})")

                if isinstance(response_data, Exception) or not response_data or 'info' not in response_data:
                    print(f"Dados incompletos para {package_name}. Pulando.")
                    continue
                
                info = response_data['info']

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
                version = info.get('version', '')
                
                try:
                    latest_release = response_data['releases'].get(info.get('version', ''))
                    size = latest_release[0]['size'] if latest_release and latest_release[0] else 0
                except (IndexError, KeyError, TypeError):
                    size = 0

                dev_status = next((c for c in info.get('classifiers', []) if 'Development Status' in c), '')

                node_attributes = {
                    'size': size,
                    'vulnerabilities': all_vulnerabilities,
                    'version': version,
                    'dev_status': dev_status,
                    'last_updated': last_updated,
                    'classifiers': classifiers_info,
                }
                
                for key, value in node_attributes.items():
                    if value is None:
                        node_attributes[key] = '' 

                graph.add_node(package_name, **node_attributes)

                dependencies = info.get('requires_dist', [])
                clean_dependencies = extract_clean_dependencies(dependencies)

                for dep in clean_dependencies:
                    graph.add_edge(dep, package_name)
                    if dep not in visited_packages and current_depth + 1 <= max_depth:
                        queue.append((dep, current_depth + 1))
                
                osv_tasks.append(get_osv_vulnerabilities(session, package_name, version))
                valid_packages_for_osv.append(package_name)
            
            osv_responses = await asyncio.gather(*osv_tasks, return_exceptions=True)
            for i, osv_vulns in enumerate(osv_responses):
                package_name = valid_packages_for_osv[i]
                if isinstance(osv_vulns, list):
                    graph.nodes[package_name]['osv_vulnerabilities'] = osv_vulns
                else:
                    graph.nodes[package_name]['osv_vulnerabilities'] = []
