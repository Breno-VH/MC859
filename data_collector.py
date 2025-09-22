import aiohttp
import asyncio
import networkx as nx
import time
import re
import os
import pandas as pd

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

            for i, response_data in enumerate(responses):
                package_name, current_depth = current_batch[i]
                print(f"Coletando dados para: {package_name} (Profundidade: {current_depth})")

                if isinstance(response_data, Exception) or not response_data or 'info' not in response_data:
                    print(f"Dados incompletos para {package_name}. Pulando.")
                    continue
                
                info = response_data['info']
                
                try:
                    latest_release = response_data['releases'].get(info.get('version', ''))
                    size = latest_release[0]['size'] if latest_release and latest_release[0] else 0
                except (IndexError, KeyError, TypeError):
                    size = 0

                vulnerabilities = str(response_data.get('vulnerabilities', []))
                version = info.get('version', '')
                # python_version_req = info.get('requires_python', '')
                dev_status = next((c for c in info.get('classifiers', []) if 'Development Status' in c), '')

                # --- Lógica de Depuração Adicionada ---
                node_attributes = {
                    'size': size,
                    'vulnerabilities': vulnerabilities,
                    'version': version,
                    # 'python_version_req': python_version_req,
                    'dev_status': dev_status
                }
                
                # Verifica se há valores None nos atributos antes de adicionar ao grafo
                for key, value in node_attributes.items():
                    if value is None:
                        print(f"DEBUG: O pacote '{package_name}' tem o atributo '{key}' com valor None. Corrigindo...")
                        node_attributes[key] = '' # Substitui o valor None por uma string vazia

                graph.add_node(package_name, **node_attributes)

                dependencies = info.get('requires_dist', [])
                clean_dependencies = extract_clean_dependencies(dependencies)

                for dep in clean_dependencies:
                    graph.add_edge(dep, package_name)
                    if dep not in visited_packages and current_depth + 1 <= max_depth:
                        queue.append((dep, current_depth + 1))