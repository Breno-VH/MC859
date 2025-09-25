import networkx as nx
import pandas as pd
import os
import asyncio
import collections
import json
import matplotlib.pyplot as plt

# Importa as funções dos módulos criados
from data_collector import build_dependency_graph
from visualizer import plot_degree_distribution, plot_scc_distribution

# --- INÍCIO DO PROJETO ---
GRAPH_FILE = 'dependency_graph.graphml'
MAX_DEPTH = 15

# 1. Tenta carregar o grafo de um arquivo, se existir
if os.path.exists(GRAPH_FILE):
    print(f"Carregando grafo do arquivo '{GRAPH_FILE}'...")
    try:
        G = nx.read_graphml(GRAPH_FILE)
        # Converte as strings JSON de volta para listas
        for node, attributes in G.nodes(data=True):
            # Converte vulnerabilidades de string JSON para lista de dicionários
            if 'vulnerabilities' in attributes and isinstance(attributes['vulnerabilities'], str):
                attributes['vulnerabilities'] = json.loads(attributes['vulnerabilities'])
            # Converte classificadores de string JSON para lista
            if 'classifiers' in attributes and isinstance(attributes['classifiers'], str):
                attributes['classifiers'] = json.loads(attributes['classifiers'])
            # Converte as vulnerabilidades OSV, se existirem
            if 'osv_vulnerabilities' in attributes and isinstance(attributes['osv_vulnerabilities'], str):
                attributes['osv_vulnerabilities'] = json.loads(attributes['osv_vulnerabilities'])
    except Exception as e:
        print(f"Erro ao carregar o grafo do arquivo: {e}")
        print("Iniciando a coleta de dados da API.")
        G = nx.DiGraph()
        
        try:
            df = pd.read_csv('qty_downloads_libs.csv', skiprows=1, header=None, names=['package_name', 'country_code', 'total_downloads'])
            initial_packages_list = df['package_name'].tolist()
        except FileNotFoundError:
            print("Erro: O arquivo 'qty_downloads_libs.csv' não foi encontrado.")
            exit()
            
        # Chama a função de forma assíncrona
        asyncio.run(build_dependency_graph(initial_packages_list, G, set(), MAX_DEPTH))
        
        # Converte listas para strings JSON antes de salvar
        for node, attributes in G.nodes(data=True):
            if 'vulnerabilities' in attributes:
                attributes['vulnerabilities'] = json.dumps(attributes['vulnerabilities'])
            if 'classifiers' in attributes:
                attributes['classifiers'] = json.dumps(attributes['classifiers'])
            if 'osv_vulnerabilities' in attributes:
                attributes['osv_vulnerabilities'] = json.dumps(attributes['osv_vulnerabilities'])
        
        nx.write_graphml(G, GRAPH_FILE)
        print(f"Grafo construído e salvo em '{GRAPH_FILE}'.")
else:
    # 2. Se o arquivo não existir, inicia a coleta de dados
    print(f"Arquivo '{GRAPH_FILE}' não encontrado. Coletando dados da API...")
    try:
        df = pd.read_csv('qty_downloads_libs.csv', skiprows=1, header=None, names=['package_name', 'country_code', 'total_downloads'])
        initial_packages_list = df['package_name'].tolist()
    except FileNotFoundError:
        print("Erro: O arquivo 'qty_downloads_libs.csv' não foi encontrado.")
        exit()
    
    G = nx.DiGraph()
    visited = set()
    
    # Chama a função de forma assíncrona
    asyncio.run(build_dependency_graph(initial_packages_list, G, visited, MAX_DEPTH))
    
    # Converte listas para strings JSON antes de salvar
    for node, attributes in G.nodes(data=True):
        if 'vulnerabilities' in attributes:
            attributes['vulnerabilities'] = json.dumps(attributes['vulnerabilities'])
        if 'classifiers' in attributes:
            attributes['classifiers'] = json.dumps(attributes['classifiers'])
        if 'osv_vulnerabilities' in attributes:
            attributes['osv_vulnerabilities'] = json.dumps(attributes['osv_vulnerabilities'])
    
    nx.write_graphml(G, GRAPH_FILE)
    print(f"Grafo construído e salvo em '{GRAPH_FILE}'.")

# 3. Análise do Grafo e Impressão de Métricas
print("\n" + "="*60 + "\n")
print("Análise do Grafo de Dependências:")

num_vertices = G.number_of_nodes()
num_edges = G.number_of_edges()
avg_degree = (2 * num_edges) / num_vertices if num_vertices > 0 else 0
scc = list(nx.strongly_connected_components(G))
num_scc = len(scc)
largest_scc_size = max(len(c) for c in scc) if scc else 0

print(f"Número de Vértices: {num_vertices}")
print(f"Número de Arestas: {num_edges}")
print(f"Grau Médio dos Vértices: {avg_degree:.2f}")
print(f"Número de Componentes Fortemente Conexas (CFSs): {num_scc}")
print(f"Tamanho da Maior CFS: {largest_scc_size}")

# 4. Análise de Vulnerabilidades
vulnerable_nodes = []
for node, attributes in G.nodes(data=True):
    # Agora a verificação de vulnerabilidades é baseada na API OSV
    osv_vulnerabilities = attributes.get('osv_vulnerabilities')
    if isinstance(osv_vulnerabilities, list) and len(osv_vulnerabilities) > 0:
        vulnerable_nodes.append(node)

print("\n" + "="*60 + "\n")
print("Análise de Vulnerabilidades:")
print(f"Total de pacotes com vulnerabilidades conhecidas: {len(vulnerable_nodes)}")
print("Lista de pacotes vulneráveis:")
for pkg in vulnerable_nodes:
    print(f"- {pkg}")


# 5. Análise e Visualização de CFSs
print("\n" + "="*60 + "\n")
print("Análise de Componentes Fortemente Conexas (CFSs):")

# Encontra e exibe a primeira CFS de tamanho entre 3 e 6
found_scc = False
for component in scc:
    if 3 <= len(component) <= 6:
        print(f"Primeira CFS encontrada com tamanho entre 3 e 6 ({len(component)}):")
        for member in component:
            print(f"  - {member}")
        found_scc = True
        break
if not found_scc:
    print("Nenhuma CFS com tamanho entre 3 e 6 foi encontrada.")

# Plota a distribuição do tamanho das CFSs
plot_scc_distribution(G)

# Simulação de Propagação (descomentada, se necessário)
# VULNERABLE_PACKAGE_TO_SIMULATE = 'awscrt'
# affected_set = simulate_vulnerability_spread(G, VULNERABLE_PACKAGE_TO_SIMULATE)
# print(f"\nSimulação de propagação para '{VULNERABLE_PACKAGE_TO_SIMULATE}':")
# if affected_set:
#     print(f"Total de pacotes afetados: {len(affected_set)}")
# else:
#     print("Nenhum pacote afetado encontrado (ou o pacote inicial não está no grafo).")

# 6. Visualização da Distribuição de Graus
plot_degree_distribution(G)