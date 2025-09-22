import networkx as nx
import pandas as pd
import os
import asyncio
import collections

# Importa as funções dos módulos criados
from data_collector import build_dependency_graph
from visualizer import plot_degree_distribution

# --- INÍCIO DO PROJETO ---
GRAPH_FILE = 'dependency_graph.graphml'
MAX_DEPTH = 25

# 1. Tenta carregar o grafo de um arquivo, se existir
if os.path.exists(GRAPH_FILE):
    print(f"Carregando grafo do arquivo '{GRAPH_FILE}'...")
    try:
        G = nx.read_graphml(GRAPH_FILE)
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

# Simulação de Propagação (descomentada, se necessário)
# VULNERABLE_PACKAGE_TO_SIMULATE = 'awscrt'
# affected_set = simulate_vulnerability_spread(G, VULNERABLE_PACKAGE_TO_SIMULATE)
# print(f"\nSimulação de propagação para '{VULNERABLE_PACKAGE_TO_SIMULATE}':")
# if affected_set:
#     print(f"Total de pacotes afetados: {len(affected_set)}")
# else:
#     print("Nenhum pacote afetado encontrado (ou o pacote inicial não está no grafo).")

# 4. Visualização da Distribuição de Graus
plot_degree_distribution(G)
