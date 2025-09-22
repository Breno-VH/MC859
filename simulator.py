# simulator.py
import networkx as nx

def simulate_vulnerability_spread(graph, vulnerable_package):
    """
    Simula a propagação de uma vulnerabilidade a partir de um pacote.
    Retorna um conjunto de pacotes afetados (incluindo o vulnerável).
    """
    if vulnerable_package not in graph:
        print(f"Erro: O pacote '{vulnerable_package}' não foi encontrado no grafo.")
        return set()

    # Usamos DFS do grafo para encontrar todos os dependentes
    # que seriam afetados por uma vulnerabilidade no pacote fonte.
    affected_packages = nx.dfs_preorder_nodes(graph, source=vulnerable_package)
    
    return set(affected_packages)