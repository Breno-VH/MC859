import networkx as nx
from typing import Dict, List, Any

def get_shortest_path_to_vulnerable_node(G: nx.DiGraph, vulnerable_node: str) -> int:
    """
    Calcula o comprimento do caminho mais curto (profundidade) de qualquer nó raiz
    (pacote de nível superior/dependência direta) até o pacote vulnerável.
    
    O caminho mais curto (menor profundidade) indica maior risco de uso direto.
    Retorna o comprimento do caminho mais curto, ou -1 se for inalcançável a partir do topo.
    """
    
    # 1. Identificar nós raiz (pacotes de nível superior - in_degree 0)
    # Estes são os pontos de entrada no grafo.
    root_nodes = [node for node, degree in G.in_degree() if degree == 0]
    
    min_path_length = float('inf')
    
    # 2. Encontrar o caminho mais curto de qualquer nó raiz para o nó vulnerável
    for root in root_nodes:
        try:
            # nx.shortest_path_length retorna o número de arestas
            path_length = nx.shortest_path_length(G, source=root, target=vulnerable_node)
            if path_length < min_path_length:
                min_path_length = path_length
        except nx.NetworkXNoPath:
            # Não há caminho entre este nó raiz e o nó vulnerável
            continue

    # 3. Retornar a profundidade
    if min_path_length != float('inf'):
        # +1 para converter o número de arestas para Profundidade do Pacote
        return int(min_path_length) + 1
    else:
        # -1 indica que o pacote vulnerável está isolado ou não faz parte da dependência principal
        return -1

def calculate_reachability_metrics(G: nx.DiGraph, vulnerability_report: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Adiciona a métrica de alcance (profundidade mínima) a cada item no relatório.
    """
    print("Iniciando cálculo de alcance (reachability)...")
    
    for item in vulnerability_report:
        package_name = item['package_name']
        
        # Calcular a profundidade mínima
        min_depth = get_shortest_path_to_vulnerable_node(G, package_name)
        
        # Armazenar o resultado no relatório
        item['min_dependency_depth'] = min_depth

    print("Cálculo de alcance concluído.")
    return vulnerability_report
