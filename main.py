import networkx as nx
import json
import random
from typing import Dict, List, Any, Tuple
# NOVAS DEPENDÊNCIAS PARA VISUALIZAÇÃO
import matplotlib.pyplot as plt
import seaborn as sns 
import asyncio # <--- IMPORTAÇÃO NECESSÁRIA PARA EXECUTAR FUNÇÕES ASSÍNCRONAS
# IMPORTAÇÕES DE FUNÇÕES DOS UTILITY FILES
# Assume-se que 'analysis_utils.py' e 'reachability_analysis.py' estão no diretório
from analysis_utils import analyze_risk_classification, extract_project_risk_data
from reachability_analysis import calculate_reachability_metrics

# --- CONFIGURAÇÕES DE PONTUAÇÃO DE RISCO ---
# Mapeamento de severidade para pontuação numérica (escalado de 1.0 a 5.0)
RISK_SCORES = {
    "LOW": 1.0,
    "MODERATE": 2.0,
    "HIGH": 4.0,
    "CRITICAL": 5.0,
}

def load_dependency_graph(file_path: str) -> nx.DiGraph:
    """
    Carrega o grafo de dependências a partir de um arquivo GraphML.
    Garante que os atributos complexos (como vulnerabilidades JSON) e
    os novos atributos de repositório (stars, contributors) sejam carregados corretamente.
    """
    try:
        # Tenta ler o grafo GraphML
        G = nx.read_graphml(file_path)
        print(f"Grafo carregado com sucesso: {G.number_of_nodes()} pacotes.")

        for node, data in G.nodes(data=True):
            raw_vuln_str = ''
            
            # --- Parsing de Vulnerabilidades (Garantindo que a string JSON seja carregada como Lista) ---
            # O NetworkX pode salvar listas como strings em GraphML, com chaves genéricas (d1, d6, etc.)
            
            # Tenta encontrar a string JSON em várias chaves comuns
            if isinstance(data.get('osv_vulnerabilities'), str) and data['osv_vulnerabilities'].strip().startswith('['):
                 raw_vuln_str = data['osv_vulnerabilities']
            elif isinstance(data.get('vulnerabilities'), str) and data['vulnerabilities'].strip().startswith('['):
                raw_vuln_str = data['vulnerabilities']
            # Chaves genéricas que o NetworkX pode usar (adicionadas para robustez)
            elif isinstance(data.get('d6'), str) and data['d6'].strip().startswith('['):
                raw_vuln_str = data['d6']
            elif isinstance(data.get('d1'), str) and data['d1'].strip().startswith('['):
                raw_vuln_str = data['d1']
            
            # Processar a string JSON encontrada
            if raw_vuln_str and raw_vuln_str != 'ALREADY_PROCESSED':
                try:
                    # Armazena na chave limpa 'vulnerabilities' para o restante do pipeline
                    data['vulnerabilities'] = json.loads(raw_vuln_str)
                except json.JSONDecodeError:
                    data['vulnerabilities'] = []
            elif not 'vulnerabilities' in data or raw_vuln_str == 'ALREADY_PROCESSED':
                # Se não for uma string JSON, garante que é uma lista vazia
                if not isinstance(data.get('vulnerabilities'), list):
                    data['vulnerabilities'] = []


            # --- Inicialização/Conversão de NOVOS Atributos de Repositório ---
            # Garante que os valores numéricos sejam inteiros (pois podem ter sido salvos como string)
            data['repo_stars'] = int(data.get('repo_stars', 0))
            data['repo_contributors'] = int(data.get('repo_contributors', 0))
            data['dev_status'] = data.get('dev_status', 'N/A')
            data['repo_url'] = data.get('repo_url', 'N/A')

            # Limpa as chaves brutas que não são mais necessárias
            if 'd6' in data: del data['d6']
            if 'd1' in data: del data['d1']
            
        return G
    except Exception as e:
        print(f"Erro ao carregar o grafo (GraphML): {e}")
        return nx.DiGraph()


def analyze_risks_and_generate_report(G: nx.DiGraph) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Calcula o risco ponderado inicial (Segurança x Influência) para cada pacote vulnerável.
    """
    vulnerability_report = []
    
    # 1. Calcular o In-Degree para todos os nós (número de dependentes)
    in_degree_map = dict(G.in_degree())

    for package_name, data in G.nodes(data=True):
        # data['vulnerabilities'] é garantido como uma lista de dicionários (ou vazia)
        vulnerabilities = data.get('vulnerabilities', [])
        
        if vulnerabilities:
            max_risk_score = 0
            max_risk_level = "LOW"
            
            all_cwe_ids = set()
            vulnerability_summary = []

            for vuln in vulnerabilities:
                # Determinar o nível de severidade e pontuação
                severity = vuln.get('database_specific', {}).get('severity', 'LOW').upper()
                score = RISK_SCORES.get(severity, 1.0)
                
                if score > max_risk_score:
                    max_risk_score = score
                    max_risk_level = severity
                    
                # --- Lógica de Coleta e Normalização de CWE IDs ---
                vuln_cwe_ids_raw = vuln.get('database_specific', {}).get('cwe_ids', []) or \
                                   vuln.get('cwe_ids', []) or \
                                   vuln.get('cwe', [])
                    
                for cwe_id in vuln_cwe_ids_raw:
                    if isinstance(cwe_id, str):
                        cwe_id_upper = cwe_id.strip().upper()
                        if cwe_id_upper.startswith('CWE-'):
                            all_cwe_ids.add(cwe_id_upper)

                # Resumo das vulnerabilidades para o relatório detalhado
                vulnerability_summary.append({
                    'id': vuln.get('id', 'N/A'),
                    'summary': vuln.get('summary') or 'Sem resumo', 
                    'severity': severity,
                    'cwe_ids': vuln_cwe_ids_raw
                })


            in_degree = in_degree_map.get(package_name, 0)
            
            # Risco ponderado: multiplica a pontuação de risco pela influência (log/raiz quadrada de dependentes)
            weighted_risk_score = max_risk_score * (1 + (in_degree ** 0.5))

            vulnerability_report.append({
                'package_name': package_name,
                'max_risk_score': max_risk_score,
                'risk_level': max_risk_level,
                'in_degree_dependents': in_degree,
                'weighted_risk_score': weighted_risk_score,
                'cwe_ids': list(all_cwe_ids), 
                'vulnerability_summary': vulnerability_summary,
            })

    # 2. Ordenar o relatório pelo Risco Ponderado
    vulnerability_report.sort(key=lambda x: x['weighted_risk_score'], reverse=True)
    
    # Separar os pacotes mais arriscados (Top N) para a análise de risco de projeto/manutenção
    top_packages_for_project_analysis = vulnerability_report[:10] # Top 10 para a análise de Projeto/Manutenção

    return vulnerability_report, top_packages_for_project_analysis


def print_report(vulnerability_report: List[Dict[str, Any]], project_risk_data: List[Dict[str, Any]], cwe_classification: List[Tuple[str, int]]):
    """Imprime os relatórios de análise no console."""

    # 1. RELATÓRIO TOP 15 DE RISCO PONDERADO (Segurança x Influência)
    print("====================================================================================================")
    print("RELATÓRIO DE ANÁLISE DE DEPENDÊNCIAS - RISCO PONDERADO E ALCANCE (TOP 15)")
    print("====================================================================================================")
    
    header = f"{'PACOTE':<30} | {'RISCO MÁX.':<12} | {'DEPENDENTES':<15} | {'PROF. MIN.':<12} | {'RISCO POND.':<15}"
    separator = "-" * len(header)
    
    print(header)
    print(separator)
    
    for item in vulnerability_report[:15]:
        vuln_details = item.get('vulnerability_summary', [{}])[0]
        
        depth = item.get('min_dependency_depth', -1)
        depth_display = f"{depth}{' (DIRETA)' if depth == 1 else ''}" if depth >= 0 else "ISOLADO"

        print(
            f"{item['package_name']:<30} | "
            f"{item['risk_level']:<12} | "
            f"{item['in_degree_dependents']:<15} | "
            f"{depth_display:<12} | " 
            f"{item['weighted_risk_score']:.2f}{'<-- CRÍTICO' if item['risk_level'] == 'CRITICAL' else '':<15}"
        )
        
        if item.get('vulnerability_summary'):
            summary = vuln_details.get('summary') 
            
            if summary is None or not str(summary).strip():
                summary = "Sem resumo detalhado disponível."
            
            print(f"    Resumo: {str(summary)[:100]}...")
            
            cwe_list_display = ', '.join(item['cwe_ids']) if item['cwe_ids'] else '[]'
            print(f"    CWEs: {cwe_list_display}")
    
    print(separator)
    print("\n")

    # 2. ANÁLISE DE CLASSIFICAÇÃO DE RISCO (CWE)
    print("ANÁLISE DE CLASSIFICAÇÃO DE RISCO (CWE) - TOP TIPOS DE FALHA:")
    print("-" * 70)
    print(f"{'CWE CATEGORIA':<55} | {'CONTAGEM':<8}")
    print("-" * 70)
    # Mostra os resultados da classificação CWE
    for category, count in cwe_classification:
        print(f"{category:<55} | {count:<8}")
    if not cwe_classification:
        print(f"{'Nenhum CWE ID encontrado para classificação':<55} | {0:<8}")
    print("-" * 70)
    print("\n")

    # 3. ANÁLISE DE RISCO DE PROJETO (MANUTENÇÃO) - COM DADOS DE REPOSITÓRIO
    print("RISCO DE PROJETO (MANUTENÇÃO) - TOP PACOTES:")
    print("-" * 120)
    # Adicionando Estrelas e Contribuidores ao header
    header_proj = f"{'PACOTE':<30} | {'RISCO PROJ.':<15} | {'DEPENDENTES':<12} | {'ESTRELAS':<12} | {'CONTRIB.':<12} | {'STATUS DEV':<25}"
    print(header_proj)
    print("-" * 120)
    for item in project_risk_data:
        # Extrai os novos campos
        stars = item.get('repo_stars', 0)
        contributors = item.get('repo_contributors', 0)
        
        print(
            f"{item['package_name']:<30} | "
            f"{item['weighted_score']:.2f}{'':<15} | "
            f"{item['in_degree']:<12} | "
            f"{stars:<12} | " 
            f"{contributors:<12} | " 
            f"{item['dev_status'][:25]:<25}"
        )
    print("-" * 120)


def generate_cwe_histogram(cwe_classification: List[Tuple[str, int]]):
    """
    Gera um histograma (gráfico de barras) das ocorrências de CWE.
    O gráfico é salvo como 'cwe_histogram.png'.
    """
    if not cwe_classification:
        print("AVISO: Dados de classificação CWE vazios. O histograma não foi gerado.")
        return

    # Usaremos apenas os top 10 para melhor visualização
    top_cwe = cwe_classification[:10]
    
    cwe_labels = [item[0] for item in top_cwe]
    cwe_counts = [item[1] for item in top_cwe]
    
    # Utiliza o estilo do Seaborn
    sns.set_theme(style="whitegrid", palette="viridis")
    plt.figure(figsize=(14, 7))
    
    bars = plt.bar(cwe_labels, cwe_counts, color=sns.color_palette("viridis", len(cwe_labels)))

    # Adiciona rótulos de contagem nas barras
    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, yval + 0.1, int(yval), 
                 ha='center', va='bottom', fontsize=10, weight='bold')

    plt.title('Distribuição de Frequência de Tipos de Vulnerabilidade (CWE) - Top 10', 
              fontsize=16, weight='bold')
    plt.xlabel('CWE ID (Categorias de Falha)', fontsize=12)
    plt.ylabel('Contagem de Pacotes Afetados', fontsize=12)
    plt.xticks(rotation=45, ha='right')
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.tight_layout()
    
    output_file = "cwe_histogram.png"
    plt.savefig(output_file)
    plt.close() 
    
    print(f"\nHistograma de CWE gerado com sucesso: {output_file}")


# --- FUNÇÃO PRINCIPAL ---
def main():
    GRAPHML_FILE = "dependency_graph.graphml"
    
    # 1. Carregar Grafo (e seus atributos enriquecidos)
    G = load_dependency_graph(GRAPHML_FILE)
    if not G.number_of_nodes():
        print("Não foi possível processar o relatório. Verifique o arquivo do grafo.")
        return

    # 2. Analisar Riscos Iniciais (Pontuação Ponderada: Segurança x Influência)
    vulnerability_report, top_packages_for_project_analysis = analyze_risks_and_generate_report(G)
    
    if not vulnerability_report:
        print("AVISO: Nenhuma vulnerabilidade (LOW, MODERATE, HIGH ou CRITICAL) foi detectada.")
        return

    # 3. Analisar Alcance (Reachability)
    # Usa a função 'calculate_reachability_metrics' do seu Canvas
    vulnerability_report = calculate_reachability_metrics(G, vulnerability_report)

    # 4. Classificar Tipos de Risco (CWE)
    cwe_classification = analyze_risk_classification(vulnerability_report)
    
    # 5. Analisar Risco de Projeto/Manutenção (usando Estrelas/Contribuidores)
    # Chamada corrigida para lidar com a função assíncrona extract_project_risk_data
    print("\nIniciando a análise de Risco de Projeto (Manutenção) que requer chamadas externas (GitHub API)...")
    try:
        # Usa asyncio.run() para executar a função assíncrona
        project_risk_data = asyncio.run(
            extract_project_risk_data(G, top_packages_for_project_analysis, count=10)
        )
    except Exception as e:
        print(f"ERRO CRÍTICO ao executar a análise de risco de projeto assíncrona: {e}")
        project_risk_data = [] # Retorna lista vazia em caso de falha.


    # 6. Imprimir Relatório Final
    print_report(vulnerability_report, project_risk_data, cwe_classification)
    
    # 7. Gerar Visualização de Dados
    generate_cwe_histogram(cwe_classification) 

if __name__ == "__main__":
    # Garante que 'main' seja sempre executada como a função de entrada
    main()
