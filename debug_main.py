import networkx as nx
import json
import asyncio
from typing import Dict, List, Any, Tuple
# AVISO: Se você não tiver os arquivos "analysis_utils.py" e "reachability_analysis.py",
# o script falhará. Você precisa ter esses arquivos no seu diretório de trabalho.
# Se esses arquivos estiverem faltando, defina as funções como MOCKS abaixo:

try:
    # Tente importar as funções originais
    from analysis_utils import analyze_risk_classification
    from reachability_analysis import calculate_reachability_metrics
except ImportError:
    print("AVISO: analysis_utils ou reachability_analysis não encontrados. Usando MOCKS.")
    # Mocks para que o main_debug.py possa rodar
    def analyze_risk_classification(report): return [('Outras Vulnerabilidades (CWE)', 12)]
    def calculate_reachability_metrics(G, report): 
        for item in report: item['min_dependency_depth'] = 1
        return report

# Importação da função de DEBUG (Pressupõe que github_debug_util.py existe e é o mesmo)
from github_debug_util import extract_project_risk_data_debug

# --- CONFIGURAÇÕES DE PONTUAÇÃO DE RISCO ---
RISK_SCORES = {
    "LOW": 1.0, "MODERATE": 2.0, "HIGH": 4.0, "CRITICAL": 5.0,
}

def load_dependency_graph(file_path: str) -> nx.DiGraph:
    """
    Carrega o grafo de dependências e APRIMORA a leitura do 'repo_url', 
    buscando a URL dentro do JSON de vulnerabilidade se o campo principal estiver vazio.
    """
    print(f"\n[SETUP] Tentando carregar o grafo de: {file_path}")
    try:
        G = nx.read_graphml(file_path)
        print(f"[SETUP] Grafo carregado com sucesso: {G.number_of_nodes()} pacotes.")

        for node, data in G.nodes(data=True):
            raw_vuln_str = data.get('osv_vulnerabilities') or data.get('vulnerabilities')
            
            # 1. Garante que 'vulnerabilities' é uma lista
            vulnerabilities = []
            if isinstance(raw_vuln_str, str) and raw_vuln_str.strip().startswith('['):
                try:
                    vulnerabilities = json.loads(raw_vuln_str)
                    data['vulnerabilities'] = vulnerabilities
                except json.JSONDecodeError:
                    data['vulnerabilities'] = []
            elif not 'vulnerabilities' in data:
                data['vulnerabilities'] = []
            
            # 2. Tenta obter a URL de um atributo de grafo conhecido ('repo_url')
            current_repo_url = str(data.get('repo_url') or data.get('d7', 'N/A'))

            # 3. SE A URL ESTIVER FALTANDO, PROCURA NO JSON DE VULNERABILIDADE
            if 'github.com' not in current_repo_url or current_repo_url == 'N/A':
                
                # print(f"DEBUG LOAD: URL principal faltando para '{node}'. Buscando em 'vulnerabilities'.")
                
                for vuln in vulnerabilities:
                    references = vuln.get('references', [])
                    for ref in references:
                        ref_type = ref.get('type', '').upper()
                        ref_url = ref.get('url', '')
                        
                        # Prioriza PACKAGE ou REPOSITORY, mas aceita WEB se for do GitHub
                        if ('github.com' in ref_url) and (ref_type in ['PACKAGE', 'REPOSITORY', 'WEB']):
                            # print(f"DEBUG LOAD: URL do repositório ENCONTRADA dentro das vulnerabilidades (tipo: {ref_type}) para '{node}': {ref_url}")
                            current_repo_url = ref_url
                            break # Sai do loop de referências
                    if 'github.com' in current_repo_url and current_repo_url != 'N/A':
                        break # Sai do loop de vulnerabilidades

            data['repo_url'] = current_repo_url
            
            # DEBUG POINT: Verifica se a URL final foi carregada
            if 'github.com' in data['repo_url']:
                 print(f"DEBUG LOAD: URL FINAL do repositório para '{node}': {data['repo_url']}")

            # Inicializa métricas
            data['repo_stars'] = int(data.get('repo_stars', 0))
            data['repo_contributors'] = int(data.get('repo_contributors', 0))
            data['dev_status'] = data.get('dev_status', 'N/A')
            
        return G
    except FileNotFoundError:
        print(f"ERRO: Arquivo '{file_path}' não encontrado. Gere o arquivo mock.")
        return nx.DiGraph()
    except Exception as e:
        print(f"ERRO CRÍTICO ao carregar o grafo (GraphML): {e}")
        return nx.DiGraph()


def analyze_risks_and_generate_report(G: nx.DiGraph) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Calcula o risco ponderado inicial (Segurança x Influência) para cada pacote vulnerável."""
    # ... (Restante da função permanece o mesmo) ...
    vulnerability_report = []
    in_degree_map = dict(G.in_degree())

    for package_name, data in G.nodes(data=True):
        vulnerabilities = data.get('vulnerabilities', [])
        
        if vulnerabilities:
            max_risk_score = 0
            max_risk_level = "LOW"
            all_cwe_ids = set()
            vulnerability_summary = []

            for vuln in vulnerabilities:
                severity = vuln.get('database_specific', {}).get('severity', 'LOW').upper()
                score = RISK_SCORES.get(severity, 1.0)
                if score > max_risk_score:
                    max_risk_score = score
                    max_risk_level = severity
                    
                # Simplificação da extração de CWE para o mock
                all_cwe_ids.add('CWE-999')

                vulnerability_summary.append({
                    'summary': vuln.get('summary') or 'Sem resumo', 
                    'severity': severity,
                })

            in_degree = in_degree_map.get(package_name, 0)
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

    vulnerability_report.sort(key=lambda x: x['weighted_risk_score'], reverse=True)
    top_packages_for_project_analysis = vulnerability_report[:10]

    return vulnerability_report, top_packages_for_project_analysis

# --- As funções print_report e main permanecem as mesmas, 
# mas garantirão que a nova URL seja usada. ---

def print_report(vulnerability_report: List[Dict[str, Any]], project_risk_data: List[Dict[str, Any]], cwe_classification: List[Tuple[str, int]]):
    """Imprime os relatórios de análise no console."""

    # 1. RELATÓRIO TOP 15 DE RISCO PONDERADO (Segurança x Influência)
    print("\n\n" + "=" * 100)
    print("RELATÓRIO DE ANÁLISE DE DEPENDÊNCIAS - RISCO PONDERADO E ALCANCE (TOP 15)")
    print("= (ESTE RELATÓRIO PODE ESTAR INCONSISTENTE DEVIDO A MOCKS) =" + "=" * 16)
    
    header = f"{'PACOTE':<30} | {'RISCO MÁX.':<12} | {'DEPENDENTES':<15} | {'PROF. MIN.':<12} | {'RISCO POND.':<15}"
    separator = "-" * len(header)
    
    print(header)
    print(separator)
    
    for item in vulnerability_report[:15]:
        depth_display = item.get('min_dependency_depth', 1) 
        
        print(
            f"{item['package_name']:<30} | "
            f"{item['risk_level']:<12} | "
            f"{item['in_degree_dependents']:<15} | "
            f"{depth_display:<12} | " 
            f"{item['weighted_risk_score']:.2f}{'<-- CRÍTICO' if item['risk_level'] == 'CRITICAL' else '':<15}"
        )
        print(f"    Resumo: {item.get('vulnerability_summary', [{}])[0].get('summary', 'Mock Summary')}...")
        print(f"    CWEs: {', '.join(item['cwe_ids'])}")
    
    print(separator)
    print("\n")

    # 3. ANÁLISE DE RISCO DE PROJETO (MANUTENÇÃO) - COM DADOS DE REPOSITÓRIO
    print("RISCO DE PROJETO (MANUTENÇÃO) - TOP PACOTES:")
    print("-" * 120)
    header_proj = f"{'PACOTE':<30} | {'RISCO PROJ.':<15} | {'DEPENDENTES':<12} | {'ESTRELAS':<12} | {'CONTRIB.':<12} | {'STATUS DEV':<25}"
    print(header_proj)
    print("-" * 120)
    for item in project_risk_data:
        stars = item.get('repo_stars', 0)
        contributors = item.get('repo_contributors', 0)
        
        # AQUI VEM O RESULTADO DO DEBUG!
        print(
            f"{item['package_name']:<30} | "
            f"{item['weighted_score']:.2f}{'':<15} | "
            f"{item['in_degree']:<12} | "
            f"{stars:<12} | " # Se for diferente de 0, a chamada à API funcionou!
            f"{contributors:<12} | " 
            f"{item['dev_status'][:25]:<25}"
        )
    print("-" * 120)
    print("\n[DEBUGGING COMPLETO] Por favor, analise as mensagens 'DEBUG API' para o status das chamadas HTTP.")


# --- FUNÇÃO PRINCIPAL DE EXECUÇÃO ---
def main():
    GRAPHML_FILE = "dependency_graph.graphml"
    
    print("Iniciando o Main Debugging Script...")
    
    # 1. Carregar Grafo
    G = load_dependency_graph(GRAPHML_FILE)
    if not G.number_of_nodes():
        return

    # 2. Analisar Riscos Iniciais (Para gerar a lista de pacotes para a API)
    vulnerability_report, top_packages_for_project_analysis = analyze_risks_and_generate_report(G)
    
    if not vulnerability_report:
        print("AVISO: Nenhuma vulnerabilidade detectada no mock graph.")
        return

    # 3. Analisar Alcance (Chama o mock ou a função real)
    vulnerability_report = calculate_reachability_metrics(G, vulnerability_report)

    # 4. Classificar Tipos de Risco (Chama o mock ou a função real)
    cwe_classification = analyze_risk_classification(vulnerability_report)
    
    # 5. Analisar Risco de Projeto/Manutenção (usando FUNÇÃO DE DEBUG)
    print("\n" + "="*50)
    print("INICIANDO CHAMADAS EXTERNAS AO GITHUB (DEBUG)")
    print("="*50)
    try:
        # CHAMA A FUNÇÃO DE DEBUG COM EXTENSO LOGGING
        project_risk_data = asyncio.run(
            extract_project_risk_data_debug(G, top_packages_for_project_analysis, count=5) # Limitado a 5 para poupar o rate limit
        )
    except Exception as e:
        print(f"ERRO CRÍTICO ao executar a análise de risco de projeto assíncrona (DEBUG): {e}")
        project_risk_data = []


    # 6. Imprimir Relatório Final (com os novos dados de Estrelas/Contribuidores)
    print_report(vulnerability_report, project_risk_data, cwe_classification)
    
if __name__ == "__main__":
    main()
