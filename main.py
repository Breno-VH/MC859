import networkx as nx
import json
import random
from typing import Dict, List, Any, Tuple
from analysis_utils import analyze_risk_classification, extract_project_risk_data # Importando funções de análise

# --- CONFIGURAÇÕES DE PONTUAÇÃO DE RISCO ---
RISK_SCORES = {
    "LOW": 1.0,
    "MODERATE": 2.0,
    "HIGH": 4.0,
    "CRITICAL": 5.0,
}

def load_dependency_graph(file_path: str) -> nx.DiGraph:
    """
    Carrega o grafo de dependências a partir de um arquivo GraphML, garantindo que o 
    JSON de vulnerabilidades seja deserializado corretamente, buscando em várias chaves
    comuns do NetworkX/GraphML.
    """
    try:
        G = nx.read_graphml(file_path)
        print(f"Grafo carregado com sucesso: {G.number_of_nodes()} pacotes.")

        for node, data in G.nodes(data=True):
            raw_vuln_str = ''
            
            # Tenta encontrar a string JSON bruta em 4 locais comuns:
            # 1. Chave semântica (se o NetworkX a preservou)
            if isinstance(data.get('osv_vulnerabilities'), str) and data['osv_vulnerabilities'].strip().startswith('['):
                 raw_vuln_str = data['osv_vulnerabilities']
            
            # 2. Chave 'vulnerabilities' (Outra chave semântica comum)
            if not raw_vuln_str and isinstance(data.get('vulnerabilities'), str) and data['vulnerabilities'].strip().startswith('['):
                raw_vuln_str = data['vulnerabilities']
                
            # 3. Chave genérica 'd6' (Muitas vezes usada pelo NetworkX para JSON)
            if not raw_vuln_str and isinstance(data.get('d6'), str) and data['d6'].strip().startswith('['):
                raw_vuln_str = data['d6']
                
            # 4. Chave genérica 'd1' (Outra chave genérica comum)
            if not raw_vuln_str and isinstance(data.get('d1'), str) and data['d1'].strip().startswith('['):
                raw_vuln_str = data['d1']

            # Processar a string JSON encontrada
            if raw_vuln_str:
                try:
                    # Armazena na chave limpa 'vulnerabilities' para o restante do pipeline
                    data['vulnerabilities'] = json.loads(raw_vuln_str)
                except json.JSONDecodeError:
                    # Se falhar, garante que o atributo seja uma lista vazia
                    data['vulnerabilities'] = []
            else:
                data['vulnerabilities'] = []

            # Limpa as chaves brutas que não são mais necessárias
            if 'osv_vulnerabilities' in data: del data['osv_vulnerabilities']
            if 'd6' in data: del data['d6']
            if 'd1' in data: del data['d1']
            
        return G
    except Exception as e:
        print(f"Erro ao carregar o grafo (GraphML): {e}")
        return nx.DiGraph()


def analyze_risks_and_generate_report(G: nx.DiGraph) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Calcula o risco ponderado para cada pacote vulnerável e gera um relatório.
    """
    vulnerability_report = []
    
    # 1. Calcular o In-Degree para todos os nós (número de dependentes)
    in_degree_map = dict(G.in_degree())

    for package_name, data in G.nodes(data=True):
        # data['vulnerabilities'] é agora garantido como uma lista de dicionários (ou vazia)
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
                    
                # --- LÓGICA DE COLETA E NORMALIZAÇÃO DE CWE IDs ---
                # Esta lógica é robusta, buscando nos 3 campos comuns da OSV
                
                vuln_cwe_ids_raw = vuln.get('database_specific', {}).get('cwe_ids', [])
                if not vuln_cwe_ids_raw:
                    vuln_cwe_ids_raw = vuln.get('cwe_ids', [])
                if not vuln_cwe_ids_raw:
                    vuln_cwe_ids_raw = vuln.get('cwe', [])
                    
                for cwe_id in vuln_cwe_ids_raw:
                    if isinstance(cwe_id, str):
                        cwe_id_upper = cwe_id.strip().upper()
                        
                        if cwe_id_upper.startswith('CWE-'):
                            all_cwe_ids.add(cwe_id_upper)
                        elif cwe_id_upper.isdigit():
                            all_cwe_ids.add(f'CWE-{cwe_id_upper}')
                        elif cwe_id_upper:
                            all_cwe_ids.add(cwe_id_upper)

                # Resumo das vulnerabilidades para o relatório detalhado
                vulnerability_summary.append({
                    'id': vuln.get('id', 'N/A'),
                    'summary': vuln.get('summary') or 'Sem resumo', 
                    'severity': severity,
                    'cwe_ids': vuln_cwe_ids_raw
                })


            in_degree = in_degree_map.get(package_name, 0)
            
            # Risco ponderado: multiplica a pontuação de risco pela influência (log(dependentes))
            weighted_risk_score = max_risk_score * (1 + (in_degree ** 0.5))

            vulnerability_report.append({
                'package_name': package_name,
                'max_risk_score': max_risk_score,
                'risk_level': max_risk_level,
                'in_degree_dependents': in_degree,
                'weighted_risk_score': weighted_risk_score,
                'cwe_ids': list(all_cwe_ids), # Lista única e normalizada de CWE IDs para classificação
                'vulnerability_summary': vulnerability_summary,
            })

    # 2. Ordenar o relatório pelo Risco Ponderado
    vulnerability_report.sort(key=lambda x: x['weighted_risk_score'], reverse=True)
    
    # Separar os pacotes mais arriscados (Top 5) para a análise de risco de projeto
    top_packages_for_project_analysis = vulnerability_report[:5]

    return vulnerability_report, top_packages_for_project_analysis


def print_packages_with_cwe(vulnerability_report: List[Dict[str, Any]]):
    """
    Imprime um relatório detalhado de pacotes que conseguiram ter CWE IDs extraídos.
    """
    
    packages_with_cwe = [
        item for item in vulnerability_report 
        if item['cwe_ids']
    ]

    print("\n====================================================================================================")
    print("--- DETALHE: PACOTES VULNERÁVEIS COM CWE ID REGISTRADO (TODOS OS NÍVEIS) ---")
    
    if packages_with_cwe:
        packages_with_cwe.sort(key=lambda x: x['weighted_risk_score'], reverse=True)
        
        print(f"Total de {len(packages_with_cwe)} itens com CWE IDs válidos encontrados:")
        
        header = f"\n{'PACOTE':<30} | {'RISCO MÁX.':<12} | {'RISCO POND.':<12} | {'CWE IDs':<40}"
        print("-" * len(header))
        print(header)
        print("-" * len(header))

        for item in packages_with_cwe[:10]:
            cwe_list_display = ', '.join(item['cwe_ids'])
            
            print(
                f"{item['package_name']:<30} | "
                f"{item['risk_level']:<12} | "
                f"{item['weighted_risk_score']:.2f}{'':<12} | "
                f"{cwe_list_display:<40}"
            )
            summary = item.get('vulnerability_summary', [{}])[0].get('summary', 'Sem resumo detalhado disponível.')
            print(f"    Resumo (Primeira Vuln): {str(summary)[:100]}...")
            print("-" * len(header))
        
        if len(packages_with_cwe) > 10:
             print(f"... e mais {len(packages_with_cwe) - 10} pacotes com CWE ID registrado.")
    else:
        print("Nenhum pacote vulnerável com CWE ID válido encontrado nos dados de entrada.")
        print("\n--- AVISO DE DADOS FALTANTES ---")
        print("A ausência de CWE IDs indica que o campo 'cwe_ids' está faltando ou é inválido nos dados de vulnerabilidade do GraphML.")
        print("---------------------------------")

    print("====================================================================================================")


def print_report(vulnerability_report: List[Dict[str, Any]], project_risk_data: List[Dict[str, str]], cwe_classification: List[Tuple[str, int]]):
    """Imprime os relatórios de análise no console."""

    # 1. RELATÓRIO TOP 15 DE RISCO PONDERADO
    print("====================================================================================================")
    print("RELATÓRIO DE ANÁLISE DE DEPENDÊNCIAS - RISCO PONDERADO (TOP 15)")
    print("====================================================================================================")
    
    header = f"{'PACOTE':<30} | {'VERSÃO ATINGIDA':<20} | {'RISCO MÁX.':<12} | {'DEPENDENTES':<15} | {'RISCO POND.':<15}"
    separator = "-" * len(header)
    
    print(header)
    print(separator)
    
    for item in vulnerability_report[:15]:
        vuln_details = item.get('vulnerability_summary', [{}])[0]
        version_display = f"({item['package_name']} vulnerável)"

        print(
            f"{item['package_name']:<30} | "
            f"{version_display:<20} | "
            f"{item['risk_level']:<12} | "
            f"{item['in_degree_dependents']:<15} | "
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
    print("-" * 50)
    print(f"{'CWE CATEGORIA':<40} | {'CONTAGEM':<8}")
    print("-" * 50)
    # Mostra os resultados da classificação CWE
    for category, count in cwe_classification:
        print(f"{category:<40} | {count:<8}")
    if not cwe_classification:
        print(f"{'Nenhum CWE ID encontrado para classificação':<40} | {0:<8}")
    print("-" * 50)
    print("\n")

    # 3. ANÁLISE DE RISCO DE PROJETO (MANUTENÇÃO)
    print("RISCO DE PROJETO (MANUTENÇÃO) - TOP 5 PACOTES:")
    print("-" * 80)
    print(f"{'PACOTE':<30} | {'SCORE':<7} | {'DEPENDENTES':<12} | {'STATUS DEV':<25}")
    print("-" * 80)
    for item in project_risk_data:
        print(
            f"{item['package_name']:<30} | "
            f"{item['weighted_score']:.2f}{'':<7} | "
            f"{item['in_degree']:<12} | "
            f"{item['dev_status']:<25}"
        )
    print("-" * 80)


# --- FUNÇÃO PRINCIPAL ---
def main():
    GRAPHML_FILE = "dependency_graph.graphml"
    
    # 1. Carregar Grafo
    G = load_dependency_graph(GRAPHML_FILE)
    if not G.number_of_nodes():
        print("Não foi possível processar o relatório. Verifique o arquivo do grafo.")
        return

    # 2. Analisar Riscos
    vulnerability_report, top_packages_for_project_analysis = analyze_risks_and_generate_report(G)
    
    if not vulnerability_report:
        print("Nenhuma vulnerabilidade crítica ou de alto risco encontrada para relatar.")
        return

    # =========================================================================
    # 3. SEÇÃO DE DEBUG PARA ENCONTRAR ITENS SEM CWE ID
    # =========================================================================
    print("\n====================================================================================================")
    print("--- DEBUG: ITENS DE ALTO/CRÍTICO RISCO SEM CWE ID ---")
    
    high_or_critical_items = [
        item for item in vulnerability_report 
        if item['risk_level'] in ['HIGH', 'CRITICAL']
    ]
    
    no_cwe_items = [
        item for item in vulnerability_report 
        if item['risk_level'] in ['HIGH', 'CRITICAL'] and not item['cwe_ids']
    ]
    
    if not high_or_critical_items:
         print("NOTA: Nenhum pacote foi classificado como ALTO ou CRÍTICO. O sucesso abaixo é trivial.")

    if no_cwe_items:
        print(f"Total de {len(no_cwe_items)} itens de ALTO/CRÍTICO risco sem CWE ID registrado no 'vulnerability_report':")
        for item in no_cwe_items:
            print(f"- Pacote: {item['package_name']} | Risco: {item['risk_level']} | Score: {item['weighted_risk_score']:.2f}")
            
            for idx, vuln in enumerate(item.get('vulnerability_summary', [])):
                cwe_list_display = ', '.join(vuln.get('cwe_ids', [])) if vuln.get('cwe_ids') else '[]'
                print(f"  > Vuln {idx+1} ({vuln.get('id', 'N/A')}): CWEs coletados (RAW): {cwe_list_display}")

            print("---")
    else:
        print("SUCESSO: Todos os itens de alto risco contêm pelo menos um CWE ID (normalizado).")
    
    print("====================================================================================================")
    
    # =========================================================================
    # 4. SEÇÃO ADICIONAL: PACOTES COM CWE ID REGISTRADO (ENCONTRADOS)
    # =========================================================================
    print_packages_with_cwe(vulnerability_report)
    
    # 5. Classificar e Extrair Dados Adicionais
    cwe_classification = analyze_risk_classification(vulnerability_report)
    project_risk_data = extract_project_risk_data(G, top_packages_for_project_analysis, count=5)

    # 6. Imprimir Relatório Final (TOP 15, CWE CLASSIFICATION, PROJETO)
    print_report(vulnerability_report, project_risk_data, cwe_classification)

if __name__ == "__main__":
    main()
