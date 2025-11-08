import networkx as nx
import json
import re
from typing import Dict, List, Any, Tuple
import matplotlib.pyplot as plt
import seaborn as sns 
import asyncio

# Import functions from utility files
from analysis_utils import analyze_risk_classification, extract_project_risk_data
from reachability_analysis import calculate_reachability_metrics

# --- RISK SCORING CONFIGURATION ---
RISK_SCORES = {
    "LOW": 1.0,
    "MODERATE": 2.0,
    "HIGH": 4.0,
    "CRITICAL": 5.0,
}

def extract_github_url_from_vulnerabilities(vulnerabilities: List[Dict[str, Any]]) -> str:
    """
    Extract GitHub repository URL from vulnerability references.
    Prioritizes PACKAGE and REPOSITORY type references.
    """
    if not vulnerabilities:
        return ""
    
    for vuln in vulnerabilities:
        references = vuln.get('references', [])
        
        # First pass: Look for PACKAGE or REPOSITORY types
        for ref in references:
            ref_type = ref.get('type', '').upper()
            ref_url = ref.get('url', '')
            
            if 'github.com' in ref_url.lower() and ref_type in ['PACKAGE', 'REPOSITORY']:
                # Extract base repository URL (remove /issues, /commit, etc.)
                match = re.match(r'(https?://github\.com/[^/]+/[^/]+)', ref_url, re.IGNORECASE)
                if match:
                    clean_url = match.group(1)
                    print(f"      Found repo URL (type: {ref_type}): {clean_url}")
                    return clean_url
        
        # Second pass: Accept WEB type if it's a direct GitHub repo
        for ref in references:
            ref_type = ref.get('type', '').upper()
            ref_url = ref.get('url', '')
            
            if 'github.com' in ref_url.lower():
                # Make sure it's not a commit, issue, or pull request
                if not any(x in ref_url.lower() for x in ['/commit/', '/issues/', '/pull/', '/wiki/', '/blob/']):
                    match = re.match(r'(https?://github\.com/[^/]+/[^/]+)', ref_url, re.IGNORECASE)
                    if match:
                        clean_url = match.group(1)
                        print(f"      Found repo URL (type: {ref_type}): {clean_url}")
                        return clean_url
    
    return ""


def load_dependency_graph(file_path: str) -> nx.DiGraph:
    """
    Load dependency graph from GraphML file.
    ENHANCED: Extracts repository URLs from vulnerability data if not present in node attributes.
    """
    try:
        G = nx.read_graphml(file_path)
        print(f"Grafo carregado com sucesso: {G.number_of_nodes()} pacotes.")

        urls_extracted_from_vulns = 0
        urls_already_present = 0
        
        for node, data in G.nodes(data=True):
            raw_vuln_str = ''
            
            # --- Parse Vulnerabilities (ensure JSON string is loaded as List) ---
            # NetworkX may save lists as strings in GraphML with generic keys (d1, d6, etc.)
            
            # Try to find JSON string in various common keys
            if isinstance(data.get('osv_vulnerabilities'), str) and data['osv_vulnerabilities'].strip().startswith('['):
                raw_vuln_str = data['osv_vulnerabilities']
            elif isinstance(data.get('vulnerabilities'), str) and data['vulnerabilities'].strip().startswith('['):
                raw_vuln_str = data['vulnerabilities']
            # Generic keys that NetworkX might use (for robustness)
            elif isinstance(data.get('d6'), str) and data['d6'].strip().startswith('['):
                raw_vuln_str = data['d6']
            elif isinstance(data.get('d1'), str) and data['d1'].strip().startswith('['):
                raw_vuln_str = data['d1']
            elif isinstance(data.get('d2'), str) and data['d2'].strip().startswith('['):
                raw_vuln_str = data['d2']
            
            # Process found JSON string
            vulnerabilities = []
            if raw_vuln_str and raw_vuln_str != 'ALREADY_PROCESSED':
                try:
                    vulnerabilities = json.loads(raw_vuln_str)
                    data['vulnerabilities'] = vulnerabilities
                except json.JSONDecodeError:
                    data['vulnerabilities'] = []
            elif not 'vulnerabilities' in data or raw_vuln_str == 'ALREADY_PROCESSED':
                if not isinstance(data.get('vulnerabilities'), list):
                    data['vulnerabilities'] = []
            else:
                vulnerabilities = data.get('vulnerabilities', [])

            # --- ENHANCED: Repository URL Extraction ---
            # Get existing repo_url from graph
            current_repo_url = data.get('repo_url', 'N/A')
            
            # Also check other possible keys where URL might be stored
            if current_repo_url == 'N/A' or not current_repo_url:
                for key in ['d7', 'd8', 'd9', 'd10']:
                    potential_url = data.get(key, '')
                    if potential_url and 'github.com' in potential_url:
                        current_repo_url = potential_url
                        break
            
            # If we still don't have a valid GitHub URL, extract from vulnerabilities
            if current_repo_url == 'N/A' or not current_repo_url or 'github.com' not in current_repo_url:
                if vulnerabilities:
                    print(f"   Extracting URL for: {node}")
                    extracted_url = extract_github_url_from_vulnerabilities(vulnerabilities)
                    if extracted_url:
                        current_repo_url = extracted_url
                        urls_extracted_from_vulns += 1
            else:
                if 'github.com' in current_repo_url:
                    urls_already_present += 1
            
            # Store final URL
            data['repo_url'] = current_repo_url

            # --- Initialize/Convert NEW Repository Attributes ---
            data['repo_stars'] = int(data.get('repo_stars', 0))
            data['repo_contributors'] = int(data.get('repo_contributors', 0))
            data['dev_status'] = data.get('dev_status', 'N/A')

            # Clean up raw keys that are no longer needed
            for key in ['d1', 'd2', 'd6', 'd7', 'd8', 'd9', 'd10']:
                if key in data:
                    del data[key]
        
        print(f"\n📊 URL Extraction Summary:")
        print(f"   ✅ URLs already in graph: {urls_already_present}")
        print(f"   🔍 URLs extracted from vulnerabilities: {urls_extracted_from_vulns}")
        print(f"   📝 Total packages with GitHub URLs: {urls_already_present + urls_extracted_from_vulns}\n")
        
        return G
    except Exception as e:
        print(f"Erro ao carregar o grafo (GraphML): {e}")
        import traceback
        traceback.print_exc()
        return nx.DiGraph()


def analyze_risks_and_generate_report(G: nx.DiGraph) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Calculate initial weighted risk (Security x Influence) for each vulnerable package.
    """
    vulnerability_report = []
    
    # 1. Calculate In-Degree for all nodes (number of dependents)
    in_degree_map = dict(G.in_degree())

    for package_name, data in G.nodes(data=True):
        vulnerabilities = data.get('vulnerabilities', [])
        
        if vulnerabilities:
            max_risk_score = 0
            max_risk_level = "LOW"
            
            all_cwe_ids = set()
            vulnerability_summary = []

            for vuln in vulnerabilities:
                # Determine severity level and score
                severity = vuln.get('database_specific', {}).get('severity', 'LOW').upper()
                score = RISK_SCORES.get(severity, 1.0)
                
                if score > max_risk_score:
                    max_risk_score = score
                    max_risk_level = severity
                    
                # --- CWE ID Collection and Normalization Logic ---
                vuln_cwe_ids_raw = vuln.get('database_specific', {}).get('cwe_ids', []) or \
                                   vuln.get('cwe_ids', []) or \
                                   vuln.get('cwe', [])
                    
                for cwe_id in vuln_cwe_ids_raw:
                    if isinstance(cwe_id, str):
                        cwe_id_upper = cwe_id.strip().upper()
                        if cwe_id_upper.startswith('CWE-'):
                            all_cwe_ids.add(cwe_id_upper)

                # Vulnerability summary for detailed report
                vulnerability_summary.append({
                    'id': vuln.get('id', 'N/A'),
                    'summary': vuln.get('summary') or 'Sem resumo', 
                    'severity': severity,
                    'cwe_ids': vuln_cwe_ids_raw
                })

            in_degree = in_degree_map.get(package_name, 0)
            
            # Weighted risk: multiply risk score by influence (sqrt of dependents)
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

    # 2. Sort report by Weighted Risk
    vulnerability_report.sort(key=lambda x: x['weighted_risk_score'], reverse=True)
    
    # Separate most risky packages (Top N) for project/maintenance risk analysis
    top_packages_for_project_analysis = vulnerability_report[:10]

    return vulnerability_report, top_packages_for_project_analysis


def print_report(vulnerability_report: List[Dict[str, Any]], project_risk_data: List[Dict[str, Any]], cwe_classification: List[Tuple[str, int]]):
    """Print analysis reports to console."""

    # 1. TOP 15 WEIGHTED RISK REPORT (Security x Influence)
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

    # 2. CWE RISK CLASSIFICATION ANALYSIS
    print("ANÁLISE DE CLASSIFICAÇÃO DE RISCO (CWE) - TOP TIPOS DE FALHA:")
    print("-" * 70)
    print(f"{'CWE CATEGORIA':<55} | {'CONTAGEM':<8}")
    print("-" * 70)
    for category, count in cwe_classification:
        print(f"{category:<55} | {count:<8}")
    if not cwe_classification:
        print(f"{'Nenhum CWE ID encontrado para classificação':<55} | {0:<8}")
    print("-" * 70)
    print("\n")

    # 3. PROJECT RISK (MAINTENANCE) ANALYSIS - WITH REPOSITORY DATA
    print("RISCO DE PROJETO (MANUTENÇÃO) - TOP PACOTES:")
    print("-" * 120)
    header_proj = f"{'PACOTE':<30} | {'RISCO PROJ.':<15} | {'DEPENDENTES':<12} | {'ESTRELAS':<12} | {'CONTRIB.':<12} | {'STATUS DEV':<25}"
    print(header_proj)
    print("-" * 120)
    for item in project_risk_data:
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
    """Generate histogram (bar chart) of CWE occurrences."""
    if not cwe_classification:
        print("AVISO: Dados de classificação CWE vazios. O histograma não foi gerado.")
        return

    top_cwe = cwe_classification[:10]
    
    cwe_labels = [item[0] for item in top_cwe]
    cwe_counts = [item[1] for item in top_cwe]
    
    sns.set_theme(style="whitegrid", palette="viridis")
    plt.figure(figsize=(14, 7))
    
    bars = plt.bar(cwe_labels, cwe_counts, color=sns.color_palette("viridis", len(cwe_labels)))

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


# --- MAIN FUNCTION ---
def main():
    GRAPHML_FILE = "dependency_graph.graphml"
    
    # 1. Load Graph (with enhanced URL extraction)
    G = load_dependency_graph(GRAPHML_FILE)
    if not G.number_of_nodes():
        print("Não foi possível processar o relatório. Verifique o arquivo do grafo.")
        return

    # 2. Analyze Initial Risks (Weighted Score: Security x Influence)
    vulnerability_report, top_packages_for_project_analysis = analyze_risks_and_generate_report(G)
    
    if not vulnerability_report:
        print("AVISO: Nenhuma vulnerabilidade (LOW, MODERATE, HIGH ou CRITICAL) foi detectada.")
        return

    # 3. Analyze Reachability
    vulnerability_report = calculate_reachability_metrics(G, vulnerability_report)

    # 4. Classify Risk Types (CWE)
    cwe_classification = analyze_risk_classification(vulnerability_report)
    
    # 5. Analyze Project/Maintenance Risk (using Stars/Contributors)
    print("\nIniciando a análise de Risco de Projeto (Manutenção) que requer chamadas externas (GitHub API)...")
    try:
        project_risk_data = asyncio.run(
            extract_project_risk_data(G, top_packages_for_project_analysis, count=10)
        )
    except Exception as e:
        print(f"ERRO CRÍTICO ao executar a análise de risco de projeto assíncrona: {e}")
        import traceback
        traceback.print_exc()
        project_risk_data = []

    # 6. Print Final Report
    print_report(vulnerability_report, project_risk_data, cwe_classification)
    
    # 7. Generate Data Visualization
    generate_cwe_histogram(cwe_classification) 

if __name__ == "__main__":
    main()