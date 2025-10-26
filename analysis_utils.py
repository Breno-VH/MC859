import json
import networkx as nx # Adicionando import para o tipo de G
from typing import List, Dict, Any, Tuple
from collections import Counter

# Mapeamento de CWE IDs comuns para categorias legíveis.
# Baseado na CWE Top 25 e nos erros de software mais frequentes.
CWE_MAPPING = {
    # ------------------------------------------------------------------
    # INJEÇÃO E EXECUÇÃO DE CÓDIGO (Injection & Code Execution)
    # ------------------------------------------------------------------
    "CWE-77": "Command and Argument Injection",
    "CWE-78": "OS Command Injection",
    "CWE-89": "SQL Injection",
    "CWE-94": "Code Injection",
    "CWE-116": "Improper Encoding or Escaping",
    "CWE-434": "Unrestricted Upload of File with Dangerous Type",
    "CWE-502": "Deserialization of Untrusted Data (RCE)",
    "CWE-918": "Server-Side Request Forgery (SSRF)",

    # ------------------------------------------------------------------
    # PROBLEMAS DE VALIDAÇÃO E XSS (Input Validation & XSS)
    # ------------------------------------------------------------------
    "CWE-20": "Improper Input Validation",
    "CWE-79": "Cross-Site Scripting (XSS)",
    "CWE-134": "Use of Externally-Controlled Format String",
    "CWE-601": "URL Redirection to Untrusted Site (Open Redirect)",
    "CWE-611": "Improper Restriction of XML External Entity Reference (XXE)",
    
    # ------------------------------------------------------------------
    # SEGURANÇA DE MEMÓRIA E BUFFER (Memory/Buffer Safety)
    # ------------------------------------------------------------------
    "CWE-119": "Improper Restriction of Memory Buffer Operations",
    "CWE-120": "Buffer Overflow",
    "CWE-125": "Out-of-bounds Read",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-416": "Use After Free",
    "CWE-787": "Out-of-bounds Write",
    
    # ------------------------------------------------------------------
    # AUTENTICAÇÃO, AUTORIZAÇÃO E SESSÃO (Auth/Authz/Session)
    # ------------------------------------------------------------------
    "CWE-287": "Improper Authentication",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-862": "Missing Authorization",
    "CWE-22": "Path Traversal",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-269": "Improper Privilege Management",
    "CWE-732": "Incorrect Permission Assignment for Critical Resource",
    
    # ------------------------------------------------------------------
    # EXPOSIÇÃO DE INFORMAÇÃO E CONFIGURAÇÃO (Info Exposure & Config)
    # ------------------------------------------------------------------
    "CWE-200": "Information Exposure",
    "CWE-312": "Cleartext Storage of Sensitive Information",
    "CWE-522": "Missing Protection for Sensitive Data (e.g., Password)", # Adicionado CWE-522
    "CWE-532": "Information Exposure (Secrets/Logs)",
    "CWE-668": "Exposure of Resource to Wrong Sphere",
    
    # ------------------------------------------------------------------
    # OUTRAS FALHAS DE DESIGN E CONCORRÊNCIA
    # ------------------------------------------------------------------
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-362": "Race Condition",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-754": "Improper Check for Unusual or Exceptional Conditions",
}

def get_cwe_category(cwe_id: str) -> str:
    """Retorna a categoria legível de um CWE ID ou 'Outras' se não mapeado."""
    return CWE_MAPPING.get(cwe_id, "Outras (Não mapeado)")


def analyze_risk_classification(vulnerability_report: List[Dict[str, Any]]) -> List[Tuple[str, int]]:
    """
    Classifica as vulnerabilidades por tipo de CWE e retorna a contagem dos principais tipos de falha.
    """
    cwe_counts = {}
    for item in vulnerability_report:
        for cwe_id in item.get('cwe_ids', []):
            # Normaliza o CWE para a categoria principal (ex: CWE-59/CWE-61)
            # Como a normalização ocorre em main.py, a string aqui já deve ser "CWE-XXX"
            category = cwe_id 
            cwe_counts[category] = cwe_counts.get(category, 0) + 1
            
    # Converte para lista de tuplas e ordena pela contagem
    sorted_cwe = sorted(cwe_counts.items(), key=lambda item: item[1], reverse=True)

    # Retorna apenas o Top 10
    return sorted_cwe[:10]

def extract_project_risk_data(G: nx.DiGraph, top_packages_report: List[Dict[str, Any]], count: int = 5) -> List[Dict[str, str]]:
    """
    Extrai informações de risco de projeto/manutenção para os pacotes de maior risco.
    """
    project_risk_data = []
    
    # Processa apenas os 'count' pacotes de maior risco
    for item in top_packages_report[:count]:
        package_name = item['package_name']
        data = G.nodes[package_name]
        
        # Simula a extração de status de desenvolvimento do PyPI (campo 'classifiers' no GraphML)
        classifiers = data.get('classifiers')
        dev_status = "Não Informado (PyPI)"
        
        # Tenta extrair o status de desenvolvimento dos classificadores
        if isinstance(classifiers, str):
            try:
                classifier_list = json.loads(classifiers)
                for classifier in classifier_list:
                    if 'Development Status ::' in classifier:
                        dev_status = classifier.split('::')[-1].strip()
                        break
            except json.JSONDecodeError:
                pass 
        
        project_risk_data.append({
            'package_name': package_name,
            # 'weighted_score' é o score que já foi calculado em main.py
            'weighted_score': item['weighted_risk_score'],
            'in_degree': item['in_degree_dependents'],
            'dev_status': dev_status,
        })
        
    return project_risk_data

