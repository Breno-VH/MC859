import httpx
import os
import asyncio
from typing import List, Dict, Any, Tuple
import networkx as nx

# --- CONFIGURAÇÃO ---
# TOKEN DE ACESSO PESSOAL (PAT) DO GITHUB: 
# Por favor, crie esta variável de ambiente ou substitua "SEU_TOKEN_AQUI_PARA_TESTE"
# por um token real para evitar o limite de taxa (rate limiting) de 60 requisições/hora.
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")

MAX_RETRIES = 3
INITIAL_DELAY = 1.0 # 1 segundo

# --- FUNÇÕES AUXILIARES ---

def parse_repo_details(repo_url: str) -> Tuple[str, str] | Tuple[None, None]:
    """
    Analisa o URL do GitHub para extrair o proprietário e o nome do repositório.
    """
    if not repo_url or 'github.com' not in repo_url:
        print(f"DEBUG PARSING: URL não é do GitHub ou está vazia: {repo_url}")
        return None, None
    
    # Remove o prefixo http/https, www e o .git final
    cleaned_url = repo_url.replace('https://', '').replace('http://', '').replace('www.', '').replace('.git', '')
    
    # Divide pelos segmentos (ex: ['github.com', 'owner', 'repo'])
    parts = [p for p in cleaned_url.split('/') if p]
    
    # Garante que temos 'github.com' e pelo menos mais dois segmentos
    if len(parts) >= 3 and parts[0] == 'github.com':
        owner = parts[1]
        repo = parts[2]
        print(f"DEBUG PARSING: URL '{repo_url}' analisada com sucesso -> Proprietário: '{owner}', Repositório: '{repo}'")
        return owner, repo
        
    print(f"DEBUG PARSING: Falha na análise da estrutura do URL: {repo_url}")
    return None, None


async def fetch_github_metrics_debug(package_name: str, repo_url: str, client: httpx.AsyncClient) -> Tuple[int, int]:
    """
    Função assíncrona com logging detalhado para obter estrelas e contribuidores.
    Retorna (stars, contributors).
    """
    owner, repo = parse_repo_details(repo_url)

    if owner is None or repo is None:
        print(f"DEBUG API: Pacote '{package_name}' pulado. Não foi possível analisar o URL do repositório.")
        return 0, 0
    
    api_url = f"https://api.github.com/repos/{owner}/{repo}"
    
    headers = {}
    if GITHUB_TOKEN and GITHUB_TOKEN != "SEU_TOKEN_AQUI_PARA_TESTE":
        headers['Authorization'] = f"token {GITHUB_TOKEN}"
        print(f"DEBUG API: Usando Token para chamada: {api_url}")
    else:
        print(f"DEBUG API: Nenhum Token encontrado/usado. Usando limite de taxa não autenticado (60 req/h): {api_url}")
    
    delay = INITIAL_DELAY
    for attempt in range(MAX_RETRIES):
        try:
            response = await client.get(api_url, headers=headers)
            
            # --- PONTO DE VERIFICAÇÃO 1: STATUS DA RESPOSTA ---
            if response.status_code == 200:
                data = response.json()
                stars = data.get('stargazers_count', 0)
                # Usando forks_count como proxy para Contribuidores para simplificar o debug
                contributors_proxy = data.get('forks_count', 0) 
                
                print(f"DEBUG SUCESSO: Pacote '{package_name}' - Status 200 OK. Estrelas: {stars}, Proxy Contribuidores: {contributors_proxy}")
                return stars, contributors_proxy
            
            elif response.status_code == 404:
                print(f"DEBUG ERRO 404: Pacote '{package_name}'. Repositório não encontrado: {api_url}")
                return 0, 0
            
            elif response.status_code == 403:
                # Geralmente Rate Limit ou acesso proibido
                rate_limit = response.headers.get('X-RateLimit-Remaining', 'N/A')
                print(f"DEBUG ERRO 403: Rate Limit ou Proibido para '{package_name}'. Tentativa {attempt + 1}/{MAX_RETRIES}. Limite restante: {rate_limit}")
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(delay)
                    delay *= 2
                else:
                    print(f"DEBUG ERRO: Máximo de retries atingido para {package_name}.")
                    return 0, 0
            else:
                print(f"DEBUG ERRO HTTP: Pacote '{package_name}' - Status {response.status_code}: {response.text}")
                return 0, 0

        except httpx.ConnectError as e:
            # Erro de rede ou DNS
            print(f"DEBUG ERRO CONEXÃO: Pacote '{package_name}'. Tentativa {attempt + 1}/{MAX_RETRIES}. Erro: {e}")
            if attempt < MAX_RETRIES - 1:
                await asyncio.sleep(delay)
                delay *= 2
            else:
                return 0, 0
        except Exception as e:
            print(f"DEBUG ERRO INESPERADO: Pacote '{package_name}'. Erro: {e}")
            return 0, 0
    
    return 0, 0


async def extract_project_risk_data_debug(
    G: nx.DiGraph, 
    vulnerability_report: List[Dict[str, Any]], 
    count: int = 10
) -> List[Dict[str, Any]]:
    """
    Versão de Debug da função para extrair dados de risco de projeto/manutenção
    incluindo métricas do GitHub (estrelas e contribuidores) de forma assíncrona.
    """
    print("\n[GITHUB API DEBUG] Iniciando busca assíncrona de métricas de manutenção com logging...")
    
    packages_to_check = vulnerability_report[:count]
    tasks = []
    
    async with httpx.AsyncClient(timeout=10.0) as client:
        
        for item in packages_to_check:
            package_name = item['package_name']
            
            node_data = G.nodes.get(package_name, {})
            # A chave 'repo_url' deve ser carregada corretamente pelo load_dependency_graph
            repo_url = node_data.get('repo_url', '') 
            
            if repo_url:
                print(f"DEBUG SETUP: Pacote '{package_name}' - URL encontrada no nó: {repo_url}")
                task = fetch_github_metrics_debug(package_name, repo_url, client)
                tasks.append(task)
            else:
                print(f"DEBUG SETUP: Pacote '{package_name}' - Sem URL de repositório no nó. Usando 0.")
                tasks.append(asyncio.sleep(0, result=(0, 0)))

        results = await asyncio.gather(*tasks)

    project_risk_data = []
    for i, item in enumerate(packages_to_check):
        stars, contributors = results[i]
        
        item['repo_stars'] = stars
        item['repo_contributors'] = contributors
        
        in_degree = item.get('in_degree_dependents', 0)
        
        # Fórmula de risco de Manutenção (simples, alto risco se a manutenção for baixa)
        complexity_metric = stars + contributors
        maintenance_score = 100 / (1 + complexity_metric**0.5) 
        weighted_score = maintenance_score * (1 + in_degree ** 0.5)
        
        item['weighted_score'] = weighted_score
        item['in_degree'] = in_degree
        item['dev_status'] = G.nodes.get(item['package_name'], {}).get('dev_status', 'N/A')
        
        project_risk_data.append(item)
        
        print(f"DEBUG RESULTADO FINAL: Pacote '{item['package_name']}' - Estrelas: {stars}, Score Ponderado (Manutenção): {weighted_score:.2f}")

    project_risk_data.sort(key=lambda x: x['weighted_score'], reverse=True)

    return project_risk_data
