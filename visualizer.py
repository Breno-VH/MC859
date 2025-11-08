import networkx as nx
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from typing import List, Dict, Any
import collections

# Set style for all plots
sns.set_theme(style="whitegrid", palette="deep")
plt.rcParams['figure.figsize'] = (14, 8)
plt.rcParams['font.size'] = 10


# ==================== ORIGINAL FUNCTIONS ====================

def plot_degree_distribution(G):
    """
    Plota a distribuição de graus do grafo.
    Usa escalas log-log para destacar a estrutura de cauda longa.
    """
    try:
        in_degrees = G.in_degree()
        out_degrees = G.out_degree()

        in_degree_sequence = sorted([d for n, d in in_degrees], reverse=True)
        out_degree_sequence = sorted([d for n, d in out_degrees], reverse=True)

        in_degree_count = collections.Counter(in_degree_sequence)
        out_degree_count = collections.Counter(out_degree_sequence)

        in_deg, in_cnt = zip(*in_degree_count.items())
        out_deg, out_cnt = zip(*out_degree_count.items())

        plt.figure(figsize=(12, 6))

        plt.subplot(1, 2, 1)
        plt.loglog(in_deg, in_cnt, 'b.', marker='o')
        plt.title("Distribuição do Grau de Entrada")
        plt.xlabel("Grau de Entrada (k)")
        plt.ylabel("Contagem (P(k))")
        plt.grid(True, alpha=0.3)

        plt.subplot(1, 2, 2)
        plt.loglog(out_deg, out_cnt, 'r.', marker='o')
        plt.title("Distribuição do Grau de Saída")
        plt.xlabel("Grau de Saída (k)")
        plt.ylabel("Contagem (P(k))")
        plt.grid(True, alpha=0.3)

        plt.tight_layout()
        plt.savefig('visualizations/degree_distribution.png', dpi=300, bbox_inches='tight')
        plt.close()
        print("✅ Saved: degree_distribution.png")

    except ImportError:
        print("\nErro: matplotlib não está instalado. Por favor, instale com 'pip install matplotlib'.")


def plot_scc_distribution(G):
    """
    Plota a distribuição do tamanho das Componentes Fortemente Conexas (CFSs).
    Usa escala log-log para destacar a estrutura de cauda longa, se existir.
    """
    try:
        scc = list(nx.strongly_connected_components(G))
        scc_sizes = [len(c) for c in scc]
        scc_counts = collections.Counter(scc_sizes)

        sizes = list(scc_counts.keys())
        counts = list(scc_counts.values())

        plt.figure(figsize=(10, 6))
        plt.loglog(sizes, counts, 'g.', marker='o', markersize=10)
        plt.title('Distribuição do Tamanho das Componentes Fortemente Conexas (CFSs)')
        plt.xlabel('Tamanho da CFS')
        plt.ylabel('Frequência (Número de CFSs)')
        plt.grid(True, which="both", ls="--", alpha=0.3)
        plt.tight_layout()
        plt.savefig('visualizations/scc_distribution.png', dpi=300, bbox_inches='tight')
        plt.close()
        print("✅ Saved: scc_distribution.png")

    except ImportError:
        print("\nErro: matplotlib não está instalado. Por favor, instale com 'pip install matplotlib'.")


# ==================== NEW ADVANCED VISUALIZATIONS ====================

def plot_vulnerability_impact_bubble(vulnerability_report: List[Dict[str, Any]], top_n: int = 20):
    """
    Bubble chart showing vulnerability severity vs. impact (dependents).
    Bubble size = weighted risk score
    Color = severity level
    """
    data = vulnerability_report[:top_n]
    
    if not data:
        print("⚠️  No data for vulnerability impact bubble chart")
        return
    
    # Extract data
    packages = [item['package_name'] for item in data]
    severities = [item['risk_level'] for item in data]
    dependents = [item['in_degree_dependents'] for item in data]
    risk_scores = [item['weighted_risk_score'] for item in data]
    
    # Map severity to numeric for y-axis
    severity_map = {'LOW': 1, 'MODERATE': 2, 'HIGH': 3, 'CRITICAL': 4}
    severity_numeric = [severity_map.get(s, 0) for s in severities]
    
    # Color mapping
    color_map = {'LOW': '#90EE90', 'MODERATE': '#FFD700', 'HIGH': '#FF8C00', 'CRITICAL': '#FF0000'}
    colors = [color_map.get(s, 'gray') for s in severities]
    
    # Create plot
    fig, ax = plt.subplots(figsize=(14, 8))
    
    # Bubble sizes (scaled for visibility)
    sizes = [min(r * 20, 2000) for r in risk_scores]
    
    scatter = ax.scatter(dependents, severity_numeric, s=sizes, c=colors, 
                        alpha=0.6, edgecolors='black', linewidth=1.5)
    
    # Add labels for top 10
    for i in range(min(10, len(packages))):
        ax.annotate(packages[i], (dependents[i], severity_numeric[i]),
                   fontsize=8, ha='center', va='center',
                   bbox=dict(boxstyle='round,pad=0.3', facecolor='white', alpha=0.7))
    
    ax.set_xlabel('Número de Pacotes Dependentes (Alcance)', fontsize=12, fontweight='bold')
    ax.set_ylabel('Severidade da Vulnerabilidade', fontsize=12, fontweight='bold')
    ax.set_yticks([1, 2, 3, 4])
    ax.set_yticklabels(['LOW', 'MODERATE', 'HIGH', 'CRITICAL'])
    ax.set_title(f'Impacto de Vulnerabilidades - Top {top_n} Pacotes\n(Tamanho da bolha = Score de Risco Ponderado)', 
                fontsize=14, fontweight='bold', pad=20)
    ax.grid(True, alpha=0.3)
    
    # Legend
    legend_elements = [plt.scatter([], [], s=100, c=color_map[sev], alpha=0.6, 
                                  edgecolors='black', linewidth=1.5, label=sev)
                      for sev in ['LOW', 'MODERATE', 'HIGH', 'CRITICAL'] if sev in severities]
    ax.legend(handles=legend_elements, title='Severidade', loc='upper left', fontsize=10)
    
    plt.tight_layout()
    plt.savefig('visualizations/vulnerability_impact_bubble.png', dpi=300, bbox_inches='tight')
    plt.close()
    print("✅ Saved: vulnerability_impact_bubble.png")


def plot_health_vs_risk_scatter(project_risk_data: List[Dict[str, Any]]):
    """
    Scatter plot: Repository Health Score vs. Maintenance Risk Score
    Shows correlation between project health and risk.
    """
    if not project_risk_data:
        print("⚠️  No data for health vs. risk scatter plot")
        return
    
    # Extract data
    packages = [item['package_name'] for item in project_risk_data]
    health_scores = [item.get('maintenance_health_score', 0) for item in project_risk_data]
    risk_scores = [item['weighted_score'] for item in project_risk_data]
    severities = [item.get('risk_level', 'UNKNOWN') for item in project_risk_data]
    
    # Color mapping by severity
    color_map = {'LOW': '#90EE90', 'MODERATE': '#FFD700', 'HIGH': '#FF8C00', 
                 'CRITICAL': '#FF0000', 'UNKNOWN': '#808080'}
    colors = [color_map.get(s, 'gray') for s in severities]
    
    fig, ax = plt.subplots(figsize=(12, 8))
    
    scatter = ax.scatter(health_scores, risk_scores, c=colors, s=200, 
                        alpha=0.6, edgecolors='black', linewidth=1.5)
    
    # Add package labels for notable points
    for i in range(min(len(packages), 15)):
        ax.annotate(packages[i], (health_scores[i], risk_scores[i]),
                   fontsize=8, ha='right', va='bottom',
                   bbox=dict(boxstyle='round,pad=0.3', facecolor='white', alpha=0.7))
    
    # Add quadrant lines
    median_health = np.median(health_scores) if health_scores else 50
    median_risk = np.median(risk_scores) if risk_scores else 10
    
    ax.axvline(median_health, color='gray', linestyle='--', alpha=0.5, linewidth=1)
    ax.axhline(median_risk, color='gray', linestyle='--', alpha=0.5, linewidth=1)
    
    # Quadrant labels
    max_risk = max(risk_scores) if risk_scores else 20
    min_risk = min(risk_scores) if risk_scores else 0
    
    ax.text(5, max_risk*0.95, 'Alto Risco\nBaixa Saúde', 
           fontsize=10, color='red', weight='bold', alpha=0.5)
    ax.text(95, max_risk*0.95, 'Alto Risco\nAlta Saúde', 
           fontsize=10, color='orange', weight='bold', alpha=0.5, ha='right')
    ax.text(5, min_risk*1.1 if min_risk > 0 else 0.1, 'Baixo Risco\nBaixa Saúde', 
           fontsize=10, color='blue', weight='bold', alpha=0.5)
    ax.text(95, min_risk*1.1 if min_risk > 0 else 0.1, 'Baixo Risco\nAlta Saúde', 
           fontsize=10, color='green', weight='bold', alpha=0.5, ha='right')
    
    ax.set_xlabel('Score de Saúde do Repositório (0-100)', fontsize=12, fontweight='bold')
    ax.set_ylabel('Score de Risco de Manutenção', fontsize=12, fontweight='bold')
    ax.set_title('Correlação: Saúde do Repositório vs. Risco de Manutenção', 
                fontsize=14, fontweight='bold', pad=20)
    ax.set_xlim(-5, 105)
    ax.grid(True, alpha=0.3)
    
    # Legend
    legend_elements = [plt.scatter([], [], s=100, c=color_map[sev], alpha=0.6, 
                                  edgecolors='black', linewidth=1.5, label=sev)
                      for sev in ['CRITICAL', 'HIGH', 'MODERATE', 'LOW'] if sev in severities]
    if legend_elements:
        ax.legend(handles=legend_elements, title='Severidade', loc='upper right', fontsize=10)
    
    plt.tight_layout()
    plt.savefig('visualizations/health_vs_risk_scatter.png', dpi=300, bbox_inches='tight')
    plt.close()
    print("✅ Saved: health_vs_risk_scatter.png")


def plot_activity_timeline(project_risk_data: List[Dict[str, Any]], top_n: int = 15):
    """
    Horizontal bar chart showing days since last activity for top risky packages.
    Color-coded by activity status.
    """
    if not project_risk_data:
        print("⚠️  No data for activity timeline")
        return
    
    data = project_risk_data[:top_n]
    
    packages = [item['package_name'] for item in data]
    days_since_push = [item.get('days_since_last_push', -1) for item in data]
    
    # Replace -1 with 0 for unknown
    days_since_push = [max(0, d) for d in days_since_push]
    
    # Color based on activity
    colors = []
    for days in days_since_push:
        if days < 30:
            colors.append('#90EE90')  # Green - Active
        elif days < 180:
            colors.append('#FFD700')  # Yellow - Moderate
        elif days < 365:
            colors.append('#FF8C00')  # Orange - Slow
        else:
            colors.append('#FF0000')  # Red - Stale
    
    fig, ax = plt.subplots(figsize=(12, 8))
    
    y_pos = np.arange(len(packages))
    bars = ax.barh(y_pos, days_since_push, color=colors, edgecolor='black', linewidth=1)
    
    ax.set_yticks(y_pos)
    ax.set_yticklabels(packages)
    ax.invert_yaxis()  # Top to bottom
    ax.set_xlabel('Dias Desde o Último Commit', fontsize=12, fontweight='bold')
    ax.set_title(f'Atividade de Desenvolvimento - Top {top_n} Pacotes de Risco', 
                fontsize=14, fontweight='bold', pad=20)
    ax.grid(axis='x', alpha=0.3)
    
    # Add value labels
    max_days = max(days_since_push) if days_since_push else 1
    for i, (bar, days) in enumerate(zip(bars, days_since_push)):
        if days >= 0:
            label = f'{days}d' if days < 365 else f'{days//365}y'
            ax.text(days + max_days*0.01, i, label, 
                   va='center', fontsize=9, fontweight='bold')
    
    # Legend
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor='#90EE90', edgecolor='black', label='Ativo (<30d)'),
        Patch(facecolor='#FFD700', edgecolor='black', label='Moderado (30-180d)'),
        Patch(facecolor='#FF8C00', edgecolor='black', label='Lento (180-365d)'),
        Patch(facecolor='#FF0000', edgecolor='black', label='Inativo (>365d)'),
    ]
    ax.legend(handles=legend_elements, loc='lower right', fontsize=9)
    
    plt.tight_layout()
    plt.savefig('visualizations/activity_timeline.png', dpi=300, bbox_inches='tight')
    plt.close()
    print("✅ Saved: activity_timeline.png")


def plot_health_components_radar(project_risk_data: List[Dict[str, Any]], package_indices: List[int] = None):
    """
    Radar chart comparing health components of top risky packages.
    Shows: Stars, Contributors, Activity, Issue Management
    """
    if not project_risk_data:
        print("⚠️  No data for health components radar")
        return
    
    if package_indices is None:
        package_indices = list(range(min(5, len(project_risk_data))))
    
    data = [project_risk_data[i] for i in package_indices if i < len(project_risk_data)]
    
    if not data:
        print("⚠️  Not enough data for radar chart")
        return
    
    # Categories
    categories = ['Popularidade\n(Stars)', 'Comunidade\n(Contributors)', 
                 'Atividade\n(Recente)', 'Gestão de\nIssues', 'Segurança']
    N = len(categories)
    
    # Compute angles
    angles = [n / float(N) * 2 * np.pi for n in range(N)]
    angles += angles[:1]
    
    fig, ax = plt.subplots(figsize=(10, 10), subplot_kw=dict(projection='polar'))
    
    # Plot each package
    colors = plt.cm.Set2(np.linspace(0, 1, len(data)))
    
    for idx, (item, color) in enumerate(zip(data, colors)):
        # Normalize metrics to 0-100 scale
        stars_norm = min(item.get('repo_stars', 0) / 100, 100)  # Cap at 10K
        contrib_norm = min(item.get('repo_contributors', 0), 100)
        
        days = item.get('days_since_last_push', 365)
        activity_norm = max(0, 100 - (days / 3.65))  # Invert: recent = high score
        
        open_issues = item.get('open_issues', 0)
        watchers = max(item.get('watchers', 1), 1)
        issue_norm = max(0, 100 - (open_issues / watchers * 100))
        
        security_norm = 100 if item.get('has_security_policy', False) else 0
        
        values = [stars_norm, contrib_norm, activity_norm, issue_norm, security_norm]
        values += values[:1]
        
        ax.plot(angles, values, 'o-', linewidth=2, label=item['package_name'], color=color)
        ax.fill(angles, values, alpha=0.15, color=color)
    
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(categories, fontsize=10)
    ax.set_ylim(0, 100)
    ax.set_title('Comparação de Componentes de Saúde do Repositório\n(Escala: 0-100)', 
                fontsize=14, fontweight='bold', pad=30)
    ax.legend(loc='upper right', bbox_to_anchor=(1.3, 1.1), fontsize=9)
    ax.grid(True)
    
    plt.tight_layout()
    plt.savefig('visualizations/health_components_radar.png', dpi=300, bbox_inches='tight')
    plt.close()
    print("✅ Saved: health_components_radar.png")


def plot_risk_distribution_pie(vulnerability_report: List[Dict[str, Any]]):
    """
    Pie chart showing distribution of vulnerability severity levels.
    """
    if not vulnerability_report:
        print("⚠️  No data for risk distribution pie chart")
        return
    
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MODERATE': 0, 'LOW': 0}
    
    for item in vulnerability_report:
        level = item['risk_level']
        if level in severity_counts:
            severity_counts[level] += 1
    
    # Filter out zero counts
    labels = [k for k, v in severity_counts.items() if v > 0]
    sizes = [v for v in severity_counts.values() if v > 0]
    
    if not sizes:
        print("⚠️  No severity data for pie chart")
        return
    
    colors = ['#FF0000', '#FF8C00', '#FFD700', '#90EE90'][:len(labels)]
    explode = [0.1 if label == 'CRITICAL' else 0 for label in labels]
    
    fig, ax = plt.subplots(figsize=(10, 8))
    
    wedges, texts, autotexts = ax.pie(sizes, explode=explode, labels=labels, colors=colors,
                                       autopct='%1.1f%%', startangle=90, textprops={'fontsize': 12})
    
    # Bold percentage text
    for autotext in autotexts:
        autotext.set_color('white')
        autotext.set_fontweight('bold')
        autotext.set_fontsize(14)
    
    ax.set_title('Distribuição de Severidade de Vulnerabilidades', 
                fontsize=14, fontweight='bold', pad=20)
    
    plt.tight_layout()
    plt.savefig('visualizations/risk_distribution_pie.png', dpi=300, bbox_inches='tight')
    plt.close()
    print("✅ Saved: risk_distribution_pie.png")


def plot_correlation_heatmap(project_risk_data: List[Dict[str, Any]]):
    """
    Heatmap showing correlations between different metrics.
    """
    if not project_risk_data:
        print("⚠️  No data for correlation heatmap")
        return
    
    import pandas as pd
    
    # Prepare data
    df_data = []
    for item in project_risk_data:
        df_data.append({
            'Risk Score': item['weighted_score'],
            'Health Score': item.get('maintenance_health_score', 0),
            'Stars': item.get('repo_stars', 0),
            'Contributors': item.get('repo_contributors', 0),
            'Days Since Push': item.get('days_since_last_push', 0),
            'Open Issues': item.get('open_issues', 0),
            'Dependents': item.get('in_degree', 0),
        })
    
    if len(df_data) < 2:
        print("⚠️  Not enough data for correlation heatmap (need at least 2 packages)")
        return
    
    df = pd.DataFrame(df_data)
    
    # Calculate correlation matrix
    corr_matrix = df.corr()
    
    fig, ax = plt.subplots(figsize=(10, 8))
    
    sns.heatmap(corr_matrix, annot=True, fmt='.2f', cmap='coolwarm', 
               center=0, square=True, linewidths=1, cbar_kws={"shrink": 0.8},
               ax=ax)
    
    ax.set_title('Matriz de Correlação entre Métricas de Risco e Saúde', 
                fontsize=14, fontweight='bold', pad=20)
    
    plt.tight_layout()
    plt.savefig('visualizations/correlation_heatmap.png', dpi=300, bbox_inches='tight')
    plt.close()
    print("✅ Saved: correlation_heatmap.png")


def generate_all_visualizations(G: nx.DiGraph, 
                                vulnerability_report: List[Dict[str, Any]], 
                                project_risk_data: List[Dict[str, Any]]):
    """
    Generate all visualization charts and save them as PNG files.
    """
    print("\n" + "="*80)
    print("📊 GENERATING COMPREHENSIVE VISUALIZATIONS")
    print("="*80 + "\n")
    
    try:
        # Graph structure visualizations
        print("🔵 Creating graph structure visualizations...")
        plot_degree_distribution(G)
        plot_scc_distribution(G)
        
        # Vulnerability visualizations
        print("\n🔴 Creating vulnerability analysis visualizations...")
        plot_vulnerability_impact_bubble(vulnerability_report, top_n=20)
        plot_risk_distribution_pie(vulnerability_report)
        
        # Health and maintenance visualizations
        print("\n🟢 Creating repository health visualizations...")
        if project_risk_data:
            plot_health_vs_risk_scatter(project_risk_data)
            plot_activity_timeline(project_risk_data, top_n=15)
            plot_health_components_radar(project_risk_data, package_indices=[0, 1, 2, 3, 4])
            plot_correlation_heatmap(project_risk_data)
        else:
            print("⚠️  No project risk data available for health visualizations")
        
        print("\n" + "="*80)
        print("✅ ALL VISUALIZATIONS GENERATED SUCCESSFULLY!")
        print("="*80)
        print("\nGenerated files:")
        print("  📊 degree_distribution.png")
        print("  📊 scc_distribution.png")
        print("  📊 vulnerability_impact_bubble.png")
        print("  📊 risk_distribution_pie.png")
        if project_risk_data:
            print("  📊 health_vs_risk_scatter.png")
            print("  📊 activity_timeline.png")
            print("  📊 health_components_radar.png")
            print("  📊 correlation_heatmap.png")
        print("  📊 cwe_histogram.png (from main.py)")
        
    except Exception as e:
        print(f"\n❌ Error generating visualizations: {e}")
        import traceback
        traceback.print_exc()