import networkx as nx
import matplotlib.pyplot as plt
import collections

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

        plt.subplot(1, 2, 2)
        plt.loglog(out_deg, out_cnt, 'r.', marker='o')
        plt.title("Distribuição do Grau de Saída")
        plt.xlabel("Grau de Saída (k)")
        plt.ylabel("Contagem (P(k))")

        plt.tight_layout()
        plt.show()

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
        plt.loglog(sizes, counts, 'g.', marker='o')
        plt.title('Distribuição do Tamanho das Componentes Fortemente Conexas (CFSs)')
        plt.xlabel('Tamanho da CFS')
        plt.ylabel('Frequência (Número de CFSs)')
        plt.grid(True, which="both", ls="--")
        plt.show()

    except ImportError:
        print("\nErro: matplotlib não está instalado. Por favor, instale com 'pip install matplotlib'.")
