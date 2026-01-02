import math
import networkx as nx
import re

# --- Constants ---
ENTRY_KEYWORDS = ["web", "ui", "frontend", "shop", "wordpress"]
CRITICAL_KEYWORDS = ["db", "redis", "api", "admin", "backend"]

# Node importance weight configuration
IMPORTANCE_CONFIG = {
    "db": 4.0,
    "redis": 3.0,
    "api": 3.0,
    "admin": 3.0,
    "backend": 3.0,
    "default": 1.0,
}

# --- Helper Functions ---
def _normalize_text(text: str) -> str:
    """Converts text to a consistent format for comparison."""
    if not text:
        return ""
    return re.sub(r"[\s\-_]+", "", text.lower())

# --- Graph Building and Enrichment ---

def build_graph_from_dict(data: dict):
    """Creates a directed graph from a dictionary of nodes and edges."""
    G = nx.DiGraph()
    for node in data["nodes"]:
        G.add_node(node["id"], label=node.get("label", "unknown"))
    for edge in data["edges"]:
        G.add_edge(edge["source"], edge["target"])
    return G

def attach_vuln_data_dict(G, vuln_dict: dict, manual_map: dict):
    """
    Attaches vulnerability data to graph nodes, prioritizing manual mapping
    but falling back to automatic name matching.
    """
    # Pre-normalize maps for efficient and robust lookup
    norm_vuln_map = {_normalize_text(k): v for k, v in vuln_dict.items()}
    norm_manual_map = {_normalize_text(k): v for k, v in manual_map.items()}

    for node_id, data in G.nodes(data=True):
        # Initialize with defaults
        data["Vuln_Count"] = 0
        data["Severity"] = 0.0
        
        label = data.get("label")
        if not label:
            continue

        norm_label = _normalize_text(label)

        # Priority 1: Manual Mapping (normalized)
        host_key = norm_manual_map.get(norm_label)
        if host_key and host_key in vuln_dict:
            v = vuln_dict[host_key]
            data["Vuln_Count"] = v.get("Vuln_Count", 0)
            data["Severity"] = v.get("Severity", 0.0)
            continue # Move to next node once mapped

        # Priority 2: Automatic Fallback Mapping
        for norm_host, vuln_data in norm_vuln_map.items():
            if norm_label in norm_host:
                data["Vuln_Count"] = vuln_data.get("Vuln_Count", 0)
                data["Severity"] = vuln_data.get("Severity", 0.0)
                # print(f"Auto-mapped '{label}' to '{norm_host}'") # Optional: for debugging
                break # Stop after first match
    return G


def compute_proximity(G, entry_nodes: list, beta: float = 0.7):
    """
    Computes proximity to entry points for all nodes in the graph.
    """
    for node_id in G.nodes:
        G.nodes[node_id]["proximity"] = 0.0

    for entry in entry_nodes:
        if entry not in G:
            continue
        
        lengths = nx.single_source_shortest_path_length(G, entry)
        for target, d in lengths.items():
            proximity = math.exp(-beta * d)
            G.nodes[target]["proximity"] = max(
                G.nodes[target].get("proximity", 0), proximity
            )
    return G

def assign_importance(G):
    """Assigns an 'Importance' score to each node based on its label."""
    for node_id, data in G.nodes(data=True):
        label = data.get("label", "").lower()
        importance = IMPORTANCE_CONFIG["default"]
        for key, value in IMPORTANCE_CONFIG.items():
            if key != "default" and key in label:
                importance = value
                break
        data["Importance"] = importance
    return G

def calculate_risk_score(G):
    """
    Calculates the 'Risk_Score' for each node based on its attributes.
    Risk_Score = (Vuln_Count * Severity) * Importance * proximity
    """
    for node_id, data in G.nodes(data=True):
        vuln_count = data.get("Vuln_Count", 0)
        severity = data.get("Severity", 0.0)
        importance = data.get("Importance", 1.0)
        proximity = data.get("proximity", 0.0)

        risk = (vuln_count * severity) * importance * proximity
        data["Risk_Score"] = round(risk, 6)
    return G

# --- Node Detection and Path Extraction ---

def detect_nodes_by_keywords(G, keywords: list):
    """Finds nodes whose labels contain any of the given keywords."""
    matched_nodes = []
    for node_id, data in G.nodes(data=True):
        label = data.get("label", "").lower()
        if any(k in label for k in keywords):
            matched_nodes.append(node_id)
    return matched_nodes

def detect_entry_nodes(G):
    """
    Detects potential entry nodes based on graph topology or keywords.
    """
    entries = set(n for n in G.nodes if G.in_degree(n) == 0)
    keyword_entries = detect_nodes_by_keywords(G, ENTRY_KEYWORDS)
    entries.update(keyword_entries)
    return list(entries)

def detect_critical_nodes(G):
    """Detects critical nodes based on keywords in their labels."""
    return detect_nodes_by_keywords(G, CRITICAL_KEYWORDS)

def extract_attack_paths(G, entry_nodes: list, critical_nodes: list):
    """Finds all shortest paths from entry nodes to critical nodes."""
    paths = []
    for e in entry_nodes:
        for c in critical_nodes:
            if G.has_node(e) and G.has_node(c) and nx.has_path(G, e, c):
                for path in nx.all_shortest_paths(G, source=e, target=c):
                    paths.append(path)
    return paths

# --- Main Orchestration Function ---

def build_attack_graph(drawio_dict, vuln_dict, manual_map, entry_nodes=None, critical_nodes=None):
    """
    Builds and enriches the attack graph with all relevant data and calculations.
    """
    G = build_graph_from_dict(drawio_dict)
    G = attach_vuln_data_dict(G, vuln_dict, manual_map)

    if not entry_nodes:
        entry_nodes = detect_entry_nodes(G)
    if not critical_nodes:
        critical_nodes = detect_critical_nodes(G)

    # Compute metrics and risk
    G = compute_proximity(G, entry_nodes)
    G = assign_importance(G)
    G = calculate_risk_score(G)

    # Find attack paths
    paths = extract_attack_paths(G, entry_nodes, critical_nodes)

    return G, paths
