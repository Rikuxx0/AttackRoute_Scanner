import json
import math
import argparse
import networkx as nx


def build_graph(drawio_json_path: str):
    # loading a drawio architecture map
    with open(drawio_json_path, "r") as f:
        data = json.load(f)

    G = nx.DiGraph() # directed graph

    # adding nodes and edges
    for node in data["nodes"]:
        G.add_node(node["id"], label=node.get("label", "unknown"))

    for edge in data["edges"]:
        G.add_edge(edge["source"], edge["target"])

    return G

def attach_vuln_data(G, vuln_files: list, mapping_file: str):
    #associating parsed info with nodes and edges
    
    #loading mapping info with networkx
    with open(mapping_file, "r") as f:
        raw_mapping = json.load(f)
    mapping = {v: k for k, v in raw_mapping.items()}

    # associate vuln datas with mapping info
    vuln_data = {}
    for path in vuln_files:
        with open(path, "r") as f:
            vuln_data.update(json.load(f))

    # associate every vuln datas with nodes
    for node_id, node_data in G.nodes(data=True):
        label = node_data.get("label")
        host_key = mapping.get(label)
        if host_key and host_key in vuln_data:
            vdata = vuln_data[host_key]
            G.nodes[node_id]["Vuln_Count"] = vdata["Vuln_Count"]
            G.nodes[node_id]["Severity"] = vdata["Severity"]
        else:
            G.nodes[node_id]["Vuln_Count"] = 0
            G.nodes[node_id]["Severity"] = 0

    return G



def compute_proximity(G, entry_nodes: list, beta: float = 0.7):
    # Calculate the hop distance from the intruder node using exponential decay
    for entry in entry_nodes:
        lengths = nx.single_source_shortest_path_length(G, entry)
        for target, d in lengths.items():
            proximity = math.exp(-beta * d)
            if "proximity" not in G.nodes[target]:
                G.nodes[target]["proximity"] = proximity
            else:
                G.nodes[target]["proximity"] = max(G.nodes[target]["proximity"], proximity)

    return G     

def extract_attack_paths(G, entry_nodes: list, critical_nodes: list):
    # Extract the route from the intrusion origin to the important node
    paths = []
    for e in entry_nodes:
        for c in critical_nodes:
            if nx.has_path(G, e, c):
                paths.append(nx.shortest_path(G, e, c))
    return paths

def main(args):
    G = build_graph(args.drawio)

    G = attach_vuln_data(
        G,
        vuln_files=args.vuln_reports,
        mapping_file=args.mapping
    )

    G = compute_proximity(G, entry_nodes=args.entry_nodes)
    paths = extract_attack_paths(G, args.entry_nodes, args.critical_nodes)

    # output section
    output_lines = []
    output_lines.append("\n=== Attack Chain ===")
    if paths:
        for p in paths:
            output_lines.append(" → ".join([G.nodes[n]['label'] for n in p]))
    else:
        output_lines.append("(no valid attack chain found)")

    output_lines.append("\n=== node info ===")
    for n, data in G.nodes(data=True):
        output_lines.append(f"{data.get('label', n)}: {data}")

    # show result
    print("\n".join(output_lines))

    # save to file if specified
    if args.out:
        with open(args.out, "w") as f:
            f.write("\n".join(output_lines))
        print(f"\n[+] Result saved to {args.out}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Attack Chain Builder with NetworkX")
    parser.add_argument("--drawio", required=True, help="Path to Draw.io JSON file")
    parser.add_argument("--mapping", required=True, help="Path to manual_mapping.json")
    parser.add_argument("--vuln_reports", nargs="+", required=True, help="List of parsed vuln report JSONs")
    parser.add_argument("--out", required=True, help="Output file path to save result")
    parser.add_argument("--entry_nodes", nargs="+", required=True, help="Entry node IDs (external nodes)")
    parser.add_argument("--critical_nodes", nargs="+", required=True, help="Critical node IDs (target nodes)")
    args = parser.parse_args()

    main(args) 



