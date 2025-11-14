import streamlit as st
import json
import pandas as pd
import networkx as nx
from pyvis.network import Network
import tempfile
import os


# UI setting
st.set_page_config(page_title="Attack Chain Visulaication", layout="wide")

st.title("攻撃チェーン・リスク可視化デモ")

st.subheader("入力ファイル")
drawio_file = st.file_uploader("Draw.io の JSON をアップロードしてください（構造情報）", type=["json"])
risk_file = st.file_uploader("Risk 計算結果の JSON をアップロードしてください（Vuln/Score）", type=["json"])

if drawio_file and risk_file:

    # loading json file
    drawio_data = json.load(drawio_file)
    risk_data = json.load(risk_file)

    # labal → risk info map
    risk_map = {node["label"]: node for node in risk_data["nodes"]}
    
    merged_nodes = []
    
    # merge risk info into nodes
    for node in drawio_data["nodes"]:
        label = node["label"]
        merged = node.copy()

        if label in risk_map:
            merged.update(risk_map[label])
        else:
            merged.update({
                "Vuln_Count": 0,
                "Severity": 0,
                "Risk_Score": 0,
                "Importance": 0,
                "proximity": 0
            })

        merged_nodes.append(merged)

    # display DataFrame
    st.subheader("統合ノード情報（Draw.io × Risk）")
    df = pd.DataFrame(merged_nodes)
    st.dataframe(df.sort_values("Risk_Score", ascending=False))



    # Graph construction
    G = nx.DiGraph()
    for node in merged_nodes:
        node_id = node["id"]
        label = node["label"]
        risk =float(node.get("Risk_Score", 0))
        vuln = int(node.get("Vuln_Count", 0))
        sev = node.get("Severity", 0)

        # node color
        color = f"rgb({min(255, int(risk * 10))}, {max(0, 150 - int(risk * 5))}, 80)"

        G.add_node(
            node_id,
            label=label,
            size=10 + vuln,  #  change size 
            color=color,
            title=f"""
            {label}
            Vuln Count: {vuln}
            Severity: {sev}
            Risk Score: {risk:.2f}
            """
        )
    
    # adding edges
    for edge in drawio_data["edges"]:
        G.add_edge(edge["source"], edge["target"])


    #  display interaction graph with Pyvis 
    st.subheader("攻撃チェーン可視化")

    net = Network(height="755px", width="100%", bgcolor="#ffffff", directed=True)
    net.from_nx(G)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as tmp_file:
        net.save_graph(tmp_file.name)
        html = open(tmp_file.name, 'r', encoding='utf-8').read()
        st.components.v1.html(html, height=750)
        os.remove(tmp_file.name)


else:
    st.info("Draw.io JSON と Risk JSON を両方アップロードしてください。")