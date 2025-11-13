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

uploaded_file = st.file_uploader("リスク結果ファイルをアップロードしてください(形式: .json)")

if uploaded_file:

    # loading json file
    data = json.load(uploaded_file)
    df = pd.DataFrame(data["nodes"])

    st.subheader("ノード情報")
    st.dataframe(df.sort_values("Risk_Score", ascending=False))

    # Graph construction
    G = nx.Graph()
    for node in data["nodes"]:
        label = node["label"]
        risk = node["Risk_Score"]
        vuln = node["Vuln_Count"]
        sev = node["Severity"]

        # node color
        color = f"rgb({min(255, int(risk * 10))}, {max(0, 200 - int(risk * 10))}, 100)"

        G.add_node(
            label,
            label=label,
            size=30 + vuln,  #  change size 
            color=color,
            title=f"""
            {label}
            Vuln Count: {vuln}
            Severity: {sev}
            Risk Score: {risk:.2f}
            """
        )

    #  display interaction graph with Pyvis 
    net = Network(height="600px", width="100%", bgcolor="#ffffff", directed=False)
    net.from_nx(G)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as tmp_file:
        net.save_graph(tmp_file.name)
        st.components.v1.html(open(tmp_file.name, 'r', encoding='utf-8').read(), height=600)
        os.remove(tmp_file.name)


else:
    st.info("上のファイルアップローダーにリスク結果ファイルをアップロードしてください。")