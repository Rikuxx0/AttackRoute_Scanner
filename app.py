import streamlit as st
import json
import pandas as pd
import networkx as nx
from pyvis.network import Network
import tempfile
import os

from utils.parse_drawio_html import parse_drawio_from_html_text
from utils.parse_vuln import parse_vuln_report_text
from utils.manual_mapping_script.add_node_name_to_parsed import add_node_names_from_dict
from utils.networkx_core import build_attack_graph
from utils.risk_calc import calc_risk_from_txt



# UI setting
st.set_page_config(page_title="Attack Chain Visulaication", layout="wide")

st.title("攻撃チェーン・リスク可視化デモ")

st.subheader("入力ファイル")
drawio_html = st.file_uploader("Draw.io の html をアップロードしてください（構造情報）", type=["html"])
uploaded_reports = st.file_uploader("TXTファイルで出力された脆弱性レポート (Nuclei/Nikto)をアップロードしてください", type=["txt"], accept_multiple_files=True)
uploaded_map = st.file_uploader("あらかじめ、ドメイン名とdrawio上のホスト名が紐付いたJSONファイルをアップロードしてください", type=["json"])

if drawio_html and uploaded_reports:

    # translate drawio html into drawio json
    drawio_html_text = drawio_html.read().decode("utf-8")
    drawio_dict = parse_drawio_from_html_text(drawio_html_text)

    # parse vuln reports
    vuln_dict = {}   

    for rep in uploaded_reports:
        txt = rep.read().decode("utf-8")
        parsed = parse_vuln_report_text(txt)
        vuln_dict.update(parsed)  

    # load to manual_mapping.json
    manual_map = json.loads(uploaded_map.read())


    # add node name to parsed info
    merged_vuln = add_node_names_from_dict(vuln_dict, drawio_dict, manual_map)


    # create attack chains and display node info (ex. label, Vuln Count, Severity, proximity)
    entry_nodes = ["dHFCAMS9d22uKoxJosNZ-4"] # ← 必要に応じて入力欄に変更可能
    critical_nodes = ["dHFCAMS9d22uKoxJosNZ-1"]  # ← 必要に応じて変更
    G, attack_paths = build_attack_graph(drawio_dict, merged_vuln, manual_map, entry_nodes, critical_nodes)
    

    # collect node information into a string
    attack_result_txt = ""
    for node_id, data in G.nodes(data=True):
        attack_result_txt += (
            f"{data['label']}: "
            f"{{'label': '{data['label']}', "
            f"'Vuln_Count': {data.get('Vuln_Count', 0)}, "
            f"'Severity': {data.get('Severity', 0)}, "
            f"'proximity': {data.get('proximity', 0)}}}\n"
        )


    # calculate risk score in all
    risk_dict = calc_risk_from_txt(attack_result_txt)

    # loading dictionary file
    drawio_data = drawio_dict
    risk_data = risk_dict


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
        G.add_node(node_id, label=label, title=label)

    for edge in drawio_data["edges"]:
        source_id = edge["source"]
        target_id = edge["target"]

        target_node = next((n for n in merged_nodes if n["id"] == target_id), None)
        if target_node:
            risk = float(target_node.get("Risk_Score", 0))
            vuln = int(target_node.get("Vuln_Count", 0))
            sev = float(target_node.get("Severity", 0))

            # decide edge thickness according to risk and vulnerability
            width = 1 + risk 

            # varying edge color based on risk
            red = min(255, int(risk * 10))
            green = max(0, 150 - int(risk * 5))
            color = f"rgb({red},{green},80)"

            title = f"""
            To: {target_node['label']}
            Risk Score: {risk:.2f}
            Vuln Count: {vuln}
            Severity: {sev}
            """
        else:
            width = 1
            color = "gray"
            title = "Edge"

        G.add_edge(
            source_id,
            target_id,
            width=width,
            color=color,
            title=title
        )
    

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
    st.info("Draw.io JSON と Risk JSON と Manual Map JSON をアップロードしてください。")