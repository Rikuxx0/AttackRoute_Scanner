import streamlit as st
import json
import pandas as pd
import networkx as nx
from pyvis.network import Network
import tempfile
import os

from utils.parse_drawio_xml import parse_drawio_xml
from utils.parse_vuln import parse_vuln_report_text
from utils.networkx_core import build_attack_graph

# --- UI settings ---
st.set_page_config(page_title="Attack Chain Visualization", layout="wide")
st.title("攻撃チェーン・リスク可視化デモ")

# --- File Uploaders ---
st.subheader("入力ファイル")
drawio_xml = st.file_uploader("Draw.io の XML をアップロードしてください（構造情報）", type=["xml"])
uploaded_reports = st.file_uploader("TXTファイルで出力された脆弱性レポート (Nuclei/Nikto)をアップロードしてください", type=["txt"], accept_multiple_files=True)
uploaded_map = st.file_uploader("あらかじめ、ドメイン名とdrawio上のホスト名が紐付いたJSONファイルをアップロードしてください", type=["json"])

# --- Main processing block ---
if drawio_xml and uploaded_reports and uploaded_map:

    # 1. Parse all input files
    drawio_xml_text = drawio_xml.read().decode("utf-8")
    drawio_dict = parse_drawio_xml(drawio_xml_text)

    vuln_dict = {}
    for rep in uploaded_reports:
        txt = rep.read().decode("utf-8")
        parsed = parse_vuln_report_text(txt)
        for key, value in parsed.items():
            if key in vuln_dict:
                vuln_dict[key]['findings'].extend(value['findings'])
            else:
                vuln_dict[key] = value

    # Recalculate Vuln_Count and Severity after merging
    for h, data in vuln_dict.items():
        sev_values = [f["severity"] for f in data["findings"]]
        data["Vuln_Count"] = len(sev_values)
        data["Severity"] = round(sum(sev_values) / len(sev_values), 2) if sev_values else 0

    manual_map = json.loads(uploaded_map.read())

    # --- Analysis Configuration (Optional Overrides) ---
    st.subheader("解析設定（オプション）")
    
    node_label_to_id = {node['label']: node['id'] for node in drawio_dict.get('nodes', []) if node.get('label')}
    all_node_labels = sorted(node_label_to_id.keys())

    selected_entry_labels = st.multiselect(
        "侵入口となるノードを自動検出の代わり手動で選択",
        options=all_node_labels,
        help="指定しない場合はキーワードやグラフ構造に基づき自動検出されます。"
    )
    selected_critical_labels = st.multiselect(
        "重要なノード（攻撃対象）を自動検出の代わり手動で選択",
        options=all_node_labels,
        help="指定しない場合はキーワードに基づき自動検出されます。"
    )

    selected_entry_nodes = [node_label_to_id[label] for label in selected_entry_labels]
    selected_critical_nodes = [node_label_to_id[label] for label in selected_critical_labels]

    # 2. Build and enrich the graph
    G, attack_paths = build_attack_graph(
        drawio_dict,
        vuln_dict,
        manual_map,
        entry_nodes=selected_entry_nodes or None,
        critical_nodes=selected_critical_nodes or None
    )

    # 3. Prepare data for display
    node_data = [data for _, data in G.nodes(data=True)]
    
    # 4. Display the integrated node information table
    st.subheader("統合ノード情報")
    if node_data:
        df = pd.DataFrame(node_data)
        display_cols = ["label", "Risk_Score", "Vuln_Count", "Severity", "Importance", "proximity"]
        existing_cols = [col for col in display_cols if col in df.columns]
        st.dataframe(df[existing_cols].sort_values("Risk_Score", ascending=False))
    else:
        st.warning("グラフにノードがありません。")

    # 5. Display Detected Attack Paths
    st.subheader("検出された攻撃パス（最短経路）")
    if attack_paths:
        for i, path in enumerate(attack_paths):
            path_labels = [G.nodes[node_id].get('label', 'unknown') for node_id in path]
            st.markdown(f"**Path {i+1}:** `{' → '.join(path_labels)}`")
    else:
        st.info("侵入口から重要ノードへの攻撃パスは見つかりませんでした。")


    # 6. Build and display the interactive graph with Pyvis
    st.subheader("攻撃チェーン可視化")
    
    net = Network(height="755px", width="100%", bgcolor="#ffffff", directed=True)
    
    # Get a set of all nodes that are part of any attack path
    path_nodes = set(node for path in attack_paths for node in path)

    for node_id, data in G.nodes(data=True):
        node_color = {"border": "#FF0000", "background": "#FFDCDC"} if node_id in path_nodes else {}
        border_width = 3 if node_id in path_nodes else 1
        
        net.add_node(
            node_id,
            label=data.get('label'),
            title=str(data),
            color=node_color,
            borderWidth=border_width
        )

    for source_id, target_id, _ in G.edges(data=True):
        target_node_data = G.nodes[target_id]
        
        risk = target_node_data.get("Risk_Score", 0.0)
        width = 1 + (risk / 10)
        red = min(255, int(risk * 10))
        green = max(0, 150 - int(risk * 5))
        color = f"rgb({red},{green},80)"

        title = f"To: {target_node_data.get('label', 'N/A')}\n" + json.dumps(target_node_data, indent=2)

        net.add_edge(source_id, target_id, width=width, color=color, title=title)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as tmp_file:
        net.save_graph(tmp_file.name)
        html_content = open(tmp_file.name, 'r', encoding='utf-8').read()
        st.components.v1.html(html_content, height=750)
        os.remove(tmp_file.name)

else:
    st.info("Draw.io XML, 脆弱性レポート, และ Manual Map JSON をすべてアップロードしてください。")