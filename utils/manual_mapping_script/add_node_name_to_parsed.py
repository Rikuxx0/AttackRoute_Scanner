#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
add_node_name_to_parsed.py + manual_mapping対応版
"""

import json
import argparse
from typing import Dict, Any, List

def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_json(obj: Any, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)

def extract_labels_from_drawio(drawio: Dict[str, Any]) -> List[str]:
    return [n.get("label", "").strip().lower()
            for n in drawio.get("nodes", [])
            if isinstance(n.get("label"), str) and n["label"].strip()]

def try_match_label_for_host(host_key: str, host_entry: Dict[str, Any], labels: List[str]) -> str:
    findings = host_entry.get("findings", [])
    for vuln in findings:
        url = vuln.get("url", "")
        if not isinstance(url, str):
            continue
        url_l = url.lower()
        for label in labels:
            if label in url_l:
                return label
    hk = host_key.lower()
    for label in labels:
        if label in hk:
            return label
    return ""

def add_node_names_from_dict(vuln_dict: dict, drawio_dict: dict, manual_map: dict = None) -> dict:
    ## vuln = load_json(vuln_path)
    ## drawio = load_json(drawio_path)


    labels = extract_labels_from_drawio(drawio_dict)
    label_map = {l: l for l in labels}
    
    # --- 手動マッピング読み込み ---
    ## manual_map = {}
    ## if mapping_path:
    ##     manual_map = load_json(mapping_path)
    ##     print(f"manual_mapping.json 読み込み完了 ({len(manual_map)} 件)")

    if manual_map is None:
        manual_map = {}


    unmapped = []


    for host_key, entry in vuln_dict.items():
        # 1 手動マッピング優先
        if host_key in manual_map:
            entry["node_name"] = manual_map[host_key]
            continue

        # 2 自動マッチ
        matched = try_match_label_for_host(host_key, entry, labels)
        if matched:
            entry["node_name"] = label_map.get(matched, matched)
        else:
            unmapped.append(host_key)

    if unmapped:
        for u in unmapped:
            print("  -", u)

    return vuln_dict

## def main():
##     p = argparse.ArgumentParser(description="Add node_name to parsed nuclei JSON (manual mapping supported)")
##     p.add_argument("--vuln", "-v", required=True, help="parsed nuclei JSON file (input)")
##     p.add_argument("--drawio", "-d", required=True, help="draw.io JSON file")
##     p.add_argument("--mapping", "-m", required=False, help="manual_mapping.json (optional)")
##     p.add_argument("--out", "-o", required=True, help="output JSON file")
##     args = p.parse_args()
##
##     merged = add_node_names(args.vuln, args.drawio, args.mapping)
##     save_json(merged, args.out)
##     print(f" 出力完了: {args.out}")

## if __name__ == "__main__":
##    main()
