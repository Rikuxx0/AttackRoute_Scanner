import re
## import argparse

# ====== Node importance weight configuration ======
IMPORTANCE = {
    "admin UI": 4.0,
    "redis": 3.0,
    "vuln-api": 2.0,
    "owasp juice-shop": 1.0,
    "default": 1.0
}
# ==================================================

def infer_importance(label):
    """Infer importance value from node label"""
    k = label.lower()
    for key, val in IMPORTANCE.items():
        if key != "default" and key in k:
            return val
    return IMPORTANCE["default"]

def calc_risk_from_txt(text: str):
    node_re = re.compile(
        r"^(?P<label>[^:]+): \{'label': '[^']*', 'Vuln_Count': (?P<count>[\d]+), "
        r"'Severity': (?P<sev>[\d\.]+), 'proximity': (?P<prox>[\d\.eE+-]+)\}"
    )

    nodes = []

    for line in text.splitlines():
        m = node_re.search(line.strip())
        if m:
            label = m.group("label").strip()
            count = int(m.group("count"))
            sev = float(m.group("sev"))
            prox = float(m.group("prox"))
            imp = infer_importance(label)
            risk = (count * sev) * imp * prox

            nodes.append({
                "label": label,
                "Vuln_Count": count,
                "Severity": sev,
                "proximity": prox,
                "Importance": imp,
                "Risk_Score": round(risk, 6)
            })

    return {"nodes": nodes}



## def parse_txt_to_json(input_path, output_path):
##     """
##     Parse attack chain text output and compute risk score for each node.
##     Risk_Score = (Vuln_Count × Severity) × Importance × proximity
##     """
## 
##     # Regex to extract node data
##     node_re = re.compile(
##         r"^(?P<label>[^:]+): \{'label': '[^']*', 'Vuln_Count': (?P<count>[\d]+), "
##         r"'Severity': (?P<sev>[\d\.]+), 'proximity': (?P<prox>[\d\.eE+-]+)\}"
##     )
##
##     nodes = []
##     with open(input_path, "r", encoding="utf-8") as f:
##         for line in f:
##             m = node_re.search(line.strip())
##             if m:
##                 label = m.group("label").strip()
##                 count = int(m.group("count"))
##                 sev = float(m.group("sev"))
##                 prox = float(m.group("prox"))
##                 imp = infer_importance(label)
##                 risk = (count * sev) * imp * prox
##                 nodes.append({
##                     "label": label,
##                     "Vuln_Count": count,
##                     "Severity": sev,
##                     "proximity": prox,
##                     "Importance": imp,
##                     "Risk_Score": round(risk, 6)
##                 })

    # Write to JSON file
    ## result = {"nodes": nodes}
    ## with open(output_path, "w", encoding="utf-8") as fo:
    ##    json.dump(result, fo, indent=2, ensure_ascii=False)

    # Console summary
    ## print(f"[+] Wrote {len(nodes)} nodes to {output_path}")
    ## for n in nodes:
    ##    print(f" - {n['label']}: Risk_Score={n['Risk_Score']}")

## if __name__ == "__main__":
##    parser = argparse.ArgumentParser(description="Convert attack result TXT to JSON and calculate risk scores")
##    parser.add_argument("--input", required=True, help="Path to attack result .txt file")
##    parser.add_argument("--output", required=True, help="Path to output .json file")
##    args = parser.parse_args()
##
##    parse_txt_to_json(args.input, args.output)
