# save as parse_drawio_html.py
import json
import html
import re
import sys
from xml.etree import ElementTree as ET

def extract_mxfile_from_html(html_text):
    # find data-mxgraph="...mxfile..."
    m = re.search(r'data-mxgraph="({.*?})"', html_text)
    if not m:
        raise ValueError("data-mxgraph JSON not found in HTML")

    # unescape HTML entities
    json_str = html.unescape(m.group(1))

     # sometimes the attribute includes surrounding braces or JSON wrapper; try to find actual <mxfile ...>...</mxfile>
    data = json.loads(json_str)
    xml_text = data.get("xml", None)
    if not xml_text:
        raise ValueError("No 'xml' field found inside data-mxgraph")
    
    return xml_text

def parse_mxfile(xml_text):
    ns = {}  # no namespaces usually
    root = ET.fromstring(xml_text)
    # find mxGraphModel -> diagram -> mxGraphModel -> root -> mxCell
    cells = []
    for mxcell in root.findall(".//mxCell"):
        attr = mxcell.attrib.copy()
        # find geometry child if exists
        geom = mxcell.find("mxGeometry")
        geom_attrib = geom.attrib.copy() if geom is not None else {}
        value = attr.get("value", "")
        # sometimes value contains HTML encoded snippets; unescape
        value = html.unescape(value)
        cells.append({
            "id": attr.get("id"),
            "value": value,
            "vertex": attr.get("vertex"),
            "edge": attr.get("edge"),
            "source": attr.get("source"),
            "target": attr.get("target"),
            "parent": attr.get("parent"),
            "style": attr.get("style"),
            "geometry": geom_attrib
        })
    return cells

def to_graph_json(cells):
    nodes = []
    edges = []
    for c in cells:
        if c.get("vertex") == "1":
            # extract a readable label: strip html tags if present
            label = re.sub(r'<[^>]+>', '', c.get("value") or "").strip()
            nodes.append({
                "id": c["id"],
                "label": label,
                "style": c.get("style"),
                "geometry": c.get("geometry")
            })
        if c.get("edge") == "1":
            edges.append({
                "id": c["id"],
                "source": c.get("source"),
                "target": c.get("target"),
                "style": c.get("style")
            })
    return {"nodes": nodes, "edges": edges}

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python parse_drawio_html.py diagram.html [out.json]")
        sys.exit(1)
    html_path = sys.argv[1]
    outjson = sys.argv[2] if len(sys.argv) > 2 else "diagram.json"
    with open(html_path, "r", encoding="utf-8", errors="ignore") as f:
        h = f.read()
    mxfile = extract_mxfile_from_html(h)
    if not mxfile:
        print("mxfile not found in HTML")
        sys.exit(2)
    cells = parse_mxfile(mxfile)
    graph = to_graph_json(cells)
    with open(outjson, "w", encoding="utf-8") as fo:
        json.dump(graph, fo, ensure_ascii=False, indent=2)
    print(f"wrote {outjson} (nodes: {len(graph['nodes'])}, edges: {len(graph['edges'])})")
