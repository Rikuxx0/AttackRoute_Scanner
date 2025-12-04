import html
import re
from xml.etree import ElementTree as ET


def parse_mxfile(xml_text: str):
    """
    Parse pure draw.io XML (the content of a .drawio file)
    """
    root = ET.fromstring(xml_text)
    cells = []

    for mxcell in root.iter("mxCell"):
        attr = mxcell.attrib.copy()

        geom = mxcell.find("mxGeometry")
        geom_attrib = geom.attrib.copy() if geom is not None else {}

        value = html.unescape(attr.get("value", ""))

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
    """
    Convert parsed cells → nodes + edges dictionary
    """
    nodes = []
    edges = []

    for c in cells:
        # vertex = node
        if c.get("vertex") == "1":
            label = re.sub(r"<[^>]+>", "", c.get("value") or "").strip()
            nodes.append({
                "id": c["id"],
                "label": label,
                "style": c.get("style"),
                "geometry": c.get("geometry"),
            })

        # edge
        if c.get("edge") == "1":
            edges.append({
                "id": c["id"],
                "source": c.get("source"),
                "target": c.get("target"),
                "style": c.get("style"),
            })

    return {"nodes": nodes, "edges": edges}


def parse_drawio_xml(xml_text: str):
    """
    Entry point: parse only pure draw.io XML
    """
    cells = parse_mxfile(xml_text)
    graph = to_graph_json(cells)
    return graph




## if __name__ == "__main__":
##    if len(sys.argv) < 2:
##        print("Usage: python parse_drawio_html.py diagram.html [out.json]")
##        sys.exit(1)
##    html_path = sys.argv[1]
##    outjson = sys.argv[2] if len(sys.argv) > 2 else "diagram.json"
##    with open(html_path, "r", encoding="utf-8", errors="ignore") as f:
##        h = f.read()
##    mxfile = extract_mxfile_from_html(h)
##    if not mxfile:
##        print("mxfile not found in HTML")
##        sys.exit(2)
##    cells = parse_mxfile(mxfile)
##    graph = to_graph_json(cells)
##  with open(outjson, "w", encoding="utf-8") as fo:
##        json.dump(graph, fo, ensure_ascii=False, indent=2)
##    print(f"wrote {outjson} (nodes: {len(graph['nodes'])}, edges: {len(graph['edges'])})")
