#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import json

def read_file(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()

# detect Nikto or Nuclei
def detect_tool(text: str) -> str:
    if "Nikto" in text or "Target Host" in text:
        return "nikto"
    elif "[http]" in text or "nuclei" in text:
        return "nuclei"
    else:
        return "unknown"

# extract tool, host, port, url, title, severity
def extract_findings(text: str, tool: str):
    findings = []

    if tool == "nuclei":
        pattern = re.compile(r"\[(?P<template>[^\]]+)\]\s+\[http\]\s+\[(?P<sev>[^\]]+)\]\s+(?P<url>\S+)")
        for m in pattern.finditer(text):
            url = m.group("url")
            host_match = re.search(r"https?://([^/:]+)(?::(\d+))?", url)
            host = host_match.group(1) if host_match else "unknown"
            port = int(host_match.group(2)) if host_match and host_match.group(2) else 80
            sev_map = {"info":1,"low":2,"medium":3,"high":4,"critical":5} #セキュリティリスクレベルの基準値
            findings.append({
                "tool": "nuclei",
                "host": host,
                "port": port,
                "url": url,
                "title": m.group("template"),
                "severity": sev_map.get(m.group("sev").lower(),1)
            })

    elif tool == "nikto":
        host_match = re.search(r"Target Host:\s*(\S+)", text)
        port_match = re.search(r"Target Port:\s*(\d+)", text)
        host = host_match.group(1) if host_match else "unknown"
        port = int(port_match.group(1)) if port_match else 80

        for line in text.splitlines():
            if line.startswith("+ "):
                msg = line[2:].strip()
                # セキュリティリスクレベルの基準値
                sev = 2
                if "missing" in msg.lower(): sev = 3
                if "config" in msg.lower(): sev = 4 
                
                findings.append({
                    "tool": "nikto",
                    "host": host,
                    "port": port,
                    "url": f"http://{host}:{port}/",
                    "title": msg[:80],
                    "severity": sev
                })
    return findings


def parse_vuln_report(filepath: str):
    text = read_file(filepath)
    tool = detect_tool(text)
    findings = extract_findings(text, tool)

    hosts = {}
    for f in findings:
        key = f"{f['host']}:{f['port']}"
        if key not in hosts:
            hosts[key] = {"findings": [], "host": f["host"], "port": f["port"]}
        hosts[key]["findings"].append(f)

    for h, data in hosts.items():
        sev_values = [f["severity"] for f in data["findings"]]
        data["Vuln_Count"] = len(sev_values)
        data["Severity"] = round(sum(sev_values) / len(sev_values), 2) if sev_values else 0

    return hosts

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Simple Vulnerability Report Parser")
    parser.add_argument("--input", "-i", required=True, help="Input report file (txt)")
    parser.add_argument("--output", "-o", required=True, help="Output JSON file")
    args = parser.parse_args()

    result = parse_vuln_report(args.input)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"[+] Parsed and saved to {args.output}")
