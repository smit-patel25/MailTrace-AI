import hashlib
import html
import ipaddress
import re
import urllib.parse
from typing import Any

import plotly.graph_objects as go

MAX_NODES = 100
MAX_EDGES = 200
MAX_LABEL_LENGTH = 30

NODE_COLORS = {
    "Case": "#4C8DFF",      # accent-blue
    "IP": "#2DBE8C",        # success / teal
    "Domain": "#F0B44D",    # warning / amber
    "URL Host": "#A678FF",  # accent-purple
    "Hash": "#E11D48"       # accent-rose
}

NODE_X = {
    "Case": 0,
    "IP": 1,
    "Domain": 2,
    "URL Host": 3,
    "Hash": 4
}

# Strict validation regexes
DOMAIN_REGEX = re.compile(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")
DEFANG_REGEX = re.compile(r"\[\.\]")


def _is_valid_domain(domain: Any) -> str | None:
    if not isinstance(domain, str) or not domain.strip():
        return None
    d = domain.strip().lower()
    if d.endswith("."):
        d = d[:-1]
    if len(d) > 253:
        return None
    labels = d.split(".")
    if len(labels) < 2:
        return None
    for label in labels:
        if not label or len(label) > 63:
            return None
        if label.startswith("-") or label.endswith("-"):
            return None
        if not re.match(r"^[a-z0-9\-]+$", label):
            return None
    return d


def _is_valid_sha256(hash_str: str) -> bool:
    if not isinstance(hash_str, str):
        return False
    return bool(SHA256_REGEX.match(hash_str.strip()))


def _is_valid_ip(ip_str: str) -> str:
    if not isinstance(ip_str, str):
        return ""
    try:
        return str(ipaddress.ip_address(ip_str.strip()))
    except ValueError:
        return ""


def _extract_hostnames(urls: Any) -> set:
    hosts = set()
    if not isinstance(urls, (list, tuple)):
        return hosts
    for url in urls:
        if not isinstance(url, str):
            continue
        url_clean = url.strip()
        if not url_clean:
            continue
        # Support defanged URLs
        url_clean = DEFANG_REGEX.sub(".", url_clean)
        # Normalize hxxp/hxxps to http/https case-insensitively
        url_clean = re.sub(r'(?i)^hxxp', 'http', url_clean)
        try:
            parsed = urllib.parse.urlparse(url_clean)
            if parsed.scheme.lower() not in ("http", "https"):
                continue
            host = parsed.hostname
            if not host:
                continue
            host = str(host).lower().strip()
            ip = _is_valid_ip(host)
            if ip:
                hosts.add(ip)
            else:
                normalized_domain = _is_valid_domain(host)
                if normalized_domain:
                    hosts.add(normalized_domain)
        except (ValueError, TypeError):
            continue
    return hosts


def _sanitize_label(label: str) -> str:
    s = str(label).strip()
    if len(s) > MAX_LABEL_LENGTH:
        return s[:MAX_LABEL_LENGTH - 3] + "..."
    return s


def build_ioc_graph(cases: Any) -> dict:
    nodes = {}
    edges = set()
    truncated = False

    if not isinstance(cases, (list, tuple)):
        return {"nodes": [], "edges": [], "truncated": False}

    valid_cases = [c for c in cases if isinstance(c, dict) and c.get("case_id")]
    valid_cases.sort(key=lambda x: str(x["case_id"]))

    def add_node(node_id: str, ntype: str, label: str) -> bool:
        nonlocal truncated
        if node_id not in nodes:
            if len(nodes) >= MAX_NODES:
                truncated = True
                return False
            # Bound the full label to 256 for display
            full_label = str(label).strip()[:256]
            nodes[node_id] = {
                "id": node_id,
                "type": ntype,
                "label": _sanitize_label(full_label),
                "full_label": full_label
            }
        return True

    def add_edge(source_id: str, target_id: str) -> None:
        nonlocal truncated
        if source_id in nodes and target_id in nodes:
            edge = (source_id, target_id)
            if edge not in edges:
                if len(edges) >= MAX_EDGES:
                    truncated = True
                    return
                edges.add(edge)

    for case in valid_cases:
        case_id = str(case.get("case_id", "Unknown")).strip()
        if not case_id:
            continue

        case_internal_id = f"case_{hashlib.sha256(case_id.encode('utf-8')).hexdigest()}"
        case_label = case_id if len(case_id) <= 256 else case_id[:253] + "..."
        case_node_id = case_internal_id

        if not add_node(case_node_id, "Case", case_label):
            break

        # IP
        ip = _is_valid_ip(case.get("probable_origin_ip", ""))
        if ip:
            ip_id = f"ip_{ip}"
            if add_node(ip_id, "IP", ip):
                add_edge(case_node_id, ip_id)

        # Sender Domain
        sender = str(case.get("sender_domain", "")).strip()
        normalized_sender = _is_valid_domain(sender)
        if normalized_sender:
            sd_id = f"domain_{normalized_sender}"
            if add_node(sd_id, "Domain", normalized_sender):
                add_edge(case_node_id, sd_id)

        # Reply-to Domain
        reply = str(case.get("reply_to_domain", "")).strip()
        normalized_reply = _is_valid_domain(reply)
        if normalized_reply and normalized_reply != normalized_sender:
            rd_id = f"domain_{normalized_reply}"
            if add_node(rd_id, "Domain", normalized_reply):
                add_edge(case_node_id, rd_id)

        # URLs
        for host in sorted(_extract_hostnames(case.get("extracted_urls"))):
            h_id = f"url_{host}"
            if add_node(h_id, "URL Host", host):
                add_edge(case_node_id, h_id)

        # Attachment Hashes
        analyzer_results = case.get("analyzer_results")
        if isinstance(analyzer_results, dict):
            att_analysis = analyzer_results.get("attachment_analysis")
            if isinstance(att_analysis, dict):
                attachments = att_analysis.get("attachments")
                if isinstance(attachments, (list, tuple)):
                    for att in attachments:
                        if isinstance(att, dict):
                            h = str(att.get("sha256", "")).lower().strip()
                            if _is_valid_sha256(h):
                                h_id = f"hash_{h}"
                                if add_node(h_id, "Hash", h):
                                    add_edge(case_node_id, h_id)

    # Compute deterministic layout
    grouped_nodes = {t: [] for t in NODE_X.keys()}
    for n in nodes.values():
        grouped_nodes[n["type"]].append(n)

    for ntype, items in grouped_nodes.items():
        count = len(items)
        if count == 0:
            continue
        # Sort for determinism
        items.sort(key=lambda x: x["id"])

        # Center them around Y=0
        for i, item in enumerate(items):
            item["x"] = NODE_X[ntype]
            item["y"] = i - (count - 1) / 2.0

    # Calculate degree for shared IOC highlighting
    for n in nodes.values():
        n["degree"] = sum(1 for e in edges if e[0] == n["id"] or e[1] == n["id"])

    # Sort nodes and edges before returning
    sorted_nodes = sorted(list(nodes.values()), key=lambda x: x["id"])
    sorted_edges = [{"source": s, "target": t} for s, t in sorted(list(edges))]

    return {
        "nodes": sorted_nodes,
        "edges": sorted_edges,
        "truncated": truncated
    }


def render_ioc_graph(graph_data: dict) -> go.Figure:
    fig = go.Figure()

    nodes = graph_data.get("nodes", [])
    edges = graph_data.get("edges", [])

    if not nodes:
        fig.update_layout(
            xaxis=dict(visible=False), yaxis=dict(visible=False),
            annotations=[dict(text="No relationship data available.", showarrow=False, font=dict(size=14, color="#94A3B8"))],
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)"
        )
        return fig

    node_by_id = {n["id"]: n for n in nodes}

    # Edges
    edge_x = []
    edge_y = []
    for edge in edges:
        s = node_by_id.get(edge["source"])
        t = node_by_id.get(edge["target"])
        if s and t:
            edge_x.extend([s["x"], t["x"], None])
            edge_y.extend([s["y"], t["y"], None])

    fig.add_trace(go.Scatter(
        x=edge_x, y=edge_y,
        mode="lines",
        line=dict(width=1, color="#334155"),
        hoverinfo="none",
        showlegend=False
    ))

    # Nodes by type for legend
    grouped_nodes = {}
    for n in nodes:
        grouped_nodes.setdefault(n["type"], []).append(n)

    ordered_types = ["Case", "IP", "Domain", "URL Host", "Hash"]

    for ntype in ordered_types:
        if ntype not in grouped_nodes:
            continue
        items = grouped_nodes[ntype]
        nx = [n["x"] for n in items]
        ny = [n["y"] for n in items]

        # Highlight shared IOCs: if degree > 1 and not a Case
        markers = []
        for n in items:
            color = NODE_COLORS.get(ntype, "#CBD5E1")
            line_color = "#F1F5F9" if (n["type"] != "Case" and n.get("degree", 0) > 1) else color
            line_width = 2 if (n["type"] != "Case" and n.get("degree", 0) > 1) else 0
            markers.append(dict(color=color, line=dict(color=line_color, width=line_width)))

        marker_colors = [m["color"] for m in markers]
        marker_line_colors = [m["line"]["color"] for m in markers]
        marker_line_widths = [m["line"]["width"] for m in markers]

        hover_text = [
            f"<b>{html.escape(n['type'])}</b><br>{html.escape(n['full_label'])}<br>Connections: {n.get('degree', 0)}"
            for n in items
        ]

        # Determine text position based on column
        if ntype == "Case":
            textpos = "middle right"
        elif ntype == "Hash":
            textpos = "middle left"
        else:
            textpos = "top center"

        fig.add_trace(go.Scatter(
            x=nx, y=ny,
            mode="markers+text",
            name=ntype,
            marker=dict(
                size=22,
                color=marker_colors,
                line=dict(color=marker_line_colors, width=marker_line_widths)
            ),
            text=[n["label"] for n in items],
            textposition=textpos,
            hoverinfo="text",
            hovertext=hover_text,
            textfont=dict(color="#F1F5F9", size=10)
        ))

    fig.update_layout(
        title_text="",
        showlegend=True,
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1,
            font=dict(color="#CBD5E1")
        ),
        margin=dict(l=40, r=40, t=60, b=40),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        hoverlabel=dict(bgcolor="#152638", font_color="#F1F5F9", bordercolor="#334155"),
        dragmode="pan"
    )

    fig.update_xaxes(visible=False)
    fig.update_yaxes(visible=False)

    return fig


def generate_fallback_table(graph_data: dict) -> list:
    nodes = graph_data.get("nodes", [])
    edges = graph_data.get("edges", [])

    if not nodes or not edges:
        return []

    node_by_id = {n["id"]: n for n in nodes}

    rows = []
    # Find all Case nodes
    case_nodes = [n for n in nodes if n["type"] == "Case"]

    for c in case_nodes:
        case_edges = [e for e in edges if e["source"] == c["id"]]
        for e in case_edges:
            target = node_by_id.get(e["target"])
            if target:
                rows.append({
                    "Case": c["full_label"],
                    "Indicator Type": target["type"],
                    "Indicator Value": target["full_label"],
                    "Shared Connections": target.get("degree", 0)
                })

    # Sort for deterministic output
    rows.sort(key=lambda x: (x["Case"], x["Indicator Type"], x["Indicator Value"]))
    return rows
