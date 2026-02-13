#!/usr/bin/env python3
"""Render Gentoo dependency graph artifacts as DOT or Mermaid."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def render_dot(nodes: list[dict], edges: list[dict]) -> str:
    lines = ["digraph gentoo_top100 {", "  rankdir=LR;"]
    for node in nodes:
        atom = node["atom"]
        tier = node.get("tier", "unknown")
        wave = node.get("build_wave", "?")
        lines.append(f'  "{atom}" [label="{atom}\\n{tier}\\nwave={wave}"];')
    for edge in edges:
        lines.append(f'  "{edge["from"]}" -> "{edge["to"]}" [label="{edge.get("kind", "")}"];')
    lines.append("}")
    return "\n".join(lines) + "\n"


def render_mermaid(nodes: list[dict], edges: list[dict]) -> str:
    lines = ["flowchart LR"]
    for node in nodes:
        atom = node["atom"]
        nid = atom.replace("/", "_").replace("-", "_")
        lines.append(f'  {nid}["{atom}"]')
    for edge in edges:
        src = edge["from"].replace("/", "_").replace("-", "_")
        dst = edge["to"].replace("/", "_").replace("-", "_")
        kind = edge.get("kind", "")
        lines.append(f"  {src} -->|{kind}| {dst}")
    return "\n".join(lines) + "\n"


def main() -> int:
    root = repo_root()
    parser = argparse.ArgumentParser(description="Render dependency graph to DOT or Mermaid.")
    parser.add_argument(
        "--graph",
        type=Path,
        default=root / "data/gentoo/dependency-graph.json",
        help="Path to dependency-graph.json",
    )
    parser.add_argument(
        "--format",
        choices=["dot", "mermaid"],
        default="dot",
        help="Output format",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output file path (default: stdout)",
    )
    args = parser.parse_args()

    graph = json.loads(args.graph.read_text(encoding="utf-8"))
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])

    rendered = render_dot(nodes, edges) if args.format == "dot" else render_mermaid(nodes, edges)
    if args.output is None:
        print(rendered, end="")
        return 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")
    print(f"OK: wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
