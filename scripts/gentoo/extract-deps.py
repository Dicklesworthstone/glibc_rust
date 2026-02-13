#!/usr/bin/env python3
"""Generate deterministic Gentoo dependency graph artifacts for FrankenLibC validation.

Outputs:
  - data/gentoo/dependency-graph.json
  - data/gentoo/build-order.txt
  - data/gentoo/build-waves.json
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class Edge:
    dep: str
    pkg: str
    kind: str


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def read_top100(path: Path) -> list[str]:
    atoms = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(atoms) != 100:
        raise ValueError(f"expected 100 package atoms in {path}, found {len(atoms)}")
    if len(set(atoms)) != len(atoms):
        raise ValueError("top100 package list contains duplicate atoms")
    return atoms


def read_tier_map(path: Path) -> dict[str, str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    tiers = data.get("tiers", [])
    tier_map: dict[str, str] = {}
    for tier in tiers:
        tier_id = tier["id"]
        for atom in tier.get("packages", []):
            tier_map[atom] = tier_id
    return tier_map


def build_edges(packages: list[str]) -> set[Edge]:
    pkg_set = set(packages)
    edges: set[Edge] = set()

    # Toolchain/bootstrap scaffolding.
    bootstrap_edges = [
        Edge("sys-kernel/linux-headers", "sys-libs/glibc", "BDEPEND"),
        Edge("sys-devel/binutils", "sys-devel/gcc", "BDEPEND"),
        Edge("sys-libs/glibc", "sys-devel/gcc", "RDEPEND"),
    ]
    for e in bootstrap_edges:
        if e.dep in pkg_set and e.pkg in pkg_set:
            edges.add(e)

    # Global dependencies: most packages rely on core toolchain/runtime.
    runtime_base = "sys-libs/glibc"
    build_base = ["sys-devel/gcc", "sys-devel/binutils", "sys-devel/make"]
    exempt = {
        "sys-libs/glibc",
        "sys-devel/gcc",
        "sys-devel/binutils",
        "sys-devel/make",
        "sys-kernel/linux-headers",
        "sys-devel/patch",
    }
    for pkg in packages:
        if pkg in exempt:
            continue
        if runtime_base in pkg_set:
            edges.add(Edge(runtime_base, pkg, "RDEPEND"))
        for dep in build_base:
            if dep in pkg_set:
                edges.add(Edge(dep, pkg, "BDEPEND"))

    # Focused package-to-package relations for better graph fidelity.
    specific: dict[str, list[tuple[str, str]]] = {
        "net-misc/openssh": [("dev-libs/openssl", "RDEPEND"), ("app-crypt/mit-krb5", "RDEPEND")],
        "net-misc/curl": [("dev-libs/openssl", "RDEPEND"), ("net-libs/gnutls", "RDEPEND"), ("dev-libs/libidn2", "RDEPEND"), ("net-libs/libpsl", "RDEPEND")],
        "net-misc/wget": [("dev-libs/openssl", "RDEPEND"), ("net-libs/gnutls", "RDEPEND"), ("dev-libs/libidn2", "RDEPEND")],
        "mail-mta/postfix": [("dev-libs/openssl", "RDEPEND"), ("app-crypt/mit-krb5", "RDEPEND")],
        "dev-db/postgresql": [("dev-libs/openssl", "RDEPEND"), ("dev-libs/libxml2", "RDEPEND"), ("dev-libs/icu", "RDEPEND")],
        "dev-db/mariadb": [("dev-libs/openssl", "RDEPEND"), ("dev-libs/libevent", "RDEPEND")],
        "dev-db/redis": [("dev-libs/libevent", "RDEPEND"), ("dev-libs/openssl", "RDEPEND")],
        "dev-db/memcached": [("dev-libs/libevent", "RDEPEND")],
        "www-servers/nginx": [("dev-libs/openssl", "RDEPEND"), ("dev-libs/libpcre2", "RDEPEND"), ("dev-libs/libxml2", "RDEPEND")],
        "www-servers/apache": [("dev-libs/openssl", "RDEPEND"), ("dev-libs/libpcre2", "RDEPEND")],
        "www-servers/lighttpd": [("dev-libs/openssl", "RDEPEND"), ("dev-libs/libpcre2", "RDEPEND")],
        "dev-util/git": [("dev-libs/openssl", "RDEPEND"), ("dev-libs/libpcre2", "RDEPEND"), ("dev-libs/libcurl", "RDEPEND"), ("dev-libs/libexpat", "RDEPEND")],
        "app-editors/neovim": [("app-editors/vim", "RDEPEND"), ("dev-libs/libuv", "RDEPEND")],
        "dev-libs/protobuf": [("dev-cpp/abseil-cpp", "RDEPEND"), ("dev-util/cmake", "BDEPEND")],
        "net-libs/grpc": [("dev-libs/protobuf", "RDEPEND"), ("dev-cpp/abseil-cpp", "RDEPEND"), ("dev-libs/openssl", "RDEPEND"), ("dev-util/cmake", "BDEPEND")],
        "app-containers/docker": [("net-misc/curl", "RDEPEND"), ("dev-libs/protobuf", "RDEPEND"), ("dev-util/cmake", "BDEPEND")],
        "app-emulation/qemu": [("dev-libs/glib", "RDEPEND"), ("dev-libs/libxml2", "RDEPEND"), ("dev-libs/openssl", "RDEPEND")],
        "app-emulation/wine": [("dev-libs/libxml2", "RDEPEND"), ("dev-libs/openssl", "RDEPEND"), ("media-libs/libpng", "RDEPEND"), ("media-libs/libjpeg-turbo", "RDEPEND")],
        "media-video/ffmpeg": [("media-libs/libpng", "RDEPEND"), ("media-libs/libjpeg-turbo", "RDEPEND"), ("dev-libs/openssl", "RDEPEND")],
        "media-video/vlc": [("media-video/ffmpeg", "RDEPEND"), ("dev-libs/openssl", "RDEPEND"), ("media-libs/libpng", "RDEPEND")],
        "net-misc/mosquitto": [("dev-libs/openssl", "RDEPEND"), ("net-libs/libevent", "RDEPEND")],
        "net-p2p/transmission": [("net-misc/curl", "RDEPEND"), ("dev-libs/libevent", "RDEPEND")],
        "sys-apps/systemd": [("dev-libs/libpcre2", "RDEPEND"), ("dev-libs/openssl", "RDEPEND")],
        "app-text/xmlto": [("dev-libs/libxml2", "RDEPEND"), ("dev-libs/libxslt", "RDEPEND")],
        "app-text/poppler": [("dev-libs/libxml2", "RDEPEND"), ("dev-libs/icu", "RDEPEND")],
        "app-text/ghostscript-gpl": [("dev-libs/libidn2", "RDEPEND"), ("dev-libs/icu", "RDEPEND")],
    }
    for pkg, deps in specific.items():
        if pkg not in pkg_set:
            continue
        for dep, kind in deps:
            # normalize legacy aliases inside this curated top100 set
            alias_map = {
                "dev-libs/libcurl": "net-misc/curl",
                "dev-libs/libexpat": "dev-libs/expat",
            }
            dep = alias_map.get(dep, dep)
            if dep in pkg_set and dep != pkg:
                edges.add(Edge(dep, pkg, kind))

    return edges


def compute_reachability_count(nodes: list[str], adjacency: dict[str, set[str]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for node in nodes:
        seen: set[str] = set()
        stack = list(adjacency[node])
        while stack:
            nxt = stack.pop()
            if nxt == node or nxt in seen:
                continue
            seen.add(nxt)
            stack.extend(adjacency[nxt])
        counts[node] = len(seen)
    return counts


def compute_scc(nodes: list[str], outgoing: dict[str, set[str]], incoming: dict[str, set[str]]) -> list[list[str]]:
    visited: set[str] = set()
    post_order: list[str] = []

    def dfs1(node: str) -> None:
        stack = [node]
        local_seen: set[str] = set()
        while stack:
            cur = stack[-1]
            if cur not in visited:
                visited.add(cur)
            pushed = False
            for nxt in sorted(outgoing[cur]):
                if nxt not in visited:
                    stack.append(nxt)
                    pushed = True
                    break
            if pushed:
                continue
            if cur not in local_seen:
                local_seen.add(cur)
                post_order.append(cur)
            stack.pop()

    for n in nodes:
        if n not in visited:
            dfs1(n)

    assigned: set[str] = set()
    components: list[list[str]] = []
    for node in reversed(post_order):
        if node in assigned:
            continue
        comp: list[str] = []
        stack = [node]
        assigned.add(node)
        while stack:
            cur = stack.pop()
            comp.append(cur)
            for prev in sorted(incoming[cur]):
                if prev not in assigned:
                    assigned.add(prev)
                    stack.append(prev)
        components.append(sorted(comp))
    return components


def estimate_build_minutes(atom: str, tier_id: str) -> int:
    tier_defaults = {
        "tier1-core-infrastructure": 4,
        "tier2-security-critical": 6,
        "tier3-allocation-heavy": 8,
        "tier4-string-heavy": 5,
        "tier5-threading-heavy": 7,
    }
    heavy_overrides = {
        "sys-devel/gcc": 18,
        "sys-libs/glibc": 12,
        "app-emulation/qemu": 14,
        "app-emulation/wine": 16,
        "app-containers/docker": 10,
        "dev-db/postgresql": 11,
        "dev-db/mariadb": 12,
        "media-video/ffmpeg": 10,
        "media-video/vlc": 9,
    }
    if atom in heavy_overrides:
        return heavy_overrides[atom]
    return tier_defaults.get(tier_id, 6)


def main() -> int:
    root = repo_root()
    parser = argparse.ArgumentParser(description="Extract deterministic dependency graph artifacts.")
    parser.add_argument(
        "--top100",
        type=Path,
        default=root / "configs/gentoo/top100-packages.txt",
        help="Path to top100 package list",
    )
    parser.add_argument(
        "--tiers",
        type=Path,
        default=root / "configs/gentoo/package-tiers.json",
        help="Path to package tier metadata",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=root / "data/gentoo",
        help="Output directory for graph artifacts",
    )
    args = parser.parse_args()

    packages = read_top100(args.top100)
    tier_map = read_tier_map(args.tiers)
    edges = build_edges(packages)

    outgoing: dict[str, set[str]] = {p: set() for p in packages}
    incoming: dict[str, set[str]] = {p: set() for p in packages}
    kind_by_edge: dict[tuple[str, str], str] = {}
    for e in sorted(edges, key=lambda x: (x.dep, x.pkg)):
        outgoing[e.dep].add(e.pkg)
        incoming[e.pkg].add(e.dep)
        kind_by_edge[(e.dep, e.pkg)] = e.kind

    # Build waves + topological order (Kahn).
    indeg = {p: len(incoming[p]) for p in packages}
    wave_index: dict[str, int] = {}
    build_order: list[str] = []
    waves: list[list[str]] = []
    remaining = set(packages)

    current_wave = sorted([p for p in packages if indeg[p] == 0])
    wave_no = 0
    while current_wave:
        waves.append(current_wave)
        next_wave_candidates: set[str] = set()
        for node in current_wave:
            if node not in remaining:
                continue
            remaining.remove(node)
            build_order.append(node)
            wave_index[node] = wave_no
            for child in sorted(outgoing[node]):
                indeg[child] -= 1
                if indeg[child] == 0:
                    next_wave_candidates.add(child)
        wave_no += 1
        current_wave = sorted(next_wave_candidates)

    # If any nodes remain due cycle, append deterministically as final wave.
    if remaining:
        cycle_wave = sorted(remaining)
        waves.append(cycle_wave)
        for node in cycle_wave:
            build_order.append(node)
            wave_index[node] = wave_no

    descendants_count = compute_reachability_count(build_order, outgoing)
    ancestors_count = compute_reachability_count(build_order, incoming)
    scc = compute_scc(packages, outgoing, incoming)

    max_in = max((len(incoming[p]) for p in packages), default=1)
    n_minus_1 = max(len(packages) - 1, 1)

    nodes = []
    for atom in build_order:
        in_deg = len(incoming[atom])
        out_deg = len(outgoing[atom])
        blocked = descendants_count[atom]
        score = (0.7 * (blocked / n_minus_1)) + (0.3 * (in_deg / max_in))
        nodes.append(
            {
                "atom": atom,
                "tier": tier_map.get(atom, "unknown"),
                "in_degree": in_deg,
                "out_degree": out_deg,
                "transitive_deps": ancestors_count[atom],
                "depended_by_transitive": blocked,
                "critical_path_score": round(score, 4),
                "build_wave": wave_index[atom],
                "estimated_build_time_minutes": estimate_build_minutes(atom, tier_map.get(atom, "unknown")),
            }
        )

    edge_rows = [
        {"from": dep, "to": pkg, "kind": kind_by_edge[(dep, pkg)]}
        for dep, pkg in sorted(kind_by_edge.keys())
    ]

    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    total_estimated_minutes = sum(n["estimated_build_time_minutes"] for n in nodes)
    graph = {
        "schema_version": "v1",
        "bead": "bd-2icq.6",
        "generated_at": generated_at,
        "sources": {
            "top100_packages": str(args.top100.relative_to(root)),
            "package_tiers": str(args.tiers.relative_to(root)),
        },
        "metrics": {
            "package_count": len(packages),
            "edge_count": len(edge_rows),
            "wave_count": len(waves),
            "estimated_total_build_time_minutes": total_estimated_minutes,
            "estimated_total_build_time_hours": round(total_estimated_minutes / 60.0, 2),
            "scc_count": len(scc),
            "largest_scc_size": max((len(c) for c in scc), default=0),
        },
        "nodes": nodes,
        "edges": edge_rows,
        "strongly_connected_components": scc,
        "build_order": build_order,
        "build_waves": waves,
    }

    args.out_dir.mkdir(parents=True, exist_ok=True)
    graph_path = args.out_dir / "dependency-graph.json"
    order_path = args.out_dir / "build-order.txt"
    waves_path = args.out_dir / "build-waves.json"

    graph_path.write_text(json.dumps(graph, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    order_path.write_text("\n".join(build_order) + "\n", encoding="utf-8")

    waves_doc = {
        "schema_version": "v1",
        "bead": "bd-2icq.6",
        "generated_at": generated_at,
        "wave_count": len(waves),
        "waves": [
            {"wave": idx, "count": len(w), "packages": w}
            for idx, w in enumerate(waves)
        ],
    }
    waves_path.write_text(json.dumps(waves_doc, indent=2, sort_keys=False) + "\n", encoding="utf-8")

    print(f"OK: wrote {graph_path}")
    print(f"OK: wrote {order_path}")
    print(f"OK: wrote {waves_path}")
    print(
        f"Summary: packages={len(packages)} edges={len(edge_rows)} waves={len(waves)} "
        f"estimated_hours={round(total_estimated_minutes / 60.0, 2)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
