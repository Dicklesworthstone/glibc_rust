#!/usr/bin/env bash
# export_matrix_dashboard.sh — Dashboard export for bd-38s
#
# Generates a compact, operator-friendly dashboard view from the
# verification matrix. Shows per-bead coverage status, obligation
# gaps, and traceable test commands / artifact paths.
#
# Output formats:
#   text   — terminal-friendly table (default)
#   json   — machine-readable JSON
#
# Usage:
#   bash scripts/export_matrix_dashboard.sh [text|json] [> dashboard.txt]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MATRIX="${ROOT}/tests/conformance/verification_matrix.json"
FORMAT="${1:-text}"

if [[ ! -f "${MATRIX}" ]]; then
    echo "ERROR: verification_matrix.json not found" >&2
    exit 1
fi

python3 -c "
import json, sys

fmt = '${FORMAT}'

with open('${MATRIX}') as f:
    matrix = json.load(f)

entries = matrix.get('entries', [])
dashboard = matrix.get('dashboard', {})

# Build per-entry summary
rows = []
for e in entries:
    bid = e['bead_id']
    title = e.get('title', '')[:60]
    priority = e.get('priority', 99)
    cs = e.get('coverage_summary', {})
    overall = cs.get('overall', 'missing')
    required = cs.get('required', 0)
    complete_count = cs.get('complete', 0)
    partial_count = cs.get('partial', 0)
    missing_count = cs.get('missing', 0)

    # Collect gap details
    coverage = e.get('coverage', {})
    obligations = e.get('obligations', {})
    gaps = []
    for ob_type, ob_info in obligations.items():
        if not ob_info.get('required', False):
            continue
        cov = coverage.get(ob_type, {})
        cov_status = cov.get('status', 'missing')
        if cov_status != 'complete':
            gaps.append(ob_type)

    rows.append({
        'bead_id': bid,
        'priority': priority,
        'title': title,
        'overall': overall,
        'required': required,
        'complete': complete_count,
        'partial': partial_count,
        'missing': missing_count,
        'gaps': gaps
    })

# Sort: by coverage status (missing first), then priority, then bead_id
status_order = {'missing': 0, 'partial': 1, 'complete': 2}
rows.sort(key=lambda r: (status_order.get(r['overall'], 0), r['priority'], r['bead_id']))

if fmt == 'json':
    output = {
        'generated_utc': __import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat(),
        'bead': 'bd-38s',
        'summary': {
            'total': len(rows),
            'complete': sum(1 for r in rows if r['overall'] == 'complete'),
            'partial': sum(1 for r in rows if r['overall'] == 'partial'),
            'missing': sum(1 for r in rows if r['overall'] == 'missing')
        },
        'by_priority': {},
        'rows': rows
    }
    for p in [0, 1, 2]:
        prows = [r for r in rows if r['priority'] == p]
        output['by_priority'][f'P{p}'] = {
            'total': len(prows),
            'complete': sum(1 for r in prows if r['overall'] == 'complete'),
            'partial': sum(1 for r in prows if r['overall'] == 'partial'),
            'missing': sum(1 for r in prows if r['overall'] == 'missing')
        }
    print(json.dumps(output, indent=2))
else:
    # Text format
    total = len(rows)
    complete = sum(1 for r in rows if r['overall'] == 'complete')
    partial = sum(1 for r in rows if r['overall'] == 'partial')
    missing = sum(1 for r in rows if r['overall'] == 'missing')

    print('=== Verification Matrix Dashboard (bd-38s) ===')
    print(f'Total beads: {total}  Complete: {complete}  Partial: {partial}  Missing: {missing}')
    print()

    # By priority
    for p in [0, 1, 2]:
        prows = [r for r in rows if r['priority'] == p]
        if not prows:
            continue
        pc = sum(1 for r in prows if r['overall'] == 'complete')
        pp = sum(1 for r in prows if r['overall'] == 'partial')
        pm = sum(1 for r in prows if r['overall'] == 'missing')
        print(f'P{p}: {len(prows)} beads ({pc} complete, {pp} partial, {pm} missing)')
    print()

    # Table header
    print(f\"{'BEAD':<10} {'P':>1} {'STATUS':<8} {'OB':>2}/{'>2':<2} {'GAPS'}\")
    print('-' * 72)

    for r in rows:
        status_char = {'complete': 'OK', 'partial': '~~', 'missing': '!!'}[r['overall']]
        gap_str = ', '.join(r['gaps'][:4])
        if len(r['gaps']) > 4:
            gap_str += f' (+{len(r[\"gaps\"])-4})'
        print(f\"{r['bead_id']:<10} {r['priority']:>1} {status_char:<8} {r['complete']:>2}/{r['required']:<2} {gap_str}\")

    print()
    print('Legend: OK=complete, ~~=partial, !!=missing')
    print('Gaps: obligation types that need evidence')
"
