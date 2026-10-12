"""CLI: python -m agent_access_review scan <paths> [--out review] [--as-of YYYY-MM-DD] [--fail-on high]"""
from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

from .checks import run_all
from .model import SEVERITY_ORDER
from .parsers import discover
from .report import counts, write_all


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog='agent_access_review',
                                 description='Access reviews for AI agents and MCP servers.')
    sub = ap.add_subparsers(dest='cmd', required=True)
    scan = sub.add_parser('scan', help='review agent configs and write the review packet')
    scan.add_argument('paths', nargs='+', type=Path, help='MCP config files, agents.yaml manifests, or folders')
    scan.add_argument('--out', type=Path, default=Path('review'), help='output folder (default: review)')
    scan.add_argument('--as-of', type=date.fromisoformat, default=date.today(),
                      help='review date used for recertification, rotation and dormancy (default: today)')
    scan.add_argument('--fail-on', choices=['high', 'medium', 'low', 'never'], default='never',
                      help='exit 1 if any finding is at or above this severity (for CI gates)')
    args = ap.parse_args(argv)

    missing = [p for p in args.paths if not p.exists()]
    if missing:
        ap.error(f'not found: {", ".join(map(str, missing))}')
    agents = discover(args.paths)
    if not agents:
        print('No MCP configs or agent manifests found.', file=sys.stderr)
        return 2

    results = [(a, run_all(a, args.as_of)) for a in agents]
    paths = write_all(results, args.out, args.as_of)

    print(f'{"AGENT":<28} {"TOOLS":>5} {"HIGH":>5} {"MED":>5} {"LOW":>5}')
    for agent, findings in results:
        c = counts(findings)
        print(f'{agent.id[:28]:<28} {len(agent.grants):>5} {c["high"]:>5} {c["medium"]:>5} {c["low"]:>5}')
    print(f'\nReview packet: {paths["report"]}\nDecision sheet: {paths["sheet"]}\nOSCAL: {paths["oscal"]}')

    if args.fail_on != 'never':
        floor = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f.severity] >= floor for _, fs in results for f in fs):
            return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
