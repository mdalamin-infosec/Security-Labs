"""Command line entry points. Everything here is offline; no network access is used."""

import argparse
from pathlib import Path
import sys
from .beacon import find_beacons
from .demo import write_events
from .eve import alerts_from, read_events
from .metrics import MetricsError, compare, load_records, summarize
from .report import to_json, to_markdown, to_text
from .rules import DEFAULT_RULES, RuleError, load_catalogue
from .triage import build_incidents

DEMO_EVE = "data/demo-eve.json"


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="threatwatch", description="Triage Suricata EVE alerts into prioritised incidents.")
    sub = root.add_subparsers(dest="action", required=True)
    sub.add_parser("rules", help="List the local detection rule catalogue.").add_argument("--rules", type=Path, default=DEFAULT_RULES)
    demo = sub.add_parser("demo", help="Generate synthetic events, triage them, and write reports.")
    demo.add_argument("--data-dir", type=Path, default=Path("data"))
    demo.add_argument("--report-dir", type=Path, default=Path("reports"))
    sample = sub.add_parser("generate-sample", help="Write synthetic EVE events to a file.")
    sample.add_argument("--output", type=Path, default=Path(DEMO_EVE))
    for name, text in (("triage", "Group alerts into incidents and score them."), ("beacons", "List periodic outbound connection leads.")):
        cmd = sub.add_parser(name, help=text)
        cmd.add_argument("eve", type=Path)
        cmd.add_argument("--rules", type=Path, default=DEFAULT_RULES)
        cmd.add_argument("--format", choices=("text", "json", "markdown"), default="text")
        cmd.add_argument("--output", type=Path)
        cmd.add_argument("--gap-minutes", type=int, default=15)
    metrics = sub.add_parser("metrics", help="Summarise triage and closure times from lifecycle records.")
    metrics.add_argument("csv", type=Path)
    metrics.add_argument("--baseline")
    metrics.add_argument("--treatment")
    return root


def _analyse(eve: Path, rules: Path, gap: int):
    loaded = read_events(eve)
    incidents = build_incidents(alerts_from(loaded.events), load_catalogue(rules), gap)
    return incidents, find_beacons(loaded.events), loaded.skipped


def _emit(text: str, output: Path | None) -> None:
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
        print(f"wrote {output}")
    else:
        sys.stdout.write(text)


def run(args: argparse.Namespace) -> int:
    if args.action == "rules":
        for rule in load_catalogue(args.rules).values():
            print(f"{rule.sid}  {rule.severity:<6} {rule.technique:<10} {rule.tactic:<18} {rule.msg}")
        return 0
    if args.action == "generate-sample":
        print(f"wrote {write_events(args.output)} synthetic events to {args.output}")
        return 0
    if args.action == "demo":
        eve = args.data_dir / "demo-eve.json"
        write_events(eve)
        incidents, beacons, skipped = _analyse(eve, DEFAULT_RULES, 15)
        args.report_dir.mkdir(parents=True, exist_ok=True)
        (args.report_dir / "demo-incidents.md").write_text(to_markdown(incidents, beacons, skipped), encoding="utf-8")
        (args.report_dir / "demo-incidents.json").write_text(to_json(incidents, beacons, skipped), encoding="utf-8")
        sys.stdout.write(to_text(incidents, beacons, skipped))
        print(f"\nsynthetic data: {eve}\nreports: {args.report_dir}/demo-incidents.md, demo-incidents.json")
        return 0
    if args.action in ("triage", "beacons"):
        incidents, beacons, skipped = _analyse(args.eve, args.rules, args.gap_minutes)
        if args.action == "beacons":
            incidents = []
        render = {"text": to_text, "json": to_json, "markdown": to_markdown}[args.format]
        _emit(render(incidents, beacons, skipped), args.output)
        return 0
    if args.action == "metrics":
        summary = summarize(load_records(args.csv))
        for cohort, values in summary.items():
            print(cohort, values)
        if args.baseline and args.treatment:
            print("change vs baseline (%):", compare(summary, args.baseline, args.treatment))
        return 0
    return 2


def main(argv: list[str] | None = None) -> int:
    try:
        return run(parser().parse_args(argv))
    except (OSError, RuleError, MetricsError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
