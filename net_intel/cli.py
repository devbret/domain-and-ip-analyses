import argparse
from dataclasses import asdict
from datetime import datetime

from .domain import build_domain_report
from .ip import build_ip_report
from .models import ReportBundle
from .output import to_pretty_json, write_report


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="net-intel", description="Domain + IP analysis tool")
    p.add_argument("--domain", help="Domain name to analyze (e.g. example.com)")
    p.add_argument("--ip", help="IP address to analyze (e.g. 8.8.8.8)")
    p.add_argument("--banner-port", type=int, default=80)
    p.add_argument("--scan-max-port", type=int, default=100)
    p.add_argument("--scan-threads", type=int, default=50)
    p.add_argument("--scan-timeout", type=float, default=1.0)
    p.add_argument("--preview-chars", type=int, default=1000)
    p.add_argument("--outdir", default="reports")
    p.add_argument("--no-console", action="store_true")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    if not args.domain and not args.ip:
        raise SystemExit("Provide --domain and/or --ip")

    domain_report = build_domain_report(args.domain, args.preview_chars) if args.domain else None
    ip_report = (
        build_ip_report(args.ip, args.banner_port, args.scan_max_port, args.scan_threads, args.scan_timeout)
        if args.ip
        else None
    )

    bundle = ReportBundle(
        generated_at=datetime.now(),
        domain_report=domain_report,
        ip_report=ip_report,
    )

    payload = asdict(bundle)

    target_hint = args.domain or args.ip or "report"
    outfile = write_report(args.outdir, target_hint, payload)

    if not args.no_console:
        print(to_pretty_json(payload))
        print(f"\nWrote: {outfile}")
