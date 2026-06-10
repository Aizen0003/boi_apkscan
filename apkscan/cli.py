"""APKScan command-line interface.

``analyze`` runs the full local pipeline (static -> rule scoring -> grounded GenAI
-> fusion -> report) on a single host with no commercial-API egress — the local
E2E for T0.20. Other subcommands manage the DB/users and run the services.
"""

import argparse
import sys
from pathlib import Path

from apkscan import __version__
from apkscan.config import get_settings
from apkscan.ingestion.hashing import hash_file
from apkscan.pipeline import run_analysis
from apkscan.reporting.json_report import render_json_bytes
from apkscan.reporting.pdf_report import render_pdf
from apkscan.schema import SampleMetadata


def _sample_metadata(apk: Path) -> SampleMetadata:
    h = hash_file(apk)
    return SampleMetadata(
        sha256=h["sha256"], sha1=h["sha1"], md5=h["md5"],
        file_name=apk.name, file_size=int(h["size"]),
    )


def _print_summary(apk: Path, outcome) -> None:
    score = outcome.score
    feats = outcome.features
    print(f"\nAPKScan analysis — {apk.name}")
    print(f"  SHA-256: {feats.sample.sha256}")
    print(f"  Package: {feats.sample.package_name or '—'}")
    print(
        f"  Verdict: {score.verdict.value.upper()} ({score.severity.value})   "
        f"score {score.risk_score:.1f}/100   confidence {score.confidence:.2f}   mode {score.operating_mode}"
    )
    print(f"  Sign-off required: {'yes' if score.requires_signoff else 'no'}")
    if feats.escalation.escalate:
        print(f"  Escalation: yes — {'; '.join(feats.escalation.reasons)}")
    if score.attack_techniques:
        print(f"  ATT&CK: {', '.join(score.attack_techniques)}")
    decisive = [e for e in score.evidence if e.weight > 0]
    if decisive:
        print("  Top evidence:")
        for e in sorted(decisive, key=lambda x: -x.weight)[:6]:
            print(f"    [{e.layer.value}/{e.category}] {e.title} (wt {e.weight:g})")
    if outcome.genai.generated:
        print(f"  GenAI ({outcome.genai.model_name}): {outcome.genai.summary or '(no summary)'}")
        print(
            f"    grounded {len(outcome.genai.claims)} / withheld {len(outcome.genai.withheld_claims)}"
            f"  (grounding-failure {outcome.genai.grounding_failure_rate:.0%})"
        )
    else:
        print("  GenAI: not applied (disabled/unavailable) — verdict is purely deterministic")
    if feats.analysis_gaps:
        print(f"  Analysis gaps: {', '.join(sorted({g.tool for g in feats.analysis_gaps}))}")


def cmd_analyze(args) -> int:
    apk = Path(args.apk)
    if not apk.is_file():
        print(f"error: file not found: {apk}", file=sys.stderr)
        return 1
    settings = get_settings()
    if args.mode:
        settings.operating_mode = args.mode
    if args.no_genai:
        settings.llm_enabled = False

    sample = _sample_metadata(apk)
    outcome = run_analysis(apk, sample, settings=settings, report_id=sample.sha256[:16])
    _print_summary(apk, outcome)

    if args.out:
        Path(args.out).write_bytes(render_json_bytes(outcome.report))
        print(f"  Wrote {args.out}")
    if args.pdf:
        Path(args.pdf).write_bytes(render_pdf(outcome.report))
        print(f"  Wrote {args.pdf}")

    if args.fail_on_malicious and outcome.score.verdict.value == "Malicious":
        return 2
    return 0


def cmd_init_db(args) -> int:
    from apkscan.auth.service import ensure_default_admin
    from apkscan.db import base

    base.configure()
    base.init_db()
    with base.session_scope() as session:
        created = ensure_default_admin(session)
    print("Database initialized." + (f" Created admin '{created.username}'." if created else ""))
    return 0


def cmd_create_user(args) -> int:
    from apkscan.auth.service import create_user
    from apkscan.db import base

    base.configure()
    base.init_db()
    try:
        with base.session_scope() as session:
            user = create_user(session, username=args.username, password=args.password, role=args.role)
            print(f"Created user '{user.username}' (role {user.role}).")
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


def cmd_serve(args) -> int:
    import uvicorn

    uvicorn.run("apkscan.api.main:app", host=args.host, port=args.port)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="apkscan", description="Self-hosted Android malware analysis.")
    parser.add_argument("--version", action="version", version=f"apkscan {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("analyze", help="analyze an APK locally and emit a report")
    p.add_argument("apk")
    p.add_argument("--out", help="write the JSON report to this path")
    p.add_argument("--pdf", help="write the PDF report to this path")
    p.add_argument("--mode", choices=["balanced", "high_recall"], help="operating point override")
    p.add_argument("--no-genai", action="store_true", help="skip the GenAI layer (deterministic only)")
    p.add_argument("--fail-on-malicious", action="store_true", help="exit 2 if the verdict is Malicious")
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("init-db", help="create tables and bootstrap the admin user")
    p.set_defaults(func=cmd_init_db)

    p = sub.add_parser("create-user", help="create a user")
    p.add_argument("--username", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--role", default="analyst", choices=["admin", "analyst", "viewer"])
    p.set_defaults(func=cmd_create_user)

    p = sub.add_parser("serve", help="run the web/API server")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8080)
    p.set_defaults(func=cmd_serve)

    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
