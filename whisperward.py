#!/usr/bin/env python3
"""
WhisperWard OSINT - Main CLI Entry Point
Clean & Fixed Version
"""

import typer
import asyncio
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from typing import Optional

from database import DatabaseManager
from modules import (
    RobloxOSINT,
    DiscordOSINT,
    SherlockIntegration,
    analyze_text,
    create_evidence_package,
    generate_identity_graph,
    ensure_directories,
)

# M5 evidence-lifecycle features. Imported directly from their submodules because
# they are not re-exported from modules/__init__.py.
from modules.report_generator import generate_signed_report
from modules.redaction_engine import redact_case
from modules.referral_export import export_referral
from modules.retention_enforcer import enforce_retention
# M7 CSAM hash detection. Lives at repo root, not under modules/.
from csam_hash_detector import CSAMHashDetector

app = typer.Typer(help="WhisperWard OSINT - Defensive Online Safety Toolkit")
console = Console()
db = DatabaseManager()


@app.command()
def init_db():
    db.init()
    console.print("[green]✅ Database initialized successfully.[/green]")


@app.command()
def new_case(
    name: str = typer.Option(..., "--name", help="Case name"),
    desc: Optional[str] = typer.Option(None, "--desc", help="Description"),
    analyst: str = typer.Option("Meca Dismukes", "--analyst", help="Analyst name")
):
    case_id = db.create_case(name, desc or "", analyst)
    console.print(f"[bold green]✅ Case created: {case_id}[/bold green]")


@app.command()
def add_target(
    case_id: str = typer.Option(..., "--case", help="Case ID"),
    username: str = typer.Option(..., "--username", help="Target username"),
    platform: str = typer.Option("roblox", "--platform", help="Platform")
):
    db.add_target(case_id, platform, username)
    console.print(f"[blue]→ Target added: {username} on {platform}[/blue]")


@app.command()
def scan(case_id: str = typer.Option(..., "--case", help="Case ID")):
    ensure_directories()
    targets = db.get_case_targets(case_id)
    if not targets:
        console.print("[red]No targets found.[/red]")
        return

    console.print(f"[bold cyan]🔍 Scanning {len(targets)} target(s)...[/bold cyan]")

    with Progress(SpinnerColumn(), TextColumn("[bold cyan]{task.description}")) as progress:
        task = progress.add_task("Collecting intelligence...", total=len(targets))
        
        for t in targets:
            username = t["username"]
            target_id = t["target_id"]
            platform = t["platform"].lower()

            if platform == "roblox":
                asyncio.run(RobloxOSINT().collect(username, case_id, db, target_id))
            elif platform == "discord":
                asyncio.run(DiscordOSINT().collect(username, case_id, db, target_id))

            asyncio.run(SherlockIntegration().scan_username(username, case_id, db, target_id))
            progress.advance(task)

    console.print("[bold green]✅ Scan completed[/bold green]")


@app.command()
def analyze(
    case_id: str = typer.Option(..., "--case", help="Case ID"),
    ai: bool = typer.Option(True, "--ai", help="Enable AI + RAG analysis")
):
    console.print(f"[cyan]🧠 Analyzing case {case_id} with AI + RAG...[/cyan]")
    
    text = db.get_text_for_analysis(case_id)
    targets = db.get_case_targets(case_id)
    
    if not targets:
        console.print("[red]No targets found for this case.[/red]")
        return
    
    # Analyze and persist per target (so each target gets its own real score)
    highest_score = 0.0
    for t in targets:
        results = analyze_text(
            text,
            use_ai=ai,
            case_id=case_id,
            target_id=t["target_id"],
            db=db,
        )
        score = results.get('risk_score', 0.0)
        if score > highest_score:
            highest_score = score

    console.print(f"[bold magenta]📊 Highest Risk Score: {highest_score:.1f}/10[/bold magenta]")


@app.command()
def graph(case_id: str = typer.Option(..., "--case", help="Case ID")):
    console.print(f"[cyan]📈 Generating identity relationship graph...[/cyan]")
    generate_identity_graph(case_id, db)
    console.print("[green]✅ Graph visualization saved[/green]")


@app.command()
def export(case_id: str = typer.Option(..., "--case", help="Case ID")):
    console.print(f"[cyan]📦 Creating evidence package...[/cyan]")
    create_evidence_package(case_id)


@app.command()
def report(
    case_id: str = typer.Option(..., "--case", help="Case ID"),
    analyst: str = typer.Option("Meca Dismukes", "--analyst", help="Analyst name on the report"),
    package: bool = typer.Option(False, "--package", help="Also build the evidence package alongside the report")
):
    """Generate a cryptographically signed PDF case report."""
    console.print(f"[cyan]📝 Generating signed case report for {case_id}...[/cyan]")
    result = generate_signed_report(
        case_id,
        connection=db.get_connection(),
        analyst=analyst,
        create_package=package,
    )
    if result:
        console.print(f"[bold green]✅ Signed report generated: {result}[/bold green]")
    else:
        console.print("[red]Report generation did not complete. Check that the case exists.[/red]")


@app.command()
def redact(
    case_id: str = typer.Option(..., "--case", help="Case ID"),
    analyst: str = typer.Option("Meca Dismukes", "--analyst", help="Analyst performing the redaction"),
    reason: str = typer.Option("external sharing", "--reason", help="Reason recorded in the audit chain"),
    policy: str = typer.Option("standard", "--policy", help="Redaction policy: standard or minor_involved")
):
    """Produce a redacted, shareable copy of a case. The sealed original is never modified."""
    console.print(f"[cyan]🛡️  Redacting case {case_id} (policy: {policy})...[/cyan]")
    result = redact_case(
        case_id,
        connection=db.get_connection(),
        analyst=analyst,
        reason=reason,
        policy=policy,
    )
    if result:
        path = result.get("output_path")
        total = result.get("total_redactions", 0)
        console.print(f"[bold green]✅ Redacted export created ({total} redactions): {path}[/bold green]")
    else:
        console.print("[red]Redaction did not complete. Check that the case exists.[/red]")


@app.command()
def referral(
    case_id: str = typer.Option(..., "--case", help="Case ID"),
    redact: bool = typer.Option(True, "--redact/--no-redact", help="Redact the referral (on by default)"),
    policy: str = typer.Option("standard", "--policy", help="Redaction policy when redacting")
):
    """Produce a CyberTipline-aligned representative referral export. Redacted by default."""
    console.print(f"[cyan]📨 Building referral export for {case_id} (redact: {redact})...[/cyan]")
    result = export_referral(
        case_id,
        connection=db.get_connection(),
        redact=redact,
        policy=policy,
    )
    if result:
        path = result.get("output_path")
        console.print(f"[bold green]✅ Referral export created: {path}[/bold green]")
        console.print("[yellow]Note: this is a representative format for human review, never an autonomous filing.[/yellow]")
    else:
        console.print("[red]Referral export did not complete. Check that the case exists.[/red]")


@app.command()
def retention(
    days: int = typer.Option(90, "--days", help="Retention window in days"),
    confirm: bool = typer.Option(False, "--confirm", help="Actually purge. Without this flag the command is a safe dry run."),
    analyst: str = typer.Option("Meca Dismukes", "--analyst", help="Analyst recorded in the audit chain")
):
    """Enforce the retention policy. Dry run by default; pass --confirm to purge. The audit chain is always preserved."""
    mode = "PURGE" if confirm else "DRY RUN"
    console.print(f"[cyan]🗄️  Retention enforcement ({mode}, window: {days} days)...[/cyan]")
    if not confirm:
        console.print("[yellow]Dry run — no data will be deleted. Re-run with --confirm to purge.[/yellow]")
    result = enforce_retention(
        retention_days=days,
        confirm=confirm,
        connection=db.get_connection(),
        analyst=analyst,
    )
    if result is not None:
        eligible = result.get("cases", []) if isinstance(result, dict) else result
        console.print(f"[bold green]✅ Retention check complete. Cases evaluated: {len(eligible)}[/bold green]")
    else:
        console.print("[green]✅ Retention check complete.[/green]")


@app.command()
def csam_status():
    """Report the status of the CSAM hash-detection adapters. The sensitive
    integrations (PhotoDNA, NCMEC) are approval-gated and disabled by default;
    local perceptual hashing is always active. This command surfaces that posture
    without performing any detection."""
    console.print("[bold cyan]=== CSAM Hash Detection — Adapter Status ===[/bold cyan]")
    status = CSAMHashDetector().get_adapter_status()
    console.print(f"Local database: [green]{status['local_database']}[/green]")
    photodna = status['photodna']
    ncmec = status['ncmec']
    photodna_color = "green" if photodna == "enabled" else "yellow"
    ncmec_color = "green" if ncmec == "enabled" else "yellow"
    console.print(f"PhotoDNA:       [{photodna_color}]{photodna}[/{photodna_color}]")
    console.print(f"NCMEC:          [{ncmec_color}]{ncmec}[/{ncmec_color}]")
    console.print("[dim]No matched image content is ever stored. Every match requires human review.[/dim]")


@app.command()
def status(case_id: str = typer.Option(..., "--case", help="Case ID")):
    summary = db.get_case_summary(case_id)
    console.print(f"\n[bold cyan]=== Case Status: {case_id} ===[/bold cyan]")
    console.print(f"Targets:   {summary['total_targets']}")
    console.print(f"Platforms: {list(summary['platforms'].keys())}")
    console.print(f"Artifacts: {summary['artifacts_count']}")


@app.command()
def run(
    case_id: str = typer.Option(..., "--case", help="Case ID"),
    ai: bool = typer.Option(True, "--ai", help="Enable AI + RAG analysis")
):
    ensure_directories()
    console.print(f"[bold cyan]🚀 Starting Full Pipeline: {case_id}[/bold cyan]")
    
    scan(case_id)
    analyze(case_id, ai=ai)
    graph(case_id)
    export(case_id)
    
    console.print("[bold green]🎉 Full pipeline completed successfully![/bold green]")


if __name__ == "__main__":
    app()