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
    results = analyze_text(text, use_ai=ai, case_id=case_id)
    
    targets = db.get_case_targets(case_id)
    for t in targets:
        db.save_analysis(t["target_id"], results)

    console.print(f"[bold magenta]📊 Risk Score: {results.get('risk_score', 0):.1f}/10[/bold magenta]")


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