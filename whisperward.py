#!/usr/bin/env python3
# Imports and setup
import typer
import asyncio
import json
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from typing import Optional

# These modules are built in Phases 2 and 3
from database import DatabaseManager
from modules import (
    RobloxOSINT,
    DiscordOSINT,
    analyze_text,
    create_evidence_package,
    generate_identity_graph,
)

app     = typer.Typer(help='WhisperWard OSINT - Defensive Online Safety Toolkit')
console = Console()
db      = DatabaseManager()

# new-case command
@app.command()
def new_case(
    name:    str           = typer.Option(...,              '--name',    help='Case name'),
    desc:    Optional[str] = typer.Option(None,            '--desc',    help='Description'),
    analyst: str           = typer.Option('Meca Dismukes', '--analyst', help='Analyst name')
):
    '''Create a new investigation case.'''
    case_id = db.create_case(name, desc or '', analyst)
    console.print(f'[bold green]+ Case created: {case_id}[/bold green]')

# add-target command
@app.command()
def add_target(
    case_id:  str = typer.Option(...,       '--case',     help='Case ID'),
    username: str = typer.Option(...,       '--username', help='Target username'),
    platform: str = typer.Option('roblox',  '--platform', help='Platform')
):
    '''Add a target username to a case.'''
    db.add_target(case_id, platform, username)
    console.print(f'[blue]-> Target added: {username} on {platform}[/blue]')

# scan command
@app.command()
def scan(case_id: str = typer.Option(..., '--case', help='Case ID')):
    '''Run OSINT collection against all targets in a case.'''
    targets = db.get_case_targets(case_id)
    if not targets:
        console.print('[red]No targets found.[/red]')
        return

    with Progress(SpinnerColumn(), TextColumn('[bold cyan]{task.description}')) as progress:
        task = progress.add_task(f'Scanning {len(targets)} targets...', total=len(targets))
        for t in targets:
            if t['platform'] == 'roblox':
                asyncio.run(RobloxOSINT().collect(
                    t['username'], case_id, db, t['target_id']
                ))
            elif t['platform'] == 'discord':
                asyncio.run(DiscordOSINT().collect(
                    t['username'], case_id, db, t['target_id']
                ))
            progress.advance(task)

    console.print('[bold green]+ Scan completed[/bold green]')

# analyze command
@app.command()
def analyze(
    case_id: str  = typer.Option(...,  '--case', help='Case ID'),
    ai:      bool = typer.Option(True,           help='Enable Ollama AI analysis')
):
    '''Run behavioral and AI analysis on collected artifacts.'''
    console.print(f'[cyan]Analyzing case {case_id}...[/cyan]')
    text = db.get_text_for_analysis(case_id)
    if not text:
        text = 'No text content found for analysis.'
    results = analyze_text(text, use_ai=ai)
    db.save_analysis(case_id, results)
    console.print(f'[bold magenta]Risk Score: {results.get("risk_score", 0)}/10[/bold magenta]')

# status command
@app.command()
def status(case_id: str = typer.Option(..., '--case', help='Case ID')):
    '''Show case summary and current status.'''
    summary = db.get_case_summary(case_id)
    console.print(f'\n[bold cyan]=== Case Status: {case_id} ===[/bold cyan]')
    console.print(f'Targets:   {summary["total_targets"]}')
    console.print(f'Platforms: {list(summary["platforms"].keys())}')
    console.print(f'Artifacts: {summary["artifacts_count"]}')

# graph command
@app.command()
def graph(case_id: str = typer.Option(..., '--case', help='Case ID')):
    '''Generate identity relationship graph for the case.'''
    generate_identity_graph(case_id, db)

# export command
@app.command()
def export(case_id: str = typer.Option(..., '--case', help='Case ID')):
    '''Create evidence package with chain-of-custody manifest.'''
    create_evidence_package(case_id)

# run command (full pipeline)
@app.command()
def run(
    case_id: str  = typer.Option(...,  '--case', help='Case ID'),
    ai:      bool = typer.Option(True,           help='Enable AI analysis')
):
    '''Full pipeline: Scan -> Analyze -> Graph -> Export in one command.'''
    console.print(f'[bold cyan]=== Full Pipeline: {case_id} ===[/bold cyan]')
    scan(case_id)
    analyze(case_id, ai=ai)
    graph(case_id)
    export(case_id)
    console.print('[bold green]Full pipeline completed![/bold green]')

# init-db command
@app.command()
def init_db():
    '''Initialize the SQLite database from schema.sql.'''
    db.init()
    console.print('[green]Database initialized.[/green]')


if __name__ == '__main__':
    app()
