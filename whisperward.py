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
from modules.child_safety.collectors.roblox_osint import RobloxOSINT
from modules.child_safety.collectors.discord_osint import DiscordOSINT
from modules.child_safety.collectors.sherlock_integration import SherlockIntegration
from modules.child_safety.behavioral import analyze_text
from core.evidence_packager import create_evidence_package
from core.graph_visualizer import generate_identity_graph
from core.utils import ensure_directories

# M5 evidence-lifecycle features. Imported directly from their submodules because
# they are not re-exported from modules/__init__.py.
from core.report_generator import generate_signed_report
from core.redaction_engine import redact_case
from modules.child_safety.referral_export import export_referral
from core.retention_enforcer import enforce_retention
# M7 CSAM hash detection. Lives at repo root, not under modules/.
from modules.child_safety.csam_hash_detector import CSAMHashDetector

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


def _build_correlation_profiles(case_id: str, database) -> list:
    """Build CorrelationProfile objects for every target in a case, using only
    artifacts a scan has already persisted. Nothing new is collected here: the
    correlate step reasons over the case file as it stands. Missing fields
    degrade to neutral values and simply lower signal confidence, which the
    engine already accounts for."""
    import json as _json
    from core.correlation_engine import CorrelationProfile

    profiles = []
    conn = database.get_connection()
    for target in database.get_case_targets(case_id):
        target_id = target["target_id"]
        username = target["username"]
        platform = (target["platform"] or "unknown").lower()

        messages: list = []
        avatar_phash = None
        avatar_dhash = None

        cur = conn.execute(
            "SELECT module_name, raw_data FROM artifacts WHERE target_id = ?",
            (target_id,),
        )
        for row in cur.fetchall():
            try:
                data = _json.loads(row["raw_data"])
            except (ValueError, TypeError):
                continue
            if not isinstance(data, dict):
                continue
            if row["module_name"] == "RobloxOSINT":
                description = (data.get("description") or "").strip()
                if description:
                    messages.append(description)
                avatar_phash = data.get("avatar_phash") or avatar_phash
                avatar_dhash = data.get("avatar_dhash") or avatar_dhash

        profiles.append(CorrelationProfile(
            profile_id=f"{platform}:{username}",
            platform=platform,
            username=username,
            messages=messages,
            avatar_phash=avatar_phash,
            avatar_dhash=avatar_dhash,
        ))
    return profiles


@app.command()
def correlate(
    case_id: str = typer.Option(..., "--case", help="Case ID"),
    semantic: bool = typer.Option(
        False, "--semantic",
        help="Enable semantic stylometry (downloads a local embedding model on first use)",
    ),
):
    """Run cross-platform identity correlation across all targets in a case.

    Produces pairwise correlation leads with per-signal evidence and clusters
    targets into likely-identity groups. Results are leads for a human analyst,
    never determinations, and the full result is sealed into the evidence
    store as an artifact."""
    from core.correlation_engine import CorrelationEngine

    targets = db.get_case_targets(case_id)
    if len(targets) < 2:
        console.print("[yellow]Correlation needs at least two targets in the case.[/yellow]")
        return

    console.print(f"[cyan]🔗 Correlating {len(targets)} targets in {case_id}...[/cyan]")
    profiles = _build_correlation_profiles(case_id, db)
    engine = CorrelationEngine(use_semantic=semantic)

    # Pairwise detail for the analyst
    from rich.table import Table
    table = Table(title="Pairwise Correlation", show_lines=False)
    table.add_column("Pair", style="cyan", overflow="fold")
    table.add_column("Strength", justify="right")
    table.add_column("Lead", justify="center")
    table.add_column("Top evidence", overflow="fold")

    pair_results = []
    for i in range(len(profiles)):
        for j in range(i + 1, len(profiles)):
            result = engine.correlate(profiles[i], profiles[j])
            pair_results.append(result)
            top_signal = max(result.signals, key=lambda s: s.raw_score * s.confidence)
            table.add_row(
                f"{result.profile_a} ↔ {result.profile_b}",
                f"{result.correlation_strength:.2f}",
                "[bold red]YES[/bold red]" if result.is_lead else "no",
                top_signal.rationale,
            )
    console.print(table)

    # Identity groups across the whole case
    cluster = engine.cluster_identities(profiles)
    console.print("\n[bold cyan]Identity groups:[/bold cyan]")
    for idx, group in enumerate(cluster.groups, start=1):
        members = ", ".join(sorted(group))
        label = "[bold red]linked[/bold red]" if len(group) > 1 else "standalone"
        console.print(f"  Group {idx} ({label}): {members}")

    # Seal the full result into the evidence store on the case's first target
    payload = {
        "case_id": case_id,
        "pairwise": [r.to_dict() for r in pair_results],
        "cluster": cluster.to_dict(),
        "semantic_enabled": semantic,
    }
    artifact_id = db.save_artifact(
        target_id=targets[0]["target_id"],
        module_name="CorrelationEngine",
        artifact_type="identity_correlation",
        raw_data=payload,
    )
    console.print(f"\n[green]✅ Correlation sealed as artifact {artifact_id}[/green]")
    console.print(
        "[dim]These are correlation leads with supporting evidence, not assertions "
        "of shared identity. A qualified human analyst must confirm any identity "
        "link before action.[/dim]"
    )


# ---------------------------------------------------------------------------
# Platform Phase 3 — Entity resolution, identity graph, investigation timeline
# ---------------------------------------------------------------------------

def _latest_artifact_payload(case_id: str, artifact_type: str, database):
    """Return the most recent sealed artifact of a given type for a case, or
    None. The Phase 3 commands reason over sealed correlation output rather
    than re-running analysis, so the evidence a decision rests on is exactly
    the evidence in the store."""
    import json as _json
    conn = database.get_connection()
    row = conn.execute(
        "SELECT raw_data FROM artifacts WHERE artifact_type = ? "
        "AND target_id IN (SELECT target_id FROM targets WHERE case_id = ?) "
        "ORDER BY artifact_id DESC LIMIT 1",
        (artifact_type, case_id),
    ).fetchone()
    if row is None:
        return None
    try:
        return _json.loads(row["raw_data"])
    except (ValueError, TypeError):
        return None


@app.command("propose-entities")
def propose_entities(case_id: str = typer.Option(..., "--case", help="Case ID")):
    """Propose entity candidates from the case's sealed correlation output.

    Candidates are machine-proposed groupings, never identity determinations.
    Each membership carries its supporting edges; accounts whose every path is
    contradicted are excluded with the reason on the record. Proposals are
    sealed into the evidence store for the analyst to review and, if
    warranted, promote."""
    from core.entity import EntityResolver

    payload = _latest_artifact_payload(case_id, "identity_correlation", db)
    if payload is None:
        console.print("[yellow]No sealed correlation found for this case. "
                      "Run `correlate --case " + case_id + "` first.[/yellow]")
        return

    resolver = EntityResolver()
    groups = [set(g) for g in payload.get("cluster", {}).get("groups", [])]
    candidates = resolver.propose(case_id, groups, payload.get("pairwise", []))

    if not candidates:
        console.print("[cyan]No multi-account groupings with uncontradicted "
                      "lead-strength support were found.[/cyan]")
        return

    for cand in candidates:
        console.print(f"\n[bold cyan]Candidate {cand.candidate_id}[/bold cyan] "
                      f"(mean lead strength {cand.mean_strength:.2f})")
        for member in cand.members:
            console.print(f"  [green]included[/green] {member.profile_id}")
            for edge in member.justification.supporting_edges:
                mark = "[red]contradicted[/red]" if edge["contradiction_note"] else (
                    "lead" if edge["is_lead"] else "sub-lead")
                console.print(f"      ↔ {edge['with']}  strength {edge['strength']:.2f}  ({mark})")
        for excluded in cand.excluded:
            console.print(f"  [yellow]excluded[/yellow] {excluded['profile_id']} — {excluded['reason']}")

    targets = db.get_case_targets(case_id)
    artifact_id = db.save_artifact(
        target_id=targets[0]["target_id"],
        module_name="EntityResolver",
        artifact_type="entity_candidates",
        raw_data={"case_id": case_id,
                  "candidates": [c.to_dict() for c in candidates]},
    )
    console.print(f"\n[green]✅ Proposals sealed as artifact {artifact_id}[/green]")
    console.print("[dim]Promotion to a resolved entity is an explicit analyst "
                  "decision: promote-entity --case " + case_id
                  + " --candidate <ID> --analyst \"Your Name\"[/dim]")


@app.command("promote-entity")
def promote_entity(
    case_id: str = typer.Option(..., "--case", help="Case ID"),
    candidate_id: str = typer.Option(..., "--candidate", help="Candidate ID from propose-entities"),
    analyst: str = typer.Option(..., "--analyst", help="Analyst making the resolution decision"),
    handle: Optional[str] = typer.Option(None, "--handle", help="Canonical handle for the entity"),
    note: str = typer.Option("", "--note", help="Analyst note recorded with the promotion"),
):
    """Promote a proposed candidate to a resolved entity.

    This is the human decision the resolver exists to support. The promotion
    is attributed to the named analyst and lands in the tamper-evident chain
    of custody alongside the machine's justification."""
    from core.entity import EntityResolver, candidate_from_dict

    payload = _latest_artifact_payload(case_id, "entity_candidates", db)
    if payload is None:
        console.print("[yellow]No sealed entity proposals for this case. "
                      "Run `propose-entities --case " + case_id + "` first.[/yellow]")
        return

    match = next((c for c in payload.get("candidates", [])
                  if c.get("candidate_id") == candidate_id), None)
    if match is None:
        console.print(f"[red]Candidate {candidate_id} not found in the latest "
                      "sealed proposals for this case.[/red]")
        return

    entity = EntityResolver().promote(
        candidate_from_dict(match), analyst=analyst,
        canonical_handle=handle, analyst_note=note)
    db.save_entity(entity)
    console.print(f"[bold green]✅ Entity {entity.entity_id} "
                  f"('{entity.canonical_handle}') resolved by {entity.promoted_by} "
                  "and recorded in the chain of custody.[/bold green]")
    for member in entity.members:
        console.print(f"  member: {member.profile_id}")


@app.command()
def entities(case_id: str = typer.Option(..., "--case", help="Case ID")):
    """List resolved entities for a case, with members and promotion record."""
    stored = db.get_case_entities(case_id)
    if not stored:
        console.print("[cyan]No resolved entities for this case.[/cyan]")
        return
    for record in stored:
        entity = record["entity"]
        console.print(f"\n[bold cyan]{entity['entity_id']}[/bold cyan] "
                      f"'{entity['canonical_handle']}' — promoted by "
                      f"{entity['promoted_by']} at {entity['promoted_at']}")
        if entity.get("analyst_note"):
            console.print(f"  note: {entity['analyst_note']}")
        for member in record["members"]:
            console.print(f"  member: {member['platform']}:{member['username']}")


@app.command("identity-graph")
def identity_graph(
    case_id: str = typer.Option(..., "--case", help="Case ID"),
    export_json: bool = typer.Option(False, "--json", help="Write canonical JSON to exports/"),
):
    """Build the justified identity graph from sealed correlation output.

    Every edge carries its complete justification; resolved entities label the
    nodes a human confirmed. The canonical JSON export hashes identically for
    identical content, so it can travel inside evidence packages."""
    from core.entity import entity_from_row
    from core.identity_graph import IdentityGraph

    payload = _latest_artifact_payload(case_id, "identity_correlation", db)
    if payload is None:
        console.print("[yellow]No sealed correlation found for this case. "
                      "Run `correlate --case " + case_id + "` first.[/yellow]")
        return

    resolved = [entity_from_row(r["entity"], r["members"])
                for r in db.get_case_entities(case_id)]
    graph_obj = IdentityGraph.from_correlation(
        case_id, payload.get("pairwise", []), entities=resolved)

    inputs = graph_obj.risk_inputs()
    console.print(f"[bold cyan]Identity graph for {case_id}[/bold cyan]")
    console.print(f"  nodes: {len(graph_obj.nodes())}   "
                  f"edges: {graph_obj.graph.number_of_edges()}")
    console.print(f"  contradiction-free lead edges: {inputs['graph_lead_edge_count']}   "
                  f"platforms corroborated: {inputs['graph_lead_platforms']}   "
                  f"strongest lead: {inputs['graph_max_lead_strength']:.2f}")
    if inputs["graph_has_contradictions"]:
        console.print("  [yellow]contradicted edges present — excluded from corroboration[/yellow]")
    for node in graph_obj.nodes():
        data = graph_obj.graph.nodes[node]
        label = f" → entity {data['entity_id']}" if data.get("entity_id") else ""
        console.print(f"  {node}{label}")

    if export_json:
        from pathlib import Path
        out_dir = Path("exports")
        out_dir.mkdir(exist_ok=True)
        out_path = out_dir / f"{case_id}_identity_graph.json"
        out_path.write_text(graph_obj.to_canonical_json(), encoding="utf-8")
        console.print(f"[green]✅ Canonical graph written to {out_path}[/green]")

    console.print("[dim]Edges are correlation leads with supporting evidence, "
                  "not assertions of shared identity.[/dim]")


@app.command()
def timeline(
    case_id: str = typer.Option(..., "--case", help="Case ID"),
    kind: Optional[str] = typer.Option(None, "--kind", help="Filter by event kind prefix"),
    target: Optional[int] = typer.Option(None, "--target", help="Filter by target id"),
):
    """Print the case's reconstructed investigation timeline.

    Strictly reconstructive: every event names its source table and row, and
    no event is inferred."""
    from core.timeline import InvestigationTimeline

    built = InvestigationTimeline.build(db, case_id)
    events = built.filter(kind=kind, target_id=target)
    if not events:
        console.print("[cyan]No events on record for this selection.[/cyan]")
        return
    from rich.table import Table
    table = Table(title=f"Investigation Timeline — {case_id}", show_lines=False)
    table.add_column("Timestamp (UTC)", overflow="fold")
    table.add_column("Event", style="cyan")
    table.add_column("Description", overflow="fold")
    table.add_column("Source", overflow="fold")
    for event in events:
        table.add_row(event.timestamp, event.kind, event.description,
                      f"{event.source_table}#{event.source_ref}")
    console.print(table)
    console.print(f"[dim]{len(events)} event(s); reconstructed from the case "
                  "record only.[/dim]")


# ---------------------------------------------------------------------------
# Platform Phase 4 — Standards-aware intelligence
# ---------------------------------------------------------------------------

@app.command()
def stix(
    case_id: str = typer.Option(..., "--case", help="Case ID"),
    out: Optional[str] = typer.Option(None, "--out", help="Output path (defaults to exports/<case>_stix_bundle.json)"),
):
    """Export the case as a STIX 2.1 bundle for threat-intelligence platforms.

    The bundle carries observed accounts, correlation leads with confidence
    and rationale, and analyst-resolved entities. It never asserts adversaries,
    malware, or attacks, and the scope statement travels inside the bundle.
    The export is byte-stable for identical content and is sealed into the
    evidence store."""
    from datetime import datetime, timezone
    from pathlib import Path
    from core.stix_export import StixExporter, canonical_bundle_json

    targets = db.get_case_targets(case_id)
    if not targets:
        console.print("[yellow]Case has no targets on record; nothing to export.[/yellow]")
        return

    as_of = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    bundle = StixExporter(as_of=as_of).bundle_for_case(db, case_id)
    body = canonical_bundle_json(bundle)

    out_path = Path(out) if out else Path("exports") / f"{case_id}_stix_bundle.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(body, encoding="utf-8")

    artifact_id = db.save_artifact(
        target_id=targets[0]["target_id"],
        module_name="StixExporter",
        artifact_type="stix_bundle",
        raw_data={"case_id": case_id, "as_of": as_of,
                  "object_count": len(bundle.objects),
                  "path": str(out_path)},
        file_path=str(out_path),
    )
    console.print(f"[green]✅ STIX 2.1 bundle ({len(bundle.objects)} objects) "
                  f"written to {out_path} and sealed as artifact {artifact_id}[/green]")
    console.print("[dim]The bundle asserts no adversary, malware, or attack; "
                  "relationships are correlation leads with confidence and "
                  "rationale attached.[/dim]")


@app.command("attack-map")
def attack_map(case_id: str = typer.Option(..., "--case", help="Case ID")):
    """Show the honest MITRE ATT&CK mapping for the case's latest analysis.

    Maps only the technical signals that actually fired, grades each mapping
    direct or analogue, and states explicitly which findings are outside
    ATT&CK's scope and where they are documented instead."""
    import json as _json
    from core.attack_mapping import map_risk_result

    conn = db.get_connection()
    row = conn.execute(
        "SELECT findings, target_id FROM analysis_results WHERE target_id IN "
        "(SELECT target_id FROM targets WHERE case_id = ?) "
        "AND analysis_type = 'risk_engine_v1' "
        "ORDER BY result_id DESC LIMIT 1", (case_id,)).fetchone()
    if row is None:
        console.print("[yellow]No structured risk analysis on record for this "
                      "case. Run `analyze --case " + case_id + "` first.[/yellow]")
        return
    try:
        findings = _json.loads(row["findings"])
    except (ValueError, TypeError):
        console.print("[red]Stored findings could not be parsed.[/red]")
        return

    # The anonymization flags live in the collected artifacts, not the stored
    # findings; rebuild the same signals the engine scored so the mapping can
    # distinguish Tor from VPN honestly.
    from core.risk_scoring import build_signals
    signals, _ = build_signals(conn, row["target_id"])
    mapping = map_risk_result(findings,
                              is_tor=bool(signals.is_tor),
                              is_vpn=bool(signals.is_vpn))

    if mapping["mapped"]:
        from rich.table import Table
        table = Table(title=f"ATT&CK Mapping — {case_id}", show_lines=False)
        table.add_column("Technique", style="cyan")
        table.add_column("Name", overflow="fold")
        table.add_column("Tactic")
        table.add_column("Applicability")
        for m in mapping["mapped"]:
            table.add_row(m["technique_id"], m["technique_name"],
                          m["tactic"], m["applicability"])
        console.print(table)
        for m in mapping["mapped"]:
            console.print(f"  [dim]{m['technique_id']}: {m['justification']}[/dim]")
    else:
        console.print("[cyan]No fired signal maps to an ATT&CK technique for "
                      "this analysis.[/cyan]")

    for u in mapping["unmapped"]:
        console.print(f"\n[yellow]Out of ATT&CK scope:[/yellow] {u['signal']} — "
                      f"{u['reason']} (documented in {u['documented_in']})")
    console.print(f"\n[dim]{mapping['scope_statement']}[/dim]")


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


# ---------------------------------------------------------------------------
# Persistence and reconstitution tracking
# ---------------------------------------------------------------------------

def _all_artifact_payloads(case_id: str, artifact_type: str, database) -> list:
    """Return every sealed artifact of a type for a case, oldest first.

    The persistence commands reason over sealed account state rather than a
    mutable table, so the timestamps a succession rests on are themselves
    evidence. Later records for the same profile supersede earlier ones on
    replay, and the superseded record stays in the store.
    """
    import json as _json
    conn = database.get_connection()
    rows = conn.execute(
        "SELECT raw_data FROM artifacts WHERE artifact_type = ? "
        "AND target_id IN (SELECT target_id FROM targets WHERE case_id = ?) "
        "ORDER BY artifact_id ASC",
        (artifact_type, case_id),
    ).fetchall()
    payloads = []
    for row in rows:
        try:
            payloads.append(_json.loads(row["raw_data"]))
        except (ValueError, TypeError):
            continue
    return payloads


def _load_persistence_graph(case_id: str, database):
    """Build a PersistenceGraph seeded with every sealed account state for the
    case. Returns the graph and the sealed correlation payload, or (None, None)
    when the case has no correlation to reason over."""
    from core.persistence_graph import AccountState, AccountStatus, PersistenceGraph

    payload = _latest_artifact_payload(case_id, "identity_correlation", database)
    if payload is None:
        return None, None

    pgraph = PersistenceGraph(case_id)
    for record in _all_artifact_payloads(case_id, "account_state", database):
        try:
            status = AccountStatus(record.get("status", "unknown"))
        except ValueError:
            status = AccountStatus.UNKNOWN
        pgraph.upsert_account(AccountState(
            profile_id=record["profile_id"],
            status=status,
            first_observed=record.get("first_observed", "") or "",
            created_at=record.get("created_at", "") or "",
            removed_at=record.get("removed_at", "") or "",
            last_observed=record.get("last_observed", "") or "",
        ))
    return pgraph, payload


@app.command("account-state")
def account_state(
    case_id: str = typer.Option(..., "--case", help="Case ID"),
    profile: str = typer.Option(..., "--profile", help="Profile ID as platform:username"),
    status: str = typer.Option("unknown", "--status",
                               help="active, removed, suspended, dormant or unknown"),
    created: str = typer.Option("", "--created", help="Account creation timestamp, ISO 8601"),
    removed: str = typer.Option("", "--removed", help="Removal timestamp, ISO 8601"),
    analyst: str = typer.Option("Meca Dismukes", "--analyst", help="Analyst recording the state"),
):
    """Record an account's temporal state and seal it into the evidence store.

    Succession direction is derived from removal and creation timestamps, so
    this is the input the persistence graph needs before it can order anything.
    An account with no recorded removal simply never becomes a predecessor.
    """
    from core.persistence_graph import AccountStatus

    targets = db.get_case_targets(case_id)
    if not targets:
        console.print("[yellow]No targets in this case. Add a target first.[/yellow]")
        return
    if ":" not in profile:
        console.print("[yellow]Profile must be platform:username, "
                      "matching the correlation profile IDs.[/yellow]")
        return
    try:
        parsed_status = AccountStatus(status.lower())
    except ValueError:
        console.print(f"[yellow]Unknown status '{status}'. Use active, removed, "
                      "suspended, dormant or unknown.[/yellow]")
        return
    if parsed_status is AccountStatus.REMOVED and not removed:
        console.print("[yellow]A removed account needs --removed with the removal "
                      "timestamp, otherwise it cannot be ordered in a chain.[/yellow]")
        return

    record = {
        "profile_id": profile,
        "status": parsed_status.value,
        "created_at": created,
        "removed_at": removed,
        "recorded_by": analyst,
    }
    artifact_id = db.save_artifact(
        target_id=targets[0]["target_id"],
        module_name="PersistenceGraph",
        artifact_type="account_state",
        raw_data=record,
    )
    console.print(f"[green]✅ State for {profile} sealed as artifact {artifact_id}[/green]")
    console.print(f"  status: {parsed_status.value}"
                  + (f"   created: {created}" if created else "")
                  + (f"   removed: {removed}" if removed else ""))


@app.command()
def persistence(
    case_id: str = typer.Option(..., "--case", help="Case ID"),
    floor: float = typer.Option(0.6, "--floor",
                                help="Minimum correlation strength for an inferred succession"),
    window: int = typer.Option(90, "--window",
                               help="Reconstitution window in days"),
    lead_only: bool = typer.Option(False, "--lead-only",
                                   help="Only infer from pairs the correlation engine flagged as leads"),
    export_json: bool = typer.Option(False, "--json", help="Write the referral view to exports/"),
    redacted: bool = typer.Option(False, "--redacted",
                                  help="Export the platform-facing view instead, with identifiers withheld"),
):
    """Build the reconstitution chains for a case from sealed evidence.

    Reads sealed correlation output and sealed account state, infers succession
    where a removal is followed by a creation inside the window, and reports the
    chains with their return intervals. Every inferred link is marked inferred.
    Direction comes from the timestamps, never from the correlation, which
    carries no ordering.
    """
    from rich.table import Table

    pgraph, payload = _load_persistence_graph(case_id, db)
    if pgraph is None:
        console.print("[yellow]No sealed correlation found for this case. "
                      "Run `correlate --case " + case_id + "` first.[/yellow]")
        return

    if not pgraph.states:
        console.print("[yellow]No account state recorded for this case. Record removal "
                      "and creation timestamps with `account-state` first — without them "
                      "there is nothing to order.[/yellow]")
        return

    inferred = pgraph.infer_successions(
        payload.get("pairwise", []),
        strength_floor=floor,
        window_days=window,
        require_lead=lead_only,
    )
    summary = pgraph.persistence_summary()

    console.print(f"\n[bold cyan]Persistence graph for {case_id}[/bold cyan]")
    console.print(f"  accounts tracked: {summary['accounts_tracked']}   "
                  f"removed: {summary['removed_accounts']}")
    console.print(f"  succession links: {summary['succession_links']}   "
                  f"inferred this run: {len(inferred)}")
    console.print(f"  chains: {summary['chain_count']}   "
                  f"longest chain: {summary['longest_chain_length']} accounts")
    if summary["median_gap_hours"] is not None:
        console.print(f"  median return time: {summary['median_gap_hours']:.1f} hours")
    if summary["platforms_spanned"]:
        console.print(f"  platforms spanned: {', '.join(summary['platforms_spanned'])}")

    chains = pgraph.reconstitution_chains()
    if not chains:
        console.print("\n[cyan]No reconstitution chain formed. Either no removal is "
                      "followed by a creation inside the window, or the correlation "
                      "between them sits below the strength floor.[/cyan]")
    for index, chain in enumerate(chains, start=1):
        console.print(f"\n[bold]Chain {index}[/bold]: " + "  →  ".join(chain))

    intervals = pgraph.reconstitution_intervals()
    if intervals:
        table = Table(title="Return intervals", show_lines=False)
        table.add_column("Predecessor", style="cyan", overflow="fold")
        table.add_column("Successor", style="cyan", overflow="fold")
        table.add_column("Gap (hours)", justify="right")
        table.add_column("Origin", justify="center")
        for row in intervals:
            gap = row["gap_hours"]
            table.add_row(
                row["predecessor"],
                row["successor"],
                f"{gap:.1f}" if gap is not None else "—",
                "[yellow]inferred[/yellow]" if row["inferred"] else "observed",
            )
        console.print()
        console.print(table)

    handoffs = pgraph.cross_platform_handoffs()
    if handoffs:
        console.print("\n[bold cyan]Cross-platform handoffs:[/bold cyan]")
        for row in handoffs:
            console.print(f"  {row['source']} → {row['destination']}")

    if export_json:
        import json as _json
        from pathlib import Path
        out_dir = Path("exports")
        out_dir.mkdir(exist_ok=True)
        view = pgraph.to_redacted_view() if redacted else pgraph.to_dict()
        suffix = "persistence_platform" if redacted else "persistence_referral"
        out_path = out_dir / f"{case_id}_{suffix}.json"
        out_path.write_text(_json.dumps(view, indent=2, sort_keys=True), encoding="utf-8")
        console.print(f"\n[green]✅ {'Platform' if redacted else 'Referral'} "
                      f"view written to {out_path}[/green]")

    console.print("\n[dim]Chains describe accounts believed to be operated in "
                  "coordination. They are not identifications of natural persons, "
                  "and inferred links are suggestions for an analyst to confirm.[/dim]")


if __name__ == "__main__":
    app()