"""
dump_findings.py — one-off helper to export the exact scored findings for the
two synthetic demo cases, so they can be seeded as known-good static data on
Render. Prints the risk_score and full findings JSON for each synthetic case.
"""
import sqlite3, json

c = sqlite3.connect('whisperward.db')
c.row_factory = sqlite3.Row

rows = c.execute("""
    SELECT cs.case_name, ar.risk_score, ar.findings, ar.analysis_type
    FROM cases cs
    JOIN targets t ON t.case_id = cs.case_id
    JOIN analysis_results ar ON ar.target_id = t.target_id
    WHERE cs.case_name LIKE 'SYNTHETIC%'
    ORDER BY ar.result_id DESC
""").fetchall()

seen = set()
for r in rows:
    if r['case_name'] in seen:
        continue
    seen.add(r['case_name'])
    print("=" * 70)
    print("CASE:", r['case_name'])
    print("SCORE:", r['risk_score'])
    print("TYPE:", r['analysis_type'])
    print("FINDINGS:")
    # pretty-print so it's readable, but also valid JSON we can lift
    parsed = json.loads(r['findings'])
    print(json.dumps(parsed, indent=2))
    print()