from database import DatabaseManager
import json

db = DatabaseManager()
conn = db.get_connection()

rows = conn.execute("SELECT artifact_id, target_id, module_name, artifact_type, raw_data FROM artifacts").fetchall()

print(f'Total artifacts: {len(rows)}')
print('---')

for r in rows:
    print('artifact_id:', r['artifact_id'])
    print('target_id:', r['target_id'])
    print('module:', r['module_name'])
    print('type:', r['artifact_type'])
    try:
        data = json.loads(r['raw_data'])
        if isinstance(data, dict):
            print('keys:', list(data.keys()))
        print('data preview:', json.dumps(data, indent=2)[:400])
    except Exception as e:
        print('data parse error:', e)
        print('raw:', r['raw_data'][:200])
    print('---')