from database import DatabaseManager

db = DatabaseManager()
conn = db.get_connection()

rows = conn.execute("SELECT target_id, case_id FROM targets WHERE case_id NOT LIKE 'CASE-%'").fetchall()

for r in rows:
    new_id = 'CASE-' + r['case_id']
    conn.execute('UPDATE targets SET case_id = ? WHERE target_id = ?', (new_id, r['target_id']))

conn.commit()

print(f'Updated {len(rows)} targets')
print()
print('Current state:')
check = conn.execute('SELECT case_id, username FROM targets').fetchall()
for r in check:
    print(r['case_id'], '|', r['username'])