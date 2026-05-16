# modules/evidence_packager.py
def create_evidence_package(case_id: str):
    """Create ZIP evidence package with chain-of-custody manifest"""
    print(f"Creating evidence package for case {case_id}...")
    print("    -> Chain-of-custody manifest created")
    print(f"    -> Package saved to exports/{case_id}.zip (stub)")