# modules/behavioral.py
def analyze_text(text: str, use_ai: bool = True):
    """Tier 1 + Tier 2 (Ollama) behavioral analysis"""
    print("Running behavioral analysis...")
    return {
        "analysis_type": "behavioral",
        "risk_score": 3.5,
        "findings": {"keywords": [], "patterns": []},
        "notes": "Stub analysis - AI layer coming in Phase 3"
    }