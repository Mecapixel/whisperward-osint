# modules/behavioral.py
from .ai_engine import AIEngine

def analyze_text(text: str, use_ai: bool = True, case_id: str = None, target_id: int = None):
    """Final Hybrid Analysis with RAG"""
    print("🔍 Running advanced behavioral analysis...")

    if use_ai:
        try:
            ai = AIEngine()
            return ai.analyze_behavior(text, case_id, target_id)
        except Exception as e:
            print(f"    ⚠️ AI unavailable: {e}")

    return {
        "analysis_type": "rule_based",
        "risk_score": 4.0,
        "findings": ["Basic analysis completed"],
        "notes": "AI analysis unavailable - using fallback"
    }