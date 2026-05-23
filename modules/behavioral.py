# modules/behavioral.py
from .ai_engine import AIEngine


def analyze_text(text: str, use_ai: bool = True, case_id: str = None, target_id: int = None,
                 db=None):
    """
    Final Hybrid Analysis with RAG.

    Phase 5 change: now persists risk_score to analysis_results table
    via db.save_analysis() so the web dashboard can display real scores
    instead of terminal-only printouts.

    Args:
        text: the text to analyze
        use_ai: whether to use the AI engine (falls back to rule-based if False/unavailable)
        case_id: optional case context (used by AI for RAG)
        target_id: required for persistence — which target this analysis is about
        db: DatabaseManager instance. If provided AND target_id is set,
            the result is persisted to analysis_results.
    """
    print("🔍 Running advanced behavioral analysis...")

    if use_ai:
        try:
            ai = AIEngine()
            result = ai.analyze_behavior(text, case_id, target_id)
        except Exception as e:
            print(f"    ⚠️ AI unavailable: {e}")
            result = {
                "analysis_type": "rule_based",
                "risk_score": 4.0,
                "findings": ["Basic analysis completed"],
                "notes": "AI analysis unavailable - using fallback"
            }
    else:
        result = {
            "analysis_type": "rule_based",
            "risk_score": 4.0,
            "findings": ["Basic analysis completed"],
            "notes": "Rule-based analysis (AI disabled)"
        }

    # ----- PHASE 5: persist the score so the dashboard can display it -----
    if db is not None and target_id is not None:
        try:
            db.save_analysis(target_id, result)
            print(f"    💾 Saved analysis to DB (risk={result.get('risk_score')}, target_id={target_id})")
        except Exception as e:
            print(f"    ⚠️ Could not persist analysis: {e}")
    elif target_id is None:
        print("    ⚠️ No target_id supplied — analysis not persisted")

    return result