# modules/behavioral.py
from .ai_engine import AIEngine


def analyze_text(text: str, use_ai: bool = True, case_id: str = None, target_id: int = None,
                 db=None):
    """
    Hybrid behavioral analysis with a structured, explainable risk score.

    Milestone 8 change: the numeric risk score now comes from the structured
    RiskEngine, which scores a target against weighted, documented components
    (grooming language, cross-platform footprint, anonymization, behavioral
    velocity, and historical flags). The local AI is still run when enabled, but
    its output is preserved as qualitative analyst context rather than used as
    the score. This makes the persisted score traceable: every point maps to a
    component a reviewer can account for.

    The earlier behavior persisted whatever number the AI emitted, defaulting to
    a fixed value when the model returned none, which did not reflect the data
    actually collected. The RiskEngine path replaces that.

    Args:
        text: profile text passed to the AI engine for qualitative context.
        use_ai: whether to run the AI engine for context. The score does not
            depend on it; when False or unavailable the score is unaffected.
        case_id: optional case context used by the AI for retrieval.
        target_id: required for scoring and persistence — which target this is.
        db: DatabaseManager instance. When provided with a target_id, the
            structured result is persisted to analysis_results.
    """
    print("🔍 Running structured behavioral analysis...")

    # Run the AI engine for qualitative context only. Its score is intentionally
    # not used as the risk score; it is carried into findings for the analyst.
    ai_findings = None
    if use_ai:
        try:
            ai = AIEngine()
            ai_result = ai.analyze_behavior(text, case_id, target_id)
            ai_findings = ai_result.get("findings") if isinstance(ai_result, dict) else None
        except Exception as e:
            print(f"    ⚠️ AI context unavailable: {e}")
            ai_findings = {"note": "AI context unavailable"}

    # The structured score requires a target and a database to read the target's
    # collected artifacts. Without them we cannot score against real signals.
    if db is None or target_id is None:
        print("    ⚠️ No target_id/db supplied — structured scoring requires collected artifacts; not persisted")
        return {
            "analysis_type": "risk_engine_v1",
            "risk_score": 0.0,
            "findings": {"note": "no target context for structured scoring", "ai_context": ai_findings},
            "notes": "Structured scoring requires a target and collected artifacts.",
        }

    # Score the target with the structured RiskEngine via the bridge.
    try:
        from .risk_scoring import score_target
        connection = db.get_connection()
        result = score_target(connection, target_id, ai_findings=ai_findings)
    except Exception as e:
        print(f"    ⚠️ Structured scoring failed: {e}")
        # Degrade honestly: record that scoring failed rather than inventing a number.
        result = {
            "analysis_type": "risk_engine_v1",
            "risk_score": 0.0,
            "findings": {"error": f"structured scoring failed: {e}", "ai_context": ai_findings},
            "notes": "Structured scoring failed; see error in findings.",
        }

    # Persist the structured score so the dashboard displays it.
    try:
        db.save_analysis(target_id, result)
        print(f"    💾 Saved structured analysis (risk={result.get('risk_score')}, target_id={target_id})")
    except Exception as e:
        print(f"    ⚠️ Could not persist analysis: {e}")

    return result