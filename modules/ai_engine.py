# modules/ai_engine.py
import ollama
import json
import time
from datetime import datetime
from .rag_engine import RAGEngine

class AIEngine:
    def __init__(self, model: str = "qwen2.5-coder:7b"):
        self.model = model
        self.rag = RAGEngine()
        self.max_retries = 2

    def analyze_behavior(self, text: str, case_id: str = None, target_id: int = None) -> dict:
        """AI Analysis with retry logic"""
        context = ""

        if case_id:
            try:
                rag_results = self.rag.query(
                    query_text=f"Behavioral analysis for case {case_id}",
                    n_results=3
                )
                if rag_results and rag_results.get('documents'):
                    context = "\n\nRelevant Context:\n" + "\n".join(rag_results['documents'][0][:3])
            except:
                pass

        system_prompt = """
        You are an expert online safety analyst.
        Be objective and concise. Return JSON only.
        """

        user_prompt = f"Target Data:\n{text}\n{context}"

        for attempt in range(self.max_retries + 1):
            try:
                response = ollama.chat(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    options={"temperature": 0.3}
                )

                result_text = response['message']['content']
                try:
                    findings = json.loads(result_text)
                except:
                    findings = {"summary": result_text[:400]}

                return {
                    "analysis_type": "ai_rag_behavioral",
                    "risk_score": findings.get("risk_score", 5.0),
                    "findings": findings,
                    "model_used": self.model
                }

            except Exception as e:
                if attempt == self.max_retries:
                    print(f"    ⚠️ AI failed after {self.max_retries+1} attempts: {e}")
                    break
                time.sleep(2 ** attempt)

        return {
            "analysis_type": "ai_rag_behavioral",
            "risk_score": 4.5,
            "findings": {"error": "AI analysis unavailable"},
            "model_used": self.model
        }