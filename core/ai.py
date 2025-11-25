import google.generativeai as genai
import json
import asyncio
from typing import Dict, Any

class AIAgent:
    def __init__(self, api_key: str):
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel(
            'gemini-1.5-pro-latest',
            generation_config=genai.GenerationConfig(
                max_output_tokens=8192,
                temperature=0.4
            )
        )

    async def analyze_results(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        summary_payload = {
            "target_url": scan_data.get("target"),
            "findings": {
                "auth_leak": scan_data.get("auth_leak", False),
                "writable_tables": scan_data.get("writable_tables", []),
                "exposed_rpcs": scan_data.get("executable_rpcs", []),
                "hidden_tables": scan_data.get("hidden_tables", []),
                "accepted_risks": scan_data.get("accepted_risks", [])
            }
        }

        try:
            with open("prompt/data.json", "r", encoding="utf-8") as f:
                kb_data = json.load(f)
                SUPABASE_SECURITY_KB = json.dumps(kb_data, indent=2)
        except Exception:
            SUPABASE_SECURITY_KB = "Focus on RLS, Auth, and RPC security best practices."

        prompt = f"""
        You are a Senior Supabase Security Architect and Red Team Lead.
        
        [KNOWLEDGE BASE]
        {SUPABASE_SECURITY_KB}

        Analyze the following automated scan results for a Supabase instance:
        {json.dumps(summary_payload, indent=2)}

        YOUR TASK:
        Perform a deep-dive security assessment using the provided Knowledge Base.

        1. **Executive Summary**: High-level overview for the CTO.
        2. **Risk Assessment**:
           - Assign an Overall Risk Level (Low/Medium/High/Critical).
           - Justify the level based on the *combination* of findings.
        3. **Detailed Findings & Impact Analysis**:
           - For each finding, explain the **Technical Impact** (what an attacker can do).
           - Explain the **Business Impact** (data loss, reputation damage, regulatory fines).
           - Reference specific sections from the Knowledge Base.
        4. **Step-by-Step Remediation**:
           - Provide EXACT SQL commands or Dashboard actions to fix the issues.
           - For RLS, provide the specific Policy SQL.
           - For RPCs, provide the `REVOKE` or `DROP` commands.
        5. **Verification**:
           - How can the user verify the fix?
        6. **Accepted Risks**:
           - Acknowledge "accepted_risks" and exclude them from the risk score.

        OUTPUT FORMAT:
        Return ONLY valid JSON with this structure:
        {{
            "risk_level": "Critical",
            "summary": "...",
            "impact_analysis": {{
                "technical": ["..."],
                "business": ["..."]
            }},
            "recommendations": [
                {{
                    "issue": "...",
                    "severity": "...",
                    "remediation_sql": "...",
                    "verification_steps": "..."
                }}
            ],
            "fixes": {{
                "auth": "...",
                "rls": "...",
                "rpc": "...",
                "realtime": "..."
            }}
        }}
        """

        try:
            response = await asyncio.to_thread(self.model.generate_content, prompt)
            return self._clean_json(response.text)
        except Exception as e:
            return {"error": str(e)}

    def _clean_json(self, text: str) -> Dict[str, Any]:
        text = text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1]
            if text.strip().endswith("```"):
                text = text.rsplit("\n", 1)[0]
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"error": "Invalid JSON response", "raw": text}