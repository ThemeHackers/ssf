import google.generativeai as genai
import json
import asyncio
import re
from typing import Dict, Any, Callable, Optional

class AIAgent:
    def __init__(self, api_key: str):
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel(
            'gemini-3-pro-preview',
            generation_config=genai.GenerationConfig(
                max_output_tokens=16384,
                temperature=0.5,
                top_p=0.95,
                top_k=40,
            )
        )

    async def analyze_results(self, scan_data: Dict[str, Any], stream_callback: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
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
        Perform an EXHAUSTIVE, DEEP-DIVE security assessment using the provided Knowledge Base.
        Do not be superficial. Think like an advanced attacker.

        1. **Executive Summary**: High-level overview for the CTO.
        2. **Risk Assessment**:
           - Assign an Overall Risk Level (Low/Medium/High/Critical).
           - Justify the level based on the *combination* of findings.
        3. **Detailed Findings & Impact Analysis**:
           - For each finding, explain the **Technical Impact** (what an attacker can do).
           - Explain the **Business Impact** (data loss, reputation damage, regulatory fines).
           - Reference specific sections from the Knowledge Base.
           - **Attack Chains**: Analyze how different findings can be chained together (e.g., "Exposed RPC + GraphQL Introspection = High Risk").
        4. **Step-by-Step Remediation**:
           - Provide EXACT SQL commands or Dashboard actions to fix the issues.
           - For RLS, provide the specific Policy SQL.
           - For RPCs, provide the `REVOKE` or `DROP` commands.
           - **Defense in Depth**: Suggest additional layers of security beyond just the immediate fix.
        5. **Verification**:
           - How can the user verify the fix?
        6. **Accepted Risks**:
           - Acknowledge "accepted_risks" and exclude them from the risk score.
        7. **Exploit Generation**:
           - Generate COMPLETE, READY-TO-RUN exploit scripts for the most critical finding.
           - Provide scripts in: Python (requests), JavaScript (fetch), Go (net/http), and cURL.
           - Ensure scripts handle authentication (Anon Key) properly.

        IMPORTANT: 
        1. Start your response with a "Thinking Process:" section where you explain your analysis step-by-step.
        2. Then, provide the JSON output wrapped in a markdown code block (```json ... ```).

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
            }},
            "poc": {{
                "target": "TARGET_URL",
                "apikey": "ANON_KEY",
                "service_role_key": "SERVICE_KEY_IF_LEAKED",
                "exploits": [
                    {{
                        "type": "table_dump",
                        "table": "users",
                        "filter": {{"limit": 10}}
                    }},
                    {{
                        "type": "rpc_data_leak",
                        "rpc_name": "get_secrets",
                        "payload": {{}}
                    }}
                ],
                "exploit_scripts": {{
                    "python": "import requests...",
                    "javascript": "fetch('...', ...)",
                    "go": "package main...",
                    "curl": "curl -X POST ..."
                }}
            }}
        }}
        """

        try:
            if stream_callback:
                full_text = await asyncio.to_thread(self._generate_stream, prompt, stream_callback)
                cleaned_response = self._clean_json(full_text)
            else:
                response = await asyncio.to_thread(self.model.generate_content, prompt)
                cleaned_response = self._clean_json(response.text)
            
            if "poc" in cleaned_response:
                import os
                os.makedirs("poc", exist_ok=True)
                with open("poc/exploit_generated.json", "w", encoding="utf-8") as f:
                    json.dump(cleaned_response["poc"], f, indent=2)
            
            return cleaned_response
        except Exception as e:
            return {"error": str(e)}

    def _generate_stream(self, prompt: str, callback: Callable[[str], None]) -> str:
        response = self.model.generate_content(prompt, stream=True)
        full_text = ""
        for chunk in response:
            try:
                text = chunk.text
                full_text += text
                callback(text)
            except Exception: pass
        return full_text

    def _clean_json(self, text: str) -> Dict[str, Any]:

        match = re.search(r'```json\s*(\{.*?\})\s*```', text, re.DOTALL)
        if match:
            text = match.group(1)
        else:

            start = text.find("{")
            end = text.rfind("}")
            if start != -1 and end != -1:
                text = text[start:end+1]
        
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"error": "Invalid JSON response", "raw": text}

    async def analyze_code(self, code_files: Dict[str, str], stream_callback: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
        """
        Analyzes source code for security vulnerabilities.
        """
        files_context = ""
        for name, content in code_files.items():
            files_context += f"\n--- FILE: {name} ---\n{content}\n"
            
        prompt = f"""
        You are a Senior Supabase Security Auditor.
        
        Analyze the following source code files from a Supabase project for security vulnerabilities.
        Perform a LINE-BY-LINE analysis looking for subtle bugs and logic flaws.

        Focus on:
        1. **RLS Policies**: Are they too permissive? Do they use `true` incorrectly?
        2. **Supabase Client Creation**: Is the `service_role` key used on the client side?
        3. **SQL Injections**: In raw SQL queries or RPCs.
        4. **Sensitive Data**: Hardcoded keys or secrets.
        5. **Business Logic Flaws**: In Edge Functions or backend logic.
        6. **Access Control**: Are permissions properly checked before sensitive actions?

        [CODE FILES]
        {files_context}

        OUTPUT FORMAT:
        Return ONLY valid JSON with this structure:
        {{
            "risk_level": "High",
            "summary": "...",
            "findings": [
                {{
                    "file": "path/to/file.ts",
                    "line": 10,
                    "issue": "Hardcoded Service Role Key",
                    "severity": "Critical",
                    "description": "...",
                    "remediation": "..."
                }}
            ],
            "recommendations": ["..."]
        }}
        
        Start with "Thinking Process:" then provide the JSON.
        """
        
        try:
            if stream_callback:
                full_text = await asyncio.to_thread(self._generate_stream, prompt, stream_callback)
                return self._clean_json(full_text)
            else:
                response = await asyncio.to_thread(self.model.generate_content, prompt)
                return self._clean_json(response.text)
        except Exception as e:
            return {"error": str(e)}