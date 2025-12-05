import google .generativeai as genai 
import json 
import asyncio 
import re 
from typing import Dict ,Any ,Callable ,Optional 
class AIAgent :
    def __init__ (self ,api_key :str ,model_name :str ="gemini-3-pro-preview"):
        genai .configure (api_key =api_key )
        self .model =genai .GenerativeModel (
        model_name ,
        generation_config =genai .GenerationConfig (
        max_output_tokens =16384 ,
        temperature =0.5 ,
        top_p =0.95 ,
        top_k =40 ,
        )
        )
    async def analyze_results (self ,scan_data :Dict [str ,Any ],output_dir :str ="poc",stream_callback :Optional [Callable [[str ],None ]]=None )->Dict [str ,Any ]:
        summary_payload ={
        "target_url":scan_data .get ("target"),
        "findings":{
        "auth_leak":scan_data .get ("auth_leak",False ),
        "writable_tables":scan_data .get ("writable_tables",[]),
        "exposed_rpcs":scan_data .get ("executable_rpcs",[]),
        "hidden_tables":scan_data .get ("hidden_tables",[]),
        "accepted_risks":scan_data .get ("accepted_risks",[])
        }
        }
        try :
            with open ("prompt/data.json","r",encoding ="utf-8")as f :
                kb_data =json .load (f )
                SUPABASE_SECURITY_KB =json .dumps (kb_data ,indent =2 )
        except Exception :
            SUPABASE_SECURITY_KB ="Focus on RLS, Auth, and RPC security best practices."
        prompt =f"""
        You are a Senior Supabase Security Architect and Red Team Lead.
        [KNOWLEDGE BASE]
        {SUPABASE_SECURITY_KB }
        Analyze the following automated scan results for a Supabase instance:
        {json .dumps (summary_payload ,indent =2 )}
        YOUR TASK:
        Perform an EXHAUSTIVE, DEEP-DIVE security assessment using the provided Knowledge Base.
        Do not be superficial. Think like an advanced attacker.
        
        1. **Executive Summary**: 
           - Write a comprehensive high-level overview for the CTO. 
           - Explain the overall security posture in detail.
        
        2. **Risk Assessment**:
           - Assign an Overall Risk Level (Low/Medium/High/Critical).
           - Justify the level based on the *combination* of findings.
           - Explain the reasoning in depth.

        3. **Detailed Findings & Impact Analysis**:
           - For each finding, explain the **Technical Impact** (what an attacker can do) in LONG, DETAILED paragraphs.
           - Explain the **Business Impact** (data loss, reputation damage, regulatory fines) with specific examples.
           - Reference specific sections from the Knowledge Base.
           - **Attack Chains**: Analyze how different findings can be chained together (e.g., "Exposed RPC + GraphQL Introspection = High Risk").
           - **Educational Value**: Explain *why* this is a vulnerability and how it works under the hood.

        4. **Step-by-Step Remediation**:
           - Provide EXACT SQL commands or Dashboard actions to fix the issues.
           - For RLS, provide the specific Policy SQL.
           - For RPCs, provide the `REVOKE` or `DROP` commands.
           - **Defense in Depth**: Suggest additional layers of security beyond just the immediate fix.
           - Explain *why* the fix works.

        5. **Verification**:
           - How can the user verify the fix? Provide specific commands or steps.

        6. **Accepted Risks**:
           - Acknowledge "accepted_risks" and exclude them from the risk score.

        7. **Exploit Generation**:
            - Generate COMPLETE, READY-TO-RUN exploit scripts for EACH table flagged as CRITICAL or LEAK.
            - Provide scripts in Python (requests) and cURL.
            - Format keys as: "python_<table_name>", "curl_<table_name>".
            - Example: If 'exam_keys' is critical, provide 'python_exam_keys'.
            - Ensure scripts handle authentication (Anon Key) properly.

        8. **Confidence Score**:
           - You must provide a confidence score (0-100%) for the overall risk assessment.
           - If confidence is below 90%, do NOT label as "Critical". Use "Low Risk" or "Info".
           - JUSTIFY your confidence score.

        9. **Context & Validation Check**:
           - Before flagging an issue, check if it's in a TEST file or MOCK data. If so, IGNORE or mark as LOW risk.
           - Before flagging SQL Injection, check if there is Input Validation or Type Casting. If present, lower the risk.

        IMPORTANT: 

        1. Start your response with a "## Thinking Process" section where you explain your analysis step-by-step.
        2. Then, provide the JSON output wrapped in a markdown code block (```json ... ```).

        OUTPUT FORMAT:
        Return ONLY valid JSON with this structure:
        {{ 
            "risk_level": "Critical",
            "summary": "...",
            "impact_analysis": {{ 
                "technical": ["..."],
                "business": ["..."]
            }} ,
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
            }} ,
            "poc": {{ 
                "target": "TARGET_URL",
                "apikey": "ANON_KEY",
                "service_role_key": "SERVICE_KEY_IF_LEAKED",
                "exploits": [
                    {{ 
                        "type": "table_dump",
                        "table": "users",
                        "filter": {{ 
                                    "limit": 10}}  
                    }} ,
                    {{ 
                        "type": "rpc_data_leak",
                        "rpc_name": "get_secrets",
                        "payload": {{ 
                                     }}  
                    }} 
                ],
                "exploit_scripts": {{ 
                    "python_users": "import requests...",
                    "curl_users": "curl -X GET ...",
                    "python_admin_keys": "import requests..."
                }} 
            }} 
        }} 
        """
        try :
            if stream_callback :
                full_text =await asyncio .to_thread (self ._generate_stream ,prompt ,stream_callback )
                cleaned_response =self ._clean_json (full_text )
            else :
                response =await asyncio .to_thread (self .model .generate_content ,prompt )
                cleaned_response =self ._clean_json (response .text )


            if "poc"in cleaned_response :
                poc_data =cleaned_response ["poc"]


                if "apikey"in scan_data and scan_data ["apikey"]:
                    poc_data ["apikey"]=scan_data ["apikey"]

                if "service_role_key"in scan_data and scan_data ["service_role_key"]:
                    poc_data ["service_role_key"]=scan_data ["service_role_key"]
                else :
                    poc_data ["service_role_key"]="NOT_LEAKED"


                if "target_url"in scan_data :
                    poc_data ["target"]=scan_data ["target_url"]


                import os 
                os .makedirs (output_dir ,exist_ok =True )
                with open (os .path .join (output_dir ,"exploit_generated.json"),"w",encoding ="utf-8")as f :
                    json .dump (poc_data ,f ,indent =2 )

            return cleaned_response 
        except Exception as e:
            return self._handle_ai_error(e)

    def _handle_ai_error(self, e: Exception) -> Dict[str, Any]:
        error_str = str(e)
        if "400" in error_str:
            return {"error": "AI Error (400): Invalid Request. Check your prompt or API key format."}
        elif "401" in error_str:
            return {"error": "AI Error (401): Unauthorized. Invalid API Key."}
        elif "403" in error_str:
            return {"error": "AI Error (403): Forbidden. Quota exceeded or location restricted."}
        elif "429" in error_str:
            return {"error": "AI Error (429): Rate Limit Exceeded. Please slow down."}
        elif "500" in error_str:
            return {"error": "AI Error (500): Google Internal Server Error. Try again later."}
        elif "503" in error_str:
            return {"error": "AI Error (503): Service Unavailable. The model is overloaded."}
        elif "504" in error_str or "Deadline Exceeded" in error_str:
            return {"error": "AI Error (504): High Traffic/Timeout. Please wait a moment and try again."}
        return {"error": f"AI Error: {error_str}"}

    def _generate_stream (self ,prompt :str ,callback :Callable [[str ],None ])->str :
        response =self .model .generate_content (prompt ,stream =True )
        full_text =""
        for chunk in response :
            try :
                text =chunk .text 
                full_text +=text 
                callback (text )
            except Exception :pass 
        return full_text 

    def _clean_json (self ,text :str )->Dict [str ,Any ]:
        """
        Extract and parse JSON from AI response with multiple fallback strategies
        """

        patterns =[
        r'```json\s*(\{.*?\})\s*```',
        r'```\s*(\{.*?\})\s*```',
        r'`(\{.*?\})`',
        ]

        for pattern in patterns :
            match =re .search (pattern ,text ,re .DOTALL )
            if match :
                try :
                    return json .loads (match .group (1 ))
                except json .JSONDecodeError :
                    continue 

        start =text .find ("{")
        end =text .rfind ("}")
        if start !=-1 and end !=-1 and end >start :
            potential_json =text [start :end +1 ]
            try :
                return json .loads (potential_json )
            except json .JSONDecodeError :
                pass 
        thinking_split =re .split (r'##\s+(?:Thinking|Analysis|JSON|Output)',text ,flags =re .IGNORECASE )
        if len (thinking_split )>1 :

            for part in thinking_split [1 :]:
                start =part .find ("{")
                end =part .rfind ("}")
                if start !=-1 and end !=-1 :
                    try :
                        return json .loads (part [start :end +1 ])
                    except json .JSONDecodeError :
                        continue 


        truncated_text =text [:500 ]+"..."if len (text )>500 else text 
        return {
        "error":"Invalid JSON response - AI did not return valid JSON format",
        "raw_preview":truncated_text ,
        "suggestions":[
        "The AI model may be overloaded or rate-limited",
        "Try using a different AI model (e.g., gemini-2.0-flash-exp)",
        "Check your API key and quota",
        "The prompt may be too complex - try simplifying the scan"
        ]
        }

    async def analyze_code (self ,code_files :Dict [str ,Dict [str ,str ]],stream_callback :Optional [Callable [[str ],None ]]=None )->Dict [str ,Any ]:
        combined_report ={
        "risk_level":"Low",
        "summary":"",
        "findings":[],
        "recommendations":[]
        }

        if stream_callback :
            results =[]
            if code_files .get ("sql"):
                if stream_callback :stream_callback ("\n\n**Analyzing SQL Files...**\n")
                results .append (await self ._analyze_category (code_files ["sql"],"sql",stream_callback ))

            if code_files .get ("app"):
                if stream_callback :stream_callback ("\n\n**Analyzing Application Code...**\n")
                results .append (await self ._analyze_category (code_files ["app"],"app",stream_callback ))
        else :

            tasks =[]
            if code_files .get ("sql"):
                tasks .append (self ._analyze_category (code_files ["sql"],"sql",None ))
            if code_files .get ("app"):
                tasks .append (self ._analyze_category (code_files ["app"],"app",None ))

            if not tasks :
                return {"error":"No code files to analyze."}

            results =await asyncio .gather (*tasks )

        risk_levels ={"Critical":4 ,"High":3 ,"Medium":2 ,"Low":1 }
        max_risk =1 

        for res in results :
            if "error"in res :continue 


            combined_report ["summary"]+=f"\n\n{res .get ('summary','')}"


            combined_report ["findings"].extend (res .get ("findings",[]))


            combined_report ["recommendations"].extend (res .get ("recommendations",[]))


            current_risk =risk_levels .get (res .get ("risk_level","Low"),1 )
            if current_risk >max_risk :
                max_risk =current_risk 

            for finding in res .get ("findings",[]):
                severity =finding .get ("severity","Low")
                finding_risk =risk_levels .get (severity ,1 )
                if finding_risk >max_risk :
                    max_risk =finding_risk 


        risk_map ={4 :"Critical",3 :"High",2 :"Medium",1 :"Low"}
        combined_report ["risk_level"]=risk_map [max_risk ]

        return combined_report 

    async def _analyze_category (self ,files :Dict [str ,str ],category :str ,stream_callback :Optional [Callable [[str ],None ]]=None )->Dict [str ,Any ]:
        files_context =""
        for name ,content in files .items ():
            files_context +=f"\n--- FILE: {name } ---\n{content }\n"

        if category =="sql":
            prompt =f"""
            You are a Database Security Expert specializing in PostgreSQL and Supabase.
            Analyze the following SQL files for security vulnerabilities.
            
            STRICT GUIDELINES:
            1. **Ignore Placeholders**: Do NOT flag strings like "your_key", "example", "0000", or "test_secret" as hardcoded secrets.
            2. **Ignore Test Code**: If a file is clearly a test or mock (e.g., in a 'tests' folder), lower the severity/confidence.
            3. **Confidence Scoring**: You must assign a 'confidence' score (High/Medium/Low) to each finding.
               - **High**: Definite vulnerability (e.g., `USING (true)` on a public table).
               - **Medium**: Likely vulnerability but needs context.
               - **Low**: Guess or best practice suggestion.
            4. **Context Awareness**:
               - Check if the code is in a `tests/`, `__mocks__/`, or `fixtures/` directory. If so, treat "secrets" as dummy data.
               - Look for input validation. If `id` is cast to `int` or `uuid`, it's likely NOT SQL Injection.

            FOCUS ON:
            1. **RLS Policies**: 
               - Look for `USING (true)` or `WITH CHECK (true)` (Permissive).
               - Ensure `authenticated` role is checked where appropriate.
            2. **Functions (RPCs)**:
               - Identify `SECURITY DEFINER` functions. Are they necessary? Do they set `search_path`?
               - Check for SQL Injection in dynamic SQL (`EXECUTE`).
            3. **Privileges**:
               - Excessive grants to `anon` or `authenticated` roles.
            4. **Sensitive Data**:
               - Hardcoded REAL secrets (high entropy).

            [SQL FILES]
            {files_context }
            
            OUTPUT FORMAT:
            Return ONLY valid JSON with this structure:
            {{
                "risk_level": "High",
                "summary": "Brief, balanced summary of SQL findings. Do not be alarmist.",
                "findings": [
                    {{
                        "file": "path/to/file.sql",
                        "line": 10,
                        "issue": "Permissive RLS Policy",
                        "severity": "High",
                        "confidence": "High",
                        "description": "Policy allows anyone to delete data.",
                        "remediation": "Restrict to owner: using (auth.uid() = user_id)"
                    }}
                ],
                "recommendations": ["..."]
            }}
            """
        else :
            prompt =f"""
            You are a Application Security Expert.
            Analyze the following application code (JS/TS/Python) for Supabase-related vulnerabilities.
            
            STRICT GUIDELINES:
            1. **Ignore Placeholders**: Do NOT flag strings like "your_key", "example", "0000", or "test_secret" as hardcoded secrets.
            2. **Ignore Test Code**: If a file is clearly a test or mock, lower the severity/confidence.
            3. **Confidence Scoring**: You must assign a 'confidence' score (High/Medium/Low) to each finding.
               - **High**: Definite vulnerability (e.g., `service_role` key in client-side code).
               - **Medium**: Likely vulnerability.
               - **Low**: Guess or best practice suggestion.
            4. **Context Awareness**:
               - Check if the code is in a `tests/`, `__mocks__/`, or `fixtures/` directory. If so, treat "secrets" as dummy data.
               - Look for input validation. If `id` is cast to `int` or `uuid`, it's likely NOT SQL Injection.

            FOCUS ON:
            1. **Client Initialization**:
               - Is the `service_role` key used on the client-side? (CRITICAL)
               - Is `persistSession` configured correctly?
            2. **API Handlers**:
               - Are permissions checked before performing DB operations?
               - Is user input validated?
            3. **Edge Functions**:
               - Do they verify the JWT?
               - Are secrets handled securely?
            4. **Hardcoded Secrets**:
               - API keys, tokens, or credentials (must look real).

            [CODE FILES]
            {files_context }
            
            OUTPUT FORMAT:
            Return ONLY valid JSON with this structure:
            {{
                "risk_level": "High",
                "summary": "Brief, balanced summary of App findings. Do not be alarmist.",
                "findings": [
                    {{
                        "file": "path/to/file.ts",
                        "line": 5,
                        "issue": "Leaked Service Role Key",
                        "severity": "Critical",
                        "confidence": "High",
                        "description": "Service role key found in client-side code.",
                        "remediation": "Use Anon key and RLS."
                    }}
                ],
                "recommendations": ["..."]
            }}
            """

        try :
            if stream_callback :
                full_text =await asyncio .to_thread (self ._generate_stream ,prompt ,stream_callback )
                return self ._clean_json (full_text )
            else :
                response =await asyncio .to_thread (self .model .generate_content ,prompt )
                return self ._clean_json (response .text )
        except Exception as e:
            return self._handle_ai_error(e)

    async def generate_threat_model (self ,scan_data :Dict [str ,Any ],stream_callback :Optional [Callable [[str ],None ]]=None )->Dict [str ,Any ]:
        summary_payload ={
        "target_url":scan_data .get ("target"),
        "findings":{
        "auth_leak":scan_data .get ("auth_leak",False ),
        "writable_tables":scan_data .get ("writable_tables",[]),
        "exposed_rpcs":scan_data .get ("executable_rpcs",[]),
        "hidden_tables":scan_data .get ("hidden_tables",[]),
        },
        "schema_summary":"Inferred from findings (tables, RPCs)"
        }
        prompt =f"""
        You are a Threat Modeling Expert (STRIDE/DREAD).
        Analyze the following Supabase scan data:
        {json .dumps (summary_payload ,indent =2 )}
        YOUR TASK:
        Create a comprehensive, DETAILED Threat Model for this application.
        
        1. **Data Flow Diagram (DFD)**:
           - Generate a Mermaid JS graph (`graph TD`) showing the flow of data between Users (Anon/Authenticated), the Supabase API (PostgREST/RPC), and the Database Tables.
           - Highlight trust boundaries.

        2. **Critical Assets**:
           - Identify the most valuable assets (e.g., specific tables, user data).
           - Explain *why* they are critical.

        3. **Attack Paths**:
           - Based on the findings (e.g., RLS leaks, exposed RPCs), map out concrete attack paths.
           - Format: "Entry Point -> Vulnerability -> Impact".
           - Provide a DETAILED narrative for each path.

        4. **Threat Actors**:
           - Who are the likely attackers? (e.g., Malicious User, Competitor, Script Kiddie).
           - What are their motivations?

        5. **STRIDE Analysis**:
           - For each category (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege), provide a detailed analysis.
           - Explain specific scenarios relevant to Supabase.

        OUTPUT FORMAT:
        Return ONLY valid JSON with this structure:
        {{ 
            "dfd_mermaid": "graph TD...",
            "assets": ["..."],
            "threat_actors": ["..."],
            "attack_paths": [
                {{ 
                    "name": "Admin Takeover via RPC",
                    "steps": ["Attacker calls is_admin", "Fuzzes param", "Gains admin role"],
                    "likelihood": "High",
                    "impact": "Critical",
                    "description": "Detailed description of the attack path..."
                }} 
            ],
            "stride_analysis": {{ 
                "spoofing": "...",
                "tampering": "...",
                "repudiation": "...",
                "information_disclosure": "...",
                "denial_of_service": "...",
                "elevation_of_privilege": "..."
            }} 
        }} 
        Start with "## Thinking Process" then provide the JSON.
        """
        try :
            if stream_callback :
                full_text =await asyncio .to_thread (self ._generate_stream ,prompt ,stream_callback )
                return self ._clean_json (full_text )
            else :
                response =await asyncio .to_thread (self .model .generate_content ,prompt )
                return self ._clean_json (response .text )
        except Exception as e:
            return self._handle_ai_error(e)