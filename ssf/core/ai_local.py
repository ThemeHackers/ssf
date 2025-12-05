import httpx 
import json 
import asyncio 
import re 
from typing import Dict ,Any ,Callable ,Optional 

class LocalAIAgent :
    def __init__ (self ,model_name :str ="llama3",base_url :str ="http://localhost:11434"):
        self .model_name =model_name 
        self .base_url =base_url 

    async def _generate (self ,prompt :str ,stream_callback :Optional [Callable [[str ],None ]]=None )->str :
        url =f"{self .base_url }/api/generate"
        payload ={
        "model":self .model_name ,
        "prompt":prompt ,
        "stream":stream_callback is not None 
        }

        try :
            async with httpx .AsyncClient (timeout =120.0 )as client :
                if stream_callback :
                    full_text =""
                    async with client .stream ("POST",url ,json =payload )as response :
                        async for line in response .aiter_lines ():
                            if line :
                                try :
                                    data =json .loads (line )
                                    chunk =data .get ("response","")
                                    full_text +=chunk 
                                    stream_callback (chunk )
                                    if data .get ("done",False ):
                                        break 
                                except json .JSONDecodeError :
                                    pass 
                    return full_text 
                else :
                    response =await client .post (url ,json =payload )
                    response .raise_for_status ()
                    data =response .json ()
                    return data .get ("response","")
        except Exception as e :
            error_msg =f"Error communicating with Ollama: {str (e )}"
            if "ConnectError"in str (e )or "Connection refused"in str (e )or "All connection attempts failed"in str (e ):
                error_msg +="\n\n[!] HINT: Make sure Ollama is running locally.\n    Install Ollama: curl -fsSL https://ollama.com/install.sh | sh\n    Run: 'ollama serve'\n    And pull the model: 'ollama pull <model_name>'"
            return json .dumps ({"error":error_msg })

    def _clean_json (self ,text :str )->Dict [str ,Any ]:
        match =re .search (r'```json\s*(\{.*?\})\s*```',text ,re .DOTALL )
        if match :
            text =match .group (1 )
        else :
            start =text .find ("{")
            end =text .rfind ("}")
            if start !=-1 and end !=-1 :
                text =text [start :end +1 ]

        try :
            return json .loads (text )
        except json .JSONDecodeError :
            return {"error":"Invalid JSON response from Local AI","raw":text }

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

        prompt =f"""
        You are a Senior Supabase Security Architect.
        Analyze the following scan results and provide a security assessment in JSON format.
        
        SCAN DATA:
        {json .dumps (summary_payload ,indent =2 )}
        
        OUTPUT FORMAT:
        Return ONLY valid JSON with this structure:
        {{
            "risk_level": "Critical/High/Medium/Low",
            "summary": "Executive summary...",
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
            "poc": {{
                "target": "TARGET_URL",
                "apikey": "ANON_KEY",
                "exploits": [],
                "exploit_scripts": {{}}
            }}
        }}
        
        Ensure the 'poc' section is populated if critical issues are found, similar to how a human pentester would create a proof of concept.
        """

        response_text =await self ._generate (prompt ,stream_callback )
        cleaned_response =self ._clean_json (response_text )

        if "poc"in cleaned_response :
            import os 
            os .makedirs (output_dir ,exist_ok =True )
            with open (os .path .join (output_dir ,"exploit_generated.json"),"w",encoding ="utf-8")as f :
                json .dump (cleaned_response ["poc"],f ,indent =2 )

        return cleaned_response 

    async def analyze_code (self ,code_files :Dict [str ,str ],stream_callback :Optional [Callable [[str ],None ]]=None )->Dict [str ,Any ]:
        files_context =""
        for name ,content in code_files .items ():
            files_context +=f"\n--- FILE: {name } ---\n{content }\n"

        prompt =f"""
        Analyze the following code for Supabase security vulnerabilities (RLS, SQLi, Secrets).
        
        CODE:
        {files_context }
        
        OUTPUT JSON:
        {{
            "risk_level": "High",
            "summary": "...",
            "findings": [
                {{ "file": "...", "line": 1, "issue": "...", "severity": "...", "description": "..." }}
            ]
        }}
        """
        response_text =await self ._generate (prompt ,stream_callback )
        return self ._clean_json (response_text )

    async def generate_threat_model (self ,scan_data :Dict [str ,Any ],stream_callback :Optional [Callable [[str ],None ]]=None )->Dict [str ,Any ]:
        prompt =f"""
        Generate a Threat Model (STRIDE) for this Supabase instance based on findings.
        
        FINDINGS:
        {json .dumps (scan_data ,indent =2 )}
        
        OUTPUT JSON:
        {{
            "dfd_mermaid": "graph TD...",
            "assets": [],
            "threat_actors": [],
            "attack_paths": [],
            "stride_analysis": {{}}
        }}
        """
        response_text =await self ._generate (prompt ,stream_callback )
        return self ._clean_json (response_text )
