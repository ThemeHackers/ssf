import json 
from datetime import datetime 
from typing import Dict ,Any 

VULN_TO_COMPLIANCE ={
"rls":{
"OWASP":"API1:2023 (BOLA)",
"SOC2":"CC6.1 (Access Control)"
},
"auth":{
"OWASP":"API3:2023 (BOPLA)",
"SOC2":"CC6.1 (Access Control)"
},
"rpc":{
"OWASP":"API8:2023 (Misconfiguration)",
"SOC2":"CC6.8 (Software Update)"
},
"storage":{
"OWASP":"API1:2023 (BOLA)",
"SOC2":"CC6.1 (Access Control)"
}
}

class HTMLReporter :
    def generate (self ,report :Dict [str ,Any ],diff :Dict [str ,Any ]=None )->str :
        findings =report .get ("findings",{})
        target =report .get ("target","Unknown")
        timestamp =report .get ("timestamp",datetime .now ().isoformat ())
        css ="""
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&family=JetBrains+Mono:wght@400;700&display=swap');
        :root {
            --bg-body: #0f172a;
            --bg-card: #1e293b;
            --bg-card-hover: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent-primary: #8b5cf6; /* Violet */
            --accent-secondary: #06b6d4; /* Cyan */
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
            --border: #334155;
        }
        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-body);
            color: var(--text-main);
            margin: 0;
            padding: 40px 20px;
            line-height: 1.6;
            overflow-wrap: anywhere; /* Ensure all text wraps */
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        /* Header */
        header {
            text-align: center;
            margin-bottom: 60px;
            position: relative;
        }
        header::after {
            content: '';
            position: absolute;
            bottom: -20px;
            left: 50%;
            transform: translateX(-50%);
            width: 100px;
            height: 4px;
            background: linear-gradient(90deg, var(--accent-primary), var(--accent-secondary));
            border-radius: 2px;
        }
        h1 {
            font-size: 3rem;
            font-weight: 700;
            margin: 0;
            background: linear-gradient(to right, #fff, #94a3b8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .meta {
            margin-top: 15px;
            color: var(--text-muted);
            font-size: 1.1rem;
            display: flex;
            justify-content: center;
            gap: 20px;
        }
        .meta strong { color: var(--accent-secondary); }
        /* Summary Grid */
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 25px;
            margin-bottom: 50px;
        }
        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 30px;
            text-align: center;
            transition: transform 0.2s, box-shadow 0.2s;
            position: relative;
            overflow: hidden;
        }
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 30px -10px rgba(0, 0, 0, 0.5);
            border-color: var(--accent-primary);
        }
        .stat-value {
            font-size: 3.5rem;
            font-weight: 700;
            line-height: 1;
            margin-bottom: 10px;
            background: linear-gradient(135deg, var(--text-main), var(--text-muted));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .stat-label {
            color: var(--text-muted);
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            font-weight: 600;
        }
        /* Sections */
        h2 {
            font-size: 1.8rem;
            color: var(--text-main);
            margin-top: 60px;
            margin-bottom: 25px;
            display: flex;
            align-items: center;
            gap: 15px;
        }
        h2::before {
            content: '';
            display: block;
            width: 6px;
            height: 30px;
            background: var(--accent-primary);
            border-radius: 3px;
        }
        /* Tables */
        .table-container {
            background: var(--bg-card);
            border-radius: 16px;
            border: 1px solid var(--border);
            overflow: hidden;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 20px;
            text-align: left;
            border-bottom: 1px solid var(--border);
            word-break: break-word; /* Ensure table content wraps */
        }
        th {
            background-color: rgba(255, 255, 255, 0.03);
            color: var(--text-muted);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85rem;
            letter-spacing: 1px;
        }
        tr:last-child td { border-bottom: none; }
        tr:hover { background-color: var(--bg-card-hover); }
        /* Badges */
        .badge {
            padding: 6px 12px;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            display: inline-block;
        }
        .badge.critical { background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.3); }
        .badge.high { background: rgba(245, 158, 11, 0.2); color: #fcd34d; border: 1px solid rgba(245, 158, 11, 0.3); }
        .badge.medium { background: rgba(251, 191, 36, 0.2); color: #fde68a; border: 1px solid rgba(251, 191, 36, 0.3); }
        .badge.safe { background: rgba(16, 185, 129, 0.2); color: #6ee7b7; border: 1px solid rgba(16, 185, 129, 0.3); }
        .badge.accepted { background: rgba(59, 130, 246, 0.2); color: #93c5fd; border: 1px solid rgba(59, 130, 246, 0.3); }
        /* Panels */
        .panel {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 25px;
        }
        .panel.critical {
            border-color: var(--danger);
            background: linear-gradient(to right, rgba(239, 68, 68, 0.1), transparent);
        }
        /* AI Section */
        .ai-section {
            background: linear-gradient(145deg, #2e1065, #1e1b4b);
            border: 1px solid #4c1d95;
            border-radius: 16px;
            padding: 30px;
            margin-top: 40px;
            position: relative;
            overflow: hidden;
        }
        .ai-section::before {
            content: 'AI';
            position: absolute;
            top: -20px;
            right: -20px;
            font-size: 15rem;
            font-weight: 900;
            color: rgba(255, 255, 255, 0.03);
            pointer-events: none;
        }
        .ai-header {
            display: flex;
            align-items: center;
            gap: 15px;
            margin-bottom: 20px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            padding-bottom: 15px;
        }
        .ai-title {
            font-size: 1.5rem;
            font-weight: 700;
            color: #e9d5ff;
            margin: 0;
        }
        .ai-content {
            color: #e2e8f0;
            font-size: 1.05rem;
            line-height: 1.7;
        }
        .remediation-box {
            background: rgba(0, 0, 0, 0.3);
            border-radius: 8px;
            padding: 20px;
            margin-top: 20px;
            border-left: 4px solid var(--accent-primary);
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); /* Add depth */
        }
        .remediation-title {
            color: #d8b4fe;
            font-weight: 700;
            margin-bottom: 10px;
            display: block;
            font-size: 0.9rem;
            text-transform: uppercase;
        }
        pre {
            background: #0f172a;
            padding: 15px;
            border-radius: 6px;
            white-space: pre-wrap;       /* CSS3 */
            white-space: -moz-pre-wrap;  /* Mozilla, since 1999 */
            white-space: -pre-wrap;      /* Opera 4-6 */
            white-space: -o-pre-wrap;    /* Opera 7 */
            word-wrap: break-word;       /* Internet Explorer 5.5+ */
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem;
            color: #cbd5e1;
            border: 1px solid #334155;
            margin: 0;
        }
        ul { padding-left: 20px; }
        li { margin-bottom: 8px; }
        """
        html =f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Supabase Audit Report</title>
            <style>
                   {css }</style>
        </head>
        <body>
            <div class="container">
                <header>
                    <h1>Supabase Security Audit</h1>
                    <div class="meta">
                        <span>Target: <strong>
                                              {target }</strong></span>
                        <span>•</span>
                        <span>Scanned: <strong>
                                               {timestamp }</strong></span>
                    </div>
                </header>
                <div class="summary-grid">
                    <div class="stat-card">
                        <div class="stat-value" style="color: var(--danger)">
                                                                             {len ([r for r in findings .get ('rls',[])if r ['risk']=='CRITICAL'])}</div>
                        <div class="stat-label">Critical RLS</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value" style="color: var(--warning)">
                                                                              {len ([r for r in findings .get ('rpc',[])if r .get ('risk')=='CRITICAL'])}</div>
                        <div class="stat-label">Vuln RPCs</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value" style="color: 
                                                              {'var(--danger)'if findings .get ('auth',{}).get ('leaked')else 'var(--success)'}">
                            {'YES'if findings .get ('auth',{}).get ('leaked')else 'NO'}
                        </div>
                        <div class="stat-label">Auth Leak</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">
                                                {len (findings .get ('storage',[]))}</div>
                        <div class="stat-label">Buckets</div>
                    </div>
                </div>
        """
        auth =findings .get ("auth",{})
        if auth .get ("leaked"):
            html +=f"""
            <div class="panel critical">
                <h3 style="color: var(--danger); margin-top: 0;">⚠️ CRITICAL: Auth Data Leak Detected</h3>
                <p>Found <strong>
                                 {auth .get ('count')}</strong> users exposed in public tables. Immediate action required.</p>
            </div>
            """
        html +="""
        <h2>Row Level Security (RLS)</h2>
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>Table</th>
                        <th>Read Access</th>
                        <th>Write Access</th>
                        <th>Risk Assessment</th>
                        <th>Compliance</th>
                    </tr>
                </thead>
                <tbody>
        """
        for r in findings .get ("rls",[]):
            risk_lower =r ['risk'].lower ()
            badge_class ="safe"
            if r ['risk']=='CRITICAL':badge_class ="critical"
            elif r ['risk']=='HIGH':badge_class ="high"
            elif r ['risk']=='MEDIUM':badge_class ="medium"
            elif r ['risk']=='ACCEPTED':badge_class ="accepted"
            risk_label =r ['risk']
            if r .get ('accepted_reason'):
                risk_label +=f" ({r ['accepted_reason']})"
            html +=f"""
            <tr>
                <td style="font-weight: 600; color: var(--text-main);">
                                                                       {r ['table']}</td>
                <td>
                    {'<span style="color: var(--success)">✔ Allowed</span>'if r ['read']else '<span style="color: var(--text-muted)">-</span>'}</td>
                <td>
                    {'<span style="color: var(--danger); font-weight: bold;">⚠ LEAK</span>'if r ['write']else '<span style="color: var(--text-muted)">-</span>'}</td>
                <td><span class="badge 
                                       {badge_class }">{risk_label }</span></td>
                <td>
                    <span class="badge" style="background: #334155; color: #cbd5e1;">
                                                                                     {VULN_TO_COMPLIANCE ['rls']['OWASP']}</span>
                    <span class="badge" style="background: #334155; color: #cbd5e1;">
                                                                                     {VULN_TO_COMPLIANCE ['rls']['SOC2']}</span>
                </td>
            </tr>
            """
        html +="</tbody></table></div>"
        if diff :
            html +='<h2>Comparison with Previous Scan</h2><div class="panel">'
            new_rls =diff .get ("rls",{}).get ("new",[])
            resolved_rls =diff .get ("rls",{}).get ("resolved",[])
            if new_rls :
                html +="<h3 style='color: var(--danger)'>New Issues</h3><ul>"
                for item in new_rls :
                    html +=f"<li>New RLS finding in table: <strong>{item ['table']}</strong> ({item ['risk']})</li>"
                html +="</ul>"
            elif resolved_rls :
                html +="<h3 style='color: var(--success)'>Resolved Issues</h3><ul>"
                for item in resolved_rls :
                    html +=f"<li>Resolved RLS finding in table: <strong>{item ['table']}</strong></li>"
                html +="</ul>"
            else :
                html +="<p style='color: var(--text-muted)'>No changes detected.</p>"
            html +="</div>"
        ai_analysis =report .get ("ai_analysis",{})
        if ai_analysis and "error"not in ai_analysis :
            html +=f"""
            <div class="ai-section" style="background: #ffffff; border: 1px solid #e2e8f0; color: #0f172a;">
                <div class="ai-header" style="border-bottom: 1px solid #e2e8f0;">
                    <span style="font-size: 2rem;">🤖</span>
                    <h3 class="ai-title" style="color: #4c1d95;">AI Security Assessment</h3>
                </div>
                <div class="ai-content" style="color: #334155;">
                    <p><strong>Risk Level:</strong> <span class="badge 
                                                                       {ai_analysis .get ('risk_level','LOW').lower ()}">{ai_analysis .get ('risk_level','Unknown')}</span></p>
                    <p>
                       {ai_analysis .get ('summary','').replace (chr (10 ),'<br>')}</p>
                </div>
            """
            fixes =ai_analysis .get ("fixes",{})
            if fixes :
                html +="<div style='margin-top: 30px;'><h4 style='color: #4c1d95; margin-bottom: 15px;'>🛡️ Recommended Remediation</h4>"
                for category ,fix in fixes .items ():
                    html +=f"""
                    <div class="remediation-box" style="background: #f8fafc; border-left: 4px solid #8b5cf6;">
                        <span class="remediation-title" style="color: #6d28d9;">
                                                                                {category .upper ()}</span>
                        <pre style="background: #f1f5f9; color: #0f172a; border: 1px solid #e2e8f0;">
                                                                                                     {fix }</pre>
                    </div>
                    """
                html +="</div>"
            html +="</div>"
        html +="""
            </div>
        </body>
        </html>
        """
        return html 
class FixGenerator :
    def generate (self ,report :Dict [str ,Any ])->str :
        ai_analysis =report .get ("ai_analysis",{})
        fixes =ai_analysis .get ("fixes",{})
        if not fixes :
            return "-- No automated fixes generated by AI."
        timestamp =datetime .now ().isoformat ()
        sql_content =f"""/*
Supabase Security Fix Script
Generated by SSF on 
                    {timestamp }
WARNING: Review all commands before executing!
This script is wrapped in a transaction to ensure atomicity.
*/
BEGIN;
"""
        order =["auth","rls","rpc","realtime"]
        for category in order :
            if category in fixes :
                sql_content +=f"\\n/* --- {category .upper ()} FIXES --- */\\n"
                sql_content +=fixes [category ]+"\\n"
        for category ,sql in fixes .items ():
            if category not in order :
                sql_content +=f"\\n/* --- {category .upper ()} FIXES --- */\\n"
                sql_content +=sql +"\\n"
        sql_content +="\\nCOMMIT;\\n"
        return sql_content 

class SARIFReporter:
    def generate(self, report: Dict[str, Any]) -> str:
        findings = report.get("findings", {})
        
        runs = []
        results = []

        def get_severity_details(risk: str):
            risk = risk.upper()
            if risk == "CRITICAL":
                return "error", "9.8", "CRITICAL"
            elif risk == "HIGH":
                return "error", "8.5", "HIGH"
            elif risk == "MEDIUM":
                return "warning", "5.5", "MEDIUM"
            elif risk == "LOW":
                return "warning", "2.5", "LOW"
            elif risk == "INFO":
                return "note", "0.5", "INFO"
            return "note", "0.0", "LOW" 

      
        for r in findings.get("rls", []):
            risk = r.get("risk", "LOW")
            sarif_level, score, suffix = get_severity_details(risk)
            
            results.append({
                "ruleId": f"SSF-RLS-{suffix}",
                "level": sarif_level,
                "message": {
                    "text": f"RLS Issue on table {r['table']}: {r['risk']}"
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f"database/tables/{r['table']}"
                        },
                        "region": {
                            "startLine": 1,
                            "startColumn": 1
                        }
                    }
                }]
            })

        auth = findings.get("auth", {})
        if auth.get("leaked"):

             results.append({
                 "ruleId": "SSF-AUTH-CRITICAL",
                 "level": "error",
                 "message": {
                     "text": f"Auth Leak Detected: {auth.get('count')} users exposed"
                 },
                 "locations": [{
                     "physicalLocation": {
                         "artifactLocation": {
                             "uri": "auth/users"
                         },
                         "region": {
                            "startLine": 1,
                             "startColumn": 1
                         }
                     }
                 }]
             })


        for r in findings.get("rpc", []):
             risk = r.get("risk", "LOW")
             if risk in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                sarif_level, score, suffix = get_severity_details(risk)
                results.append({
                    "ruleId": f"SSF-RPC-{suffix}",
                    "level": sarif_level,
                    "message": {
                        "text": f"Vulnerable RPC: {r['name']}"
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f"database/functions/{r['name']}"
                            },
                            "region": {
                                "startLine": 1,
                                "startColumn": 1
                            }
                        }
                    }]
                })


        rules = []
        
        for risk, score in [("CRITICAL", "9.8"), ("HIGH", "8.5"), ("MEDIUM", "5.5"), ("LOW", "2.5"), ("INFO", "0.5")]:
            rules.append({
                "id": f"SSF-RLS-{risk}",
                "name": f"Row Level Security Misconfiguration ({risk})",
                "shortDescription": {
                    "text": f"RLS policies allow unauthorized access ({risk} severity)."
                },
                "helpUri": "https://github.com/backend-developers/supabase-audit-framework",
                "properties": {
                    "security-severity": score
                }
            })


        rules.append({
            "id": "SSF-AUTH-CRITICAL",
            "name": "Authentication Leak (CRITICAL)",
            "shortDescription": {
                "text": "User data is exposed to public."
            },
            "helpUri": "https://github.com/backend-developers/supabase-audit-framework",
            "properties": {
                "security-severity": "9.8"
            }
        })

     
        for risk, score in [("CRITICAL", "9.8"), ("HIGH", "8.5"), ("MEDIUM", "5.5"), ("LOW", "2.5"), ("INFO", "0.5")]:
            rules.append({
                "id": f"SSF-RPC-{risk}",
                "name": f"Vulnerable RPC ({risk})",
                "shortDescription": {
                    "text": f"RPC function has security vulnerabilities ({risk} severity)."
                },
                "helpUri": "https://github.com/backend-developers/supabase-audit-framework",
                "properties": {
                    "security-severity": score
                }
            })

        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Supabase Security Framework (SSF)",
                        "version": "1.2.2",
                        "informationUri": "https://github.com/backend-developers/supabase-audit-framework",
                        "rules": rules
                    }
                },
                "results": results
            }]
        }

        return json.dumps(sarif, indent=2)
