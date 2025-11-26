import json
from datetime import datetime
from typing import Dict, Any

class HTMLReporter:
    def generate(self, report: Dict[str, Any], diff: Dict[str, Any] = None) -> str:
        """
        Generates a standalone HTML report.
        """
        findings = report.get("findings", {})
        target = report.get("target", "Unknown")
        timestamp = report.get("timestamp", datetime.now().isoformat())
        
        css = """
        :root {
            --bg-primary: #1a1a2e;
            --bg-secondary: #16213e;
            --text-primary: #e94560;
            --text-secondary: #a2a8d3;
            --accent: #0f3460;
            --success: #2ecc71;
            --warning: #f1c40f;
            --danger: #e74c3c;
        }
        body { font-family: 'Inter', 'Segoe UI', sans-serif; background-color: var(--bg-primary); color: #fff; margin: 0; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; background: var(--bg-secondary); padding: 40px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.3); }
        h1 { color: var(--text-primary); border-bottom: 2px solid var(--accent); padding-bottom: 15px; margin-bottom: 30px; }
        h2 { color: var(--text-secondary); margin-top: 40px; border-left: 4px solid var(--text-primary); padding-left: 10px; }
        .meta { color: #888; font-size: 0.9em; margin-bottom: 30px; background: var(--accent); padding: 15px; border-radius: 6px; }
        .panel { border: 1px solid var(--accent); border-radius: 8px; padding: 20px; margin-bottom: 20px; background: rgba(255,255,255,0.02); }
        .panel.critical { border-left: 5px solid var(--danger); background: rgba(231, 76, 60, 0.1); }
        .panel.high { border-left: 5px solid #e67e22; background: rgba(230, 126, 34, 0.1); }
        .panel.medium { border-left: 5px solid var(--warning); background: rgba(241, 196, 15, 0.1); }
        .panel.safe { border-left: 5px solid var(--success); background: rgba(46, 204, 113, 0.1); }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; background: rgba(0,0,0,0.2); border-radius: 8px; overflow: hidden; }
        th, td { padding: 15px; text-align: left; border-bottom: 1px solid var(--accent); }
        th { background-color: var(--accent); color: var(--text-secondary); font-weight: 600; }
        tr:hover { background-color: rgba(255,255,255,0.05); }
        .badge { padding: 5px 10px; border-radius: 4px; font-size: 0.85em; font-weight: bold; color: white; text-transform: uppercase; }
        .bg-red { background-color: var(--danger); }
        .bg-orange { background-color: #e67e22; }
        .bg-yellow { background-color: var(--warning); color: #333; }
        .bg-green { background-color: var(--success); }
        .bg-blue { background-color: #3498db; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: var(--accent); padding: 20px; border-radius: 8px; text-align: center; }
        .stat-value { font-size: 2.5em; font-weight: bold; color: var(--text-primary); }
        .stat-label { color: var(--text-secondary); font-size: 0.9em; text-transform: uppercase; letter-spacing: 1px; }
        """
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Supabase Audit Report - {target}</title>
            <style>{css}</style>
        </head>
        <body>
            <div class="container">
                <h1>Supabase Security Audit</h1>
                <div class="meta">
                    <strong>Target:</strong> {target} | 
                    <strong>Scan Time:</strong> {timestamp}
                </div>
                
                <div class="summary-grid">
                    <div class="stat-card">
                        <div class="stat-value">{len([r for r in findings.get('rls', []) if r['risk'] == 'CRITICAL'])}</div>
                        <div class="stat-label">Critical RLS</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{len([r for r in findings.get('rpc', []) if r.get('risk') == 'CRITICAL'])}</div>
                        <div class="stat-label">Vuln RPCs</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{'YES' if findings.get('auth', {}).get('leaked') else 'NO'}</div>
                        <div class="stat-label">Auth Leak</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{len(findings.get('storage', []))}</div>
                        <div class="stat-label">Buckets</div>
                    </div>
                </div>
        """
        
        auth = findings.get("auth", {})
        if auth.get("leaked"):
            html += f"""
            <div class="panel critical">
                <h3>CRITICAL: Auth Data Leak Detected</h3>
                <p>Found {auth.get('count')} users exposed in public tables.</p>
            </div>
            """
        
        html += "<h2>Row Level Security (RLS)</h2><table><thead><tr><th>Table</th><th>Read</th><th>Write</th><th>Risk</th></tr></thead><tbody>"
        for r in findings.get("rls", []):
            risk_class = "bg-green"
            if r['risk'] == 'CRITICAL': risk_class = "bg-red"
            elif r['risk'] == 'HIGH': risk_class = "bg-orange"
            elif r['risk'] == 'MEDIUM': risk_class = "bg-yellow"
            elif r['risk'] == 'ACCEPTED': risk_class = "bg-blue"
            
            risk_label = r['risk']
            if r.get('accepted_reason'):
                risk_label += f" ({r['accepted_reason']})"

            html += f"""
            <tr>
                <td>{r['table']}</td>
                <td>{'✔' if r['read'] else '-'}</td>
                <td>{'⚠ LEAK' if r['write'] else '-'}</td>
                <td><span class="badge {risk_class}">{risk_label}</span></td>
            </tr>
            """
        html += "</tbody></table>"
        
        if diff:
            html += "<h2>Comparison with Previous Scan</h2>"
            new_rls = diff.get("rls", {}).get("new", [])
            resolved_rls = diff.get("rls", {}).get("resolved", [])
            
            if new_rls:
                html += "<h3>New Issues</h3><ul>"
                for item in new_rls:
                    html += f"<li>New RLS finding in table: <strong>{item['table']}</strong> ({item['risk']})</li>"
                html += "</ul>"
                
            if resolved_rls:
                html += "<h3>Resolved Issues</h3><ul>"
                for item in resolved_rls:
                    html += f"<li>Resolved RLS finding in table: <strong>{item['table']}</strong></li>"
                html += "</ul>"

        ai_analysis = report.get("ai_analysis", {})
        if ai_analysis and "error" not in ai_analysis:
            html += f"""
            <div class="panel medium" style="border-color: #8e44ad; background-color: #f4ecf7;">
                <h3 style="color: #8e44ad;">🤖 AI Security Assessment</h3>
                <p><strong>Risk Level:</strong> {ai_analysis.get('risk_level', 'Unknown')}</p>
                <p>{ai_analysis.get('summary', '').replace(chr(10), '<br>')}</p>
            """
            
            fixes = ai_analysis.get("fixes", {})
            if fixes:
                html += "<h4>🛡️ Recommended Remediation</h4>"
                for category, fix in fixes.items():
                    html += f"""
                    <div style="background: #fff; padding: 10px; border-left: 3px solid #8e44ad; margin-top: 10px;">
                        <strong>{category.upper()}:</strong>
                        <pre style="background: #eee; padding: 10px; overflow-x: auto;">{fix}</pre>
                    </div>
                    """
            
            html += "</div>"

        html += """
            </div>
        </body>
        </html>
        """
        return html
        return html

class FixGenerator:
    def generate(self, report: Dict[str, Any]) -> str:
        """
        Extracts remediation SQL from the AI analysis and generates a consolidated SQL script.
        """
        ai_analysis = report.get("ai_analysis", {})
        fixes = ai_analysis.get("fixes", {})
        
        if not fixes:
            return "-- No automated fixes generated by AI."
            
        timestamp = datetime.now().isoformat()
        sql_content = f"""/*
Supabase Security Fix Script
Generated by SSF on {timestamp}
WARNING: Review all commands before executing!
This script is wrapped in a transaction to ensure atomicity.
*/

BEGIN;

"""
    
        order = ["auth", "rls", "rpc", "realtime"]
        
        for category in order:
            if category in fixes:
                sql_content += f"\n/* --- {category.upper()} FIXES --- */\n"
                sql_content += fixes[category] + "\n"
    
        for category, sql in fixes.items():
            if category not in order:
                sql_content += f"\n/* --- {category.upper()} FIXES --- */\n"
                sql_content += sql + "\n"
        
        sql_content += "\nCOMMIT;\n"
        
        return sql_content
