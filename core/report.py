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
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f4f9; color: #333; margin: 0; padding: 20px; }
        .container { max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 2px solid #eee; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        .meta { color: #7f8c8d; font-size: 0.9em; margin-bottom: 20px; }
        .panel { border: 1px solid #ddd; border-radius: 4px; padding: 15px; margin-bottom: 15px; }
        .panel.critical { border-left: 5px solid #e74c3c; background: #fdf0ed; }
        .panel.high { border-left: 5px solid #e67e22; background: #fdf6ed; }
        .panel.medium { border-left: 5px solid #f1c40f; background: #fcf8e3; }
        .panel.safe { border-left: 5px solid #2ecc71; background: #f0f9f4; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; }
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; color: white; }
        .bg-red { background-color: #e74c3c; }
        .bg-orange { background-color: #e67e22; }
        .bg-yellow { background-color: #f1c40f; color: #333; }
        .bg-green { background-color: #2ecc71; }
        .bg-blue { background-color: #3498db; }
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
