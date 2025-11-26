#!/usr/bin/env python3

import asyncio
import argparse
import json
import time
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.markdown import Markdown
from core.config import TargetConfig
from core.session import SessionManager
from core.ai import AIAgent
from core.knowledge import KnowledgeBase
from scanners.openapi import OpenAPIScanner
from scanners.rls import RLSScanner
from scanners.auth import AuthScanner
from scanners.storage import StorageScanner
from scanners.rpc import RPCScanner 
from scanners.brute import BruteScanner
from scanners.graphql import GraphQLScanner
from scanners.functions import EdgeFunctionScanner
from scanners.realtime import RealtimeScanner
from core.diff import DiffEngine
from core.report import HTMLReporter, FixGenerator
from core.banner import show_banner
from core.exploit import run_exploit

console = Console()

async def main():
    show_banner(console)
    
    import sys
    if "--compile" in sys.argv:
        from core.compiler import Compiler
        compiler = Compiler()
        compiler.compile()
        return

    parser = argparse.ArgumentParser(description="Supabase Audit Framework v1.0")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("key", help="Anon Key")
    parser.add_argument("--agent", help="Gemini API Key", default=None)
    parser.add_argument("--brute", action="store_true", help="Enable Bruteforce")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    parser.add_argument("--json", action="store_true", help="Save report to JSON file")
    parser.add_argument("--diff", help="Path to previous JSON report for comparison")
    parser.add_argument("--html", action="store_true", help="Generate HTML report")
    parser.add_argument("--knowledge", help="Path to knowledge base JSON file")
    parser.add_argument("--ci", action="store_true", help="Exit with non-zero code on critical issues (for CI/CD)")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)", default=None)
    parser.add_argument("--exploit", action="store_true", help="Automatically run generated exploits")
    parser.add_argument("--gen-fixes", action="store_true", help="Generate SQL fix script from AI analysis")
    parser.add_argument("--analyze", help="Path to file or directory for Static Code Analysis")
    parser.add_argument("--edge_rpc", help="Path to custom Edge Function wordlist file")
    parser.add_argument("--compile", action="store_true", help="Compile to standalone executable")
    args = parser.parse_args()

    if args.compile:
        # Already handled above, but kept for argparse help message consistency
        return

    config = TargetConfig(url=args.url, key=args.key, gemini_key=args.agent, verbose=args.verbose, proxy=args.proxy)


    if args.analyze:
        if not config.has_ai:
            console.print("[bold red][!] --analyze requires --agent (AI) to be enabled.[/]")
            return

        from core.utils import get_code_files
        console.print(f"[cyan][*] Reading code files from: {args.analyze}[/]")
        code_files = get_code_files(args.analyze)
        
        if not code_files:
            console.print("[yellow][!] No supported code files found.[/]")
            return
            
        console.print(f"[green][+] Found {len(code_files)} files to analyze.[/]")
        
        agent = AIAgent(config.gemini_key)
        

        ai_text = Markdown("")
        panel = Panel(ai_text, title="🤖 AI Analyzing Code...", border_style="magenta")
        
        full_ai_response = ""
        def update_ai_output_markdown(chunk):
            nonlocal full_ai_response
            full_ai_response += chunk
            panel.renderable = Markdown(full_ai_response)
            
        from rich.live import Live
        with Live(panel, refresh_per_second=8, console=console, auto_refresh=True):
             report = await agent.analyze_code(code_files, stream_callback=update_ai_output_markdown)
        
        if "error" not in report:
            console.print(Panel(Markdown(f"### Code Risk: {report.get('risk_level')}\n\n{report.get('summary')}"), title="🤖 Static Analysis Results", border_style="magenta"))

            import os
            timestamp = int(time.time())
            output_dir = f"audit_report_{timestamp}"
            os.makedirs(output_dir, exist_ok=True)
            
            filename = os.path.join(output_dir, f"code_analysis_{timestamp}.json")
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            console.print(f"\n[bold green]✔ Code Analysis Report saved: {filename}[/]")
            
        return 

    full_report = {"target": config.url, "timestamp": datetime.now().isoformat(), "findings": {}}

    
    kb = KnowledgeBase()
    if args.knowledge:
        if kb.load(args.knowledge):
            console.print(f"[green][*] Knowledge Base loaded from {args.knowledge}[/]")
        else:
            console.print(f"[red][!] Failed to load Knowledge Base from {args.knowledge}[/]")

    console.print(Panel.fit("[bold white]Supabase Audit Framework v1.0[/]\n[cyan]RLS • Auth • Storage • RPC • Realtime • AI[/]", border_style="blue"))


    shared_context = {}

    async with SessionManager(config) as client:

        with Progress(SpinnerColumn(), TextColumn("[cyan]Discovery Phase..."), console=console) as p:
            t1 = p.add_task("Spec", total=1)
            openapi = OpenAPIScanner(client, verbose=config.verbose, context=shared_context)
            spec = await openapi.scan()
            tables = openapi.parse_tables(spec)
            rpc_scanner = RPCScanner(client, verbose=config.verbose, context=shared_context)
            rpcs = rpc_scanner.extract_rpcs(spec)
            p.update(t1, completed=1)

        console.print(f"[+] Found {len(tables)} tables, {len(rpcs)} RPCs.")


        console.print("[yellow][*] Running Async Scanners...[/]")
        
        auth_scanner = AuthScanner(client, verbose=config.verbose, context=shared_context)
        rls_scanner = RLSScanner(client, verbose=config.verbose, context=shared_context)
        storage_scanner = StorageScanner(client, verbose=config.verbose, context=shared_context)
        brute_scanner = BruteScanner(client, verbose=config.verbose, context=shared_context)
        graphql_scanner = GraphQLScanner(client, verbose=config.verbose, context=shared_context)

        custom_functions = []
        import os
        
        edge_list_file = args.edge_rpc if args.edge_rpc else "edge_name.txt"
        
        should_load = args.edge_rpc or os.path.exists("edge_name.txt")
        
        if should_load and os.path.exists(edge_list_file):
            console.print(f"[cyan][*] Loading custom edge function list from {edge_list_file}...[/]")
            try:
                with open(edge_list_file, "r") as f:
                    custom_functions = [line.strip() for line in f if line.strip()]
                console.print(f"    [+] Loaded {len(custom_functions)} custom function names.", style="green")
            except Exception as e:
                console.print(f"    [red][!] Failed to load {edge_list_file}: {e}[/]")
        elif args.edge_rpc:
             console.print(f"[red][!] Custom wordlist file not found: {edge_list_file}[/]")

        function_scanner = EdgeFunctionScanner(client, verbose=config.verbose, context=shared_context, custom_list=custom_functions)
        realtime_scanner = RealtimeScanner(client, verbose=config.verbose, context=shared_context)

        MAX_CONCURRENT_REQUESTS = 20
        sem = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

        async def bounded_scan(coroutine):
            async with sem:
                return await coroutine

        res_auth = await auth_scanner.scan()
        

        rls_tasks = [
            bounded_scan(rls_scanner.scan(name, info)) 
            for name, info in tables.items()
        ]
        
        rpc_tasks = [
            bounded_scan(rpc_scanner.scan(r))
            for r in rpcs
        ]

        tasks = [
            asyncio.gather(*rls_tasks),
            storage_scanner.scan(),
            asyncio.gather(*rpc_tasks),
            brute_scanner.scan() if args.brute else asyncio.sleep(0),
            graphql_scanner.scan(),
            function_scanner.scan(),
            realtime_scanner.scan()
        ]

        results = await asyncio.gather(*tasks)
        res_rls, res_storage, res_rpc, res_brute, res_graphql, res_functions, res_realtime = (
            results[0], results[1], results[2], 
            results[3] if args.brute else [], results[4], results[5], results[6]
        )
        

        accepted_risks = []

        for r in res_rls:
            reason = kb.is_accepted(r, "rls")
            if reason:
                r["risk"] = "ACCEPTED"
                r["accepted_reason"] = reason
                accepted_risks.append(f"RLS: {r['table']} ({reason})")


        for r in res_rpc:
            reason = kb.is_accepted(r, "rpc")
            if reason:
                r["executable"] = False 
                r["risk"] = "ACCEPTED"
                r["accepted_reason"] = reason
                accepted_risks.append(f"RPC: {r['name']} ({reason})")

        full_report["findings"] = {
            "rls": res_rls, "auth": res_auth, "storage": res_storage, 
            "rpc": res_rpc, "brute": res_brute,
            "graphql": res_graphql, "functions": res_functions,
            "realtime": res_realtime
        }
        full_report["accepted_risks"] = accepted_risks

        console.print("\n")
        console.rule("[bold cyan]Scan Complete - Final Report[/]")
        console.print("\n")


        auth_status = "[bold red]LEAK DETECTED[/]" if res_auth["leaked"] else "[bold green]SECURE[/]"
        auth_details = f"Users Exposed: {res_auth['count']}" if res_auth["leaked"] else "No users found in public tables."
        console.print(Panel(f"Status: {auth_status}\n{auth_details}", title="[bold]Authentication[/]", border_style="red" if res_auth["leaked"] else "green"))


        crit_rls = len([r for r in res_rls if r["risk"] == "CRITICAL"])
        high_rls = len([r for r in res_rls if r["risk"] == "HIGH"])
        vuln_rpcs = len([r for r in res_rpc if r.get("sqli_suspected") or r.get("risk") == "CRITICAL"])
        open_chans = len(res_realtime["channels"])
        
        scorecard = f"""
        [bold red]CRITICAL RLS:[/bold red] {crit_rls}   [bold yellow]HIGH RLS:[/bold yellow] {high_rls}
        [bold red]VULN RPCs:[/bold red]    {vuln_rpcs}   [bold red]AUTH LEAK:[/bold red] {res_auth['leaked']}
        [bold yellow]OPEN CHANNELS:[/bold yellow] {open_chans}
        """
        console.print(Panel(scorecard, title="[bold]Risk Scorecard[/]", border_style="red" if crit_rls > 0 or vuln_rpcs > 0 else "green"))

        t_rls = Table(title="Row Level Security (RLS)", expand=True)
        t_rls.add_column("Table", style="cyan")
        t_rls.add_column("Read", justify="center")
        t_rls.add_column("Write", justify="center")
        t_rls.add_column("Risk", justify="center")

        res_rls.sort(key=lambda x: (x["risk"] == "ACCEPTED", x["risk"] == "SAFE", x["risk"] == "MEDIUM", x["risk"] == "HIGH", x["risk"] == "CRITICAL"))

        for r in res_rls:
            if config.verbose or r["risk"] != "SAFE":
                color = "red" if r["risk"] == "CRITICAL" else "yellow" if r["risk"] == "HIGH" else "green"
                if r["risk"] == "ACCEPTED": color = "blue"
                
                read_mark = "[green]YES[/]" if r["read"] else "[dim]-[/]"
                write_mark = "[red]LEAK[/]" if r["write"] else "[dim]-[/]"
                
                risk_label = r['risk']
                if r.get('accepted_reason'):
                    risk_label += f" ({r['accepted_reason']})"
                
                t_rls.add_row(r["table"], read_mark, write_mark, f"[{color}]{risk_label}[/]")
        
        console.print(t_rls)

        from rich.tree import Tree
        api_tree = Tree("[bold]API Surface[/]")
        
        rpc_branch = api_tree.add("Remote Procedure Calls (RPC)")
        executable_rpcs = [r for r in res_rpc if r.get("executable")]
        if executable_rpcs:
            for r in executable_rpcs:
                risk = "ACCEPTED" if r.get("risk") == "ACCEPTED" else "EXECUTABLE"
                style = "blue" if risk == "ACCEPTED" else "red"
                rpc_branch.add(f"[{style}]{r['name']} ({risk})[/{style}]")
        else:
            rpc_branch.add("[green]No executable public RPCs found[/]")

        gql_branch = api_tree.add("GraphQL")
        if res_graphql["enabled"]:
            gql_branch.add(f"[yellow]Introspection Enabled: {res_graphql['details']}[/]")
        else:
            gql_branch.add("[green]Introspection Disabled[/]")


        func_branch = api_tree.add("Edge Functions")
        if res_functions:
            for f in res_functions:
                func_branch.add(f"[red]{f['name']} (Found)[/]")
        else:
            func_branch.add("[green]No common Edge Functions found[/]")

        console.print(Panel(api_tree, title="[bold]API & Functions[/]", border_style="cyan"))

        infra_tree = Tree("[bold]Infrastructure[/]")
        

        rt_branch = infra_tree.add("Realtime")
        if res_realtime["channels"]:
            for c in res_realtime["channels"]:
                rt_branch.add(f"[red]Open Channel: {c}[/]")
        else:
            rt_branch.add("[green]No open channels detected[/]")

        store_branch = infra_tree.add("Storage")
        if isinstance(res_storage, list):
             for s in res_storage:
                 if s.get("public"):
                     store_branch.add(f"[yellow]Public Bucket: {s['name']}[/]")
        
        console.print(Panel(infra_tree, title="[bold]Realtime & Storage[/]", border_style="magenta"))

        if config.has_ai:
            from rich.live import Live
            from rich.text import Text
            
            agent = AIAgent(config.gemini_key)

            ai_input = full_report["findings"]
            ai_input["target"] = config.url
            ai_input["accepted_risks"] = accepted_risks
            

            ai_text = Markdown("")

            panel = Panel(ai_text, title="🤖 AI Agent Thinking...", border_style="magenta")
            
            def update_ai_output(chunk):
              
                nonlocal ai_text
               
                pass 
            full_ai_response = ""
            def update_ai_output_markdown(chunk):
                nonlocal full_ai_response
                full_ai_response += chunk
                panel.renderable = Markdown(full_ai_response)
            
            console.print(Panel("[magenta]Connecting to AI Agent...[/]", border_style="magenta"))
            
            with Live(panel, refresh_per_second=8, console=console, auto_refresh=True):
                 report = await agent.analyze_results(ai_input, stream_callback=update_ai_output_markdown)
            
            if "error" not in report:
                console.print(Panel(Markdown(f"### AI Risk: {report.get('risk_level')}\n\n{report.get('summary')}"), title="🤖 AI Security Assessment", border_style="magenta"))
                full_report["ai_analysis"] = report

        if args.exploit:
            console.print("\n[bold yellow][*] Running Exploit Module...[/]")
            await run_exploit(auto_confirm=True)


        diff_results = None
        if args.diff:
            try:
                with open(args.diff, "r", encoding="utf-8") as f:
                    prev_report = json.load(f)
                
                if not isinstance(prev_report, dict):
                    console.print("[red]Error: Diff file must contain a JSON object (dictionary), not a list or other type.[/]")
                    diff_results = None
                else:
                    diff_engine = DiffEngine()
                    diff_results = diff_engine.compare(full_report, prev_report)
                
                console.print("\n")
                console.rule("[bold cyan]Comparison Results[/]")
                if diff_results["rls"]["new"]:
                    console.print(f"[red]  + {len(diff_results['rls']['new'])} New RLS Issues[/]")
                if diff_results["rls"]["resolved"]:
                    console.print(f"[green]  - {len(diff_results['rls']['resolved'])} Resolved RLS Issues[/]")
                if not diff_results["rls"]["new"] and not diff_results["rls"]["resolved"]:
                    console.print("[dim]  No changes in RLS findings.[/]")
            except Exception as e:
                console.print(f"[red]Error loading diff file: {e}[/]")

        import os
        timestamp = int(time.time())
        output_dir = f"audit_report_{timestamp}"
        os.makedirs(output_dir, exist_ok=True)

        if args.json:
            filename = os.path.join(output_dir, f"audit_report_{timestamp}.json")
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(full_report, f, indent=2)
            
            console.print(f"\n[bold green]✔ JSON Report saved: {filename}[/]")

        if args.html:
            html_reporter = HTMLReporter()
            html_content = html_reporter.generate(full_report, diff_results)
            html_filename = os.path.join(output_dir, f"audit_report_{timestamp}.html")
            with open(html_filename, "w", encoding="utf-8") as f:
                f.write(html_content)
            console.print(f"[bold green]✔ HTML Report saved: {html_filename}[/]")

        if args.gen_fixes and config.has_ai and "ai_analysis" in full_report:
            fix_gen = FixGenerator()
            sql_fixes = fix_gen.generate(full_report)
            fix_filename = os.path.join(output_dir, f"fixes_{timestamp}.sql")
            with open(fix_filename, "w", encoding="utf-8") as f:
                f.write(sql_fixes)
            console.print(f"\n[bold green]✔ SQL Fix Script saved: {fix_filename}[/]")
        elif args.gen_fixes and not config.has_ai:
            console.print("\n[bold yellow][!] --gen-fixes requires --agent (AI) to be enabled.[/]")

        if args.ci:
            failure_reasons = []
            
            critical_issues = [r for r in res_rls if r.get('risk') in ['CRITICAL', 'HIGH'] and r.get('risk') != 'ACCEPTED']
            if critical_issues:
                failure_reasons.append(f"{len(critical_issues)} Critical/High RLS issues found")

            if res_auth["leaked"]:
                failure_reasons.append("Auth Leak Detected")

            if diff_results and diff_results['rls']['new']:
                failure_reasons.append(f"{len(diff_results['rls']['new'])} New RLS Regressions")

            if failure_reasons:
                console.print(f"\n[bold red]❌ CI Failure: {', '.join(failure_reasons)}[/]")
                import sys
                sys.exit(1)
            else:
                console.print("\n[bold green]✔ CI Passed: No critical issues or regressions found.[/]")

if __name__ == "__main__":
    try: asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[bold red][-] Interrupted by user[/]")

