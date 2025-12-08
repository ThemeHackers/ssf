
import asyncio
import os
import argparse
import json
import time
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.markdown import Markdown
from ssf.core.config import TargetConfig
from ssf.core.session import SessionManager
from ssf.core.ai import AIAgent
from ssf.core.knowledge import KnowledgeBase
from ssf.scanners.openapi import OpenAPIScanner
from ssf.scanners.rls import RLSScanner
from ssf.scanners.auth import AuthScanner
from ssf.scanners.storage import StorageScanner
from ssf.scanners.rpc import RPCScanner 
from ssf.scanners.brute import BruteScanner
from ssf.scanners.graphql import GraphQLScanner
from ssf.scanners.functions import EdgeFunctionScanner
from ssf.scanners.realtime import RealtimeScanner
from ssf.scanners.extensions import ExtensionsScanner
from ssf.scanners.postgres import DatabaseConfigurationScanner
from ssf.core.diff import DiffEngine
from ssf.core.report import HTMLReporter, FixGenerator
from ssf.core.banner import show_banner
from ssf.core.exploit import run_exploit
console = Console()
async def main():
    show_banner(console)
    import sys
    import os
    if "--compile" in sys.argv:
        from ssf.core.compiler import Compiler
        compiler = Compiler()
        compiler.compile()
        return
    if "--wizard" in sys.argv:
        from ssf.core.wizard import run_wizard
        run_wizard()
        return

    parser = argparse.ArgumentParser(description="Supabase Audit Framework v1.2.14")
    parser.add_argument("url", nargs="?", help="Target URL")
    parser.add_argument("key", nargs="?", help="Anon Key")
    parser.add_argument("--agent-provider", help="AI Provider (gemini, openai, anthropic, deepseek, ollama)", default="gemini", choices=["gemini", "openai", "anthropic", "deepseek", "ollama"])
    parser.add_argument("--agent", help="AI Model Name or Key (depends on provider)", default=None)
    parser.add_argument("--agent-key", help="AI API Key", default=None)
    parser.add_argument("--brute", nargs="?", const="default", help="Enable Bruteforce (optional: path to wordlist)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    parser.add_argument("--json", action="store_true", help="Save report to JSON file")
    parser.add_argument("--diff", help="Path to previous JSON report for comparison")
    parser.add_argument("--html", action="store_true", help="Generate HTML report")
    parser.add_argument("--knowledge", help="Path to knowledge base JSON file")
    parser.add_argument("--ci", action="store_true", help="Exit with non-zero code on critical issues (for CI/CD)")
    parser.add_argument("--fail-on", help="Risk level to fail on (default: HIGH)", default="HIGH", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    parser.add_argument("--ci-format", help="CI Output format", default="text", choices=["text", "github"])
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)", default=None)
    parser.add_argument("--exploit", action="store_true", help="Automatically run generated exploits")
    parser.add_argument("--gen-fixes", action="store_true", help="Generate SQL fix script from AI analysis")
    parser.add_argument("--analyze", help="Path to file or directory for Static Code Analysis")
    parser.add_argument("--edge_rpc", help="Path to custom Edge Function wordlist file")
    parser.add_argument("--roles", help="Path to JSON file with role tokens (e.g., {'user1': 'eyJ...'})")
    parser.add_argument("--threat-model", action="store_true", help="Generate Automated Threat Model (requires --agent)")
    parser.add_argument("--verify-fix", action="store_true", help="Verify remediation of accepted risks and update Knowledge Base")
    parser.add_argument("--compile", action="store_true", help="Compile to standalone executable")
    parser.add_argument("--dump-all", action="store_true", help="Dump all rows found in RLS scan (default: limit 5)")
    parser.add_argument("--sniff", nargs="?", const=10, type=int, help="Enable Realtime Sniffer for N seconds (default: 10)")
    parser.add_argument("--check-config", action="store_true", help="Check PostgREST configuration (max_rows)")
    parser.add_argument("--webui", action="store_true", help="Launch Web Management Dashboard")
    parser.add_argument("--port", type=int, default=8080, help="Port for Web UI (default: 8080)")
    parser.add_argument("--ngrok", action="store_true", help="Expose Web UI via ngrok")
    parser.add_argument("--auth", help="Username:Password for Web UI (e.g., admin:secret)")

    parser.add_argument("--stealth", action="store_true", help="Enable Stealth Mode (JA3 Spoofing)")
    parser.add_argument("--sarif", action="store_true", help="Generate SARIF report")

    parser.add_argument("--wizard", action="store_true", help="Run in wizard mode for beginners")
    parser.add_argument("--random-agent", action="store_true", help="Use a random User-Agent header")
    parser.add_argument("--level", type=int, default=1, help="Level of tests to perform (1-5, default 1)")
    parser.add_argument("--tamper", help="Tamper script name (built-in) or path to file")
    parser.add_argument("--plugins", help="Select plugins to run (comma-separated names or 'all')")
    args = parser.parse_args()
    if args.webui:
        from ssf.app.server import run_server
        await run_server(port=args.port, use_ngrok=args.ngrok, auth_credentials=args.auth)
        return
    if args.compile:
        return
    if not args.url or not args.key:
        if not args.webui and not args.analyze:
            parser.error("the following arguments are required: url, key (unless --webui or --analyze is used)")
    
    ai_key = args.agent_key
    

    if not ai_key:
        if args.agent_provider == "gemini":
            ai_key = os.getenv("GEMINI_API_KEY")
        elif args.agent_provider == "openai":
            ai_key = os.getenv("OPENAI_API_KEY")
        elif args.agent_provider == "anthropic":
            ai_key = os.getenv("ANTHROPIC_API_KEY")
        elif args.agent_provider == "deepseek":
            ai_key = os.getenv("DEEPSEEK_API_KEY")
            
    ai_model = args.agent if args.agent else "gemini-3-pro-preview"
    
    if args.agent and ":" in args.agent and not args.agent_key:
        parts = args.agent.split(":", 1)
        ai_model = parts[0]
        ai_key = parts[1]
            
    config = TargetConfig(
        url=args.url or "http://localhost", key=args.key or "dummy", ai_key=ai_key, ai_model=ai_model, ai_provider=args.agent_provider,
        verbose=args.verbose, proxy=args.proxy,
        sniff_duration=args.sniff, check_config=args.check_config,
        stealth_mode=args.stealth, random_agent=args.random_agent,
        level=args.level, tamper=args.tamper
    )
    if args.analyze:
        from ssf.scanners.sast import SASTScanner
        
        console.print(f"[cyan][*] Starting Static Analysis on: {args.analyze}[/]")
        sast_scanner = SASTScanner(target_path=args.analyze, verbose=config.verbose)
        sast_report = sast_scanner.scan()
        
        if sast_report["findings"]:
            console.print(Panel(
                f"[bold red]Found {len(sast_report['findings'])} potential issues via Static Analysis (Offline)[/]",
                title="🔍 SAST Results", border_style="red"
            ))
            t_sast = Table(show_header=True, header_style="bold magenta")
            t_sast.add_column("File")
            t_sast.add_column("Line")
            t_sast.add_column("Issue")
            t_sast.add_column("Severity")
            
            for f in sast_report["findings"]:
                color = "red" if f['severity'] == "Critical" else "yellow"
                t_sast.add_row(f['file'], str(f['line']), f['issue'], f"[{color}]{f['severity']}[/]")
            
            console.print(t_sast)
        else:
            console.print("[green][✔] No issues found by Offline SAST.[/]")

        if config.has_ai:
            from ssf.core.utils import get_code_files
            console.print(f"[cyan][*] Elevating to AI Deep Analysis...[/]")
            
            code_files = get_code_files(args.analyze)
            if not code_files:
                console.print("[yellow][!] No supported code files found for AI analysis.[/]")
                return

            agent = AIAgent(api_key=config.ai_key, model_name=config.ai_model)
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
                console.print(Panel(Markdown(f"### Code Risk: {report.get('risk_level')}\n\n{report.get('summary')}"), title="🤖 AI Analysis Results", border_style="magenta"))
                
                report["sast_findings"] = sast_report["findings"]
                
                import os
                timestamp = int(time.time())
                output_dir = f"audit_report_{timestamp}"
                os.makedirs(output_dir, exist_ok=True)
                filename = os.path.join(output_dir, f"code_analysis_{timestamp}.json")
                with open(filename, "w", encoding="utf-8") as f:
                    json.dump(report, f, indent=2)
                console.print(f"\n[bold green]✔ Hybrid Code Analysis Report saved: {filename}[/]")
            return 
        else:
            import os
            timestamp = int(time.time())
            output_dir = f"audit_report_{timestamp}"
            os.makedirs(output_dir, exist_ok=True)
            filename = os.path.join(output_dir, f"sast_report_{timestamp}.json")
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(sast_report, f, indent=2)
            console.print(f"\n[bold green]✔ SAST Report saved: {filename}[/]")
        return 
    full_report = {"target": config.url, "timestamp": datetime.now().isoformat(), "findings": {}}
    kb = KnowledgeBase()
    if args.knowledge:
        if kb.load(args.knowledge):
            console.print(f"[green][*] Knowledge Base loaded from {args.knowledge}[/]")
        else:
            console.print(f"[red][!] Failed to load Knowledge Base from {args.knowledge}[/]")
    console.print(Panel.fit("[bold white]Supabase Audit Framework v1.2.14[/]\n[cyan]RLS • Auth • Storage • RPC • Realtime • AI[/]", border_style="blue"))
    shared_context = {}
    async with SessionManager(config) as client:
        with Progress(SpinnerColumn(), TextColumn("[cyan]Discovery Phase..."), console=console) as p:
            t1 = p.add_task("Spec", total=1)
            openapi = OpenAPIScanner(client, verbose=config.verbose, context=shared_context)
            spec = await openapi.scan()
            tables = openapi.parse_tables(spec)
            rpc_scanner = RPCScanner(client, verbose=config.verbose, context=shared_context, dump_all=args.dump_all)
            rpcs = rpc_scanner.extract_rpcs(spec)
            p.update(t1, completed=1)
        console.print(f"[+] Found {len(tables)} tables, {len(rpcs)} RPCs.")
        console.print("[yellow][*] Running Async Scanners...[/]")
        roles = {}
        if args.roles:
            try:
                with open(args.roles, "r") as f:
                    roles = json.load(f)
                console.print(f"[green][*] Loaded {len(roles)} roles from {args.roles}[/]")
            except Exception as e:
                console.print(f"[red][!] Failed to load roles: {e}[/]")
        auth_scanner = AuthScanner(client, verbose=config.verbose, context=shared_context)
        rls_scanner = RLSScanner(client, verbose=config.verbose, context=shared_context, tokens=roles, dump_all=args.dump_all)
        storage_scanner = StorageScanner(client, verbose=config.verbose, context=shared_context)
        brute_scanner = BruteScanner(client, verbose=config.verbose, context=shared_context, wordlist_path=args.brute)
        graphql_scanner = GraphQLScanner(client, verbose=config.verbose, context=shared_context)
        custom_functions = []
        import os
        from importlib import resources
        edge_list_file = args.edge_rpc 
        custom_functions = []
        
        source_path = None

        base_dir = os.path.dirname(os.path.abspath(__file__))
        default_source_path = os.path.join(base_dir, "edge_name.txt")

        if args.edge_rpc:
            if os.path.exists(args.edge_rpc):
                source_path = args.edge_rpc
            else:
                 console.print(f"[red][!] Custom wordlist file not found: {args.edge_rpc}[/]")
        elif os.path.exists(default_source_path):
            source_path = default_source_path

        if source_path:
            console.print(f"[cyan][*] Loading custom edge function list from {source_path}...[/]")
            try:
                with open(source_path, "r") as f:
                    custom_functions = [line.strip() for line in f if line.strip()]
                console.print(f"    [+] Loaded {len(custom_functions)} custom function names.", style="green")
            except Exception as e:
                console.print(f"    [red][!] Failed to load {source_path}: {e}[/]")
        
        function_scanner = EdgeFunctionScanner(client, verbose=config.verbose, context=shared_context, custom_list=custom_functions)
        realtime_scanner = RealtimeScanner(client, verbose=config.verbose, context=shared_context)
        extensions_scanner = ExtensionsScanner(client, verbose=config.verbose, context=shared_context)
        postgres_scanner = DatabaseConfigurationScanner(client, verbose=config.verbose, context=shared_context)
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
            realtime_scanner.scan(),
            extensions_scanner.scan(spec),
            postgres_scanner.scan()
        ]

        from ssf.core.plugin_manager import PluginManager
        plugin_manager = PluginManager(plugin_dir=os.path.join(os.path.dirname(os.path.abspath(__file__)), "plugins"))
        plugin_classes = plugin_manager.load_plugins(plugins_arg=args.plugins)
        plugins = [p(client, verbose=config.verbose, context=shared_context) for p in plugin_classes]
        
        for p in plugins:
            tasks.append(p.scan())

        results = await asyncio.gather(*tasks)
        res_rls, res_storage, res_rpc, res_brute, res_graphql, res_functions, res_realtime, res_extensions, res_postgres = (
            results[0], results[1], results[2], 
            results[3] if args.brute else [], results[4], results[5], results[6], results[7], results[8]
        )
        plugin_results = results[9:] if len(results) > 9 else []
        console.print("[yellow][*] Running Chained RPC Tests...[/]")
        res_chains = await rpc_scanner.scan_chains(res_rpc)
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
                r["accepted_reason"] = reason
                accepted_risks.append(f"RPC: {r['name']} ({reason})")
        if args.verify_fix and args.knowledge:
            console.print("[yellow][*] Verifying Remediation of Accepted Risks...[/]")
            updates = kb.verify_remediation(full_report["findings"])
            if updates:
                for update in updates:
                    console.print(f"    [green][+] {update}[/]")
                if kb.save(args.knowledge):
                    console.print(f"    [green][✔] Knowledge Base updated: {args.knowledge}[/]")
            else:
                console.print("    [dim]No status changes in accepted risks.[/]")
        full_report["findings"] = {
            "rls": res_rls, "auth": res_auth, "storage": res_storage, 
            "rpc": res_rpc, "brute": res_brute,
            "graphql": res_graphql, "functions": res_functions,
            "realtime": res_realtime, "extensions": res_extensions,
            "chains": res_chains, "postgres": res_postgres,
            "plugins": plugin_results
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
        [bold red]CRITICAL RLS:[/bold red] 
                                           {crit_rls}   [bold yellow]HIGH RLS:[/bold yellow] {high_rls}
        [bold red]VULN RPCs:[/bold red]    
                                           {vuln_rpcs}   [bold red]AUTH LEAK:[/bold red] {res_auth['leaked']}
        [bold yellow]OPEN CHANNELS:[/bold yellow] 
                                                  {open_chans}
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
        ext_tree = Tree("[bold]Extensions[/]")
        if res_extensions:
            for ext in res_extensions:
                color = "red" if ext["risk"] == "HIGH" else "yellow" if ext["risk"] == "MEDIUM" else "blue"
                ext_tree.add(f"[{color}]{ext['name']} ({ext['risk']}) - {ext['details']}[/{color}]")
        else:
            ext_tree.add("[dim]No extensions detected[/]")
        console.print(Panel(ext_tree, title="[bold]Database Extensions[/]", border_style="cyan"))
        pg_tree = Tree("[bold]Postgres Configuration[/]")
        if res_postgres["exposed_system_tables"]:
            for t in res_postgres["exposed_system_tables"]:
                pg_tree.add(f"[bold red]EXPOSED SYSTEM TABLE: {t}[/]")
        else:
            pg_tree.add("[green]No system tables exposed[/]")
        if res_postgres["config_issues"]:
            for i in res_postgres["config_issues"]:
                pg_tree.add(f"[yellow]{i}[/]")
        elif config.check_config:
            pg_tree.add("[green]max_rows configuration appears safe[/]")
        
        if config.sniff_duration:
             if res_realtime.get("risk") == "CRITICAL":
                 rt_branch.add("[bold red]Realtime Sniffer: Captured sensitive events![/]")
             else:
                 rt_branch.add(f"[green]Realtime Sniffer: No events captured ({config.sniff_duration}s)[/]")

        console.print(Panel(pg_tree, title="[bold]Database Config[/]", border_style="magenta"))
        if config.has_ai:
            from rich.live import Live
            from rich.text import Text
            agent = AIAgent(api_key=config.ai_key, model_name=config.ai_model)
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
            else:
                console.print(Panel(f"[bold red]AI Error:[/bold red] {report['error']}", title="🤖 AI Error", border_style="red"))
        if args.threat_model and config.has_ai:
            console.print(Panel("[magenta]Generating Automated Threat Model...[/]", border_style="magenta"))
            tm_panel = Panel(Markdown(""), title="🤖 Threat Model", border_style="magenta")
            tm_text = ""
            def update_tm_output(chunk):
                nonlocal tm_text
                tm_text += chunk
                tm_panel.renderable = Markdown(tm_text)
            with Live(tm_panel, refresh_per_second=8, console=console, auto_refresh=True):
                 tm_report = await agent.generate_threat_model(ai_input, stream_callback=update_tm_output)
            if "error" not in tm_report:
                full_report["threat_model"] = tm_report
                console.print(Panel(Markdown(f"### Threat Model Generated\n\n**Critical Assets:** {', '.join(tm_report.get('assets', []))}\n\n**Attack Paths:** {len(tm_report.get('attack_paths', []))} identified."), title="🤖 Threat Model Results", border_style="magenta"))
            else:
                console.print(Panel(f"[bold red]Threat Model Error:[/bold red] {tm_report['error']}", title="🤖 Threat Model Error", border_style="red"))
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
        if args.sarif:
            from ssf.core.report import SARIFReporter
            sarif_reporter = SARIFReporter()
            sarif_content = sarif_reporter.generate(full_report)
            sarif_filename = os.path.join(output_dir, f"audit_report_{timestamp}.sarif")
            with open(sarif_filename, "w", encoding="utf-8") as f:
                f.write(sarif_content)
            console.print(f"[bold green]✔ SARIF Report saved: {sarif_filename}[/]")
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
            from ssf.core.ci import CIHandler
            ci_handler = CIHandler(fail_on=args.fail_on, format=args.ci_format)
            ci_handler.evaluate(full_report, diff_results)

def main_sync():
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[bold red][-] Interrupted by user[/]")

if __name__ == "__main__":
    main_sync()