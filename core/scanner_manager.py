import asyncio
import json
import os
from typing import Dict, Any, List
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.tree import Tree
from rich.table import Table

from core.config import TargetConfig
from core.session import SessionManager
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
from scanners.extensions import ExtensionsScanner
from scanners.postgres import DatabaseConfigurationScanner

class ScannerManager:
    def __init__(self, config: TargetConfig, args: Any):
        self.config = config
        self.args = args
        self.console = Console()
        self.shared_context = {}
        self.results = {}
        self.kb = KnowledgeBase()
        if self.args.knowledge:
            if self.kb.load(self.args.knowledge):
                self.console.print(f"[green][*] Knowledge Base loaded from {self.args.knowledge}[/]")
            else:
                self.console.print(f"[red][!] Failed to load Knowledge Base from {self.args.knowledge}[/]")

    async def run(self):
        self.console.print(Panel.fit("[bold white]Supabase Audit Framework v1.0[/]\n[cyan]RLS • Auth • Storage • RPC • Realtime • AI[/]", border_style="blue"))
        
        async with SessionManager(self.config) as client:
 
            with Progress(SpinnerColumn(), TextColumn("[cyan]Discovery Phase..."), console=self.console) as p:
                t1 = p.add_task("Spec", total=1)
                openapi = OpenAPIScanner(client, verbose=self.config.verbose, context=self.shared_context)
                spec = await openapi.scan()
                tables = openapi.parse_tables(spec)
                rpc_scanner = RPCScanner(client, verbose=self.config.verbose, context=self.shared_context, dump_all=self.args.dump_all)
                rpcs = rpc_scanner.extract_rpcs(spec)
                p.update(t1, completed=1)
            
            self.console.print(f"[+] Found {len(tables)} tables, {len(rpcs)} RPCs.")
            self.console.print("[yellow][*] Running Async Scanners...[/]")


            roles = self._load_roles()
            custom_functions = self._load_custom_functions()

            auth_scanner = AuthScanner(client, verbose=self.config.verbose, context=self.shared_context)
            rls_scanner = RLSScanner(client, verbose=self.config.verbose, context=self.shared_context, tokens=roles, dump_all=self.args.dump_all)
            storage_scanner = StorageScanner(client, verbose=self.config.verbose, context=self.shared_context)
            brute_scanner = BruteScanner(client, verbose=self.config.verbose, context=self.shared_context, wordlist_path=self.args.brute)
            graphql_scanner = GraphQLScanner(client, verbose=self.config.verbose, context=self.shared_context)
            function_scanner = EdgeFunctionScanner(client, verbose=self.config.verbose, context=self.shared_context, custom_list=custom_functions)
            realtime_scanner = RealtimeScanner(client, verbose=self.config.verbose, context=self.shared_context)
            extensions_scanner = ExtensionsScanner(client, verbose=self.config.verbose, context=self.shared_context)
            postgres_scanner = DatabaseConfigurationScanner(client, verbose=self.config.verbose, context=self.shared_context)


            MAX_CONCURRENT_REQUESTS = 20
            sem = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

            async def bounded_scan(coroutine):
                async with sem:
                    return await coroutine

            res_auth = await auth_scanner.scan()
            
            rls_tasks = [bounded_scan(rls_scanner.scan(name, info)) for name, info in tables.items()]
            rpc_tasks = [bounded_scan(rpc_scanner.scan(r)) for r in rpcs]

            tasks = [
                asyncio.gather(*rls_tasks),
                storage_scanner.scan(),
                asyncio.gather(*rpc_tasks),
                brute_scanner.scan() if self.args.brute else asyncio.sleep(0),
                graphql_scanner.scan(),
                function_scanner.scan(),
                realtime_scanner.scan(),
                extensions_scanner.scan(spec),
                postgres_scanner.scan()
            ]

            results_list = await asyncio.gather(*tasks)
            
            res_rls = results_list[0]
            res_storage = results_list[1]
            res_rpc = results_list[2]
            res_brute = results_list[3] if self.args.brute else []
            res_graphql = results_list[4]
            res_functions = results_list[5]
            res_realtime = results_list[6]
            res_extensions = results_list[7]
            res_postgres = results_list[8]

            self.console.print("[yellow][*] Running Chained RPC Tests...[/]")
            res_chains = await rpc_scanner.scan_chains(res_rpc)


            accepted_risks = self._process_accepted_risks(res_rls, res_rpc)
            
            if self.args.verify_fix and self.args.knowledge:
                self._verify_remediation(accepted_risks) 

            full_report = {
                "target": self.config.url,
                "timestamp": self._get_timestamp(),
                "findings": {
                    "rls": res_rls, "auth": res_auth, "storage": res_storage, 
                    "rpc": res_rpc, "brute": res_brute,
                    "graphql": res_graphql, "functions": res_functions,
                    "realtime": res_realtime, "extensions": res_extensions,
                    "chains": res_chains, "postgres": res_postgres
                },
                "accepted_risks": accepted_risks
            }
            

            if self.args.verify_fix and self.args.knowledge:
                 self.console.print("[yellow][*] Verifying Remediation of Accepted Risks...[/]")
                 updates = self.kb.verify_remediation(full_report["findings"])
                 if updates:
                     for update in updates:
                         self.console.print(f"    [green][+] {update}[/]")
                     if self.kb.save(self.args.knowledge):
                         self.console.print(f"    [green][✔] Knowledge Base updated: {self.args.knowledge}[/]")
                 else:
                     self.console.print("    [dim]No status changes in accepted risks.[/]")

            self._print_report(full_report, res_auth, res_rls, res_rpc, res_realtime, res_graphql, res_functions, res_storage, res_extensions, res_postgres)
            
            return full_report

    def _load_roles(self) -> Dict[str, str]:
        roles = {}
        if self.args.roles:
            try:
                with open(self.args.roles, "r") as f:
                    roles = json.load(f)
                self.console.print(f"[green][*] Loaded {len(roles)} roles from {self.args.roles}[/]")
            except Exception as e:
                self.console.print(f"[red][!] Failed to load roles: {e}[/]")
        return roles

    def _load_custom_functions(self) -> List[str]:
        custom_functions = []
        edge_list_file = self.args.edge_rpc if self.args.edge_rpc else "edge_name.txt"
        should_load = self.args.edge_rpc or os.path.exists("edge_name.txt")
        if should_load and os.path.exists(edge_list_file):
            self.console.print(f"[cyan][*] Loading custom edge function list from {edge_list_file}...[/]")
            try:
                with open(edge_list_file, "r") as f:
                    custom_functions = [line.strip() for line in f if line.strip()]
                self.console.print(f"    [+] Loaded {len(custom_functions)} custom function names.", style="green")
            except Exception as e:
                self.console.print(f"    [red][!] Failed to load {edge_list_file}: {e}[/]")
        elif self.args.edge_rpc:
             self.console.print(f"[red][!] Custom wordlist file not found: {edge_list_file}[/]")
        return custom_functions

    def _process_accepted_risks(self, res_rls, res_rpc) -> List[str]:
        accepted_risks = []
        for r in res_rls:
            reason = self.kb.is_accepted(r, "rls")
            if reason:
                r["risk"] = "ACCEPTED"
                r["accepted_reason"] = reason
                accepted_risks.append(f"RLS: {r['table']} ({reason})")
        for r in res_rpc:
            reason = self.kb.is_accepted(r, "rpc")
            if reason:
                r["executable"] = False 
                r["risk"] = "ACCEPTED"
                r["accepted_reason"] = reason
                accepted_risks.append(f"RPC: {r['name']} ({reason})")
        return accepted_risks

    def _get_timestamp(self):
        from datetime import datetime
        return datetime.now().isoformat()

    def _print_report(self, full_report, res_auth, res_rls, res_rpc, res_realtime, res_graphql, res_functions, res_storage, res_extensions, res_postgres):
        self.console.print("\n")
        self.console.rule("[bold cyan]Scan Complete - Final Report[/]")
        self.console.print("\n")
        
        auth_status = "[bold red]LEAK DETECTED[/]" if res_auth["leaked"] else "[bold green]SECURE[/]"
        auth_details = f"Users Exposed: {res_auth['count']}" if res_auth["leaked"] else "No users found in public tables."
        self.console.print(Panel(f"Status: {auth_status}\n{auth_details}", title="[bold]Authentication[/]", border_style="red" if res_auth["leaked"] else "green"))
        
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
        self.console.print(Panel(scorecard, title="[bold]Risk Scorecard[/]", border_style="red" if crit_rls > 0 or vuln_rpcs > 0 else "green"))
        
        t_rls = Table(title="Row Level Security (RLS)", expand=True)
        t_rls.add_column("Table", style="cyan")
        t_rls.add_column("Read", justify="center")
        t_rls.add_column("Write", justify="center")
        t_rls.add_column("Risk", justify="center")
        
        res_rls.sort(key=lambda x: (x["risk"] == "ACCEPTED", x["risk"] == "SAFE", x["risk"] == "MEDIUM", x["risk"] == "HIGH", x["risk"] == "CRITICAL"))
        
        for r in res_rls:
            if self.config.verbose or r["risk"] != "SAFE":
                color = "red" if r["risk"] == "CRITICAL" else "yellow" if r["risk"] == "HIGH" else "green"
                if r["risk"] == "ACCEPTED": color = "blue"
                read_mark = "[green]YES[/]" if r["read"] else "[dim]-[/]"
                write_mark = "[red]LEAK[/]" if r["write"] else "[dim]-[/]"
                risk_label = r['risk']
                if r.get('accepted_reason'):
                    risk_label += f" ({r['accepted_reason']})"
                t_rls.add_row(r["table"], read_mark, write_mark, f"[{color}]{risk_label}[/]")
        self.console.print(t_rls)
        
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
        self.console.print(Panel(api_tree, title="[bold]API & Functions[/]", border_style="cyan"))
        
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
        self.console.print(Panel(infra_tree, title="[bold]Realtime & Storage[/]", border_style="magenta"))
        
        ext_tree = Tree("[bold]Extensions[/]")
        if res_extensions:
            for ext in res_extensions:
                color = "red" if ext["risk"] == "HIGH" else "yellow" if ext["risk"] == "MEDIUM" else "blue"
                ext_tree.add(f"[{color}]{ext['name']} ({ext['risk']}) - {ext['details']}[/{color}]")
        else:
            ext_tree.add("[dim]No extensions detected[/]")
        self.console.print(Panel(ext_tree, title="[bold]Database Extensions[/]", border_style="cyan"))
        
        pg_tree = Tree("[bold]Postgres Configuration[/]")
        if res_postgres["exposed_system_tables"]:
            for t in res_postgres["exposed_system_tables"]:
                pg_tree.add(f"[bold red]EXPOSED SYSTEM TABLE: {t}[/]")
        else:
            pg_tree.add("[green]No system tables exposed[/]")
        if res_postgres["config_issues"]:
            for i in res_postgres["config_issues"]:
                pg_tree.add(f"[yellow]{i}[/]")
        elif self.config.check_config:
            pg_tree.add("[green]max_rows configuration appears safe[/]")
        
        if self.config.sniff_duration:
             if res_realtime.get("risk") == "CRITICAL":
                 rt_branch.add("[bold red]Realtime Sniffer: Captured sensitive events![/]")
             else:
                 rt_branch.add(f"[green]Realtime Sniffer: No events captured ({self.config.sniff_duration}s)[/]")

        self.console.print(Panel(pg_tree, title="[bold]Database Config[/]", border_style="magenta"))
