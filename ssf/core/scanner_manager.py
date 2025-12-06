import asyncio 
import json 
import os 
from typing import Dict ,Any ,List ,Optional ,Callable 
from rich .console import Console 
from rich .progress import Progress ,SpinnerColumn ,TextColumn 
from rich .panel import Panel 
from rich .tree import Tree 
from rich .table import Table 

from ssf.core .config import TargetConfig 
from ssf.core .session import SessionManager 
from ssf.core .knowledge import KnowledgeBase 
from ssf.core .ai import AIAgent 

from ssf.scanners .openapi import OpenAPIScanner 
from ssf.scanners .rls import RLSScanner 
from ssf.scanners .auth import AuthScanner 
from ssf.scanners .storage import StorageScanner 
from ssf.scanners .rpc import RPCScanner 
from ssf.scanners .brute import BruteScanner 
from ssf.scanners .graphql import GraphQLScanner 
from ssf.scanners .functions import EdgeFunctionScanner 
from ssf.scanners .realtime import RealtimeScanner 
from ssf.scanners .extensions import ExtensionsScanner 
from ssf.scanners .extensions import ExtensionsScanner 
from ssf.scanners .postgres import DatabaseConfigurationScanner 
from ssf.scanners .jwt_attack import JWTScanner 
from ssf.scanners .postgrest_fuzzer import PostgRESTFuzzer 
from ssf.core .plugin_manager import PluginManager 

class ScannerManager :
    def __init__ (self ,config :TargetConfig ,args :Any ,output_dir :str =None ,logger_callback :Optional [Callable [[Dict ],None ]]=None ,progress_callback :Optional [Callable [[int ],None ]]=None ,stop_callback :Optional [Callable [[],bool ]]=None ):
        self .config =config 
        self .args =args 
        self .output_dir =output_dir 
        self .logger_callback =logger_callback 
        self .progress_callback =progress_callback 
        self .stop_callback =stop_callback 
        self .console =Console ()
        self .shared_context ={}
        self .results ={}
        self .kb =KnowledgeBase ()
        if self .args .knowledge :
            if self .kb .load (self .args .knowledge ):
                self .console .print (f"[green][*] Knowledge Base loaded from {self .args .knowledge }[/]")
            else :
                self .console .print (f"[red][!] Failed to load Knowledge Base from {self .args .knowledge }[/]")

    async def run (self ):
        if self .stop_callback and self .stop_callback ():return {"error":"Scan cancelled"}
        self .console .print (Panel .fit ("[bold white]Supabase Audit Framework v2.0[/]\n[cyan]RLS • Auth • Storage • RPC • Realtime • AI[/]",border_style ="blue"))

        async with SessionManager (self .config )as client :

            with Progress (SpinnerColumn (),TextColumn ("[cyan]Discovery Phase..."),console =self .console )as p :
                t1 =p .add_task ("Spec",total =1 )
                openapi =OpenAPIScanner (client ,verbose =self .config .verbose ,context =self .shared_context )
                spec =await openapi .scan ()
                tables =openapi .parse_tables (spec )
                rpc_scanner =RPCScanner (client ,verbose =self .config .verbose ,context =self .shared_context ,dump_all =self .args .dump_all ,output_dir =self .output_dir )
                rpcs =rpc_scanner .extract_rpcs (spec )
                p .update (t1 ,completed =1 )

            if self .progress_callback :self .progress_callback (15 )

            self .console .print (f"[+] Found {len (tables )} tables, {len (rpcs )} RPCs.")
            self .console .print ("[yellow][*] Running Async Scanners...[/]")


            roles =self ._load_roles ()
            custom_functions =self ._load_custom_functions ()

            auth_scanner =AuthScanner (client ,verbose =self .config .verbose ,context =self .shared_context )
            rls_scanner =RLSScanner (client ,verbose =self .config .verbose ,context =self .shared_context ,tokens =roles ,dump_all =self .args .dump_all ,output_dir =self .output_dir )
            storage_scanner =StorageScanner (client ,verbose =self .config .verbose ,context =self .shared_context )
            brute_scanner =BruteScanner (client ,verbose =self .config .verbose ,context =self .shared_context ,wordlist_path =self .args .brute )
            graphql_scanner =GraphQLScanner (client ,verbose =self .config .verbose ,context =self .shared_context )
            function_scanner =EdgeFunctionScanner (client ,verbose =self .config .verbose ,context =self .shared_context ,custom_list =custom_functions )
            realtime_scanner =RealtimeScanner (client ,verbose =self .config .verbose ,context =self .shared_context )
            extensions_scanner =ExtensionsScanner (client ,verbose =self .config .verbose ,context =self .shared_context )
            extensions_scanner =ExtensionsScanner (client ,verbose =self .config .verbose ,context =self .shared_context )
            postgres_scanner =DatabaseConfigurationScanner (client ,verbose =self .config .verbose ,context =self .shared_context )
            jwt_scanner =JWTScanner (client ,verbose =self .config .verbose ,context =self .shared_context )
            postgrest_fuzzer =PostgRESTFuzzer (client ,verbose =self .config .verbose ,context =self .shared_context )

            plugin_manager =PluginManager ()
            plugin_classes =plugin_manager .load_plugins (getattr(self.args, "plugins", None))
            plugins =[p (client ,verbose =self .config .verbose ,context =self .shared_context )for p in plugin_classes ]


            MAX_CONCURRENT_REQUESTS =20 
            sem =asyncio .Semaphore (MAX_CONCURRENT_REQUESTS )

            async def bounded_scan (coroutine ):
                async with sem :
                    return await coroutine 

            def should_run (name ):
                skip_attr =f"skip_{name }"
                if hasattr (self .args ,skip_attr )and getattr (self .args ,skip_attr ):
                    return False 
                return True 

            res_auth =await auth_scanner .scan ()if should_run ("auth")else {"leaked":False ,"users":[]}

            if should_run ("rls"):
                rls_tasks =[bounded_scan (rls_scanner .scan (name ,info ))for name ,info in tables .items ()]
                rls_future =asyncio .gather (*rls_tasks )
            else :
                rls_future =asyncio .sleep (0 )

            if should_run ("rpc"):
                rpc_tasks =[bounded_scan (rpc_scanner .scan (r ))for r in rpcs ]
                rpc_future =asyncio .gather (*rpc_tasks )
            else :
                rpc_future =asyncio .sleep (0 )

            tasks =[
            rls_future ,
            storage_scanner .scan ()if should_run ("storage")else asyncio .sleep (0 ),
            rpc_future ,
            brute_scanner .scan ()if self .args .brute else asyncio .sleep (0 ),
            graphql_scanner .scan ()if should_run ("graphql")else asyncio .sleep (0 ),
            function_scanner .scan ()if should_run ("functions")else asyncio .sleep (0 ),
            realtime_scanner .scan ()if should_run ("realtime")else asyncio .sleep (0 ),
            extensions_scanner .scan (spec )if should_run ("extensions")else asyncio .sleep (0 ),
            postgres_scanner .scan ()if should_run ("postgres")else asyncio .sleep (0 ),
            jwt_scanner .scan (),
            postgrest_fuzzer .scan (),
            *[p .scan ()for p in plugins ]
            ]

            if self .progress_callback :self .progress_callback (20 )


            total_tasks =len (tasks )
            completed_tasks =0 

            async def progress_wrapper (coro ):
                if self .stop_callback and self .stop_callback ():return None 
                nonlocal completed_tasks 
                res =await coro 
                completed_tasks +=1 

                current =20 +int ((completed_tasks /total_tasks )*60 )
                if self .progress_callback :self .progress_callback (current )
                return res 

            wrapped_tasks =[progress_wrapper (t )for t in tasks ]
            results_list =await asyncio .gather (*wrapped_tasks )

            if self .stop_callback and self .stop_callback ():return {"error":"Scan cancelled"}

            res_rls =results_list [0 ]if results_list [0 ]is not None else []
            res_storage =results_list [1 ]if results_list [1 ]is not None else []
            res_rpc =results_list [2 ]if results_list [2 ]is not None else []
            res_brute =results_list [3 ]if results_list [3 ]is not None else []
            res_graphql =results_list [4 ]if results_list [4 ]is not None else []
            res_functions =results_list [5 ]if results_list [5 ]is not None else []
            res_realtime =results_list [6 ]if results_list [6 ]is not None else []
            res_extensions =results_list [7 ]if results_list [7 ]is not None else []
            res_postgres =results_list [8 ]if results_list [8 ]is not None else []








            res_jwt =results_list [9 ]if len (results_list )>9 else {}
            res_postgrest =results_list [10 ]if len (results_list )>10 else {}

            plugin_results =[]
            if len (results_list )>11 :
                plugin_results =results_list [11 :]

            self .console .print ("[yellow][*] Running Chained RPC Tests...[/]")
            if self .progress_callback :self .progress_callback (85 )
            res_chains =await rpc_scanner .scan_chains (res_rpc )


            accepted_risks =self ._process_accepted_risks (res_rls ,res_rpc )


            full_report ={
            "target":self .config .url ,
            "timestamp":self ._get_timestamp (),
            "findings":{
            "rls":res_rls ,"auth":res_auth ,"storage":res_storage ,
            "rpc":res_rpc ,"brute":res_brute ,
            "graphql":res_graphql ,"functions":res_functions ,
            "realtime":res_realtime ,"extensions":res_extensions ,
            "realtime":res_realtime ,"extensions":res_extensions ,
            "chains":res_chains ,"postgres":res_postgres ,
            "jwt":res_jwt ,"postgrest":res_postgrest ,"plugins":plugin_results 
            },
            "accepted_risks":accepted_risks 
            }

            if self .config .ai_provider and self .config .ai_key :
                self .console .print (f"[yellow][*] AI Analysis with {self .config .ai_provider }...[/]")
                if self .progress_callback :self .progress_callback (90 )
                if self .logger_callback :
                    self .logger_callback ({"timestamp":self ._get_timestamp (),"level":"info","message":f"Starting AI analysis with {self .config .ai_provider }..."})

                try :
                    agent =AIAgent (api_key =self .config .ai_key ,model_name =self .config .ai_model or "gemini-2.0-flash")

                    scan_summary ={
                    "target":self .config .url ,
                    "apikey":self .config .key ,
                    "service_role_key":res_auth .get ("service_role_key",None )if res_auth .get ("leaked")else None ,
                    "auth_leak":res_auth .get ("leaked",False ),
                    "writable_tables":[t ["table"]for t in res_rls if t .get ("write")],
                    "executable_rpcs":[r ["name"]for r in res_rpc if r .get ("risk")!="SAFE"],
                    "hidden_tables":[t ["table"]for t in res_rls if t .get ("read")and t .get ("risk")=="SAFE"],
                    "accepted_risks":accepted_risks 
                    }

                    self .console .print ("[cyan]    Generating Security Report & Exploits...[/]")
                    if self .logger_callback :
                        self .logger_callback ({"timestamp":self ._get_timestamp (),"level":"info","message":"Generating security report and exploits..."})

                    ai_report =await agent .analyze_results (scan_summary ,output_dir =self .output_dir )


                    if "error"not in ai_report :
                        full_report ["ai_analysis"]=ai_report 
                        self .console .print ("[green]    [+] AI Report & Exploits Generated![/]")
                        if self .logger_callback :
                            self .logger_callback ({"timestamp":self ._get_timestamp (),"level":"success","message":"AI report and exploits generated successfully."})
                    else :
                        error_msg =ai_report .get ('error','Unknown error')
                        self .console .print (f"[red]    [!] AI Error: {error_msg }[/]")


                        if 'suggestions'in ai_report :
                            self .console .print ("[yellow]    Suggestions:[/]")
                            for suggestion in ai_report ['suggestions']:
                                self .console .print (f"[yellow]      • {suggestion }[/]")


                        if 'raw_preview'in ai_report :
                            self .console .print (f"[dim]    Response preview: {ai_report ['raw_preview']}[/]")

                        if self .logger_callback :
                            self .logger_callback ({"timestamp":self ._get_timestamp (),"level":"error","message":f"AI Error: {error_msg }"})

                except Exception as e :
                    self .console .print (f"[red]    [!] AI Agent Failed: {e }[/]")
                    if self .logger_callback :
                        self .logger_callback ({"timestamp":self ._get_timestamp (),"level":"error","message":f"AI Agent Failed: {e }"})


            if self .args .verify_fix and self .args .knowledge :
                 self .console .print ("[yellow][*] Verifying Remediation of Accepted Risks...[/]")
                 updates =self .kb .verify_remediation (full_report ["findings"])
                 if updates :
                     for update in updates :
                         self .console .print (f"    [green][+] {update }[/]")
                     if self .kb .save (self .args .knowledge ):
                         self .console .print (f"    [green][✔] Knowledge Base updated: {self .args .knowledge }[/]")
                 else :
                     self .console .print ("    [dim]No status changes in accepted risks.[/]")

            self ._print_report (full_report ,res_auth ,res_rls ,res_rpc ,res_realtime ,res_graphql ,res_functions ,res_storage ,res_extensions ,res_postgres )

            return full_report 

    def _load_roles (self )->Dict [str ,str ]:
        roles ={}
        if self .args .roles :
            try :
                with open (self .args .roles ,"r")as f :
                    roles =json .load (f )
                self .console .print (f"[green][*] Loaded {len (roles )} roles from {self .args .roles }[/]")
            except Exception as e :
                self .console .print (f"[red][!] Failed to load roles: {e }[/]")
        return roles 

    def _load_custom_functions(self) -> List[str]:
        custom_functions = []
        edge_rpc = self.args.edge_rpc
        if isinstance(edge_rpc, bool):
            edge_rpc = None

        package_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        default_edge_list = os.path.join(package_root, "edge_name.txt")
        
        target_file = None
        if edge_rpc:
            if os.path.exists(edge_rpc):
                target_file = edge_rpc
            else:
                 self.console.print(f"[red][!] Custom wordlist file not found: {edge_rpc}[/]")
        elif self.args.edge_rpc or os.path.exists(default_edge_list):
   
             target_file = default_edge_list

        if target_file and os.path.exists(target_file):
            self.console.print(f"[cyan][*] Loading custom edge function list from {target_file}...[/]")
            try:
                with open(target_file, "r") as f:
                    custom_functions = [line.strip() for line in f if line.strip()]
                self.console.print(f"    [+] Loaded {len(custom_functions)} custom function names.", style="green")
            except Exception as e:
                self.console.print(f"    [red][!] Failed to load {target_file}: {e}[/]")
        
        return custom_functions 

    def _process_accepted_risks (self ,res_rls ,res_rpc )->List [str ]:
        accepted_risks =[]
        for r in res_rls :
            reason =self .kb .is_accepted (r ,"rls")
            if reason :
                r ["risk"]="ACCEPTED"
                r ["accepted_reason"]=reason 
                accepted_risks .append (f"RLS: {r ['table']} ({reason })")
        for r in res_rpc :
            reason =self .kb .is_accepted (r ,"rpc")
            if reason :
                r ["executable"]=False 
                r ["risk"]="ACCEPTED"
                r ["accepted_reason"]=reason 
                accepted_risks .append (f"RPC: {r ['name']} ({reason })")
        return accepted_risks 

    def _get_timestamp (self ):
        from datetime import datetime 
        return datetime .now ().isoformat ()

    def _print_report (self ,full_report ,res_auth ,res_rls ,res_rpc ,res_realtime ,res_graphql ,res_functions ,res_storage ,res_extensions ,res_postgres ):
        self .console .print ("\n")
        self .console .rule ("[bold cyan]Scan Complete - Final Report[/]")
        self .console .print ("\n")

        auth_status ="[bold red]LEAK DETECTED[/]"if res_auth ["leaked"]else "[bold green]SECURE[/]"
        auth_details =f"Users Exposed: {res_auth ['count']}"if res_auth ["leaked"]else "No users found in public tables."
        self .console .print (Panel (f"Status: {auth_status }\n{auth_details }",title ="[bold]Authentication[/]",border_style ="red"if res_auth ["leaked"]else "green"))

        crit_rls =len ([r for r in res_rls if r ["risk"]=="CRITICAL"])
        high_rls =len ([r for r in res_rls if r ["risk"]=="HIGH"])
        vuln_rpcs =len ([r for r in res_rpc if r .get ("sqli_suspected")or r .get ("risk")=="CRITICAL"])
        open_chans =len (res_realtime ["channels"])

        scorecard =f"""
        [bold red]CRITICAL RLS:[/bold red] 
                                           {crit_rls }   [bold yellow]HIGH RLS:[/bold yellow] {high_rls }
        [bold red]VULN RPCs:[/bold red]    
                                           {vuln_rpcs }   [bold red]AUTH LEAK:[/bold red] {res_auth ['leaked']}
        [bold yellow]OPEN CHANNELS:[/bold yellow] 
                                                  {open_chans }
        """
        self .console .print (Panel (scorecard ,title ="[bold]Risk Scorecard[/]",border_style ="red"if crit_rls >0 or vuln_rpcs >0 else "green"))

        t_rls =Table (title ="Row Level Security (RLS)",expand =True )
        t_rls .add_column ("Table",style ="cyan")
        t_rls .add_column ("Read",justify ="center")
        t_rls .add_column ("Write",justify ="center")
        t_rls .add_column ("Risk",justify ="center")

        res_rls .sort (key =lambda x :(x ["risk"]=="ACCEPTED",x ["risk"]=="SAFE",x ["risk"]=="MEDIUM",x ["risk"]=="HIGH",x ["risk"]=="CRITICAL"))

        for r in res_rls :
            if self .config .verbose or r ["risk"]!="SAFE":
                color ="red"if r ["risk"]=="CRITICAL"else "yellow"if r ["risk"]=="HIGH"else "green"
                if r ["risk"]=="ACCEPTED":color ="blue"
                read_mark ="[green]YES[/]"if r ["read"]else "[dim]-[/]"
                write_mark ="[red]LEAK[/]"if r ["write"]else "[dim]-[/]"
                risk_label =r ['risk']
                if r .get ('accepted_reason'):
                    risk_label +=f" ({r ['accepted_reason']})"
                t_rls .add_row (r ["table"],read_mark ,write_mark ,f"[{color }]{risk_label }[/]")
        self .console .print (t_rls )

        api_tree =Tree ("[bold]API Surface[/]")
        rpc_branch =api_tree .add ("Remote Procedure Calls (RPC)")
        executable_rpcs =[r for r in res_rpc if r .get ("executable")]
        if executable_rpcs :
            for r in executable_rpcs :
                risk ="ACCEPTED"if r .get ("risk")=="ACCEPTED"else "EXECUTABLE"
                style ="blue"if risk =="ACCEPTED"else "red"
                rpc_branch .add (f"[{style }]{r ['name']} ({risk })[/{style }]")
        else :
            rpc_branch .add ("[green]No executable public RPCs found[/]")

        gql_branch =api_tree .add ("GraphQL")
        if res_graphql ["enabled"]:
            gql_branch .add (f"[yellow]Introspection Enabled: {res_graphql ['details']}[/]")
        else :
            gql_branch .add ("[green]Introspection Disabled[/]")

        func_branch =api_tree .add ("Edge Functions")
        if res_functions :
            for f in res_functions :
                func_branch .add (f"[red]{f ['name']} (Found)[/]")
        else :
            func_branch .add ("[green]No common Edge Functions found[/]")
        self .console .print (Panel (api_tree ,title ="[bold]API & Functions[/]",border_style ="cyan"))

        infra_tree =Tree ("[bold]Infrastructure[/]")
        rt_branch =infra_tree .add ("Realtime")
        if res_realtime ["channels"]:
            for c in res_realtime ["channels"]:
                rt_branch .add (f"[red]Open Channel: {c }[/]")
        else :
            rt_branch .add ("[green]No open channels detected[/]")

        store_branch =infra_tree .add ("Storage")
        if isinstance (res_storage ,list ):
             for s in res_storage :
                 if s .get ("public"):
                     store_branch .add (f"[yellow]Public Bucket: {s ['name']}[/]")
        self .console .print (Panel (infra_tree ,title ="[bold]Realtime & Storage[/]",border_style ="magenta"))

        ext_tree =Tree ("[bold]Extensions[/]")
        if res_extensions :
            for ext in res_extensions :
                color ="red"if ext ["risk"]=="HIGH"else "yellow"if ext ["risk"]=="MEDIUM"else "blue"
                ext_tree .add (f"[{color }]{ext ['name']} ({ext ['risk']}) - {ext ['details']}[/{color }]")
        else :
            ext_tree .add ("[dim]No extensions detected[/]")
        self .console .print (Panel (ext_tree ,title ="[bold]Database Extensions[/]",border_style ="cyan"))

        pg_tree =Tree ("[bold]Postgres Configuration[/]")
        if res_postgres ["exposed_system_tables"]:
            for t in res_postgres ["exposed_system_tables"]:
                pg_tree .add (f"[bold red]EXPOSED SYSTEM TABLE: {t }[/]")
        else :
            pg_tree .add ("[green]No system tables exposed[/]")
        if res_postgres ["config_issues"]:
            for i in res_postgres ["config_issues"]:
                pg_tree .add (f"[yellow]{i }[/]")
        elif self .config .check_config :
            pg_tree .add ("[green]max_rows configuration appears safe[/]")

        if self .config .sniff_duration :
             if res_realtime .get ("risk")=="CRITICAL":
                 rt_branch .add ("[bold red]Realtime Sniffer: Captured sensitive events![/]")
             else :
                 rt_branch .add (f"[green]Realtime Sniffer: No events captured ({self .config .sniff_duration }s)[/]")

        self .console .print (Panel (pg_tree ,title ="[bold]Database Config[/]",border_style ="magenta"))
