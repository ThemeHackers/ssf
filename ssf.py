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
from core.config import TargetConfig
from core.session import SessionManager
from core.ai import AIAgent
from core.knowledge import KnowledgeBase
from core.scanner_manager import ScannerManager
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
    if "--update" in sys.argv:
        from core.updater import update_tool
        update_tool()
        return
    if "--wizard" in sys.argv:
        from core.wizard import run_wizard
        wizard_args = run_wizard()
        class Args:
            pass
        args = Args()
        for k, v in wizard_args.items():
            setattr(args, k, v)
        
        args.compile = False
        args.check_config = False
        args.update = False
        args.proxy = None
        args.sniff = None
        args.analyze = None
        args.edge_rpc = None
        args.roles = None
        args.threat_model = False
        args.verify_fix = False
        args.dump_all = False
        args.gen_fixes = False
        args.exploit = False
        args.diff = None
        args.knowledge = None
        args.ci = False
        args.fail_on = "HIGH"
        args.ci_format = "text"
        args.tamper = None 
        
    else:
        parser = argparse.ArgumentParser(description="Supabase Audit Framework v2.0")
        parser.add_argument("url", help="Target URL")
        parser.add_argument("key", help="Anon Key")
        parser.add_argument("--agent", help="AI Model Name (e.g., gemini-2.5-flash, llama3)", default="gemini-2.5-flash")
        parser.add_argument("--agent-key", help="AI API Key (for Gemini/OpenAI/DeepSeek/Anthropic)", default=None)
        parser.add_argument("--agent-provider", help="AI Provider (gemini, ollama, openai, deepseek, anthropic)", default="gemini", choices=["gemini", "ollama", "openai", "deepseek", "anthropic"])
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
        parser.add_argument("--update", action="store_true", help="Update the tool to the latest version")
        parser.add_argument("--wizard", action="store_true", help="Run in wizard mode for beginners")
        parser.add_argument("--random-agent", action="store_true", help="Use a random User-Agent header")
        parser.add_argument("--level", type=int, default=1, help="Level of tests to perform (1-5, default 1)")
        parser.add_argument("--tamper", help="Path to tamper script (e.g., tamper.py)")
        args = parser.parse_args()
    
    if args.compile:
        return
        
    ai_key = args.agent_key
    ai_model = args.agent
    
    if not ai_key and args.agent_provider == "gemini":
        ai_key = os.getenv("GEMINI_API_KEY")

    config = TargetConfig(
        url=args.url, key=args.key, ai_key=ai_key, ai_model=ai_model, ai_provider=args.agent_provider,
        verbose=args.verbose, proxy=args.proxy,
        sniff_duration=args.sniff, check_config=args.check_config,
        random_agent=args.random_agent, level=args.level, tamper=args.tamper
    )
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
        if config.ai_provider == "ollama":
            from core.ai_local import LocalAIAgent
            agent = LocalAIAgent(model_name=config.ai_model)
        else:
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
            console.print(Panel(Markdown(f"### Code Risk: {report.get('risk_level')}\n\n{report.get('summary')}"), title="🤖 Static Analysis Results", border_style="magenta"))

            timestamp = int(time.time())
            output_dir = f"audit_report_{timestamp}"
            os.makedirs(output_dir, exist_ok=True)
            filename = os.path.join(output_dir, f"code_analysis_{timestamp}.json")
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            console.print(f"\n[bold green]✔ Code Analysis Report saved: {filename}[/]")
        return 
    manager = ScannerManager(config, args)
    full_report = await manager.run()
    
    from core.ai_local import LocalAIAgent
    from core.ai_generic import GenericAIAgent
    from core.ai_anthropic import AnthropicAIAgent
    ai_agent = None
    if config.has_ai or config.ai_provider == "ollama":
        console.print(Panel("Connecting to AI Agent...", style="bold blue"))
        try:
            if config.ai_provider == "ollama":
                ai_agent = LocalAIAgent(model_name=config.ai_model)
            elif config.ai_provider == "openai":
                ai_agent = GenericAIAgent(api_key=config.ai_key, model_name=config.ai_model, base_url="https://api.openai.com/v1")
            elif config.ai_provider == "deepseek":
                ai_agent = GenericAIAgent(api_key=config.ai_key, model_name=config.ai_model, base_url="https://api.deepseek.com")
            elif config.ai_provider == "anthropic":
                ai_agent = AnthropicAIAgent(api_key=config.ai_key, model_name=config.ai_model)
            else: 
                ai_agent = AIAgent(api_key=config.ai_key, model_name=config.ai_model)
        except Exception as e:
            console.print(f"[bold red][!] Failed to initialize AI Agent: {e}[/]")

    if ai_agent: 
        from rich.live import Live
        from rich.text import Text
        ai_input = full_report["findings"]
        ai_input["target"] = config.url
        ai_input["accepted_risks"] = full_report["accepted_risks"]
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
        console.print(Panel("[magenta]Connecting to AI Agent...[/]", border_style="magenta", expand=False))
        with Live(panel, refresh_per_second=8, console=console, auto_refresh=True):
             report = await agent.analyze_results(ai_input, stream_callback=update_ai_output_markdown)
        if "error" not in report:
            console.print(Panel(Markdown(f"### AI Risk: {report.get('risk_level')}\n\n{report.get('summary')}"), title="🤖 AI Security Assessment", border_style="magenta", expand=False))
            full_report["ai_analysis"] = report
        else:
            console.print(Panel(f"[bold red]AI Error:[/bold red] {report['error']}", title="🤖 AI Error", border_style="red", expand=False))
    if args.threat_model and (config.has_ai or config.ai_provider == "ollama"):
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
        if (config.has_ai or config.ai_provider == "ollama") and "ai_analysis" in full_report:
            console.print("\n[bold yellow][*] Running Exploit Module...[/]")
            await run_exploit(auto_confirm=True)
        elif (config.has_ai or config.ai_provider == "ollama"):
            console.print("\n[bold red][!] Skipping Exploit Module: AI Analysis failed, so no exploit plan was generated.[/]")
        else:
            console.print("\n[bold red][!] --exploit requires --agent (AI) to be enabled to generate the exploit plan.[/]")
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
    if args.gen_fixes and (config.has_ai or config.ai_provider == "ollama") and "ai_analysis" in full_report:
        fix_gen = FixGenerator()
        sql_fixes = fix_gen.generate(full_report)
        fix_filename = os.path.join(output_dir, f"fixes_{timestamp}.sql")
        with open(fix_filename, "w", encoding="utf-8") as f:
            f.write(sql_fixes)
        console.print(f"\n[bold green]✔ SQL Fix Script saved: {fix_filename}[/]")
    elif args.gen_fixes and not (config.has_ai or config.ai_provider == "ollama"):
        console.print("\n[bold yellow][!] --gen-fixes requires --agent (AI) to be enabled.[/]")
    if args.ci:
        from core.ci import CIHandler
        ci_handler = CIHandler(fail_on=args.fail_on, format=args.ci_format)
        ci_handler.evaluate(full_report, diff_results)
if __name__ == "__main__":
    try: asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[bold red][-] Interrupted by user[/]")
