from rich.console import Console
from rich.panel import Panel
from rich.text import Text
def show_banner(console: Console):
    banner_art = r"""
  _________ ____________________
 /   _____//   _____/\_   _____/
 \_____  \ \_____  \  |    __)  
 /        \/        \ |     \   
/_______  /_______  / \___  /   
        \/        \/      \/    
"""
    description = "ssf is a supabase security framework that checks the security of your supabase system where most of the developers tend to forget important settings or leave too much anon privileges causing vulnerabilities."
    console.print(f"[bold cyan]{banner_art}[/]")
    console.print(Panel(description, border_style="cyan", title="Supabase Security Framework", subtitle="v1.0"))