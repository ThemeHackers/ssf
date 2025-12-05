import os 
import subprocess 
import sys 
from rich .console import Console 

console =Console ()

def update_tool ():
    """
    Updates the tool by pulling the latest changes from the git repository.
    """
    console .print ("[bold cyan][*] Checking for updates...[/]")

    if not os .path .exists (".git"):
        console .print ("[bold red][!] Not a git repository. Cannot auto-update.[/]")
        console .print ("[yellow]Please download the latest version manually from the repository.[/]")
        sys .exit (1 )

    try:

        console.print("[cyan][*] Fetching latest changes...[/]")
        fetch_result = subprocess.run(
            ["git", "fetch", "origin"],
            capture_output=True,
            text=True,
            check=False
        )

        if fetch_result.returncode != 0:
            console.print("[bold red][!] Fetch failed:[/]")
            console.print(f"[red]{fetch_result.stderr.strip()}[/]")
            return


        console.print("[cyan][*] Resetting local changes...[/]")
        reset_result = subprocess.run(
            ["git", "reset", "--hard", "origin/main"],
            capture_output=True,
            text=True,
            check=False
        )

        if reset_result.returncode == 0:
            console.print(f"[green]{reset_result.stdout.strip()}[/]")
            console.print("[bold green][✔] Update completed successfully![/]")
            console.print("[dim]All local changes have been discarded. Please restart the tool.[/]")
        else:
            console.print("[bold red][!] Reset failed:[/]")
            console.print(f"[red]{reset_result.stderr.strip()}[/]")

    except FileNotFoundError :
        console .print ("[bold red][!] 'git' command not found. Please install git to use this feature.[/]")
    except Exception as e :
        console .print (f"[bold red][!] An unexpected error occurred: {e }[/]")
