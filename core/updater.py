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

    try :
        result =subprocess .run (
        ["git","pull"],
        capture_output =True ,
        text =True ,
        check =False 
        )

        if result .returncode ==0 :
            console .print (f"[green]{result .stdout .strip ()}[/]")
            console .print ("[bold green][✔] Update completed successfully![/]")
            console .print ("[dim]Please restart the tool to use the new version.[/]")
        else :
            console .print ("[bold red][!] Update failed:[/]")
            console .print (f"[red]{result .stderr .strip ()}[/]")

    except FileNotFoundError :
        console .print ("[bold red][!] 'git' command not found. Please install git to use this feature.[/]")
    except Exception as e :
        console .print (f"[bold red][!] An unexpected error occurred: {e }[/]")
