from rich .console import Console 
from rich .prompt import Prompt ,Confirm 

console =Console ()

def run_wizard ():
    """
    Runs an interactive wizard to configure the scan.
    Returns a dictionary of arguments.
    """
    console .print (Panel ("[bold cyan]Supabase Security Framework - Wizard Mode[/]",border_style ="cyan"))
    console .print ("This wizard will guide you through setting up a scan.\n")

    args ={}

    while True :
        args ['url']=Prompt .ask ("[bold green]Target URL[/]")
        if args ['url'].startswith ("http://")or args ['url'].startswith ("https://"):
            break 
        console .print ("[red]URL must start with http:// or https://[/]")

    while True :
        args ['key']=Prompt .ask ("[bold green]Anon Key[/]")
        if args ['key'].strip ():
            break 
        console .print ("[red]Anon Key cannot be empty[/]")

    if Confirm .ask ("Enable AI Analysis? (Requires Gemini API Key)"):
        args ['agent']=Prompt .ask ("Gemini API Key (or model:key)")
    else :
        args ['agent']=None 

    if Confirm .ask ("Enable Bruteforce for hidden tables?"):
        args ['brute']="default"
    else :
        args ['brute']=None 

    args ['level']=int (Prompt .ask ("Scan Level (1-5)",default ="1"))

    if Confirm .ask ("Use Random User-Agent?"):
        args ['random_agent']=True 
    else :
        args ['random_agent']=False 

    if Confirm .ask ("Generate HTML Report?"):
        args ['html']=True 
    else :
        args ['html']=False 

    if Confirm .ask ("Save results to JSON?"):
        args ['json']=True 
    else :
        args ['json']=False 

    if Confirm .ask ("Enable Verbose Logging?"):
        args ['verbose']=True 
    else :
        args ['verbose']=False 

    console .print ("\n[bold green]Configuration Complete![/]")
    return args 

from rich .panel import Panel 
