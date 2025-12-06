import subprocess 
import sys 
import os 
import platform 
from rich .console import Console 
from rich .progress import Progress ,SpinnerColumn ,TextColumn 
console =Console ()
class Compiler :
    def __init__ (self ):
        self .os_name =platform .system ().lower ()
    def compile (self ):
        console .print (f"[bold cyan][*] Starting compilation for {self .os_name }...[/]")
        cmd =[
        "pyinstaller",
        "--noconfirm",
        "--onefile",
        "--clean",
        "--name","ssf",
        "--hidden-import","rich",
        "--hidden-import","httpx",
        "--hidden-import","pydantic",
        "--exclude-module","matplotlib",
        "--exclude-module","tkinter",
        "--exclude-module","notebook",
        "--exclude-module","scipy",
        "--exclude-module","pandas",
        "--exclude-module","numpy",
        "--noupx",
        "ssf.py"
        ]
        try :
            process =subprocess .Popen (
            cmd ,
            stdout =subprocess .PIPE ,
            stderr =subprocess .PIPE ,
            text =True 
            )
            with Progress (
            SpinnerColumn (),
            TextColumn ("[progress.description]{task.description}"),
            console =console 
            )as progress :
                task =progress .add_task ("[cyan]Initializing PyInstaller...",total =None )
                while True :
                    output =process .stdout .readline ()
                    if output ==''and process .poll ()is not None :
                        break 
                    if output :
                        line =output .strip ()
                        if line :
                            progress .update (task ,description =f"[cyan]{line }")
            if process .returncode ==0 :
                console .print ("\n[bold green]✔ Compilation Successful![/]")


                import shutil 
                dist_path =os .path .join ("dist","ssf")
                if self .os_name =="windows":
                    dist_path +=".exe"

                dest_path =os .path .join (os .getcwd (),"ssf")
                if self .os_name =="windows":
                    dest_path +=".exe"

                if os .path .exists (dist_path ):
                    if os .path .exists (dest_path ):
                        try :
                            os .remove (dest_path )
                        except OSError :
                            pass 
                    shutil .move (dist_path ,dest_path )
                    console .print (f"[green]    Executable moved to: {dest_path }[/]")


                    if self .os_name !="windows":
                        os .chmod (dest_path ,0o755 )
                else :
                    console .print (f"[red]    Could not find compiled binary at {dist_path }[/]")


                console .print ("[cyan]    Cleaning up build artifacts...[/]")
                dirs_to_remove =["build","dist"]
                for d in dirs_to_remove :
                    if os .path .exists (d ):
                        shutil .rmtree (d )

                if os .path .exists ("ssf.spec"):
                    os .remove ("ssf.spec")

                for root ,dirs ,files in os .walk ("."):
                    for d in dirs :
                        if d =="__pycache__":
                            shutil .rmtree (os .path .join (root ,d ))

            else :
                console .print ("\n[bold red]❌ Compilation Failed![/]")
                console .print (process .stderr .read ())
        except Exception as e :
            console .print (f"[bold red]❌ Error: {e }[/]")