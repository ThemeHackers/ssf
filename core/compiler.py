import subprocess
import sys
import os
import platform
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
console = Console()
class Compiler:
    def __init__(self):
        self.os_name = platform.system().lower()
    def compile(self):
        console.print(f"[bold cyan][*] Starting compilation for {self.os_name}...[/]")
        cmd = [
            "pyinstaller",
            "--noconfirm",
            "--onefile",
            "--clean",
            "--name", "ssf",
            "--hidden-import", "rich",
            "--hidden-import", "httpx",
            "--hidden-import", "pydantic",
            "ssf.py"
        ]
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("[cyan]Initializing PyInstaller...", total=None)
                while True:
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    if output:
                        line = output.strip()
                        if line:
                            progress.update(task, description=f"[cyan]{line}")
            if process.returncode == 0:
                console.print("\n[bold green]✔ Compilation Successful![/]")
                dist_path = os.path.join("dist", "ssf")
                if self.os_name == "windows":
                    dist_path += ".exe"
                console.print(f"[green]    Executable created at: {dist_path}[/]")
            else:
                console.print("\n[bold red]❌ Compilation Failed![/]")
                console.print(process.stderr.read())
        except Exception as e:
            console.print(f"[bold red]❌ Error: {e}[/]")