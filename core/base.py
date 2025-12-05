from abc import ABC ,abstractmethod 
import httpx 
from rich .console import Console 
from typing import Dict ,Any 
class BaseScanner (ABC ):
    def __init__ (self ,client :httpx .AsyncClient ,verbose :bool =False ,context :Dict [str ,Any ]=None ):
        self .client =client 
        self .verbose =verbose 
        self .console =Console ()
        self .context =context if context is not None else {}
    @abstractmethod 
    async def scan (self )->Any :
        pass 
    def log (self ,message :str ,style :str =""):
        if self .verbose :
            self .console .print (f"[{style }]{message }[/{style }]"if style else message )

    def log_info (self ,message :str ):
        self .log (f"[INFO] {message }","blue")

    def log_warn (self ,message :str ):
        self .log (f"[WARN] {message }","yellow")

    def log_risk (self ,message :str ,level :str ="HIGH"):
        color ="red"if level =="CRITICAL"else "yellow"if level =="HIGH"else "blue"
        self .log (f"[RISK: {level }] {message }",f"bold {color }")

    def log_error (self ,error :Exception ):
        if self .verbose :
            self .console .print (f"[bold red][!] Error: {error }[/]")