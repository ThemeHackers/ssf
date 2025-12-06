import asyncio
import os 
from typing import List 
from ssf.core .base import BaseScanner 
from ssf.core .config import Wordlists 
from rich .table import Table 

class BruteScanner (BaseScanner ):
    def __init__ (self ,client ,verbose =False ,context =None ,wordlist_path =None ):
        super ().__init__ (client ,verbose ,context )
        self .wordlist_path =wordlist_path 
        self .common_tables =self ._load_wordlist ()
    def _load_wordlist(self) -> List[str]:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        default_path = os.path.join(base_dir, "table_lists.txt")
        
        path = default_path
        if self.wordlist_path and self.wordlist_path != "default" and not isinstance(self.wordlist_path, bool):
            path = self.wordlist_path
            self.log_info(f"[*] Using custom wordlist: {path}")

        try:
            with open(path, "r") as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            self.log_warn(f"Wordlist not found at {path} (Base: {base_dir}), falling back to default list.")
            return Wordlists.tables 

    async def scan (self )->List [str ]:
        self .log_info ("[*] Starting table bruteforce...")
        tasks =[self ._check (t )for t in self .common_tables ]
        results =[t for t in await asyncio .gather (*tasks )if t ]
        if results :
            self .log_risk (f"    [+] Discovered {len (results )} hidden tables!","HIGH")

            table =Table (title ="Discovered Hidden Tables",expand =True )
            table .add_column ("Table Name",style ="cyan")
            table .add_column ("Status",justify ="center",style ="green")

            for res in results :
                table .add_row (res ,"FOUND")

            self .console .print (table )
            self .console .print ("\n")

        return results 

    async def _check (self ,table :str )->str :
        try :
            r =await self .client .head (f"/rest/v1/{table }")
            if r .status_code !=404 :return table 
        except Exception as e :
            self .log_error (e )
        return None 