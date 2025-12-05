from typing import Dict ,Any 
from ssf.core .base import BaseScanner 
class OpenAPIScanner (BaseScanner ):
    async def scan (self )->Dict [str ,Any ]:
        self .log ("[*] Fetching OpenAPI Spec...","cyan")
        try :
            resp =await self .client .get ("/rest/v1/",headers ={"Accept":"application/json"})
            if resp .status_code ==200 :
                self .log ("    [+] Spec found!","green")
                return resp .json ()
        except Exception as e :
            self .log_error (e )
        return {}
    def parse_tables (self ,spec :Dict )->Dict [str ,Dict ]:
        tables ={}
        definitions =spec .get ("definitions",{})
        for schema_name ,details in definitions .items ():
            columns ={}
            pk ="id"
            if "description"in details and "<pk/>"in details ["description"]:
                pass 
            for col ,col_det in details .get ("properties",{}).items ():
                columns [col ]=col_det .get ("format",col_det .get ("type","string"))
                if "Primary Key"in col_det .get ("description",""):
                    pk =col 
            tables [schema_name ]={
            "columns":columns ,
            "pk":pk 
            }
        return tables 