from typing import Dict ,Any ,List 
from ssf.core .base import BaseScanner 
import urllib .parse 

class PostgRESTFuzzer (BaseScanner ):
    async def scan (self )->Dict [str ,Any ]:
        self .log_info ("[*] Starting PostgREST Filter Fuzzer...")
        result ={
        "vulnerabilities":[],
        "errors":[],
        "risk":"SAFE"
        }

        tables =self .context .get ("tables",[])
        if not tables :


            tables =["users","profiles","todos"]





        payloads =[
        ("eq","1' OR '1'='1"),
        ("eq","1::text::int"),
        ("in","(1,2,3)"),
        ("in","(1,2,3))))"),
        ("cs","{1,2}"),
        ("cs","{1,2"),
        ("not.eq","1"),
        ("not.and.eq","1"),
        ("select","*,count(*)"),
        ("ov","{1,2}"),
        ("sl","1"),
        ("sr","1"),
        ("nxl","1"),
        ("nxr","1"),
        ("adj","1"),
        ]

        for table in tables :
            if isinstance (table ,dict ):
                table_name =table .get ("name","users")
            else :
                table_name =table 

            self .log_info (f"    Fuzzing table: {table_name }")

            baseline_count =0 
            try :
                r =await self .client .get (f"/rest/v1/{table_name }",params ={"select":"count","limit":"1"},headers ={"Prefer":"count=exact"})
                if r .status_code ==200 :
                    baseline_count =int (r .headers .get ("Content-Range","0-0/0").split ("/")[-1 ])
            except :pass 

            for op ,val in payloads :
                try :
                    columns =["id","name","email","created_at"]

                    for col in columns :
                        query_param =f"{col }={op }.{val }"
                        if op =="select":
                            query_param =f"select={val }"

                        url =f"/rest/v1/{table_name }?{query_param }"
                        r =await self .client .get (url )

                        if r .status_code ==500 :
                            self .log_risk (f"    [!] 500 Error on {url }","medium")
                            result ["errors"].append (url )
                            result ["risk"]="MEDIUM"
                        elif "syntax error"in r .text .lower ():
                            self .log_risk (f"    [!] Syntax Error on {url }","HIGH")
                            result ["vulnerabilities"].append ({"url":url ,"type":"Syntax Error"})
                            result ["risk"]="HIGH"
                        elif r .status_code ==200 :
                            if op =="eq"and "OR '1'='1"in val :
                                try :
                                    rows =len (r .json ())
                                    if rows >0 and rows >=baseline_count :
                                        self .log_risk (f"    [!] Potential SQLi/Bypass on {url } (Rows: {rows })","HIGH")
                                        result ["vulnerabilities"].append ({"url":url ,"type":"Potential SQLi"})
                                        result ["risk"]="HIGH"
                                except :pass 
                except Exception :
                    pass 

        return result 
