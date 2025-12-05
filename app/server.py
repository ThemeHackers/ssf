import os 
import json 
import asyncio 
import uvicorn 
import webbrowser 
import uuid 
from typing import Optional ,Dict ,List ,Any 
from fastapi import FastAPI ,HTTPException ,BackgroundTasks 
from fastapi .staticfiles import StaticFiles 
from fastapi .middleware .cors import CORSMiddleware 
from pydantic import BaseModel 
from core .config import TargetConfig 
from core .scanner_manager import ScannerManager 
from core .knowledge import KnowledgeBase 
from core .exploit import run_exploit 

app =FastAPI (title ="Supabase Security Framework API",version ="3.0")

app .add_middleware (
CORSMiddleware ,
allow_origins =["*"],
allow_credentials =True ,
allow_methods =["*"],
allow_headers =["*"],
)

class AppState :
    def __init__ (self ):
        self .is_scanning =False 
        self .current_report =None 
        self .scan_progress =0 
        self .scan_status ="Idle"
        self .last_error =None 
        self .session_id =str (uuid .uuid4 ())
        self .logs =[]
        self .stop_requested =False 

state =AppState ()

class ScanConfig (BaseModel ):
    url :str 
    key :str 
    ai_provider :str ="gemini"
    ai_model :str ="gemini-2.5-flash"
    ai_key :Optional [str ]=None 
    level :int =1 
    sniff_duration :int =10 
    modules :Dict [str ,bool ]={}

class RiskAcceptance (BaseModel ):
    finding_id :str 
    reason :str 

async def run_scan_task (config :ScanConfig ):
    state .is_scanning =True 
    state .scan_status ="Initializing..."
    state .scan_progress =10 
    state .last_error =None 
    state .stop_requested =False 

    try :
        target_config =TargetConfig (
        url =config .url .strip (),
        key =config .key .strip (),
        ai_key =config .ai_key .strip ()if config .ai_key else None ,
        ai_model =config .ai_model ,
        ai_provider =config .ai_provider ,
        level =config .level ,
        sniff_duration =config .sniff_duration ,
        verbose =True 
        )

        class Args :
            knowledge ="knowledge.json"
            roles =None 
            edge_rpc =True 
            brute =True 
            dump_all =True 
            verify_fix =True 
            skip_rls =not config .modules .get ("rls",True )
            skip_auth =not config .modules .get ("auth",True )
            skip_storage =not config .modules .get ("storage",True )
            skip_rpc =not config .modules .get ("rpc",True )
            skip_realtime =not config .modules .get ("realtime",True )
            skip_postgres =not config .modules .get ("postgres",True )

        args =Args ()

        state .scan_status ="Scanning..."
        state .scan_progress =30 

        import time 
        start_time =time .time ()
        output_dir =f"reports/web_scan_{int (start_time )}"
        os .makedirs (output_dir ,exist_ok =True )

        def update_progress (p ):
            state .scan_progress =p 

        scanner_mgr =ScannerManager (target_config ,args ,output_dir =output_dir ,logger_callback =lambda log :state .logs .append (log ),progress_callback =update_progress ,stop_callback =lambda :state .stop_requested )

        report =await scanner_mgr .run ()

        if config .ai_provider and config .ai_key and "ai_analysis"in report :
            try :
                from core .ai import AIAgent 
                agent =AIAgent (api_key =config .ai_key ,model_name =config .ai_model )

                ai_input =report ["findings"]
                ai_input ["target"]=config .url 
                ai_input ["accepted_risks"]=report .get ("accepted_risks",[])

                print ("Generating Threat Model...")
                tm_report =await agent .generate_threat_model (ai_input )

                if "error"not in tm_report :
                    report ["threat_model"]=tm_report 
                    print ("Threat Model Generated!")
                else :
                    print (f"Threat Model Error: {tm_report ['error']}")
            except Exception as e :
                print (f"Failed to generate threat model: {e }")


        end_time =time .time ()
        report ["duration"]=end_time -start_time 
        report ["config"]=config .dict ()

        with open (os .path .join (output_dir ,"report.json"),"w")as f :
             json .dump (report ,f ,indent =2 )

        state .current_report =report 
        state .scan_status ="Complete"
        state .scan_progress =100 

    except Exception as e :
        state .last_error =str (e )
        state .scan_status ="Failed"
        state .scan_progress =0 
        print (f"Scan failed: {e }")
    finally :
        state .is_scanning =False 

@app .get ("/api/status")
def get_status ():
    return {
    "is_scanning":state .is_scanning ,
    "status":state .scan_status ,
    "progress":state .scan_progress ,
    "error":state .last_error ,
    "session_id":state .session_id ,
    "logs":state .logs [-50 :]
    }

@app .post ("/api/scan/start")
async def start_scan (config :ScanConfig ,background_tasks :BackgroundTasks ):
    if state .is_scanning :
        raise HTTPException (status_code =400 ,detail ="Scan already in progress")

    background_tasks .add_task (run_scan_task ,config )
    return {"message":"Scan started"}

@app .post ("/api/scan/stop")
async def stop_scan ():
    if not state .is_scanning :
        raise HTTPException (status_code =400 ,detail ="No scan in progress")

    state .stop_requested =True 
    state .scan_status ="Stopping..."
    return {"message":"Stop requested"}

@app .get ("/api/report/latest")
async def get_latest_report ():
    if not state .current_report :
        try :
            reports_dir ="reports"
            if os .path .exists (reports_dir ):
                scans =sorted ([os .path .join (reports_dir ,d )for d in os .listdir (reports_dir )if d .startswith ("scan_")],key =os .path .getmtime ,reverse =True )
                if scans :
                    latest_scan_dir =scans [0 ]
                    for f in os .listdir (latest_scan_dir ):
                        if f .endswith (".json"):
                            with open (os .path .join (latest_scan_dir ,f ),"r")as rf :
                                state .current_report =json .load (rf )
                                break 
        except Exception :
            pass 

    if not state .current_report :
        return {}
    return state .current_report 

@app .post ("/api/risk/accept")
async def accept_risk (acceptance :RiskAcceptance ):
    kb =KnowledgeBase ()
    kb .load ("knowledge.json")

    parts =acceptance .finding_id .split (":",1 )
    if len (parts )!=2 :
        raise HTTPException (status_code =400 ,detail ="Invalid finding ID format")

    risk_type ,identifier =parts 

    existing_rule =None 
    for rule in kb .rules :
        if rule .get ("type")==risk_type and rule .get ("pattern")==identifier :
            existing_rule =rule 
            break 

    if existing_rule :
        existing_rule ["reason"]=acceptance .reason 
        existing_rule ["timestamp"]="now"
        existing_rule ["user"]="web-admin"
    else :
        kb .rules .append ({
        "type":risk_type ,
        "pattern":identifier ,
        "reason":acceptance .reason ,
        "timestamp":"now",
        "user":"web-admin",
        "status":"active"
        })

    kb .save ("knowledge.json")
    return {"message":"Risk accepted"}

@app .get ("/api/history")
async def get_history ():
    reports_dir ="reports"
    if not os .path .exists (reports_dir ):
        return []

    scans =[]
    for d in os .listdir (reports_dir ):
        if d .startswith ("scan_")or d .startswith ("web_scan_"):
            path =os .path .join (reports_dir ,d )
            try :
                timestamp =int (d .split ("_")[-1 ])
                report_file =None 
                for f in os .listdir (path ):
                    if f .endswith (".json")and not f .startswith ("exploit"):
                        report_file =f 
                        break 

                if report_file :
                    scans .append ({
                    "id":d ,
                    "timestamp":timestamp ,
                    "date":os .path .getmtime (path ),
                    "path":path 
                    })
            except :
                pass 

    scans .sort (key =lambda x :x ["timestamp"],reverse =True )
    return scans 

@app .delete ("/api/history/{scan_id}")
async def delete_history (scan_id :str ):

    if ".."in scan_id or "/"in scan_id or "\\"in scan_id :
        raise HTTPException (status_code =400 ,detail ="Invalid scan ID")

    reports_dir ="reports"
    scan_path =os .path .join (reports_dir ,scan_id )

    if os .path .exists (scan_path )and os .path .isdir (scan_path ):
        import shutil 
        try :
            shutil .rmtree (scan_path )
            return {"message":"Scan deleted successfully"}
        except Exception as e :
             raise HTTPException (status_code =500 ,detail =f"Failed to delete scan: {str (e )}")
    else :
        raise HTTPException (status_code =404 ,detail ="Scan not found")

@app .get ("/api/report/{scan_id}")
async def get_report (scan_id :str ):
    reports_dir ="reports"
    report_path =os .path .join (reports_dir ,scan_id ,"report.json")

    if os .path .exists (report_path ):
        try :
            with open (report_path ,"r")as f :
                data =json .load (f )
                data ["scan_id"]=scan_id 
                return data 
        except :
            raise HTTPException (status_code =500 ,detail ="Failed to load report")
    raise HTTPException (status_code =404 ,detail ="Report not found")

@app .get ("/api/dumps")
async def list_dumps ():
    reports_dir ="reports"
    dumps =[]

    if not os .path .exists (reports_dir ):
        return []

    for scan_id in os .listdir (reports_dir ):
        scan_path =os .path .join (reports_dir ,scan_id )
        dumps_path =os .path .join (scan_path ,"dumps")

        if os .path .isdir (dumps_path ):
            scan_files =[]
            for f in os .listdir (dumps_path ):
                file_path =os .path .join (dumps_path ,f )
                if os .path .isfile (file_path ):
                    scan_files .append ({
                    "name":f ,
                    "size":os .path .getsize (file_path ),
                    "path":file_path 
                    })

            if scan_files :
                timestamp =0 
                try :
                    timestamp =int (scan_id .split ("_")[-1 ])
                except :pass 

                dumps .append ({
                "scan_id":scan_id ,
                "timestamp":timestamp ,
                "files":scan_files 
                })

    dumps .sort (key =lambda x :x ["timestamp"],reverse =True )
    return dumps 

@app .get ("/api/download/{scan_id}/{filename}")
async def download_dump (scan_id :str ,filename :str ):
    if ".."in scan_id or ".."in filename or "/"in scan_id or "/"in filename :
        raise HTTPException (status_code =400 ,detail ="Invalid path")

    file_path =os .path .join ("reports",scan_id ,"dumps",filename )

    if os .path .exists (file_path )and os .path .isfile (file_path ):
        from fastapi .responses import FileResponse 
        return FileResponse (file_path ,filename =filename )

    raise HTTPException (status_code =404 ,detail ="File not found")

@app .get ("/api/risks")
async def get_risks ():
    kb =KnowledgeBase ()
    kb .load ("knowledge.json")

    grouped ={}
    for rule in kb .rules :
        rtype =rule .get ("type","unknown")
        if rtype not in grouped :
            grouped [rtype ]={}
        rid =rule .get ("pattern","unknown")
        grouped [rtype ][rid ]=rule 
    return grouped 

@app .get ("/api/exploits")
def get_exploits (scan_id :str =None ):
    reports_dir ="reports"
    target_dir =None 

    if scan_id :
        target_dir =os .path .join (reports_dir ,scan_id )
    elif state .current_report :

        target_ts =state .current_report .get ("timestamp")
        if os .path .exists (reports_dir ):
            for d in os .listdir (reports_dir ):
                path =os .path .join (reports_dir ,d )
                for f in os .listdir (path ):
                    if f .endswith (".json")and not f .startswith ("exploit"):
                        try :
                            with open (os .path .join (path ,f ),"r")as rf :
                                data =json .load (rf )
                                if data .get ("timestamp")==target_ts :
                                    target_dir =path 
                                    break 
                        except :pass 
                if target_dir :break 

    if target_dir :
        exploit_file =os .path .join (target_dir ,"exploit_generated.json")
        if os .path .exists (exploit_file ):
            with open (exploit_file ,"r")as f :
                return json .load (f )

    return {"exploits":[]}

class ExploitRequest (BaseModel ):
    overrides :List [Dict [str ,Any ]]=[]

@app .post ("/api/exploit/run")
async def run_exploit_endpoint (req :ExploitRequest ,background_tasks :BackgroundTasks ):
    if not state .current_report :
         raise HTTPException (status_code =400 ,detail ="No report loaded")

    target_ts =state .current_report .get ("timestamp")
    reports_dir ="reports"
    found_dir =None 

    if os .path .exists (reports_dir ):
        for d in os .listdir (reports_dir ):
            path =os .path .join (reports_dir ,d )
            for f in os .listdir (path ):
                if f .endswith (".json")and not f .startswith ("exploit"):
                    try :
                        with open (os .path .join (path ,f ),"r")as rf :
                            data =json .load (rf )
                            if data .get ("timestamp")==target_ts :
                                found_dir =path 
                                break 
                    except :
                        pass 
            if found_dir :break 

    if not found_dir :
        raise HTTPException (status_code =404 ,detail ="Report directory not found")

    background_tasks .add_task (run_exploit ,auto_confirm =True ,output_dir =found_dir ,overrides =req .overrides )
    return {"message":"Exploit execution started"}

@app .get ("/api/exploit/results")
def get_exploit_results (scan_id :str =None ):
    reports_dir ="reports"
    target_dir =None 

    if scan_id :
        target_dir =os .path .join (reports_dir ,scan_id )
    elif state .current_report :
        target_ts =state .current_report .get ("timestamp")
        if os .path .exists (reports_dir ):
            for d in os .listdir (reports_dir ):
                path =os .path .join (reports_dir ,d )
                for f in os .listdir (path ):
                    if f .endswith (".json")and not f .startswith ("exploit"):
                        try :
                            with open (os .path .join (path ,f ),"r")as rf :
                                data =json .load (rf )
                                if data .get ("timestamp")==target_ts :
                                    target_dir =path 
                                    break 
                        except :pass 
                if target_dir :break 

    if target_dir :
        results_file =os .path .join (target_dir ,"exploit_results.json")
        if os .path .exists (results_file ):
            with open (results_file ,"r")as f :
                return json .load (f )

    return []

os .makedirs ("app/static",exist_ok =True )
app .mount ("/",StaticFiles (directory ="app/static",html =True ),name ="static")

def run_server (port =8080 ,open_browser =True ):
    if open_browser :
        webbrowser .open (f"http://localhost:{port }")

    config =uvicorn .Config (app ,host ="0.0.0.0",port =port )
    server =uvicorn .Server (config )

    try :
        loop =asyncio .get_running_loop ()
    except RuntimeError :
        loop =None 

    if loop and loop .is_running ():
        return server .serve ()
    else :
        server .run ()
