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
from ssf.core .config import TargetConfig 
from ssf.core .scanner_manager import ScannerManager 
from ssf.core .knowledge import KnowledgeBase 
from ssf.core .exploit import run_exploit 
import secrets
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
import base64

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

        self .stop_requested =False 
        self .auth_credentials = None

state =AppState ()

class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if not state.auth_credentials:
            return await call_next(request)

        if request.url.path == "/favicon.ico":
             return await call_next(request)

        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Basic "):
            return Response(
                status_code=401,
                headers={"WWW-Authenticate": "Basic"},
                content="Unauthorized"
            )

        try:
            encoded_creds = auth_header.split(" ")[1]
            decoded_bytes = base64.b64decode(encoded_creds)
            decoded_str = decoded_bytes.decode("utf-8")
            username, password = decoded_str.split(":", 1)
            
            expected_user, expected_pass = state.auth_credentials
            
            is_user_correct = secrets.compare_digest(username, expected_user)
            is_pass_correct = secrets.compare_digest(password, expected_pass)
            
            if not (is_user_correct and is_pass_correct):
                return Response(
                    status_code=401,
                    headers={"WWW-Authenticate": "Basic"},
                    content="Invalid credentials"
                )
        except Exception:
             return Response(
                status_code=401,
                headers={"WWW-Authenticate": "Basic"},
                content="Invalid authentication header"
            )
            
        return await call_next(request)

app.add_middleware(AuthMiddleware)


class ScanConfig (BaseModel ):
    url :str 
    key :str 
    ai_provider :str ="gemini"
    ai_model :str ="gemini-2.5-flash"
    ai_key :Optional [str ]=None 
    level :int =1 
    sniff_duration :int =10 
    plugins :Optional [str ]=None 
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
            knowledge = DEFAULT_KNOWLEDGE_PATH
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
            skip_realtime =not config .modules .get ("realtime",True )
            skip_postgres =not config .modules .get ("postgres",True )
            plugins =config .plugins 

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
                from ssf.core .ai import AIAgent 
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

def safe_join(base: str, *paths: str) -> str:
    """
    Safely join paths ensuring the result is within the base directory.
    """
    try:
        base = os.path.abspath(base)
        final_path = os.path.abspath(os.path.join(base, *paths))
        if os.path.commonpath([base, final_path]) != base:
            raise ValueError("Path traversal attempt detected")
        return final_path
    except Exception:
        raise ValueError("Invalid path")

@app.get("/api/status")
def get_status():
    error_msg = None
    if state.last_error:
        error_msg = "An error occurred during the scan. Check server logs for details."
        
    return {
        "is_scanning": state.is_scanning,
        "status": state.scan_status,
        "progress": state.scan_progress,
        "error": error_msg,
        "session_id": state.session_id,
        "logs": state.logs[-50:]
    }

@app.post("/api/scan/start")
async def start_scan(config: ScanConfig, background_tasks: BackgroundTasks):
    if state.is_scanning:
        raise HTTPException(status_code=400, detail="Scan already in progress")

    background_tasks.add_task(run_scan_task, config)
    return {"message": "Scan started"}

@app.post("/api/scan/stop")
async def stop_scan():
    if not state.is_scanning:
        raise HTTPException(status_code=400, detail="No scan in progress")

    state.stop_requested = True
    state.scan_status = "Stopping..."
    return {"message": "Stop requested"}

@app.get("/api/report/latest")
async def get_latest_report():
    if not state.current_report:
        try:
            reports_dir = "reports"
            if os.path.exists(reports_dir):
                scans = sorted([os.path.join(reports_dir, d) for d in os.listdir(reports_dir) if d.startswith("scan_")], key=os.path.getmtime, reverse=True)
                if scans:
                    latest_scan_dir = scans[0]
                    for f in os.listdir(latest_scan_dir):
                        if f.endswith(".json"):
                            with open(os.path.join(latest_scan_dir, f), "r") as rf:
                                state.current_report = json.load(rf)
                                break
        except Exception:
            pass

    if not state.current_report:
        return {}
    return state.current_report

@app.post("/api/risk/accept")
async def accept_risk(acceptance: RiskAcceptance):
    kb = KnowledgeBase()
    kb.load(DEFAULT_KNOWLEDGE_PATH)

    parts = acceptance.finding_id.split(":", 1)
    if len(parts) != 2:
        raise HTTPException(status_code=400, detail="Invalid finding ID format")

    risk_type, identifier = parts

    existing_rule = None
    for rule in kb.rules:
        if rule.get("type") == risk_type and rule.get("pattern") == identifier:
            existing_rule = rule
            break

    if existing_rule:
        existing_rule["reason"] = acceptance.reason
        existing_rule["timestamp"] = "now"
        existing_rule["user"] = "web-admin"
    else:
        kb.rules.append({
            "type": risk_type,
            "pattern": identifier,
            "reason": acceptance.reason,
            "timestamp": "now",
            "user": "web-admin",
            "status": "active"
        })

    kb.save(DEFAULT_KNOWLEDGE_PATH)
    return {"message": "Risk accepted"}

@app.get("/api/history")
async def get_history():
    reports_dir = "reports"
    if not os.path.exists(reports_dir):
        return []

    scans = []
    for d in os.listdir(reports_dir):
        if d.startswith("scan_") or d.startswith("web_scan_"):
            path = os.path.join(reports_dir, d)
            try:
                timestamp = int(d.split("_")[-1])
                report_file = None
                for f in os.listdir(path):
                    if f.endswith(".json") and not f.startswith("exploit"):
                        report_file = f
                        break

                if report_file:
                    scans.append({
                        "id": d,
                        "timestamp": timestamp,
                        "date": os.path.getmtime(path),
                        "path": path
                    })
            except:
                pass

    scans.sort(key=lambda x: x["timestamp"], reverse=True)
    return scans

@app.delete("/api/history/{scan_id}")
async def delete_history(scan_id: str):
    import re
    if not re.match(r'^[\w-]+$', scan_id):
        raise HTTPException(status_code=400, detail="Invalid scan ID format")
    reports_dir = os.path.abspath("reports")
    try:
        scan_path = safe_join(reports_dir, scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan ID")

    if os.path.exists(scan_path) and os.path.isdir(scan_path):
        import shutil
        try:
            shutil.rmtree(scan_path)
            return {"message": "Scan deleted successfully"}
        except Exception as e:
             raise HTTPException(status_code=500, detail=f"Failed to delete scan: {str(e)}")
    else:
        raise HTTPException(status_code=404, detail="Scan not found")

@app.get("/api/report/{scan_id}")
async def get_report(scan_id: str):
    import re
    if not re.match(r'^[\w-]+$', scan_id):
        raise HTTPException(status_code=400, detail="Invalid scan ID format")
    reports_dir = os.path.abspath("reports")
    try:
        report_path = safe_join(reports_dir, scan_id, "report.json")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan ID")

    if os.path.exists(report_path):
        try:
            with open(report_path, "r") as f:
                data = json.load(f)
                data["scan_id"] = scan_id
                return data
        except:
            raise HTTPException(status_code=500, detail="Failed to load report")
    raise HTTPException(status_code=404, detail="Report not found")

@app.get("/api/dumps")
async def list_dumps():
    reports_dir = "reports"
    dumps = []

    if not os.path.exists(reports_dir):
        return []

    for scan_id in os.listdir(reports_dir):
        scan_path = os.path.join(reports_dir, scan_id)
        dumps_path = os.path.join(scan_path, "dumps")

        if os.path.isdir(dumps_path):
            scan_files = []
            for f in os.listdir(dumps_path):
                file_path = os.path.join(dumps_path, f)
                if os.path.isfile(file_path):
                    scan_files.append({
                        "name": f,
                        "size": os.path.getsize(file_path),
                        "path": file_path
                    })

            if scan_files:
                timestamp = 0
                try:
                    timestamp = int(scan_id.split("_")[-1])
                except: pass

                dumps.append({
                    "scan_id": scan_id,
                    "timestamp": timestamp,
                    "files": scan_files
                })

    dumps.sort(key=lambda x: x["timestamp"], reverse=True)
    return dumps

@app.get("/api/download/{scan_id}/{filename}")
async def download_dump(scan_id: str, filename: str):
    import re
    if not re.match(r'^[\w-]+$', scan_id) or '..' in filename or '/' in filename or '\\' in filename:
         raise HTTPException(status_code=400, detail="Invalid parameters")
    filename = os.path.basename(filename)
    reports_dir = os.path.abspath("reports")
    

    full_path = os.path.join(reports_dir, scan_id, "dumps", filename)
    full_path = os.path.abspath(full_path)
    
    expected_base = os.path.abspath(os.path.join(reports_dir, scan_id, "dumps"))
    
    if os.path.commonpath([expected_base, full_path]) != expected_base:
        raise HTTPException(status_code=400, detail="Path traversal detected")
        
    file_path = full_path

    if os.path.exists(file_path) and os.path.isfile(file_path):
        from fastapi.responses import FileResponse
        return FileResponse(file_path, filename=filename)

    raise HTTPException(status_code=404, detail="File not found")

@app.get("/api/risks")
async def get_risks():
    kb = KnowledgeBase()
    kb.load(DEFAULT_KNOWLEDGE_PATH)


    grouped = {}
    for rule in kb.rules:
        rtype = rule.get("type", "unknown")
        if rtype not in grouped:
            grouped[rtype] = {}
        rid = rule.get("pattern", "unknown")
        grouped[rtype][rid] = rule
    return grouped

@app.get("/api/exploits")
def get_exploits(scan_id: str = None):
    import re
    if scan_id and not re.match(r'^[\w-]+$', scan_id):
        raise HTTPException(status_code=400, detail="Invalid scan ID format")
    reports_dir = os.path.abspath("reports")
    target_dir = None

    if scan_id:
        try:
            target_dir = safe_join(reports_dir, scan_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid scan ID")
    elif state.current_report:

        target_ts = state.current_report.get("timestamp")
        if os.path.exists(reports_dir):
            for d in os.listdir(reports_dir):
                path = os.path.join(reports_dir, d)
                for f in os.listdir(path):
                    if f.endswith(".json") and not f.startswith("exploit"):
                        try:
                            with open(os.path.join(path, f), "r") as rf:
                                data = json.load(rf)
                                if data.get("timestamp") == target_ts:
                                    target_dir = path
                                    break
                        except: pass
                if target_dir: break

    if target_dir:
        exploit_file = os.path.join(target_dir, "exploit_generated.json")
        if os.path.exists(exploit_file):
            with open(exploit_file, "r") as f:
                return json.load(f)

    return {"exploits": []}

class ExploitRequest(BaseModel):
    overrides: List[Dict[str, Any]] = []

@app.post("/api/exploit/run")
async def run_exploit_endpoint(req: ExploitRequest, background_tasks: BackgroundTasks):
    if not state.current_report:
         raise HTTPException(status_code=400, detail="No report loaded")

    target_ts = state.current_report.get("timestamp")
    reports_dir = "reports"
    found_dir = None

    if os.path.exists(reports_dir):
        for d in os.listdir(reports_dir):
            path = os.path.join(reports_dir, d)
            for f in os.listdir(path):
                if f.endswith(".json") and not f.startswith("exploit"):
                    try:
                        with open(os.path.join(path, f), "r") as rf:
                            data = json.load(rf)
                            if data.get("timestamp") == target_ts:
                                found_dir = path
                                break
                    except:
                        pass
            if found_dir: break

    if not found_dir:
        raise HTTPException(status_code=404, detail="Report directory not found")

    background_tasks.add_task(run_exploit, auto_confirm=True, output_dir=found_dir, overrides=req.overrides)
    return {"message": "Exploit execution started"}

@app.get("/api/exploit/results")
def get_exploit_results(scan_id: str = None):
    import re
    if scan_id and not re.match(r'^[\w-]+$', scan_id):
        raise HTTPException(status_code=400, detail="Invalid scan ID format")
    reports_dir = os.path.abspath("reports")
    target_dir = None

    if scan_id:
        try:
            target_dir = safe_join(reports_dir, scan_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid scan ID")
    elif state.current_report:
        target_ts = state.current_report.get("timestamp")
        if os.path.exists(reports_dir):
            for d in os.listdir(reports_dir):
                path = os.path.join(reports_dir, d)
                for f in os.listdir(path):
                    if f.endswith(".json") and not f.startswith("exploit"):
                        try:
                            with open(os.path.join(path, f), "r") as rf:
                                data = json.load(rf)
                                if data.get("timestamp") == target_ts:
                                    target_dir = path
                                    break
                        except: pass
                if target_dir: break

    if target_dir:
        results_file = os.path.join(target_dir, "exploit_results.json")
        if os.path.exists(results_file):
            with open(results_file, "r") as f:
                return json.load(f)

    return []

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
PACKAGE_ROOT = os.path.dirname(BASE_DIR)
DEFAULT_KNOWLEDGE_PATH = os.path.join(PACKAGE_ROOT, "knowledge.json")

os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")


def run_server(port=8080, open_browser=True, use_ngrok=False, auth_credentials=None):
    

    if use_ngrok and not auth_credentials:
    
        gen_user = "admin"
        gen_pass = secrets.token_urlsafe(16)
        state.auth_credentials = (gen_user, gen_pass)
        print(f"\n[!] Ngrok Enabled but no auth provided. Generated secure credentials:")
        print(f"    Username: {gen_user}")
        print(f"    Password: {gen_pass}\n")
    elif auth_credentials:
        if ":" in auth_credentials:
            user, pwd = auth_credentials.split(":", 1)
            state.auth_credentials = (user, pwd)
            print(f"[*] Web UI Authentication Enabled (User: {user})")
        else:
            print("[!] Invalid auth format. Use username:password. Starting without auth.")

    if use_ngrok:
        try:
            from pyngrok import ngrok, conf
            
           
            ngrok_token = os.getenv("NGROK_AUTHTOKEN")
            if ngrok_token:
                conf.get_default().auth_token = ngrok_token
                
            public_url = ngrok.connect(port).public_url
            print(f"\n[+] Ngrok Tunnel Established: {public_url}")
            if state.auth_credentials:
               
                 print(f"[+] Login required at: {public_url}\n")
                 
            if open_browser:
                webbrowser.open(public_url)
                open_browser = False 
                
        except ImportError:
            print("[!] pyngrok not installed. Install with: pip install pyngrok")
        except Exception as e:
            print(f"[!] Ngrok Error: {e}")

    if open_browser:
        webbrowser.open(f"http://localhost:{int(port)}")

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
