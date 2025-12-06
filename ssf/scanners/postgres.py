
from typing import Dict ,Any ,List 
import httpx 
from ssf.core .base import BaseScanner 
class DatabaseConfigurationScanner (BaseScanner ):
    async def scan (self )->Dict [str ,Any ]:
        self .log ("[*] Starting Deep Postgres/PostgREST Configuration Scan...","cyan")
        result ={
        "exposed_system_tables":[],
        "inferred_privileges":[],
        "config_issues":[],
        "risk":"SAFE"
        }
        system_tables =[
        "pg_settings","pg_roles","pg_shadow","pg_authid",
        "pg_config","pg_hba_file_rules","pg_stat_activity",
        "pg_proc","pg_namespace","pg_available_extensions",
        "pg_available_extension_versions","pg_extension",
        "pg_extension_config","pg_extension_config_map",
        ]
        for table in system_tables :
            endpoint =f"/rest/v1/{table }"
            try :
                r =await self .client .get (endpoint ,params ={"limit":1 })
                if r .status_code in [200 ,206 ]:
                    self .log (f"    [!] EXPOSED SYSTEM TABLE: {table }","bold red on white")
                    result ["exposed_system_tables"].append (table )
                    result ["risk"]="CRITICAL"
            except Exception as e :
                self .log_error (e )

        if "pg_settings"in result ["exposed_system_tables"]:
            try :
                self .log ("    [*] Checking Authentication & Connection Security...","cyan")

                r =await self .client .get ("/rest/v1/pg_settings",params ={"name":"eq.ssl","select":"setting"})
                if r .status_code ==200 :
                    settings =r .json ()
                    if settings and settings [0 ].get ("setting")=="off":
                        result ["config_issues"].append ("SSL is disabled (ssl=off)")
                        self .log ("    [!] ISSUE: SSL is disabled.","yellow")


                r =await self .client .get ("/rest/v1/pg_settings",params ={"name":"eq.superuser_reserved_connections","select":"setting"})
                if r .status_code ==200 :
                    settings =r .json ()
                    if settings and int (settings [0 ].get ("setting",3 ))<3 :
                        result ["config_issues"].append ("superuser_reserved_connections < 3")
                        self .log ("    [!] ISSUE: superuser_reserved_connections is too low.","yellow")
            except Exception as e :
                self .log_error (e )

        if "pg_hba_file_rules"in result ["exposed_system_tables"]:
            try :
                self .log ("    [*] Checking pg_hba.conf rules...","cyan")
                r =await self .client .get ("/rest/v1/pg_hba_file_rules",params ={"select":"type,auth_method"})
                if r .status_code ==200 :
                    rules =r .json ()
                    for rule in rules :
                        method =rule .get ("auth_method","")
                        type_ =rule .get ("type","")
                        if method in ["trust","password","md5"]:
                            result ["config_issues"].append (f"Weak auth method '{method }' found in pg_hba.conf")
                            self .log (f"    [!] ISSUE: Weak auth method '{method }' found.","yellow")
                        if type_ =="hostnossl":
                            result ["config_issues"].append ("hostnossl rule found (allows non-SSL connections)")
                            self .log ("    [!] ISSUE: hostnossl rule found.","yellow")
            except Exception as e :
                self .log_error (e )

        if "pg_settings"in result ["exposed_system_tables"]:
            try :
                self .log ("    [*] Checking Logging & Auditing configuration...","cyan")

                r =await self .client .get ("/rest/v1/pg_settings",params ={"name":"eq.log_statement","select":"setting"})
                if r .status_code ==200 :
                    settings =r .json ()
                    if settings and settings [0 ].get ("setting")=="none":
                        result ["config_issues"].append ("Statement logging is disabled (log_statement=none)")
                        self .log ("    [!] ISSUE: Statement logging is disabled.","yellow")


                r =await self .client .get ("/rest/v1/pg_settings",params ={"name":"eq.log_min_duration_statement","select":"setting"})
                if r .status_code ==200 :
                    settings =r .json ()
                    val =int (settings [0 ].get ("setting",-1 ))
                    if val ==-1 :
                        result ["config_issues"].append ("Slow query logging disabled (log_min_duration_statement=-1)")
                        self .log ("    [!] ISSUE: Slow query logging disabled.","yellow")

                for param in ["log_connections","log_disconnections"]:
                    r =await self .client .get ("/rest/v1/pg_settings",params ={"name":f"eq.{param }","select":"setting"})
                    if r .status_code ==200 :
                        settings =r .json ()
                        if settings and settings [0 ].get ("setting")=="off":
                            result ["config_issues"].append (f"{param } is disabled")
                            self .log (f"    [!] ISSUE: {param } is disabled.","yellow")
            except Exception as e :
                self .log_error (e )

        if "pg_settings"in result ["exposed_system_tables"]:
            try :
                self .log ("    [*] Checking global search_path configuration...","cyan")
                r =await self .client .get ("/rest/v1/pg_settings",params ={"name":"eq.search_path","select":"setting"})
                if r .status_code ==200 :
                    settings =r .json ()
                    if settings :
                        search_path =settings [0 ].get ("setting","")
                        self .log (f"    [i] Global search_path: {search_path }","blue")

                        paths =[p .strip ()for p in search_path .split (",")]
                        if "public"in paths :
                            result ["config_issues"].append (f"Insecure search_path: 'public' found in path ({search_path })")
                            self .log ("    [!] ISSUE: 'public' schema found in search_path. This can be risky.","yellow")
            except Exception as e :
                self .log_error (e )

        if "pg_proc"in result ["exposed_system_tables"]and "pg_namespace"in result ["exposed_system_tables"]:
            try :
                self .log ("    [*] Checking for vulnerable SECURITY DEFINER functions...","cyan")

                r =await self .client .get ("/rest/v1/pg_proc",params ={
                "prosecdef":"is.true",
                "select":"proname,proconfig,pronamespace"
                })

                if r .status_code ==200 :
                    funcs =r .json ()
                    vulnerable_funcs =[]
                    for f in funcs :
                        proname =f .get ("proname")
                        proconfig =f .get ("proconfig")


                        is_safe =False 
                        if proconfig :
                            for config in proconfig :
                                if config .startswith ("search_path="):
                                    is_safe =True 
                                    break 

                        if not is_safe :
                            vulnerable_funcs .append (proname )
                            self .log (f"    [!] VULNERABLE FUNCTION: {proname } (SECURITY DEFINER without fixed search_path)","bold red")

                    if vulnerable_funcs :
                        result ["config_issues"].append (f"Found {len (vulnerable_funcs )} SECURITY DEFINER functions without fixed search_path (CVE-2020-14349 risk): {', '.join (vulnerable_funcs [:5 ])}...")
                        result ["risk"]="CRITICAL"
                    else :
                        self .log ("    [+] No vulnerable SECURITY DEFINER functions found.","green")

            except Exception as e :
                self .log_error (e )

        if "pg_available_extensions"in result ["exposed_system_tables"]:
            try :
                self .log ("    [*] Checking for dangerous extensions...","cyan")
                dangerous_extensions =["adminpack","dblink","file_fdw","plpythonu","plperlu","lo","postgres_fdw"]
                r =await self .client .get ("/rest/v1/pg_available_extensions",params ={"installed_version":"not.is.null","select":"name,installed_version"})

                if r .status_code ==200 :
                    extensions =r .json ()
                    installed_exts =[e .get ("name")for e in extensions ]
                    for ext in dangerous_extensions :
                        if ext in installed_exts :
                            result ["config_issues"].append (f"Dangerous extension installed: {ext }")
                            self .log (f"    [!] ISSUE: Dangerous extension '{ext }' is installed.","bold red")
            except Exception as e :
                self .log_error (e )

        try :
            r =await self .client .get ("/")
            if r .status_code ==200 :
                data =r .json ()
                if "swagger"in data or "openapi"in data :
                    info =data .get ("info",{})
                    desc =info .get ("description","")
                    if "PostgREST"in desc :
                         result ["config_issues"].append (f"PostgREST version exposed in root: {info .get ('version','unknown')}")
        except :pass 
        try :
            r =await self .client .get ("/rest/v1/",params ={"limit":0 },headers ={"Prefer":"count=exact"})
            if "Content-Range"in r .headers :
                pass 
        except :pass 

        if self .client .config .check_config :
            self .log ("[*] Checking PostgREST max_rows configuration...","cyan")

            target_table =None 
            if result ["exposed_system_tables"]:
                target_table =result ["exposed_system_tables"][0 ]
            elif self .context .get ("rls_findings"):

                 for finding in self .context .get ("rls_findings"):
                     if finding .get ("read"):
                         target_table =finding .get ("table")
                         break 

            if target_table :
                try :

                    limit =10000 
                    self .log (f"    [*] Testing max_rows on table '{target_table }' with limit={limit }...","cyan")
                    r =await self .client .get (f"/rest/v1/{target_table }",params ={"select":"*","limit":limit })
                    if r .status_code ==200 :
                        rows =r .json ()
                        count =len (rows )
                        if count >=limit :
                            self .log (f"    [!] HIGH RISK: max_rows seems very high or unlimited! (Returned {count } rows)","bold red")
                            result ["config_issues"].append (f"Potential DoS: max_rows >= {limit }")
                        else :
                            self .log (f"    [+] max_rows check: SAFE. Returned {count } rows (Limit request: {limit })","green")
                    else :
                        self .log (f"    [!] max_rows check failed: HTTP {r .status_code }","yellow")
                except Exception as e :
                    self .log_error (e )
            else :
                self .log ("    [!] Skipping max_rows check: No readable table found to test against.","yellow")
        if result ["exposed_system_tables"]:
            result ["inferred_privileges"].append ("Possible Superuser/High Privilege (System Tables Exposed)")
        return result 