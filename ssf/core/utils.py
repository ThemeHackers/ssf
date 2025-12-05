from typing import Dict ,Any 
def generate_smart_payload (columns :Dict [str ,str ])->Dict [str ,Any ]:
    payload ={}
    for col_name ,col_type in columns .items ():
        col_type =col_type .lower ()
        if col_name in ["created_at","updated_at","id"]:
            if "uuid"in col_type :
                payload [col_name ]="00000000-0000-0000-0000-000000000000"
            continue 
        if any (t in col_type for t in ["int","float","number"]):
            payload [col_name ]=1 
        elif "bool"in col_type :
            payload [col_name ]=True 
        elif "json"in col_type :
            payload [col_name ]={"audit_test":True ,"nested":{"level":1 },"tags":["admin","test"]}
        elif "array"in col_type :
            payload [col_name ]=[]
        elif any (t in col_type for t in ["date","time"]):
            payload [col_name ]="2025-01-01"
        elif "uuid"in col_type :
            payload [col_name ]="00000000-0000-0000-0000-000000000000"
        elif "inet"in col_type or "cidr"in col_type :
            payload [col_name ]="127.0.0.1"
        elif "macaddr"in col_type :
            payload [col_name ]="00:00:00:00:00:00"
        else :
            if "email"in col_name :
                payload [col_name ]="audit_test@example.com"
            else :
                payload [col_name ]="audit_test"
    return payload 
import os 
def get_code_files (path :str )->Dict [str ,Dict [str ,str ]]:
    code_files ={
    "sql":{},
    "app":{}
    }

    if os .path .isfile (path ):
        try :
            with open (path ,"r",encoding ="utf-8")as f :
                content =f .read ()
                if path .endswith (".sql"):
                    code_files ["sql"][os .path .basename (path )]=content 
                else :
                    code_files ["app"][os .path .basename (path )]=content 
        except Exception :pass 
        return code_files 

    ignore_dirs ={".git","node_modules","__pycache__",".venv","dist","build",".next",".nuxt","tests","__mocks__","fixtures"}
    sql_exts ={".sql"}
    app_exts ={".js",".ts",".jsx",".tsx",".py",".json",".toml"}

    for root ,dirs ,files in os .walk (path ):
        dirs [:]=[d for d in dirs if d not in ignore_dirs ]
        for file in files :
            full_path =os .path .join (root ,file )
            rel_path =os .path .relpath (full_path ,path )

            try :
                if os .path .getsize (full_path )<100 *1024 :
                    if any (file .endswith (ext )for ext in sql_exts ):
                        with open (full_path ,"r",encoding ="utf-8")as f :
                            code_files ["sql"][rel_path ]=f .read ()
                    elif any (file .endswith (ext )for ext in app_exts ):
                        with open (full_path ,"r",encoding ="utf-8")as f :
                            code_files ["app"][rel_path ]=f .read ()
            except Exception :pass 

    return code_files 