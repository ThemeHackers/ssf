import os 
import os 
from pydantic import BaseModel ,Field 
from typing import Optional 
class TargetConfig (BaseModel ):
    url :str 
    key :str 
    ai_key :Optional [str ]=Field (default =None )
    ai_model :Optional [str ]=Field (default ="gemini-3-pro-preview")
    ai_provider :str ="gemini"
    proxy :Optional [str ]=Field (default =None )
    timeout :int =10 
    verbose :bool =False 
    sniff_duration :Optional [int ]=Field (default =None )
    check_config :bool =False 
    random_agent :bool =False 
    level :int =1 
    tamper :Optional [str ]=Field (default =None )
    proxy_list :Optional [list [str ]]=Field (default =None )
    rotate_proxy :bool =False 
    stealth_mode :bool =False 
    @property 
    def has_ai (self )->bool :
        return bool (self .ai_key )
class Wordlists :
    tables =[
    "users","profiles","admin","secrets","logs","transactions",
    "api_keys","migrations","user_secrets","audit_trail","payments",
    "orders","settings","config","internal","staff","employees",
    "roles","permissions","invoices","billing","customers"
    ]
    functions =[
    "hello","test","auth","user","payment","stripe","webhook",
    "email","send-email","notify","openai","ai","search","cron",
    "reset_password","invite_user","create_user","delete_user"
    ]
    buckets =[
    "avatars","files","images","public","documents","uploads","assets",
    "private","backup","logs","contracts","signatures"
    ]