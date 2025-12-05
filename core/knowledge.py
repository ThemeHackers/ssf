import json 
import re 
from typing import Dict ,List ,Optional 
class KnowledgeBase :
    def __init__ (self ):
        self .rules =[]
    def load (self ,path :str )->bool :
        try :
            with open (path ,'r',encoding ='utf-8')as f :
                data =json .load (f )
                self .rules =data .get ("accepted_risks",[])
            return True 
        except Exception as e :
            print (f"[!] Error loading knowledge base: {e }")
            return False 
    def save (self ,path :str )->bool :
        try :
            with open (path ,'w',encoding ='utf-8')as f :
                json .dump ({"accepted_risks":self .rules },f ,indent =2 )
            return True 
        except Exception as e :
            print (f"[!] Error saving knowledge base: {e }")
            return False 
    def verify_remediation (self ,findings :Dict [str ,List [Dict ]])->List [str ]:
        updates =[]
        for rule in self .rules :
            rule_type =rule .get ("type")
            pattern =rule .get ("pattern")
            found =False 
            targets =[]
            if rule_type =="*"or rule_type =="rls":
                targets .extend ([f .get ("table","")for f in findings .get ("rls",[])])
            if rule_type =="*"or rule_type =="rpc":
                targets .extend ([f .get ("name","")for f in findings .get ("rpc",[])])
            if rule_type =="*"or rule_type =="storage":
                targets .extend ([f .get ("name","")for f in findings .get ("storage",[])])
            for t in targets :
                if re .fullmatch (pattern ,t ):
                    found =True 
                    break 
            old_status =rule .get ("status","active")
            new_status ="active"if found else "remediated"
            if old_status !=new_status :
                rule ["status"]=new_status 
                updates .append (f"Rule '{pattern }' ({rule_type }) changed from {old_status } to {new_status }")
        return updates 
    def is_accepted (self ,finding :Dict ,finding_type :str )->Optional [str ]:
        target_name =""
        if finding_type =="rls":
            target_name =finding .get ("table","")
        elif finding_type =="storage":
            target_name =finding .get ("name","")
        elif finding_type =="rpc":
            target_name =finding .get ("name","")
        elif finding_type =="functions":
            target_name =finding .get ("name","")
        elif finding_type =="realtime":
            pass 
        if not target_name :
            return None 
        for rule in self .rules :
            if rule .get ("type")!=finding_type and rule .get ("type")!="*":
                continue 
            pattern =rule .get ("pattern","")
            try :
                if re .fullmatch (pattern ,target_name ):
                    return rule .get ("reason","Accepted Risk")
            except re .error :
                continue 
        return None 