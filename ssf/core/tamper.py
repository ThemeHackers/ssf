import importlib .util 
import os 
from typing import Any 

class TamperManager :
    def __init__ (self ,tamper_script_path :str =None ):
        self .tamper_func =None 
        self .built_in_tampers ={
        "space2comment":self ._tamper_space2comment ,
        "base64encode":self ._tamper_base64encode ,
        "apostrophemask":self ._tamper_apostrophemask ,
        "between":self ._tamper_between ,
        "randomcase":self ._tamper_randomcase ,
        "charencode":self ._tamper_charencode ,
        "doubleencode":self ._tamper_doubleencode ,
        "unionall":self ._tamper_unionall ,
        "space2plus":self ._tamper_space2plus ,
        "version_comment":self ._tamper_version_comment 
        }
        if tamper_script_path :
            self .load_tamper_script (tamper_script_path )

    def load_tamper_script (self ,path :str ):
        """
        Loads a tamper script from the given path or name.
        """
        if path in self .built_in_tampers :
            self .tamper_func =self .built_in_tampers [path ]
            print (f"[*] Loaded built-in tamper: {path }")
            return 

        try :
            if not os .path .exists (path ):
                print (f"[!] Tamper script not found: {path }")
                return 

            spec =importlib .util .spec_from_file_location ("tamper_module",path )
            module =importlib .util .module_from_spec (spec )
            spec .loader .exec_module (module )

            if hasattr (module ,"tamper"):
                self .tamper_func =module .tamper 
                print (f"[*] Loaded tamper script: {path }")
            else :
                print (f"[!] Tamper script {path } does not contain a 'tamper' function.")
        except Exception as e :
            print (f"[!] Failed to load tamper script: {e }")

    def _tamper_space2comment (self ,payload :Any ,**kwargs )->Any :
        if isinstance (payload ,str ):
            return payload .replace (" ","/**/")
        return payload 

    def _tamper_base64encode (self ,payload :Any ,**kwargs )->Any :
        if isinstance (payload ,str ):
            import base64 
            return base64 .b64encode (payload .encode ()).decode ()
        return payload 

    def _tamper_apostrophemask (self ,payload :Any ,**kwargs )->Any :
        if isinstance (payload ,str ):
            return payload .replace ("'","%EF%BC%87")
        return payload 

    def _tamper_between (self ,payload :Any ,**kwargs )->Any :
        if isinstance (payload ,str ):
            return payload .replace (">"," NOT BETWEEN 0 AND ").replace ("="," BETWEEN ").replace ("<"," NOT BETWEEN 0 AND ")
        return payload 

    def _tamper_randomcase (self ,payload :Any ,**kwargs )->Any :
        if isinstance (payload ,str ):
            import random 
            return "".join (c .upper ()if random .choice ([True ,False ])else c .lower ()for c in payload )
        return payload 

    def _tamper_charencode (self ,payload :Any ,**kwargs )->Any :
        if isinstance (payload ,str ):
            import urllib .parse 
            return urllib .parse .quote (payload )
        return payload 

    def _tamper_doubleencode (self ,payload :Any ,**kwargs )->Any :
        if isinstance (payload ,str ):
            import urllib .parse 
            return urllib .parse .quote (urllib .parse .quote (payload ))
        return payload 

    def _tamper_unionall (self ,payload :Any ,**kwargs )->Any :
        if isinstance (payload ,str ):
            return payload .replace ("UNION SELECT","UNION ALL SELECT")
        return payload 

    def _tamper_space2plus (self ,payload :Any ,**kwargs )->Any :
        if isinstance (payload ,str ):
            return payload .replace (" ","+")
        return payload 

    def _tamper_version_comment (self ,payload :Any ,**kwargs )->Any :
        if isinstance (payload ,str ):
            return payload .replace (" ","/*!50000*/")
        return payload 

    def tamper (self ,payload :Any ,**kwargs )->Any :
        """
        Applies the tamper function to the payload.
        """
        if self .tamper_func :
            try :
                return self .tamper_func (payload ,**kwargs )
            except Exception as e :
                print (f"[!] Error executing tamper function: {e }")
                return payload 
        return payload 
