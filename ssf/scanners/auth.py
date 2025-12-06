from typing import Dict ,Any 
from ssf.core .base import BaseScanner 
class AuthScanner (BaseScanner ):
    async def scan (self )->Dict [str ,Any ]:
        self .log ("[*] Checking for Auth Leaks...","cyan")
        leaked_users =[]
        try :
            r =await self .client .get ("/rest/v1/auth/users",params ={"select":"*","limit":10 })
            if r .status_code ==200 :
                users =r .json ()
                if users :
                    leaked_users .extend (users )
                    self .log (f"    [!] LEAKED: auth.users table is public! ({len (users )} users found)","bold red")
        except Exception as e :
            self .log_error (e )
        try :
            r =await self .client .get ("/rest/v1/auth/identities",params ={"select":"*","limit":10 })
            if r .status_code ==200 :
                identities =r .json ()
                if identities :
                    leaked_users .extend (identities )
                    self .log (f"    [!] LEAKED: auth.identities table is public! ({len (identities )} identities found)","bold red")
        except Exception as e :
            self .log_error (e )
        if leaked_users :
            user_ids =set ()
            for u in leaked_users :
                if "id"in u :user_ids .add (u ["id"])
                if "user_id"in u :user_ids .add (u ["user_id"])
            self .context ["users"]=list (user_ids )
            if self .context ["users"]:
                self .log (f"    [+] Captured {len (self .context ['users'])} User IDs for context.","green")

        if self .client .config .level >=2 :
            self .log ("[*] Checking extra Auth endpoints (Level 2+)...","cyan")
            extra_endpoints =["/rest/v1/auth/audit_log_entries","/rest/v1/auth/schema_migrations","/rest/v1/auth/instances"]
            for ep in extra_endpoints :
                try :
                    r =await self .client .get (ep ,params ={"limit":1 })
                    if r .status_code ==200 :
                         self .log (f"    [!] LEAKED: {ep } is public!","bold red")
                except :pass 

        await self ._test_weak_password ()
        await self ._test_rate_limiting ()
        await self ._test_mfa_exposure ()
        return {
        "leaked":len (leaked_users )>0 ,
        "count":len (leaked_users ),
        "details":leaked_users [:5 ]
        }
    async def _test_weak_password (self ):
        self .log ("    [*] Testing Password Policy...","cyan")
        email ="ssf_test_weak@example.com"
        passwords =["123"]

        if self .client .config .level >=3 :
            passwords .extend (["password","123456","qwerty","admin"])

        for password in passwords :
            try :
                r =await self .client .post ("/auth/v1/signup",json ={"email":email ,"password":password })
                if r .status_code ==200 :
                    self .log (f"    [!] WEAK PASSWORD POLICY: Allowed password '{password }'","bold red")
                    break 
                elif r .status_code ==422 or r .status_code ==400 :
                    if "password"in r .text .lower ()and "length"in r .text .lower ():
                        self .log ("    [+] Password policy seems active (length check)","green")
                        break 
            except Exception as e :
                self .log_error (e )
    async def _test_rate_limiting (self ):
        self .log ("    [*] Testing Login Rate Limiting...","cyan")
        email ="ssf_test_rate@example.com"
        password ="wrongpassword"
        blocked =False 
        for i in range (10 ):
            try :
                r =await self .client .post ("/auth/v1/token?grant_type=password",json ={"email":email ,"password":password })
                if r .status_code ==429 :
                    blocked =True 
                    self .log (f"    [+] Rate Limiting Active (Blocked after {i +1 } requests)","green")
                    break 
            except Exception as e :
                self .log_error (e )
        if not blocked :
             self .log ("    [!] NO RATE LIMITING detected on login endpoint (10 bursts allowed)","yellow")
    async def _test_mfa_exposure (self ):
        self .log ("    [*] Checking MFA Configuration...","cyan")
        try :
            r =await self .client .post ("/auth/v1/factors",json ={"friendly_name":"test"})
            if r .status_code !=401 :
                self .log (f"    [!] WARNING: MFA Enrollment endpoint accessible (Status: {r .status_code })","yellow")
        except Exception as e :
            self .log_error (e )