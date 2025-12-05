import httpx 
import asyncio 
import random 
import os 
from itertools import cycle 
from .config import TargetConfig 

try :
    from curl_cffi .requests import AsyncSession 
    CURL_CFFI_AVAILABLE =True 
except ImportError :
    CURL_CFFI_AVAILABLE =False 

class SmartClient :
    def __init__ (self ,config :TargetConfig ,user_agent :str ):
        self .config =config 
        self .user_agent =user_agent 
        self .proxies =config .proxy_list 
        self .proxy_iter =cycle (self .proxies )if self .proxies else None 
        self .client =None 
        self .request_count =0 
        self .rotate_interval =10 
        self .headers ={
        "apikey":config .key ,
        "Authorization":f"Bearer {config .key }",
        "User-Agent":user_agent ,
        "Content-Type":"application/json"
        }

    async def _create_client (self ):
        proxy =next (self .proxy_iter )if self .proxy_iter else self .config .proxy 

        if self .config .stealth_mode :
            if not CURL_CFFI_AVAILABLE :
                raise ImportError ("curl_cffi is required for stealth mode. Install it with: pip install curl_cffi")


            return AsyncSession (
            base_url =self .config .url ,
            headers =self .headers ,
            timeout =self .config .timeout ,
            verify =False ,
            proxy =proxy ,
            impersonate ="chrome110"
            )
        else :

            return httpx .AsyncClient (
            base_url =self .config .url ,
            headers =self .headers ,
            timeout =self .config .timeout ,
            verify =False ,
            proxy =proxy 
            )

    async def _get_client (self ):
        if self .client and self .config .rotate_proxy and self .proxies and self .request_count >=self .rotate_interval :
            await self .aclose_client ()
            self .client =None 
            self .request_count =0 

        if not self .client :
            self .client =await self ._create_client ()

            self .client .config =self .config 

        return self .client 

    async def aclose_client (self ):
        if self .client :
            if hasattr (self .client ,"aclose"):
                await self .client .aclose ()
            elif hasattr (self .client ,"close"):




                if asyncio .iscoroutinefunction (self .client .close ):
                    await self .client .close ()
                else :
                    self .client .close ()

    async def request (self ,method ,url ,**kwargs ):
        retries =3 
        for i in range (retries ):
            try :
                client =await self ._get_client ()
                self .request_count +=1 
                return await client .request (method ,url ,**kwargs )
            except (httpx .ConnectError ,httpx .ReadTimeout ,httpx .ConnectTimeout )as e :
                if i ==retries -1 :
                    raise e 
                if self .proxies :
                    await self .aclose_client ()
                    self .client =None 
                    self .request_count =0 
            except Exception as e :
                if self .config .stealth_mode and CURL_CFFI_AVAILABLE :
                    from curl_cffi .requests import RequestsError 
                    if isinstance (e ,RequestsError ):
                        if i ==retries -1 :
                            raise e 
                        if self .proxies :
                            await self .aclose_client ()
                            self .client =None 
                            self .request_count =0 
                        continue 
                raise e 

    async def get (self ,url ,**kwargs ):return await self .request ("GET",url ,**kwargs )
    async def post (self ,url ,**kwargs ):return await self .request ("POST",url ,**kwargs )
    async def put (self ,url ,**kwargs ):return await self .request ("PUT",url ,**kwargs )
    async def delete (self ,url ,**kwargs ):return await self .request ("DELETE",url ,**kwargs )
    async def patch (self ,url ,**kwargs ):return await self .request ("PATCH",url ,**kwargs )
    async def head (self ,url ,**kwargs ):return await self .request ("HEAD",url ,**kwargs )
    async def options (self ,url ,**kwargs ):return await self .request ("OPTIONS",url ,**kwargs )

    @property 
    def base_url (self ):
        return self .config .url 

    async def aclose (self ):
        await self .aclose_client ()

class SessionManager :
    def __init__ (self ,config :TargetConfig ):
        self .config =config 
        user_agent ="SupabaseAudit/3.0"

        if config .random_agent :
            ua_file =os .path .join (os .path .dirname (__file__ ),"data","user_agents.txt")
            if os .path .exists (ua_file ):
                with open (ua_file ,"r")as f :
                    user_agents =[line .strip ()for line in f if line .strip ()]
            else :
                user_agents =[
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
                ]
            user_agent =random .choice (user_agents )

        self .smart_client =SmartClient (config ,user_agent )

    async def __aenter__ (self ):
        return self .smart_client 

    async def __aexit__ (self ,exc_type ,exc_val ,exc_tb ):
        await self .smart_client .aclose ()