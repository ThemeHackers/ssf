from typing import List, Dict
from core.base import BaseScanner
class StorageScanner(BaseScanner):
    async def scan(self) -> List[Dict]:
        results = []
        common_buckets = ["avatars", "files", "images", "public", "documents", "uploads", "assets"]
        for bucket in common_buckets:
            self.log(f"[*] Checking storage bucket: {bucket}", "cyan")
            url = f"/storage/v1/bucket/{bucket}"
            try:
                r = await self.client.get(url)
                if r.status_code == 200:
                    list_url = f"/storage/v1/object/list/{bucket}"
                    r_list = await self.client.post(list_url, json={"prefix": "", "limit": 1})
                    is_public = r_list.status_code == 200
                    results.append({
                        "name": bucket,
                        "exists": True,
                        "public": is_public
                    })
                    self.log(f"    [+] Found bucket: {bucket} (Public: {is_public})", "green")
            except:
                pass
        return results