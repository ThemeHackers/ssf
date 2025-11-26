import asyncio
import json
import websockets
from typing import Dict, Any
from core.base import BaseScanner
class RealtimeScanner(BaseScanner):
    async def scan(self) -> Dict[str, Any]:
        self.log("[*] Checking Supabase Realtime...", "cyan")
        base_host = str(self.client.base_url).replace("https://", "").replace("http://", "").split("/")[0]
        ws_url = f"wss://{base_host}/realtime/v1/websocket?apikey={self.client.headers.get('apikey')}&vsn=1.0.0"
        result = {"connected": False, "channels": [], "risk": "SAFE"}
        channels_to_test = ["realtime:*", "*", "public:*", "room:*"]
        
        risky_tables = [t["table"] for t in self.context.get("rls_findings", []) if t.get("risk") in ["CRITICAL", "HIGH"]]
        for table in risky_tables:
            channels_to_test.append(f"realtime:{table}")
            channels_to_test.append(f"{table}")
            channels_to_test.append(f"public:{table}")
            
        self.log(f"    [*] Testing {len(channels_to_test)} channels (including {len(risky_tables)} dynamic targets)...", "cyan")
        try:
            async with websockets.connect(ws_url) as ws:
                result["connected"] = True
                self.log("    [+] Realtime WebSocket Connected", "green")
                for channel in channels_to_test:
                    payload = {
                        "topic": channel,
                        "event": "phx_join",
                        "payload": {},
                        "ref": "1"
                    }
                    await ws.send(json.dumps(payload))
                    try:
                        resp = await asyncio.wait_for(ws.recv(), timeout=3.0)
                        resp_json = json.loads(resp)
                        if resp_json.get("event") == "phx_reply" and resp_json.get("payload", {}).get("status") == "ok":
                            result["channels"].append(channel)
                            self.log(f"    [!] Joined Channel: {channel}", "bold red")
                    except asyncio.TimeoutError:
                        pass
        except Exception as e:
            self.log_error(e)
        if result["channels"]:
            result["risk"] = "HIGH"
        return result
