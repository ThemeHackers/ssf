import unittest
import os
import shutil
import asyncio
from ssf.scanners.sast import SASTScanner
from ssf.scanners.rpc import RPCScanner
from ssf.core.plugin_manager import PluginManager
from rich.console import Console

# Mock Console to suppress output during tests
console = Console(quiet=True)

class TestSSF(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.test_dir = "test_data"
        os.makedirs(self.test_dir, exist_ok=True)
        # Create a file with secrets
        with open(os.path.join(self.test_dir, "vulnerable.js"), "w") as f:
            f.write("const key = 'supabase_key = \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiIsImlhdCI6MTY3ODkwMTIzNH0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\"';\n")
            f.write("supabase.auth.admin.updateUserById(1, { email: 'admin@evil.com' });\n")

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_sast_scanner(self):
        print("\n[*] Testing SAST Scanner...")
        scanner = SASTScanner(self.test_dir)
        report = scanner.scan()
        findings = report["findings"]
        self.assertTrue(any(f["issue"] == "Hardcoded Supabase Key" for f in findings))
        self.assertTrue(any(f["issue"] == "Client-side Admin Auth Usage" for f in findings))
        print(f"    [+] SAST found {len(findings)} issues as expected.")

    def test_rpc_recursive_fuzz(self):
        print("\n[*] Testing RPC Recursive Fuzzing...")
        scanner = RPCScanner(None) # Mock client not needed for internal logic test
        data = {"a": {"b": [{"c": "val"}]}}
        payload = "FUZZ"
        fuzzed = scanner._recursive_fuzz(data, "c", payload)
        self.assertEqual(fuzzed["a"]["b"][0]["c"], "FUZZ")
        print("    [+] Recursive fuzzing replaced nested value correctly.")

    def test_plugin_loading(self):
        print("\n[*] Testing Plugin Loading...")
        pm = PluginManager(plugin_dir="ssf/plugins")
        plugins = pm.load_plugins("all")
        plugin_names = [p.__name__ for p in plugins]
        self.assertIn("StorageMalwareScanner", plugin_names)
        self.assertIn("AuthMisconfigScanner", plugin_names)
        print(f"    [+] Loaded plugins: {plugin_names}")

if __name__ == '__main__':
    unittest.main()
