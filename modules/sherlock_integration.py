# modules/sherlock_integration.py
import subprocess
from pathlib import Path
from .base_module import BaseOSINTModule
from .utils import ensure_directories

class SherlockIntegration(BaseOSINTModule):
    def __init__(self):
        super().__init__("SherlockIntegration")
        self.sherlock_path = Path("sherlock/sherlock_project/sherlock.py")

    async def scan_username(self, username: str, case_id: str, db, target_id: int):
        ensure_directories()
        print(f"[Sherlock] Scanning username: {username}")

        if not self.sherlock_path.exists():
            print("    ⚠️ Sherlock not found. Skipping cross-platform scan.")
            return

        try:
            result = subprocess.run([
                "python", str(self.sherlock_path),
                username,
                "--timeout", "20",
                "--print-found"
            ], capture_output=True, text=True, timeout=90)

            found = self._parse_output(result.stdout)
            data = {
                "username": username,
                "platforms_found": len(found),
                "found_sites": found[:15]
            }
            db.save_artifact(target_id, self.module_name, "username_correlation", data)
            print(f"    ✅ Sherlock found {len(found)} possible accounts")

        except Exception as e:
            print(f"    ⚠️ Sherlock scan failed: {e}")

    def _parse_output(self, output: str):
        found = []
        for line in output.splitlines():
            if "[+] " in line and "http" in line:
                try:
                    site = line.split("[+] ")[1].split(": Found")[0]
                    found.append(site.strip())
                except:
                    pass
        return found