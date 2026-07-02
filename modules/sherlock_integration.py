# modules/sherlock_integration.py
import subprocess
from pathlib import Path
from .base_module import BaseOSINTModule
from .utils import ensure_directories
from .rate_limiter import api_limiter

class SherlockIntegration(BaseOSINTModule):
    def __init__(self):
        super().__init__("SherlockIntegration")
        self.sherlock_paths = [
            Path("sherlock/sherlock_project/sherlock.py"),
            Path("sherlock/sherlock/sherlock.py"),
            Path("sherlock/sherlock.py"),
            Path("sherlock_project/sherlock/sherlock.py"),
        ]

    async def scan_username(self, username: str, case_id: str, db, target_id: int):
        ensure_directories()
        print(f"[Sherlock] Scanning username: {username}")

        async with api_limiter:
            sherlock_script = None
            for path in self.sherlock_paths:
                if path.exists():
                    sherlock_script = path
                    print(f"    Found Sherlock at: {path}")
                    break

            if not sherlock_script:
                print("    ❌ Sherlock not found. Skipping.")
                return

            try:
                # Safe subprocess usage: arguments are passed as a list (never a
                # shell string) and shell=True is not used, so the username cannot
                # be interpreted by a shell. Verified during code review.
                result = subprocess.run([
                    "python", str(sherlock_script),
                    username,
                    "--timeout", "8",
                    "--print-found",
                    "--site", "Twitter",
                    "--site", "Instagram",
                    "--site", "Discord",
                    "--site", "Roblox",
                    "--site", "Reddit",
                    "--site", "TikTok",
                    "--site", "YouTube",
                    "--site", "Twitch"
                ], capture_output=True, text=True, timeout=90)

                found = self._parse_output(result.stdout)
                data = {
                    "username": username,
                    "platforms_found": len(found),
                    "found_sites": found[:20]
                }
                db.save_artifact(target_id, self.module_name, "username_correlation", data)
                print(f"    ✅ Sherlock found {len(found)} possible accounts")

            except subprocess.TimeoutExpired:
                print("    ⚠️ Sherlock timed out")
            except Exception as e:
                print(f"    ❌ Sherlock error: {e}")

    def _parse_output(self, output: str):
        found = []
        for line in output.splitlines():
            if "[+] " in line and "http" in line:
                try:
                    site = line.split("[+] ")[1].split(":")[0].strip()
                    found.append(site)
                except (IndexError, AttributeError):
                    # A malformed output line is skipped rather than aborting the
                    # parse of the remaining lines.
                    continue
        return found