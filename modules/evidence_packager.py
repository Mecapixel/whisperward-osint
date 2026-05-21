# modules/evidence_packager.py
import zipfile
import json
import hashlib
from datetime import datetime
from pathlib import Path
from .utils import ensure_directories

def create_evidence_package(case_id: str):
    ensure_directories()
    print(f"[Evidence Packager] Creating package for case: {case_id}")

    export_dir = Path("exports")
    package_path = export_dir / f"{case_id}_evidence_package.zip"

    manifest = {
        "case_id": case_id,
        "generated_at": datetime.now().isoformat(),
        "package_version": "1.0",
        "files": [],
        "sha256_manifest": {}
    }

    try:
        with zipfile.ZipFile(package_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file_path in export_dir.glob("**/*"):
                if file_path.is_file() and file_path.name != package_path.name:
                    arcname = file_path.relative_to(export_dir)
                    zipf.write(file_path, arcname)
                    with open(file_path, 'rb') as f:
                        file_hash = hashlib.sha256(f.read()).hexdigest()
                    manifest["files"].append(str(arcname))
                    manifest["sha256_manifest"][str(arcname)] = file_hash

            manifest_path = export_dir / f"{case_id}_manifest.json"
            with open(manifest_path, 'w', encoding='utf-8') as f:
                json.dump(manifest, f, indent=2)
            zipf.write(manifest_path, f"{case_id}_manifest.json")
            manifest_path.unlink()

        print(f"✅ Evidence package created: {package_path}")
        return str(package_path)

    except Exception as e:
        print(f"❌ Error creating evidence package: {e}")
        return None