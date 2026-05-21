# modules/metadata_extractor.py
import hashlib
from pathlib import Path

class MetadataExtractor:
    def __init__(self):
        self.exiftool_available = False

    def analyze_image(self, image_path: str, target_id: int = None):
        """Extract metadata and hash from image"""
        path = Path(image_path)
        if not path.exists():
            return {"error": "File not found"}

        try:
            data = {
                "file_name": path.name,
                "file_size": path.stat().st_size,
                "sha256": self._sha256(path),
            }

            print(f"    ✅ Analyzed image: {path.name}")
            return data

        except Exception as e:
            return {"error": str(e)}

    def _sha256(self, filepath: Path) -> str:
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()