"""In-memory + file-backed scan store (lightweight; no DB needed)."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, List, Optional

from app.schemas.policy import ScanRecord

ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = Path(os.getenv("SCAN_STORE_DIR", str(ROOT / "reports" / "scans")))
DATA_DIR.mkdir(parents=True, exist_ok=True)

_mem: Dict[str, ScanRecord] = {}


def save(scan: ScanRecord) -> None:
    _mem[scan.scan_id] = scan
    try:
        (DATA_DIR / f"{scan.scan_id}.json").write_text(scan.model_dump_json(indent=2), encoding="utf-8")
    except Exception:
        pass


def get(scan_id: str) -> Optional[ScanRecord]:
    if scan_id in _mem:
        return _mem[scan_id]
    p = DATA_DIR / f"{scan_id}.json"
    if p.exists():
        try:
            scan = ScanRecord.model_validate(json.loads(p.read_text(encoding="utf-8")))
            _mem[scan_id] = scan
            return scan
        except Exception:
            return None
    return None


def list_all() -> List[ScanRecord]:
    # merge disk + memory
    try:
        for f in DATA_DIR.glob("*.json"):
            if f.stem not in _mem:
                try:
                    _mem[f.stem] = ScanRecord.model_validate(json.loads(f.read_text(encoding="utf-8")))
                except Exception:
                    continue
    except Exception:
        pass
    return sorted(_mem.values(), key=lambda s: s.created_at, reverse=True)
