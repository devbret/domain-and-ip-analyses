import json
from datetime import date, datetime
from pathlib import Path
from typing import Any


class EnhancedJSONEncoder(json.JSONEncoder):
    def default(self, obj: Any) -> Any:
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        return super().default(obj)


def to_pretty_json(data: Any) -> str:
    return json.dumps(data, cls=EnhancedJSONEncoder, indent=2, sort_keys=True, ensure_ascii=False)


def sanitize_target(s: str) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in s).strip("._-")


def write_report(outdir: str, target_hint: str, payload: Any) -> str:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe_target = sanitize_target(target_hint) or "report"
    path = Path(outdir)
    path.mkdir(parents=True, exist_ok=True)
    outfile = path / f"{safe_target}-{ts}.json"
    outfile.write_text(to_pretty_json(payload) + "\n", encoding="utf-8")
    return str(outfile)
