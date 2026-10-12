"""Golden test: the office capture must keep producing the same project.

Regenerate after an intended change with: NETGRAPHER_UPDATE_GOLDEN=1 pytest tests/golden
and review the diff of office.json.
"""

import json
import os
from pathlib import Path
from typing import Any

from synthetic import office_frames, write_pcap

from netgrapher.discover import run_file

GOLDEN = Path(__file__).parent / "office.json"


def normalized(doc: dict[str, Any]) -> dict[str, Any]:
    doc = {k: v for k, v in doc.items() if k not in ("created", "modified", "tool_version")}
    doc["runs"] = [
        {k: v for k, v in run.items() if k not in ("analyzed", "input")} for run in doc["runs"]
    ]
    return doc


def test_office_golden(tmp_path: Path) -> None:
    pcap = tmp_path / "office.pcap"
    write_pcap(pcap, office_frames())
    actual = normalized(run_file(pcap).to_dict())
    if os.environ.get("NETGRAPHER_UPDATE_GOLDEN"):
        GOLDEN.write_text(json.dumps(actual, indent=2, sort_keys=True) + "\n")
    expected = json.loads(GOLDEN.read_text())
    assert json.loads(json.dumps(actual)) == expected
