import gzip
import json
from pathlib import Path

import pytest
from synthetic import graph_from_frames, office_frames

from netgrapher.export import ExportFormat, export_project
from netgrapher.project.format import FORMAT_VERSION, Project
from netgrapher.project.store import ProjectError, load, save


def office_project() -> Project:
    return Project(graph=graph_from_frames([f for _, f in office_frames()]))


def test_round_trip(tmp_path: Path) -> None:
    project = office_project()
    project.annotations["rtr:192.168.1.1"] = {"label": "Core GW"}
    path = tmp_path / "p.ngraph"
    save(project, path)
    loaded = load(path)
    assert loaded.to_dict() == project.to_dict()


def test_newer_version_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "p.ngraph"
    doc = office_project().to_dict() | {"version": FORMAT_VERSION + 1}
    path.write_bytes(gzip.compress(json.dumps(doc).encode()))
    with pytest.raises(ProjectError, match="newer"):
        load(path)


def test_not_a_project(tmp_path: Path) -> None:
    path = tmp_path / "p.ngraph"
    path.write_bytes(b"plain text")
    with pytest.raises(ProjectError):
        load(path)


def test_labels_and_hide_cascade_in_exports() -> None:
    project = office_project()
    project.annotations["rtr:192.168.1.1"] = {"label": "Core GW"}
    project.annotations["net:10.20.0.0/24"] = {"hidden": True}
    doc = json.loads(export_project(project, ExportFormat.JSON))
    nodes = {n["id"]: n for n in doc["nodes"]}
    assert nodes["rtr:192.168.1.1"]["label"] == "Core GW"
    assert "net:10.20.0.0/24" not in nodes
    assert "host:10.20.0.5" not in nodes  # hidden with its subnet
    assert not any("10.20.0.0" in link["target"] for link in doc["links"])
    full = json.loads(export_project(project, ExportFormat.JSON, include_hidden=True))
    assert "host:10.20.0.5" in {n["id"] for n in full["nodes"]}


@pytest.mark.parametrize("fmt", list(ExportFormat))
def test_every_export_format_renders(fmt: ExportFormat) -> None:
    import xml.etree.ElementTree as ET

    text = export_project(office_project(), fmt)
    if fmt in (ExportFormat.GRAPHML, ExportFormat.GEXF):
        ET.fromstring(text)
    elif fmt is ExportFormat.JSON:
        json.loads(text)
    else:
        assert text.startswith("graph netgrapher {")
    assert "192.168.1.0/24" in text
