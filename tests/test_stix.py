import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pipeline  # noqa: E402
import stix_builder  # noqa: E402

FIXTURE = Path(__file__).parent / "fixtures" / "kev_sample.json"
FROZEN = datetime(2026, 11, 5, 6, 0, tzinfo=UTC)


@pytest.fixture()
def catalog():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def by_type(bundle, name):
    return [obj for obj in bundle["objects"] if obj["type"] == name]


def test_mapping_contract_one_object_per_entry(catalog):
    bundle = stix_builder.build_bundle(catalog, FROZEN)
    vulnerabilities = by_type(bundle, "vulnerability")
    notes = by_type(bundle, "note")
    reports = by_type(bundle, "report")
    identities = by_type(bundle, "identity")

    assert len(vulnerabilities) == catalog["count"] == 3
    assert len(notes) == 3
    assert len(reports) == 1
    assert len(identities) == 1
    assert len(bundle["objects"]) == 8
    assert {v["name"] for v in vulnerabilities} == {
        "CVE-2024-0001",
        "CVE-2023-0002",
        "CVE-2022-0003",
    }


def test_report_references_every_vulnerability(catalog):
    bundle = stix_builder.build_bundle(catalog, FROZEN)
    report = by_type(bundle, "report")[0]
    vulnerability_ids = {v["id"] for v in by_type(bundle, "vulnerability")}
    assert set(report["object_refs"]) == vulnerability_ids
    assert report["name"] == "CISA KEV 2026.11.04"
    assert report["published"].startswith("2026-11-04")


def test_note_carries_action_due_date_and_ransomware_flag(catalog):
    bundle = stix_builder.build_bundle(catalog, FROZEN)
    note = next(
        n for n in by_type(bundle, "note") if "CVE-2024-0001" in n["content"]
    )
    assert "Required action: Apply the vendor update." in note["content"]
    assert "Due date: 2026-11-18" in note["content"]
    assert "Known ransomware campaign use: Known" in note["content"]
    assert note["object_refs"][0].startswith("vulnerability--")


def test_ids_are_deterministic(catalog):
    first = stix_builder.build_bundle(catalog, FROZEN)
    second = stix_builder.build_bundle(catalog, FROZEN)
    assert [o["id"] for o in first["objects"]] == [o["id"] for o in second["objects"]]
    assert stix_builder.stable_id("vulnerability", "CVE-2024-0001") == (
        stix_builder.stable_id("vulnerability", "CVE-2024-0001")
    )
    assert stix_builder.stable_id("vulnerability", "CVE-2024-0001") != (
        stix_builder.stable_id("vulnerability", "CVE-2024-0002")
    )


def test_external_reference_points_at_nvd(catalog):
    bundle = stix_builder.build_bundle(catalog, FROZEN)
    vulnerability = by_type(bundle, "vulnerability")[0]
    reference = vulnerability["external_references"][0]
    assert reference["source_name"] == "cve"
    assert reference["url"].startswith("https://nvd.nist.gov/vuln/detail/CVE-")


def test_count_mismatch_is_rejected(catalog):
    catalog["count"] = 4
    with pytest.raises(ValueError, match="declares 4"):
        stix_builder.build_bundle(catalog, FROZEN)


def test_summary_counts_and_latest_order(catalog):
    bundle = stix_builder.build_bundle(catalog, FROZEN)
    summary = pipeline.summarize(catalog, bundle)
    assert summary["entries"] == 3
    assert summary["objects"] == 8
    assert summary["objects_by_type"] == {
        "identity": 1,
        "note": 3,
        "report": 1,
        "vulnerability": 3,
    }
    assert summary["ransomware"] == {"Known": 1, "Unknown": 2}
    assert summary["latest"][0]["cve"] == "CVE-2024-0001"
    assert summary["top_vendors"][0] == ("Acme", 1)
    assert ("CWE-78", 1) in summary["top_cwes"]


def test_dashboard_is_self_contained(catalog, monkeypatch, tmp_path):
    monkeypatch.setattr(pipeline, "DOCS", tmp_path)
    bundle = stix_builder.build_bundle(catalog, FROZEN)
    summary = pipeline.summarize(catalog, bundle)
    pipeline.dashboard(summary)
    html = (tmp_path / "index.html").read_text(encoding="utf-8")
    assert "CISA KEV" in html
    assert "CVE-2024-0001" in html
    assert "<script" not in html
    assert (tmp_path / "summary.json").exists()


def test_timestamp_parser_handles_date_and_zulu():
    fallback = FROZEN
    assert stix_builder._timestamp("2026-11-04", fallback).isoformat() == (
        "2026-11-04T00:00:00+00:00"
    )
    assert stix_builder._timestamp("2026-11-04T20:00:05.774Z", fallback).year == 2026
    assert stix_builder._timestamp("garbage", fallback) == fallback
