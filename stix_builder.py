"""Turn the CISA Known Exploited Vulnerabilities catalog into STIX 2.1.

Mapping contract (asserted by the tests and by pipeline.py):

  * one ``vulnerability`` SDO per KEV entry, named after the CVE
  * one ``note`` per KEV entry carrying the required action, due date and
    ransomware flag, referencing its vulnerability
  * one ``report`` per run referencing every vulnerability
  * one ``identity`` describing this pipeline
  * every ID is derived with UUIDv5 from stable input, so two runs over the
    same catalog produce byte-identical output except for the report timestamp

Nothing is invented: every property comes from the feed or from the mapping
above.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import stix2

NAMESPACE = uuid.UUID("6f1c5f0a-3d8e-5b1a-9c2e-6b4d7a8f0c11")
IDENTITY_ID = f"identity--{uuid.uuid5(NAMESPACE, 'identity:kev-to-stix')}"
NVD_URL = "https://nvd.nist.gov/vuln/detail/{cve}"


def stable_id(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(NAMESPACE, f'{kind}:{key}')}"


def _timestamp(value: str, fallback: datetime) -> datetime:
    if not value:
        return fallback
    text = value if "T" in value else f"{value}T00:00:00"
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return fallback
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def identity(created: datetime) -> Any:
    return stix2.Identity(
        id=IDENTITY_ID,
        created=created,
        modified=created,
        name="kev-to-stix",
        identity_class="system",
        description=(
            "Converts the CISA Known Exploited Vulnerabilities catalog to STIX 2.1."
        ),
    )


def build_bundle(catalog: dict[str, Any], generated_at: datetime | None = None) -> dict[str, Any]:
    """Build a STIX bundle from a parsed KEV catalog."""
    entries = catalog.get("vulnerabilities") or []
    declared = catalog.get("count")
    if declared is not None and int(declared) != len(entries):
        raise ValueError(f"feed declares {declared} entries but contains {len(entries)}")

    generated_at = generated_at or datetime.now(UTC)
    released = _timestamp(str(catalog.get("dateReleased", "")), generated_at)

    objects: list[Any] = [identity(generated_at)]
    vulnerability_ids: list[str] = []
    for entry in entries:
        cve = entry["cveID"]
        added = _timestamp(str(entry.get("dateAdded", "")), released)
        vuln_id = stable_id("vulnerability", cve)
        vulnerability_ids.append(vuln_id)
        objects.append(
            stix2.Vulnerability(
                id=vuln_id,
                created=added,
                modified=added,
                created_by_ref=IDENTITY_ID,
                name=cve,
                description=(
                    f"{entry.get('vendorProject', '')} {entry.get('product', '')}: "
                    f"{entry.get('vulnerabilityName', '')}. "
                    f"{entry.get('shortDescription', '')}"
                ).strip(),
                external_references=[
                    stix2.ExternalReference(
                        source_name="cve",
                        external_id=cve,
                        url=NVD_URL.format(cve=cve),
                    )
                ],
                confidence=100,
            )
        )
        ransomware = entry.get("knownRansomwareCampaignUse", "Unknown")
        cwes = ", ".join(entry.get("cwes") or []) or "none listed"
        objects.append(
            stix2.Note(
                id=stable_id("note", cve),
                created=added,
                modified=added,
                created_by_ref=IDENTITY_ID,
                object_refs=[vuln_id],
                content=(
                    f"KEV {cve}\n"
                    f"Vendor/product: {entry.get('vendorProject', '')} / "
                    f"{entry.get('product', '')}\n"
                    f"Required action: {entry.get('requiredAction', '')}\n"
                    f"Due date: {entry.get('dueDate', '')}\n"
                    f"Known ransomware campaign use: {ransomware}\n"
                    f"Forensic triage required: {entry.get('forensicTriage', 'Unknown')}\n"
                    f"CWEs: {cwes}\n"
                    f"Notes: {entry.get('notes', '')}"
                ),
            )
        )

    report = stix2.Report(
        id=stable_id("report", str(catalog.get("catalogVersion", released.isoformat()))),
        created=generated_at,
        modified=generated_at,
        created_by_ref=IDENTITY_ID,
        name=f"CISA KEV {catalog.get('catalogVersion', 'catalog')}",
        description=(
            f"CISA Known Exploited Vulnerabilities catalog released "
            f"{catalog.get('dateReleased', 'unknown')}: {len(entries)} entries."
        ),
        published=released,
        report_types=["threat-report"],
        object_refs=vulnerability_ids,
    )
    objects.append(report)

    bundle = stix2.Bundle(objects=objects, allow_custom=False)
    return json.loads(bundle.serialize())
