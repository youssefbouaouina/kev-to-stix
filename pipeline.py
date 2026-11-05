#!/usr/bin/env python3
# ruff: noqa: E501  (the dashboard template below is HTML/CSS, not Python)
"""Fetch the CISA KEV catalog, convert it to STIX 2.1, validate and publish.

Outputs (all generated, never hand-edited):
  data/known_exploited_vulnerabilities.json  raw feed
  data/kev.stix.json                         STIX 2.1 bundle
  data/summary.json                          dashboard data
  results/validation.txt                     real validator output
  docs/index.html                            static dashboard
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import urllib.request
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import stix_builder

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
RESULTS = ROOT / "results"
DOCS = ROOT / "docs"
FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
LICENCE = (
    "CISA Known Exploited Vulnerabilities catalog. US Government work, public domain "
    "(17 U.S.C. 105). Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
)


def fetch(url: str, destination: Path) -> dict:
    request = urllib.request.Request(url, headers={"User-Agent": "kev-to-stix/1.0"})
    with urllib.request.urlopen(request, timeout=120) as response:
        payload = response.read()
    destination.write_bytes(payload)
    return json.loads(payload)


def summarize(catalog: dict, bundle: dict) -> dict:
    entries = catalog["vulnerabilities"]
    vendors = Counter(entry.get("vendorProject", "") for entry in entries)
    cwes = Counter(
        cwe for entry in entries for cwe in (entry.get("cwes") or ["none listed"])
    )
    years = Counter(
        (entry.get("dateAdded") or "unknown")[:4] for entry in entries
    )
    ransomware = Counter(
        entry.get("knownRansomwareCampaignUse", "Unknown") for entry in entries
    )
    types = Counter(obj["type"] for obj in bundle["objects"])
    return {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "catalog_version": catalog.get("catalogVersion"),
        "catalog_released": catalog.get("dateReleased"),
        "source_url": FEED_URL,
        "licence": LICENCE,
        "entries": len(entries),
        "objects": len(bundle["objects"]),
        "objects_by_type": dict(sorted(types.items())),
        "ransomware": dict(sorted(ransomware.items())),
        "forensic_triage": dict(
            sorted(Counter(e.get("forensicTriage", "Unknown") for e in entries).items())
        ),
        "top_vendors": vendors.most_common(15),
        "top_cwes": cwes.most_common(15),
        "by_year_added": dict(sorted(years.items())),
        "latest": [
            {
                "cve": entry["cveID"],
                "vendor": entry.get("vendorProject", ""),
                "product": entry.get("product", ""),
                "name": entry.get("vulnerabilityName", ""),
                "added": entry.get("dateAdded", ""),
                "due": entry.get("dueDate", ""),
                "ransomware": entry.get("knownRansomwareCampaignUse", "Unknown"),
            }
            for entry in sorted(entries, key=lambda e: e.get("dateAdded", ""), reverse=True)[:20]
        ],
    }


def validate(bundle_path: Path) -> tuple[bool, str]:
    """Run the official stix2-validator CLI and keep its real output."""
    results_path = RESULTS / "validation.txt"
    RESULTS.mkdir(exist_ok=True)
    local = Path(sys.executable).parent / (
        "stix2_validator.exe" if sys.platform == "win32" else "stix2_validator"
    )
    executable = shutil.which("stix2_validator") or (str(local) if local.exists() else None)
    if not executable:
        results_path.write_text("stix2_validator not found\n", encoding="utf-8")
        return False, "stix2_validator not found"
    command = [
        executable,
        "--version",
        "2.1",
        str(bundle_path.relative_to(ROOT)),
    ]
    process = subprocess.run(command, capture_output=True, text=True, cwd=ROOT)
    output = (process.stdout + process.stderr).strip()
    results_path.write_text(
        f"$ {' '.join(command)}\n\n{output}\n\nexit_code={process.returncode}\n",
        encoding="utf-8",
    )
    return process.returncode == 0, output


def dashboard(summary: dict) -> None:
    DOCS.mkdir(exist_ok=True)
    max_vendor = summary["top_vendors"][0][1] if summary["top_vendors"] else 1
    bars = "\n".join(
        f'<div class="bar"><span>{name}</span><div><i style="width:{value / max_vendor * 100:.1f}%"></i></div><b>{value}</b></div>'
        for name, value in summary["top_vendors"]
    )
    cwes = "\n".join(
        f"<tr><td><code>{name}</code></td><td>{value}</td></tr>"
        for name, value in summary["top_cwes"]
    )
    years = "\n".join(
        f"<tr><td>{year}</td><td>{value}</td></tr>"
        for year, value in summary["by_year_added"].items()
    )
    latest = "\n".join(
        f"<tr><td><code>{row['cve']}</code></td><td>{row['vendor']}</td><td>{row['product']}</td>"
        f"<td>{row['added']}</td><td>{row['ransomware']}</td></tr>"
        for row in summary["latest"]
    )
    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CISA KEV to STIX 2.1</title>
<style>
:root{{--bg:#0d1117;--card:#161b22;--line:#30363d;--text:#e6edf3;--muted:#8b949e;--accent:#58a6ff}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--text);font:16px/1.55 -apple-system,Segoe UI,Roboto,sans-serif}}
main{{max-width:980px;margin:0 auto;padding:40px 20px 60px}}
h1{{font-size:2rem;margin:0 0 4px}} h2{{font-size:1.15rem;margin:36px 0 12px}}
p{{color:var(--muted)}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-top:24px}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}}
.card b{{display:block;font-size:1.8rem;color:var(--accent)}}
.card span{{color:var(--muted);font-size:.85rem}}
table{{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}}
th,td{{padding:9px 12px;text-align:left;border-bottom:1px solid var(--line);font-size:.9rem}}
th{{color:var(--muted);font-weight:600}} tr:last-child td{{border-bottom:none}}
.bar{{display:grid;grid-template-columns:180px 1fr 44px;gap:10px;align-items:center;margin:6px 0;font-size:.9rem}}
.bar div{{background:var(--card);border-radius:4px;height:10px;overflow:hidden}}
.bar i{{display:block;height:100%;background:var(--accent)}}
.bar b{{text-align:right;color:var(--muted)}} code{{color:#79c0ff}}
footer{{margin-top:40px;font-size:.8rem;color:var(--muted)}}
</style>
</head>
<body><main>
<h1>CISA KEV &rarr; STIX 2.1</h1>
<p>Generated {summary['generated_at']} from catalog <strong>{summary['catalog_version']}</strong>
(released {summary['catalog_released']}). Every object below comes from the published CISA feed.</p>
<div class="cards">
<div class="card"><b>{summary['entries']}</b><span>KEV entries</span></div>
<div class="card"><b>{summary['objects']}</b><span>STIX objects</span></div>
<div class="card"><b>{summary['ransomware'].get('Known', 0)}</b><span>known ransomware use</span></div>
<div class="card"><b>{summary['forensic_triage'].get('Yes', 0)}</b><span>forensic triage</span></div>
</div>
<h2>Objects by type</h2>
<table><tr><th>Type</th><th>Count</th></tr>
{''.join(f"<tr><td><code>{k}</code></td><td>{v}</td></tr>" for k, v in summary['objects_by_type'].items())}
</table>
<h2>Most affected vendors</h2>
{bars}
<h2>Top CWEs</h2>
<table><tr><th>CWE</th><th>Entries</th></tr>{cwes}</table>
<h2>Entries added per year</h2>
<table><tr><th>Year</th><th>Entries</th></tr>{years}</table>
<h2>20 most recent additions</h2>
<table><tr><th>CVE</th><th>Vendor</th><th>Product</th><th>Added</th><th>Ransomware</th></tr>{latest}</table>
<footer>Source: {summary['licence']}<br>
Bundle and validation output: <code>data/kev.stix.json</code>, <code>results/validation.txt</code> in the repository.</footer>
</main></body></html>
"""
    (DOCS / "index.html").write_text(html, encoding="utf-8")
    (DOCS / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--feed", type=Path, help="use a local catalog instead of downloading")
    args = parser.parse_args()

    DATA.mkdir(exist_ok=True)
    raw_path = DATA / "known_exploited_vulnerabilities.json"
    if args.feed:
        catalog = json.loads(args.feed.read_text(encoding="utf-8"))
        raw_path.write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")
    else:
        catalog = fetch(FEED_URL, raw_path)

    bundle_path = DATA / "kev.stix.json"
    bundle_path.write_text(
        json.dumps(stix_builder.build_bundle(catalog), indent=2) + "\n", encoding="utf-8"
    )
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))

    summary = summarize(catalog, bundle)
    (DATA / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    dashboard(summary)
    valid, output = validate(bundle_path)

    print(f"catalog {summary['catalog_version']}: {summary['entries']} entries")
    print(f"STIX objects: {summary['objects']} {summary['objects_by_type']}")
    print(output)
    return 0 if valid else 1


if __name__ == "__main__":
    sys.exit(main())
