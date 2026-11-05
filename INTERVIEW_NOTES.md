# Interview notes — kev-to-stix

## What this project demonstrates

- A small, deterministic ETL pipeline over a real public feed: fetch CISA KEV, validate its
  declared count, model it as STIX 2.1, run the official `stix2-validator`, and publish a
  static dashboard.
- Designing IDs deliberately. Objects use UUIDv5 derived from the CVE, so two runs over the
  same catalog produce byte-identical objects and the diff is reviewable. The validator warns
  that the IDs are not UUIDv4; that warning is documented rather than "fixed" by making the
  bundle non-deterministic.
- Keeping provenance: the exact validator output (`[+] STIX JSON: Valid`, exit 0) and the
  generated bundle are committed next to the code that made them.
- Running the same pipeline on a daily schedule and on every push, with Pages deployment.

## Questions I expect

**Why STIX at all?**
Because a list of CVEs in a spreadsheet is not ingestible by a TIP or a SIEM. STIX 2.1 gives a
typed object, a relationship (`note` → `vulnerability`) and a `report` that references the whole
run. The mapping is intentionally minimal: KEV has no CVSS, EPSS, IOCs or actor attribution, so
the pipeline does not invent them.

**Why not one object per run?**
Determinism. If IDs were random, every daily run would produce a completely different bundle and
nobody could diff it. UUIDv5 over the CVE (and over the note's stable key) makes the bundle
reproducible.

**How do you catch a schema change on CISA's side?**
Two checks: the catalog's declared `count` must equal the number of entries, and the official
validator must accept the bundle. A truncated or reshaped feed fails loudly instead of producing
a partial bundle. There is also a pytest suite for the mapping functions.

**What is the dashboard for?**
A fast human view of the same data — vendor counts, ransomware flag, due dates — generated
statically so it can live on GitHub Pages without a server. It is a convenience, not a second
source of truth.

**What would you add?**
EPSS/CVSS enrichment from a licensed feed, STIX `indicator` objects only where real IOCs exist
(KEV has none), and a signed bundle / hash manifest so a consumer can verify what it ingested.
