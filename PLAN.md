# PLAN — kev-to-stix

## Goal

Turn the CISA Known Exploited Vulnerabilities (KEV) catalog into a validated STIX 2.1 bundle,
on a daily schedule, with a static dashboard. The point is the *contract*: every KEV entry
becomes exactly one vulnerability object, one note and one reference in a report, and the
official validator decides whether the output is valid.

## Source and licence

CISA KEV is a US Government work in the public domain (17 U.S.C. 105). The pipeline downloads
the live feed at run time; the raw JSON is kept in `data/` so a result can be reproduced after
the catalog changes.

## Mapping

| KEV field | STIX destination |
|---|---|
| `cveID` | `vulnerability.name` and `external_references[0].external_id` (`source_name: cve`) |
| `vendorProject` + `product` + `vulnerabilityName` + `shortDescription` | `vulnerability.description` |
| `dateAdded` | `vulnerability.created` / `modified` |
| `requiredAction`, `dueDate`, `knownRansomwareCampaignUse`, `forensicTriage`, `cwes`, `notes` | `note.content`, referencing the vulnerability |
| whole catalog | one `report` referencing every vulnerability |
| pipeline | one `identity` |

IDs are UUIDv5 derived from the CVE (and from the object type), so two runs over the same
catalog produce the same IDs. The validator reports warnings for non-UUIDv4 IDs; this is a
deliberate trade-off, documented in the README rather than hidden.

## Verification

- `stix2-validator --version 2.1 data/kev.stix.json` must exit 0. Its real output is saved in
  `results/validation.txt`.
- Unit tests assert the mapping contract on a three-entry fixture: counts, report references,
  note content, deterministic IDs, count-mismatch rejection, dashboard rendering.
- The pipeline refuses a feed whose declared `count` does not match the number of entries.

## Schedule

GitHub Actions runs the pipeline daily at 05:15 UTC and on demand. The run deploys the freshly
generated dashboard to GitHub Pages and uploads the bundle as an artifact. The committed
`data/` and `docs/` files are the snapshot from the recorded local run.

## Time box

2-3 hours. No external service or credential is required.
