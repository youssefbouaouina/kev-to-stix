# Sources and licences

| Component | Version | Licence | Use |
|---|---|---|---|
| CISA Known Exploited Vulnerabilities catalog | 2026.11.04 at run time | Public domain (US Government work, 17 U.S.C. 105) | Input feed |
| stix2 (python-stix2) | 3.0.1 | BSD-3-Clause | STIX object construction and bundle serialization |
| stix2-validator | 3.2.0 | BSD-3-Clause | Official STIX 2.1 validation |
| pytest / ruff | 8.3.4 / 0.8.4 | MIT | Tests and lint |

The feed is downloaded from
`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`.
No CVE description is copied from a source other than the CISA record. NVD links are
constructed from the CVE identifier; no NVD data is redistributed.

Source code in this repository: MIT.
