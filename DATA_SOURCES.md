# Data Sources

The ASN Risk Intelligence Platform ingests several third-party data feeds at
runtime to build its risk scores. The application code in this repository is
released under the [MIT License](LICENSE), **but the data itself is not**.

> **Important:** The MIT License covers only the source code of this project.
> It does **not** relicense, redistribute, or grant any rights over the
> upstream data feeds listed below. Anyone who deploys or operates this service
> is responsible for reviewing and honoring the terms of use of **each** feed
> provider. Some of these feeds carry their own restrictions, including
> **non-commercial-use** clauses and **attribution** requirements. When in
> doubt, consult the provider directly and obtain the appropriate license.

## Ingested Feeds

| Source | Endpoint | Type | Notes on Terms |
|--------|----------|------|----------------|
| **RIPE RIS Live** | `wss://ris-live.ripe.net/v1/ws/` | BGP routing telemetry (WebSocket stream) | RIPE NCC data. Review the RIPE NCC data terms and acceptable-use policy before redistribution. |
| **Spamhaus DROP / EDROP** | `https://www.spamhaus.org/drop/drop.txt` | Threat intelligence (do-not-route list) | Spamhaus feeds are commonly free for **non-commercial** use; commercial/high-volume use typically requires a Spamhaus data license. Verify the current Spamhaus terms. |
| **CINS Army (CINS Score)** | `https://cinsscore.com/list/ci-badguys.txt` | Threat intelligence (malicious IPs) | Provided by CINS/Sentinel IPS. Review the CINS Score usage terms for permitted uses. |
| **URLhaus** | `https://urlhaus.abuse.ch/downloads/text_online/` | Threat intelligence (malware URLs) | Operated by abuse.ch. Data is generally free to use with **attribution**; commercial usage may have specific conditions. Review the abuse.ch / URLhaus terms. |
| **PeeringDB** | `https://www.peeringdb.com/api/net?asn={asn}` | Network metadata enrichment | Community-maintained network registry. Review the PeeringDB terms of use and API acceptable-use policy. |

## Summary

- **Code:** MIT (this repository) — free to use, modify, and distribute,
  including commercially.
- **Data:** Each upstream feed is governed by **its own** terms. The MIT
  license on this code grants you no rights to the upstream data. It is your
  responsibility, as an operator of the service, to comply with every feed's
  license — including any **non-commercial** or **attribution** requirements.
