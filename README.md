# dmarky

Rust CLI to analyze DMARC reports from a local folder and generate static browsable websites.

## Features (MVP)

- Input files: `.xml`, `.gz` (single XML), `.zip` (one or more XML files)
- Detects DMARC aggregate and forensic XML reports
- Aggregates simple statistics across all files in the folder
- Generates static output (no DB, no webserver):
  - Aggregate site:
    - `index.html`
    - `data.json`
  - Forensic site:
    - `forensic/index.html`
    - `forensic/data.json`

## Usage

```bash
cargo run -- --input /path/to/dmarc/reports --output report
```

Then open:

- `report/index.html` for aggregate statistics
- `report/forensic/index.html` for forensic report statistics

## Current aggregations

- Source IP (`record/row/source_ip`)
- Reverse DNS hostname for each source IP (PTR lookup)
- Header From (`record/identifiers/header_from`)
- Disposition (`record/row/policy_evaluated/disposition`)
- DKIM result (`record/row/policy_evaluated/dkim`)
- SPF result (`record/row/policy_evaluated/spf`)
- Total files, reports, records, and messages