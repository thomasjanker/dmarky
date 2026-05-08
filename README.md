# dmarky

Rust CLI to analyze DMARC aggregate reports from a local folder and generate a static browsable website.

## Features (MVP)

- Input files: `.xml`, `.gz` (single XML), `.zip` (one or more XML files)
- Validates that each XML looks like a DMARC aggregate report
- Aggregates simple statistics across all files in the folder
- Generates static output (no DB, no webserver):
  - `index.html` (browsable report)
  - `data.json` (raw aggregated data)

## Usage

```bash
cargo run -- --input /path/to/dmarc/reports --output report
```

Then open `report/index.html` in your browser.

## Current aggregations

- Source IP (`record/row/source_ip`)
- Reverse DNS hostname for each source IP (PTR lookup)
- Header From (`record/identifiers/header_from`)
- Disposition (`record/row/policy_evaluated/disposition`)
- DKIM result (`record/row/policy_evaluated/dkim`)
- SPF result (`record/row/policy_evaluated/spf`)
- Total files, reports, records, and messages