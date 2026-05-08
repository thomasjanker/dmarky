use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{TimeZone, Utc};
use clap::Parser;
use dns_lookup::lookup_addr;
use flate2::read::GzDecoder;
use roxmltree::Document;
use serde::Serialize;
use zip::ZipArchive;

#[derive(Parser, Debug)]
#[command(
    name = "dmarky",
    version,
    about = "Analyze DMARC XML reports from a folder and generate a static HTML report"
)]
struct Cli {
    /// Folder containing DMARC reports (.xml, .gz, .zip)
    #[arg(short, long)]
    input: PathBuf,

    /// Output folder for generated static website
    #[arg(short, long, default_value = "report")]
    output: PathBuf,
}

#[derive(Debug, Serialize, Clone)]
struct ReportRecord {
    source_ip: String,
    count: u64,
    disposition: String,
    dkim: String,
    spf: String,
    dmarc_compliant: bool,
    header_from: String,
    report_day: String,
    report_org_name: String,
    report_email: String,
}

#[derive(Debug, Serialize, Default, Clone)]
struct SourceIpStats {
    total_messages: u64,
    dmarc_compliant_messages: u64,
    dmarc_non_compliant_messages: u64,
    spf_pass_messages: u64,
    spf_fail_messages: u64,
    dkim_pass_messages: u64,
    dkim_fail_messages: u64,
}

#[derive(Debug, Serialize, Default)]
struct Aggregates {
    total_files_processed: usize,
    total_reports: usize,
    total_records: usize,
    total_messages: u64,
    source_ip_counts: HashMap<String, u64>,
    source_ip_hostnames: HashMap<String, String>,
    source_ip_stats: HashMap<String, SourceIpStats>,
    header_from_counts: HashMap<String, u64>,
    disposition_counts: HashMap<String, u64>,
    dkim_result_counts: HashMap<String, u64>,
    spf_result_counts: HashMap<String, u64>,
    records: Vec<ReportRecord>,
}

#[derive(Debug, Serialize, Clone)]
struct ForensicReport {
    arrival_day: String,
    source_ip: String,
    reported_domain: String,
    delivery_result: String,
    auth_failure: String,
    user_agent: String,
    original_envelope_id: String,
    report_org_name: String,
    report_email: String,
}

#[derive(Debug, Serialize, Default)]
struct ForensicAggregates {
    total_reports: usize,
    reports: Vec<ForensicReport>,
    by_source_ip: HashMap<String, u64>,
    by_reported_domain: HashMap<String, u64>,
    by_auth_failure: HashMap<String, u64>,
    by_delivery_result: HashMap<String, u64>,
    by_report_origin: HashMap<String, u64>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if !cli.input.exists() || !cli.input.is_dir() {
        bail!("Input path must be an existing directory: {}", cli.input.display());
    }

    fs::create_dir_all(&cli.output)
        .with_context(|| format!("Creating output dir {}", cli.output.display()))?;

    let mut aggregates = Aggregates::default();
    let mut forensic = ForensicAggregates::default();

    for entry in fs::read_dir(&cli.input)
        .with_context(|| format!("Reading input dir {}", cli.input.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            process_file(&path, &mut aggregates, &mut forensic)
                .with_context(|| format!("Processing {}", path.display()))?;
        }
    }

    resolve_source_ip_hostnames(&mut aggregates);
    write_reports(&cli.output, &aggregates, &forensic)?;

    println!(
        "Reports generated in {} (files: {}, aggregate reports: {}, aggregate records: {}, forensic reports: {}).",
        cli.output.display(),
        aggregates.total_files_processed,
        aggregates.total_reports,
        aggregates.total_records,
        forensic.total_reports
    );

    Ok(())
}

fn process_file(
    path: &Path,
    aggregates: &mut Aggregates,
    forensic: &mut ForensicAggregates,
) -> Result<()> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    match ext.as_str() {
        "xml" => {
            let data = fs::read(path)?;
            process_xml_bytes(&data, aggregates, forensic)
                .with_context(|| format!("Invalid XML in {}", path.display()))?;
            aggregates.total_files_processed += 1;
        }
        "gz" => {
            let data = fs::read(path)?;
            let mut gz = GzDecoder::new(&data[..]);
            let mut decoded = Vec::new();
            gz.read_to_end(&mut decoded)
                .with_context(|| format!("Invalid gzip in {}", path.display()))?;
            process_xml_bytes(&decoded, aggregates, forensic)
                .with_context(|| format!("Invalid XML in gz file {}", path.display()))?;
            aggregates.total_files_processed += 1;
        }
        "zip" => {
            let file = fs::File::open(path)?;
            let mut archive = ZipArchive::new(file)
                .with_context(|| format!("Invalid zip archive {}", path.display()))?;

            let mut xml_found = false;
            for i in 0..archive.len() {
                let mut zipped = archive.by_index(i)?;
                let name = zipped.name().to_ascii_lowercase();
                if name.ends_with(".xml") {
                    let mut xml = Vec::new();
                    zipped.read_to_end(&mut xml)?;
                    process_xml_bytes(&xml, aggregates, forensic).with_context(|| {
                        format!("Invalid XML in zip member {} of {}", zipped.name(), path.display())
                    })?;
                    xml_found = true;
                }
            }

            if !xml_found {
                bail!("Zip file has no .xml entries: {}", path.display());
            }
            aggregates.total_files_processed += 1;
        }
        _ => {}
    }

    Ok(())
}

fn process_xml_bytes(
    bytes: &[u8],
    aggregates: &mut Aggregates,
    forensic: &mut ForensicAggregates,
) -> Result<()> {
    let s = std::str::from_utf8(bytes).context("DMARC XML is not valid UTF-8")?;
    let doc = Document::parse(s).context("Cannot parse DMARC XML document")?;

    if looks_like_aggregate_report(&doc) {
        process_aggregate_xml(&doc, aggregates)
    } else if looks_like_forensic_report(&doc) {
        process_forensic_xml(&doc, forensic)
    } else {
        bail!("XML does not look like a DMARC aggregate or forensic report");
    }
}

fn process_aggregate_xml(doc: &Document<'_>, aggregates: &mut Aggregates) -> Result<()> {
    aggregates.total_reports += 1;
    let report_day = extract_report_day(doc);
    let report_org_name = first_tag_text(doc, "org_name").unwrap_or_else(|| "unknown".to_string());
    let report_email = first_tag_text(doc, "email").unwrap_or_else(|| "unknown".to_string());

    for record in doc.descendants().filter(|n| n.has_tag_name("record")) {
        let source_ip = child_text(record, "row/source_ip").unwrap_or_else(|| "unknown".to_string());
        let count = child_text(record, "row/count")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        let disposition =
            child_text(record, "row/policy_evaluated/disposition").unwrap_or_else(|| "unknown".to_string());
        let dkim = child_text(record, "row/policy_evaluated/dkim").unwrap_or_else(|| "unknown".to_string());
        let spf = child_text(record, "row/policy_evaluated/spf").unwrap_or_else(|| "unknown".to_string());
        let header_from = child_text(record, "identifiers/header_from").unwrap_or_else(|| "unknown".to_string());
        let dmarc_compliant = spf.eq_ignore_ascii_case("pass") || dkim.eq_ignore_ascii_case("pass");

        aggregates.total_records += 1;
        aggregates.total_messages += count;

        increment_map(&mut aggregates.source_ip_counts, &source_ip, count);
        increment_map(&mut aggregates.header_from_counts, &header_from, count);
        increment_map(&mut aggregates.disposition_counts, &disposition, count);
        increment_map(&mut aggregates.dkim_result_counts, &dkim, count);
        increment_map(&mut aggregates.spf_result_counts, &spf, count);
        update_source_ip_stats(&mut aggregates.source_ip_stats, &source_ip, &spf, &dkim, count);

        aggregates.records.push(ReportRecord {
            source_ip,
            count,
            disposition,
            dkim,
            spf,
            dmarc_compliant,
            header_from,
            report_day: report_day.clone(),
            report_org_name: report_org_name.clone(),
            report_email: report_email.clone(),
        });
    }

    Ok(())
}

fn extract_report_day(doc: &Document<'_>) -> String {
    let begin_epoch = doc
        .descendants()
        .find(|n| n.has_tag_name("date_range"))
        .and_then(|n| n.children().find(|c| c.has_tag_name("begin")))
        .and_then(|n| n.text())
        .and_then(|s| s.trim().parse::<i64>().ok());

    begin_epoch
        .and_then(|ts| Utc.timestamp_opt(ts, 0).single())
        .map(|dt| dt.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn looks_like_aggregate_report(doc: &Document<'_>) -> bool {
    let has_feedback = doc.descendants().any(|n| n.has_tag_name("feedback"));
    let has_metadata = doc.descendants().any(|n| n.has_tag_name("report_metadata"));
    let has_policy = doc.descendants().any(|n| n.has_tag_name("policy_published"));
    let has_record = doc.descendants().any(|n| n.has_tag_name("record"));
    has_feedback && has_metadata && has_policy && has_record
}

fn looks_like_forensic_report(doc: &Document<'_>) -> bool {
    let has_feedback = doc.descendants().any(|n| n.has_tag_name("feedback"));
    let has_source_ip = doc.descendants().any(|n| n.has_tag_name("source_ip"));
    let has_arrival = doc.descendants().any(|n| n.has_tag_name("arrival_date"));
    let has_reported_domain = doc.descendants().any(|n| n.has_tag_name("reported_domain"));
    has_feedback && (has_source_ip || has_arrival || has_reported_domain)
}

fn process_forensic_xml(doc: &Document<'_>, forensic: &mut ForensicAggregates) -> Result<()> {
    let source_ip = first_tag_text(doc, "source_ip").unwrap_or_else(|| "unknown".to_string());
    let reported_domain =
        first_tag_text(doc, "reported_domain").unwrap_or_else(|| "unknown".to_string());
    let auth_failure = first_tag_text(doc, "auth_failure").unwrap_or_else(|| "unknown".to_string());
    let delivery_result =
        first_tag_text(doc, "delivery_result").unwrap_or_else(|| "unknown".to_string());
    let user_agent = first_tag_text(doc, "user_agent").unwrap_or_else(|| "unknown".to_string());
    let original_envelope_id =
        first_tag_text(doc, "original_envelope_id").unwrap_or_else(|| "unknown".to_string());
    let report_org_name = first_tag_text(doc, "org_name").unwrap_or_else(|| "unknown".to_string());
    let report_email = first_tag_text(doc, "email").unwrap_or_else(|| "unknown".to_string());
    let report_origin = format!("{} <{}>", report_org_name, report_email);

    let arrival_day = first_tag_text(doc, "arrival_date")
        .and_then(|s| s.parse::<i64>().ok())
        .and_then(|ts| Utc.timestamp_opt(ts, 0).single())
        .map(|dt| dt.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "unknown".to_string());

    forensic.total_reports += 1;
    increment_map(&mut forensic.by_source_ip, &source_ip, 1);
    increment_map(&mut forensic.by_reported_domain, &reported_domain, 1);
    increment_map(&mut forensic.by_auth_failure, &auth_failure, 1);
    increment_map(&mut forensic.by_delivery_result, &delivery_result, 1);
    increment_map(&mut forensic.by_report_origin, &report_origin, 1);
    forensic.reports.push(ForensicReport {
        arrival_day,
        source_ip,
        reported_domain,
        delivery_result,
        auth_failure,
        user_agent,
        original_envelope_id,
        report_org_name,
        report_email,
    });
    Ok(())
}

fn child_text(node: roxmltree::Node<'_, '_>, path: &str) -> Option<String> {
    let mut current = Some(node);
    for segment in path.split('/') {
        current = current.and_then(|n| n.children().find(|c| c.has_tag_name(segment)));
        if current.is_none() {
            break;
        }
    }
    current.and_then(|n| n.text()).map(|s| s.trim().to_string())
}

fn increment_map(map: &mut HashMap<String, u64>, key: &str, amount: u64) {
    *map.entry(key.to_string()).or_insert(0) += amount;
}

fn update_source_ip_stats(
    stats_map: &mut HashMap<String, SourceIpStats>,
    source_ip: &str,
    spf: &str,
    dkim: &str,
    count: u64,
) {
    let spf_pass = spf.eq_ignore_ascii_case("pass");
    let dkim_pass = dkim.eq_ignore_ascii_case("pass");
    let dmarc_compliant = spf_pass || dkim_pass;

    let stats = stats_map.entry(source_ip.to_string()).or_default();
    stats.total_messages += count;

    if dmarc_compliant {
        stats.dmarc_compliant_messages += count;
    } else {
        stats.dmarc_non_compliant_messages += count;
    }

    if spf_pass {
        stats.spf_pass_messages += count;
    } else {
        stats.spf_fail_messages += count;
    }

    if dkim_pass {
        stats.dkim_pass_messages += count;
    } else {
        stats.dkim_fail_messages += count;
    }
}

fn resolve_source_ip_hostnames(aggregates: &mut Aggregates) {
    for source_ip in aggregates.source_ip_counts.keys() {
        let hostname = source_ip
            .parse::<IpAddr>()
            .ok()
            .and_then(|ip| lookup_addr(&ip).ok())
            .filter(|name| !name.trim().is_empty())
            .unwrap_or_else(|| "unresolved".to_string());
        aggregates
            .source_ip_hostnames
            .insert(source_ip.clone(), hostname);
    }
}

fn write_reports(
    output_dir: &Path,
    aggregates: &Aggregates,
    forensic: &ForensicAggregates,
) -> Result<()> {
    let landing_html = render_landing_html();
    let index_path = output_dir.join("index.html");
    fs::write(&index_path, landing_html)
        .with_context(|| format!("Writing {}", index_path.display()))?;

    let aggregate_dir = output_dir.join("aggregate");
    fs::create_dir_all(&aggregate_dir)
        .with_context(|| format!("Creating {}", aggregate_dir.display()))?;
    let aggregate_html = render_aggregate_html(aggregates)?;
    fs::write(aggregate_dir.join("index.html"), aggregate_html)
        .with_context(|| format!("Writing {}", aggregate_dir.join("index.html").display()))?;

    let json_path = aggregate_dir.join("data.json");
    let json = serde_json::to_string_pretty(aggregates)?;
    fs::write(&json_path, json).with_context(|| format!("Writing {}", json_path.display()))?;

    let forensic_dir = output_dir.join("forensic");
    fs::create_dir_all(&forensic_dir)
        .with_context(|| format!("Creating {}", forensic_dir.display()))?;
    let forensic_html = render_forensic_html(forensic)?;
    fs::write(forensic_dir.join("index.html"), forensic_html)
        .with_context(|| format!("Writing {}", forensic_dir.join("index.html").display()))?;
    let forensic_json = serde_json::to_string_pretty(forensic)?;
    fs::write(forensic_dir.join("data.json"), forensic_json)
        .with_context(|| format!("Writing {}", forensic_dir.join("data.json").display()))?;

    Ok(())
}

fn render_landing_html() -> String {
    r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>dmarky Reports</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" />
</head>
<body class="bg-light">
  <main class="container py-4">
    <h1 class="mb-2">dmarky Report Index</h1>
    <p class="text-muted">Choose which report type you want to view.</p>
    <div class="row g-3">
      <div class="col-12 col-md-6">
        <div class="card h-100 shadow-sm">
          <div class="card-body">
            <h2 class="h4 card-title">Aggregate Reports</h2>
            <p class="card-text">View aggregated DMARC statistics by source IP, SPF, DKIM, disposition, and more.</p>
            <a class="btn btn-outline-primary" href="aggregate/index.html">Open Aggregate Site</a>
          </div>
        </div>
      </div>
      <div class="col-12 col-md-6">
        <div class="card h-100 shadow-sm">
          <div class="card-body">
            <h2 class="h4 card-title">Forensic Reports</h2>
            <p class="card-text">View forensic report summaries and details like auth failures and delivery results.</p>
            <a class="btn btn-outline-primary" href="forensic/index.html">Open Forensic Site</a>
          </div>
        </div>
      </div>
    </div>
  </main>
</body>
</html>"#
        .to_string()
}

fn render_aggregate_html(aggregates: &Aggregates) -> Result<String> {
    let source_ip_rows = render_source_ip_rows(
        &aggregates.source_ip_counts,
        &aggregates.source_ip_hostnames,
        &aggregates.source_ip_stats,
    );
    let header_from_rows = render_table_rows(&aggregates.header_from_counts);
    let disposition_rows = render_table_rows(&aggregates.disposition_counts);
    let dkim_rows = render_table_rows(&aggregates.dkim_result_counts);
    let spf_rows = render_table_rows(&aggregates.spf_result_counts);
    let details_by_ip_json = serde_json::to_string(&group_records_by_source_ip(&aggregates.records))?;

    let html = format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>DMARC Report</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" />
  <style>
    .clickable-row {{ cursor: pointer; }}
    .clickable-row:hover {{ background: #f5f9ff; }}
    .detail-row-clickable {{ cursor: pointer; }}
    .detail-row-clickable.table-active {{ --bs-table-accent-bg: rgba(13,110,253,.18); }}
    #modal-time-chart {{ width: 100%; height: 240px; }}
  </style>
</head>
<body class="bg-light">
  <main class="container-fluid py-3 px-3 px-md-4">
  <h1 class="mb-1">DMARC Aggregate Statistics</h1>
  <p class="text-muted">Generated by dmarky</p>

  <div class="row g-3 mb-4">
    <div class="col-6 col-lg-3"><div class="card shadow-sm"><div class="card-body"><small class="text-muted">Files Processed</small><div class="h4 mb-0">{files}</div></div></div></div>
    <div class="col-6 col-lg-3"><div class="card shadow-sm"><div class="card-body"><small class="text-muted">Reports Parsed</small><div class="h4 mb-0">{reports}</div></div></div></div>
    <div class="col-6 col-lg-3"><div class="card shadow-sm"><div class="card-body"><small class="text-muted">Records Parsed</small><div class="h4 mb-0">{records}</div></div></div></div>
    <div class="col-6 col-lg-3"><div class="card shadow-sm"><div class="card-body"><small class="text-muted">Total Messages</small><div class="h4 mb-0">{messages}</div></div></div></div>
  </div>

  <h2 class="h4">By Source IP</h2>
  <div class="table-responsive mb-2">
  <table class="table table-striped table-hover table-sm align-middle">
    <thead class="table-light">
    <tr>
      <th>Source IP</th>
      <th>Resolved Hostname</th>
      <th>Message Count</th>
      <th>DMARC Compliant</th>
      <th>DMARC Non-Compliant</th>
      <th>SPF Pass</th>
      <th>SPF Fail</th>
      <th>DKIM Pass</th>
      <th>DKIM Fail</th>
    </tr>
    </thead>
    <tbody>
    {source_ip_rows}
    </tbody>
  </table>
  </div>
  <p class="text-muted">Click a source IP row for detailed records.</p>

  <h2 class="h4">By Header From</h2>
  <div class="table-responsive"><table class="table table-striped table-sm"><thead class="table-light"><tr><th>Header From</th><th>Message Count</th></tr></thead><tbody>{header_from_rows}</tbody></table></div>

  <h2 class="h4">Disposition</h2>
  <div class="table-responsive"><table class="table table-striped table-sm"><thead class="table-light"><tr><th>Disposition</th><th>Message Count</th></tr></thead><tbody>{disposition_rows}</tbody></table></div>

  <h2 class="h4">DKIM Result</h2>
  <div class="table-responsive"><table class="table table-striped table-sm"><thead class="table-light"><tr><th>DKIM</th><th>Message Count</th></tr></thead><tbody>{dkim_rows}</tbody></table></div>

  <h2 class="h4">SPF Result</h2>
  <div class="table-responsive"><table class="table table-striped table-sm"><thead class="table-light"><tr><th>SPF</th><th>Message Count</th></tr></thead><tbody>{spf_rows}</tbody></table></div>

  <p class="text-muted">Raw aggregated JSON is available as <code>data.json</code>.</p>
  <p class="text-muted">Back to index: <code>../index.html</code>.</p>
  <p class="text-muted">Forensic report site: <code>../forensic/index.html</code>.</p>

  <div class="modal fade" id="detail-modal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-xl modal-dialog-scrollable">
      <div class="modal-content">
        <div class="modal-header">
          <h2 id="modal-title" class="modal-title fs-5">Source IP details</h2>
          <button id="modal-close" class="btn-close" type="button" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body">
        <p class="text-muted mb-2">Click a detail row to update the time chart for that row's values.</p>
        <div class="table-responsive">
        <table class="table table-striped table-sm align-middle">
          <thead class="table-light">
          <tr>
            <th>Message Count</th>
            <th>DMARC Compliance</th>
            <th>Disposition</th>
            <th>SPF</th>
            <th>DKIM</th>
            <th>Header From</th>
          </tr>
          </thead>
          <tbody id="modal-table-body"></tbody>
        </table>
        </div>
        <h3 class="h5 mt-3">Messages Over Time</h3>
        <svg id="modal-time-chart" viewBox="0 0 900 220" preserveAspectRatio="none"></svg>
        </div>
      </div>
    </div>
  </div>

  </main>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    const detailsByIp = {details_by_ip_json};
    const modalEl = document.getElementById('detail-modal');
    const modal = new bootstrap.Modal(modalEl);
    const title = document.getElementById('modal-title');
    const body = document.getElementById('modal-table-body');
    const chart = document.getElementById('modal-time-chart');
    let currentIp = null;
    let currentItems = [];

    function escapeHtml(text) {{
      return String(text)
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('\"', '&quot;')
        .replaceAll('\'', '&#39;');
    }}

    function renderTimeChart(items) {{
      const perDay = {{}};
      items.forEach((item) => {{
        const key = item.report_day || 'unknown';
        perDay[key] = (perDay[key] || 0) + Number(item.count || 0);
      }});

      const days = Object.keys(perDay).sort();
      if (days.length === 0) {{
        chart.innerHTML = '';
        return;
      }}

      const values = days.map((d) => perDay[d]);
      const maxValue = Math.max(...values, 1);
      const width = 900;
      const height = 220;
      const left = 55;
      const right = 20;
      const top = 15;
      const bottom = 45;
      const plotWidth = width - left - right;
      const plotHeight = height - top - bottom;
      const stepX = days.length > 1 ? plotWidth / (days.length - 1) : 0;

      const points = days.map((day, idx) => {{
        const x = left + idx * stepX;
        const y = top + plotHeight - (perDay[day] / maxValue) * plotHeight;
        return {{ day, x, y, value: perDay[day] }};
      }});

      const polylinePoints = points.map((p) => p.x.toFixed(2) + ',' + p.y.toFixed(2)).join(' ');
      let svg = '';
      svg += '<line x1=\"' + left + '\" y1=\"' + (top + plotHeight) + '\" x2=\"' + (width - right) + '\" y2=\"' + (top + plotHeight) + '\" stroke=\"rgb(153,153,153)\" />';
      svg += '<line x1=\"' + left + '\" y1=\"' + top + '\" x2=\"' + left + '\" y2=\"' + (top + plotHeight) + '\" stroke=\"rgb(153,153,153)\" />';
      svg += '<polyline fill=\"none\" stroke=\"rgb(13,110,253)\" stroke-width=\"2\" points=\"' + polylinePoints + '\" />';

      points.forEach((p, idx) => {{
        svg += '<circle cx=\"' + p.x + '\" cy=\"' + p.y + '\" r=\"3\" fill=\"rgb(13,110,253)\"><title>' + escapeHtml(p.day) + ': ' + p.value + '</title></circle>';
        svg += '<text x=\"' + p.x + '\" y=\"' + (height - 22) + '\" text-anchor=\"middle\" font-size=\"10\" fill=\"rgb(68,68,68)\">' + escapeHtml(p.day) + '</text>';
        if (idx === 0 || idx === points.length - 1 || idx % 3 === 0) {{
          svg += '<text x=\"' + p.x + '\" y=\"' + (p.y - 8) + '\" text-anchor=\"middle\" font-size=\"10\" fill=\"rgb(34,34,34)\">' + p.value + '</text>';
        }}
      }});

      svg += '<text x=\"' + (left - 8) + '\" y=\"' + (top + 10) + '\" text-anchor=\"end\" font-size=\"10\" fill=\"rgb(68,68,68)\">' + maxValue + '</text>';
      svg += '<text x=\"' + (left - 8) + '\" y=\"' + (top + plotHeight + 4) + '\" text-anchor=\"end\" font-size=\"10\" fill=\"rgb(68,68,68)\">0</text>';
      chart.innerHTML = svg;
    }}

    function renderDetails(ip) {{
      const allItems = detailsByIp[ip] || [];
      currentItems = allItems;
      title.textContent =
        'Source IP details: ' + ip + ' (' + allItems.length + ' records)';

      if (allItems.length === 0) {{
        body.innerHTML = '<tr><td colspan=\"6\">No details available.</td></tr>';
      }} else {{
        const grouped = {{}};
        allItems.forEach((item) => {{
          const key = [
            item.dmarc_compliant ? 'pass' : 'fail',
            item.disposition || 'unknown',
            item.spf || 'unknown',
            item.dkim || 'unknown',
            item.header_from || 'unknown'
          ].join('||');

          if (!grouped[key]) {{
            grouped[key] = {{
              message_count: 0,
              dmarc_compliance: item.dmarc_compliant ? 'pass' : 'fail',
              disposition: item.disposition || 'unknown',
              spf: item.spf || 'unknown',
              dkim: item.dkim || 'unknown',
              header_from: item.header_from || 'unknown'
            }};
          }}
          grouped[key].message_count += Number(item.count || 0);
        }});

        const groupedRows = Object.values(grouped).sort((a, b) => b.message_count - a.message_count);
        body.innerHTML = groupedRows.map((row, idx) => (
          '<tr class=\"detail-row-clickable\" data-group-idx=\"' + idx + '\">' +
            '<td>' + row.message_count + '</td>' +
            '<td>' + row.dmarc_compliance + '</td>' +
            '<td>' + escapeHtml(row.disposition) + '</td>' +
            '<td>' + escapeHtml(row.spf) + '</td>' +
            '<td>' + escapeHtml(row.dkim) + '</td>' +
            '<td>' + escapeHtml(row.header_from) + '</td>' +
          '</tr>'
        )).join('');

        document.querySelectorAll('.detail-row-clickable').forEach((rowEl) => {{
          rowEl.addEventListener('click', () => {{
            document.querySelectorAll('.detail-row-clickable').forEach((r) => r.classList.remove('table-active'));
            rowEl.classList.add('table-active');

            const selected = groupedRows[Number(rowEl.dataset.groupIdx)];
            const filtered = currentItems.filter((item) => {{
              const dmarc = item.dmarc_compliant ? 'pass' : 'fail';
              return dmarc === selected.dmarc_compliance
                && (item.disposition || 'unknown') === selected.disposition
                && (item.spf || 'unknown') === selected.spf
                && (item.dkim || 'unknown') === selected.dkim
                && (item.header_from || 'unknown') === selected.header_from;
            }});
            renderTimeChart(filtered);
          }});
        }});
      }}
      renderTimeChart(allItems);
    }}

    function openDetails(ip) {{
      currentIp = ip;
      renderDetails(ip);
      modal.show();
    }}

    function closeDetails() {{
      modal.hide();
    }}

    document.querySelectorAll('.source-ip-row').forEach((row) => {{
      row.addEventListener('click', () => {{
        openDetails(row.dataset.sourceIp);
      }});
    }});
  </script>
</body>
</html>"#,
        files = aggregates.total_files_processed,
        reports = aggregates.total_reports,
        records = aggregates.total_records,
        messages = aggregates.total_messages,
        source_ip_rows = source_ip_rows,
        header_from_rows = header_from_rows,
        disposition_rows = disposition_rows,
        dkim_rows = dkim_rows,
        spf_rows = spf_rows,
        details_by_ip_json = details_by_ip_json,
    );

    Ok(html)
}

fn render_forensic_html(forensic: &ForensicAggregates) -> Result<String> {
    let source_ip_rows = render_table_rows(&forensic.by_source_ip);
    let domain_rows = render_table_rows(&forensic.by_reported_domain);
    let auth_failure_rows = render_table_rows(&forensic.by_auth_failure);
    let delivery_result_rows = render_table_rows(&forensic.by_delivery_result);
    let report_origin_rows = render_table_rows(&forensic.by_report_origin);
    let reports_json = serde_json::to_string(&forensic.reports)?;

    let html = format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>DMARC Forensic Reports</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" />
  <style>
    .stats-table td, .stats-table th {{ white-space: nowrap; }}
  </style>
</head>
<body class="bg-light">
  <main class="container-fluid py-3 px-3 px-md-4">
  <h1 class="mb-1">DMARC Forensic Statistics</h1>
  <p class="text-muted mb-1">Generated by dmarky</p>
  <p class="text-muted mb-1">Back to index: <code>../index.html</code></p>
  <p class="text-muted">Aggregate report site: <code>../aggregate/index.html</code></p>
  <h2 class="h4">Overview</h2>
  <div class="table-responsive"><table class="table table-sm table-striped stats-table"><thead class="table-light"><tr><th>Total Forensic Reports</th></tr></thead><tbody><tr><td>{total_reports}</td></tr></tbody></table></div>
  <h2 class="h4">By Source IP</h2>
  <div class="table-responsive"><table class="table table-sm table-striped stats-table"><thead class="table-light"><tr><th>Source IP</th><th>Count</th></tr></thead><tbody>{source_ip_rows}</tbody></table></div>
  <h2 class="h4">By Reported Domain</h2>
  <div class="table-responsive"><table class="table table-sm table-striped stats-table"><thead class="table-light"><tr><th>Reported Domain</th><th>Count</th></tr></thead><tbody>{domain_rows}</tbody></table></div>
  <h2 class="h4">By Auth Failure</h2>
  <div class="table-responsive"><table class="table table-sm table-striped stats-table"><thead class="table-light"><tr><th>Auth Failure</th><th>Count</th></tr></thead><tbody>{auth_failure_rows}</tbody></table></div>
  <h2 class="h4">By Delivery Result</h2>
  <div class="table-responsive"><table class="table table-sm table-striped stats-table"><thead class="table-light"><tr><th>Delivery Result</th><th>Count</th></tr></thead><tbody>{delivery_result_rows}</tbody></table></div>
  <h2 class="h4">By Report Origin</h2>
  <div class="table-responsive"><table class="table table-sm table-striped stats-table"><thead class="table-light"><tr><th>Report Origin</th><th>Count</th></tr></thead><tbody>{report_origin_rows}</tbody></table></div>
  <h2 class="h4">Forensic Report Details</h2>
  <div class="table-responsive">
  <table class="table table-striped table-sm align-middle">
    <thead class="table-light"><tr>
      <th>Arrival Day</th>
      <th>Source IP</th>
      <th>Report Origin</th>
      <th>Reported Domain</th>
      <th>Auth Failure</th>
      <th>Delivery Result</th>
      <th>User Agent</th>
      <th>Envelope ID</th>
    </tr></thead>
    <tbody id="forensic-details-body"></tbody>
  </table>
  </div>
  </main>
  <script>
    const reports = {reports_json};
    function escapeHtml(text) {{
      return String(text)
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('\"', '&quot;')
        .replaceAll('\'', '&#39;');
    }}
    const body = document.getElementById('forensic-details-body');
    body.innerHTML = reports.map((r) => (
      '<tr>' +
      '<td>' + escapeHtml(r.arrival_day) + '</td>' +
      '<td>' + escapeHtml(r.source_ip) + '</td>' +
      '<td>' + escapeHtml((r.report_org_name || 'unknown') + ' <' + (r.report_email || 'unknown') + '>') + '</td>' +
      '<td>' + escapeHtml(r.reported_domain) + '</td>' +
      '<td>' + escapeHtml(r.auth_failure) + '</td>' +
      '<td>' + escapeHtml(r.delivery_result) + '</td>' +
      '<td>' + escapeHtml(r.user_agent) + '</td>' +
      '<td>' + escapeHtml(r.original_envelope_id) + '</td>' +
      '</tr>'
    )).join('');
  </script>
</body>
</html>"#,
        total_reports = forensic.total_reports,
        source_ip_rows = source_ip_rows,
        domain_rows = domain_rows,
        auth_failure_rows = auth_failure_rows,
        delivery_result_rows = delivery_result_rows,
        report_origin_rows = report_origin_rows,
        reports_json = reports_json
    );

    Ok(html)
}

fn render_table_rows(map: &HashMap<String, u64>) -> String {
    let mut items: Vec<_> = map.iter().collect();
    items.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));

    let mut rows = String::new();
    for (k, v) in items {
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td></tr>",
            escape_html(k),
            v
        ));
    }
    rows
}

fn render_source_ip_rows(
    count_map: &HashMap<String, u64>,
    hostname_map: &HashMap<String, String>,
    stats_map: &HashMap<String, SourceIpStats>,
) -> String {
    let mut items: Vec<_> = count_map.iter().collect();
    items.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));

    let mut rows = String::new();
    for (ip, count) in items {
        let hostname = hostname_map
            .get(ip.as_str())
            .cloned()
            .unwrap_or_else(|| "unresolved".to_string());
        let stats = stats_map.get(ip.as_str()).cloned().unwrap_or_default();
        rows.push_str(&format!(
            "<tr class=\"source-ip-row clickable-row\" data-source-ip=\"{}\"><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            escape_html(ip),
            escape_html(ip),
            escape_html(&hostname),
            count,
            stats.dmarc_compliant_messages,
            stats.dmarc_non_compliant_messages,
            stats.spf_pass_messages,
            stats.spf_fail_messages,
            stats.dkim_pass_messages,
            stats.dkim_fail_messages
        ));
    }
    rows
}

fn group_records_by_source_ip(records: &[ReportRecord]) -> HashMap<String, Vec<ReportRecord>> {
    let mut grouped: HashMap<String, Vec<ReportRecord>> = HashMap::new();
    for record in records {
        grouped
            .entry(record.source_ip.clone())
            .or_default()
            .push(record.clone());
    }
    grouped
}

fn first_tag_text(doc: &Document<'_>, tag_name: &str) -> Option<String> {
    doc.descendants()
        .find(|n| n.has_tag_name(tag_name))
        .and_then(|n| n.text())
        .map(|s| s.trim().to_string())
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
