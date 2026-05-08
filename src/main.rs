use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
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
    header_from: String,
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

fn main() -> Result<()> {
    let cli = Cli::parse();

    if !cli.input.exists() || !cli.input.is_dir() {
        bail!("Input path must be an existing directory: {}", cli.input.display());
    }

    fs::create_dir_all(&cli.output)
        .with_context(|| format!("Creating output dir {}", cli.output.display()))?;

    let mut aggregates = Aggregates::default();

    for entry in fs::read_dir(&cli.input)
        .with_context(|| format!("Reading input dir {}", cli.input.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            process_file(&path, &mut aggregates)
                .with_context(|| format!("Processing {}", path.display()))?;
        }
    }

    resolve_source_ip_hostnames(&mut aggregates);
    write_report(&cli.output, &aggregates)?;

    println!(
        "Report generated in {} (files: {}, reports: {}, records: {}).",
        cli.output.display(),
        aggregates.total_files_processed,
        aggregates.total_reports,
        aggregates.total_records
    );

    Ok(())
}

fn process_file(path: &Path, aggregates: &mut Aggregates) -> Result<()> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    match ext.as_str() {
        "xml" => {
            let data = fs::read(path)?;
            process_xml_bytes(&data, aggregates)
                .with_context(|| format!("Invalid XML in {}", path.display()))?;
            aggregates.total_files_processed += 1;
        }
        "gz" => {
            let data = fs::read(path)?;
            let mut gz = GzDecoder::new(&data[..]);
            let mut decoded = Vec::new();
            gz.read_to_end(&mut decoded)
                .with_context(|| format!("Invalid gzip in {}", path.display()))?;
            process_xml_bytes(&decoded, aggregates)
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
                    process_xml_bytes(&xml, aggregates).with_context(|| {
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

fn process_xml_bytes(bytes: &[u8], aggregates: &mut Aggregates) -> Result<()> {
    let s = std::str::from_utf8(bytes).context("DMARC XML is not valid UTF-8")?;
    let doc = Document::parse(s).context("Cannot parse DMARC XML document")?;

    validate_required_nodes(&doc)?;

    aggregates.total_reports += 1;

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
            header_from,
        });
    }

    Ok(())
}

fn validate_required_nodes(doc: &Document<'_>) -> Result<()> {
    let has_feedback = doc.descendants().any(|n| n.has_tag_name("feedback"));
    let has_metadata = doc.descendants().any(|n| n.has_tag_name("report_metadata"));
    let has_policy = doc.descendants().any(|n| n.has_tag_name("policy_published"));
    let has_record = doc.descendants().any(|n| n.has_tag_name("record"));

    if !has_feedback || !has_metadata || !has_policy || !has_record {
        bail!("XML does not look like a DMARC aggregate report");
    }
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

fn write_report(output_dir: &Path, aggregates: &Aggregates) -> Result<()> {
    let html = render_html(aggregates)?;
    let index_path = output_dir.join("index.html");
    fs::write(&index_path, html).with_context(|| format!("Writing {}", index_path.display()))?;

    let json_path = output_dir.join("data.json");
    let json = serde_json::to_string_pretty(aggregates)?;
    fs::write(&json_path, json).with_context(|| format!("Writing {}", json_path.display()))?;

    Ok(())
}

fn render_html(aggregates: &Aggregates) -> Result<String> {
    let source_ip_rows = render_source_ip_rows(
        &aggregates.source_ip_counts,
        &aggregates.source_ip_hostnames,
        &aggregates.source_ip_stats,
    );
    let header_from_rows = render_table_rows(&aggregates.header_from_counts);
    let disposition_rows = render_table_rows(&aggregates.disposition_counts);
    let dkim_rows = render_table_rows(&aggregates.dkim_result_counts);
    let spf_rows = render_table_rows(&aggregates.spf_result_counts);

    let html = format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>DMARC Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 1.5rem; color: #222; }}
    h1, h2 {{ margin-bottom: 0.5rem; }}
    .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }}
    .card {{ border: 1px solid #ddd; border-radius: 8px; padding: 1rem; background: #fafafa; }}
    table {{ border-collapse: collapse; width: 100%; margin-bottom: 1.5rem; }}
    th, td {{ border: 1px solid #ddd; padding: 0.5rem; text-align: left; }}
    th {{ background: #f3f3f3; }}
    .muted {{ color: #666; font-size: 0.9rem; }}
  </style>
</head>
<body>
  <h1>DMARC Aggregate Statistics</h1>
  <p class="muted">Generated by dmarky</p>

  <div class="cards">
    <div class="card"><strong>Files Processed</strong><br />{files}</div>
    <div class="card"><strong>Reports Parsed</strong><br />{reports}</div>
    <div class="card"><strong>Records Parsed</strong><br />{records}</div>
    <div class="card"><strong>Total Messages</strong><br />{messages}</div>
  </div>

  <h2>By Source IP</h2>
  <table>
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
    {source_ip_rows}
  </table>

  <h2>By Header From</h2>
  <table><tr><th>Header From</th><th>Message Count</th></tr>{header_from_rows}</table>

  <h2>Disposition</h2>
  <table><tr><th>Disposition</th><th>Message Count</th></tr>{disposition_rows}</table>

  <h2>DKIM Result</h2>
  <table><tr><th>DKIM</th><th>Message Count</th></tr>{dkim_rows}</table>

  <h2>SPF Result</h2>
  <table><tr><th>SPF</th><th>Message Count</th></tr>{spf_rows}</table>

  <p class="muted">Raw aggregated JSON is available as <code>data.json</code>.</p>
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
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
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

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
