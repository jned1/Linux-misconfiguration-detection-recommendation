"""
generate_report.py
------------------
Generates HTML (with charts) and JSON reports from detection findings.

Called automatically by main.py, or directly:
    python3 scripts/reporting/generate_report.py --findings reports/findings.json
"""

import argparse
import datetime
import json
import os

SEV_COLOR = {
    "CRITICAL": "#e74c3c",
    "HIGH"    : "#e67e22",
    "MEDIUM"  : "#f1c40f",
    "LOW"     : "#3498db",
    "NONE"    : "#2ecc71",
}
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]


def _badge(severity):
    color = SEV_COLOR.get(severity, "#888")
    return ('<span style="background:{c};color:#fff;padding:2px 10px;'
            'border-radius:12px;font-size:0.82em;font-weight:700;">{s}</span>').format(
                c=color, s=severity)


def _finding_row(f):
    ml_cell = f["ml_severity"] if f["ml_severity"] else "—"
    return """
        <tr>
          <td>{badge}</td>
          <td><strong>{rule_id}</strong></td>
          <td>{category}</td>
          <td>{description}</td>
          <td><code>{actual}</code></td>
          <td><code>{expected}</code></td>
          <td>{ml}</td>
          <td style="font-size:0.85em;color:#555">{rec}</td>
        </tr>""".format(
        badge=_badge(f["final_severity"]),
        rule_id=f["rule_id"],
        category=f["category"],
        description=f["description"],
        actual=f["actual_value"],
        expected=f["expected_value"],
        ml=ml_cell,
        rec=f["recommendation"],
    )


def _compliant_row(f):
    return """
        <tr>
          <td>{badge}</td>
          <td><strong>{rule_id}</strong></td>
          <td>{category}</td>
          <td>{description}</td>
          <td><code>{actual}</code></td>
          <td><code>{expected}</code></td>
        </tr>""".format(
        badge=_badge("NONE"),
        rule_id=f["rule_id"],
        category=f["category"],
        description=f["description"],
        actual=f["actual_value"],
        expected=f["expected_value"],
    )


def build_html(findings, hostname, scan_time):
    vulnerable = sorted(
        [f for f in findings if f["is_vulnerable"]],
        key=lambda x: SEV_ORDER.index(x["final_severity"]),
    )
    compliant = [f for f in findings if not f["is_vulnerable"]]

    sev_count = {s: 0 for s in SEV_ORDER}
    for f in vulnerable:
        sev_count[f["final_severity"]] += 1

    total    = len(findings)
    vuln_n   = len(vulnerable)
    comp_n   = len(compliant)

    weights   = {"CRITICAL": 10, "HIGH": 6, "MEDIUM": 3, "LOW": 1, "NONE": 0}
    raw_score = sum(sev_count[s] * weights[s] for s in SEV_ORDER)
    max_score = total * 10
    risk_score = round((1 - raw_score / max_score) * 100) if max_score else 100
    risk_label = ("CRITICAL" if risk_score < 40 else
                  "HIGH"     if risk_score < 60 else
                  "MEDIUM"   if risk_score < 80 else "LOW")
    risk_color = SEV_COLOR.get(risk_label, "#888")

    chart_labels = json.dumps(SEV_ORDER[:-1])
    chart_data   = json.dumps([sev_count[s] for s in SEV_ORDER[:-1]])
    chart_colors = json.dumps([SEV_COLOR[s] for s in SEV_ORDER[:-1]])

    finding_rows   = "".join(_finding_row(f)   for f in vulnerable)
    compliant_rows = "".join(_compliant_row(f) for f in compliant)

    vuln_table = """
    <div style="overflow-x:auto">
    <table>
      <thead><tr>
        <th>Severity</th><th>Rule ID</th><th>Category</th><th>Description</th>
        <th>Actual</th><th>Expected</th><th>ML Pred.</th><th>Recommendation</th>
      </tr></thead>
      <tbody>{rows}</tbody>
    </table>
    </div>""".format(rows=finding_rows) if vulnerable else '<div class="empty">No misconfigurations detected.</div>'

    comp_table = """
    <div style="overflow-x:auto">
    <table>
      <thead><tr>
        <th>Status</th><th>Rule ID</th><th>Category</th>
        <th>Description</th><th>Actual</th><th>Expected</th>
      </tr></thead>
      <tbody>{rows}</tbody>
    </table>
    </div>""".format(rows=compliant_rows) if compliant else '<div class="empty">No compliant checks.</div>'

    crit_class = "danger"  if sev_count["CRITICAL"] else "ok"
    high_class = "warning" if sev_count["HIGH"]     else "ok"

    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Linux Security Report - {hostname}</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <style>
    * {{ box-sizing:border-box; margin:0; padding:0; }}
    body {{ font-family:'Segoe UI',Roboto,sans-serif; background:#f0f2f5; color:#2d3748; }}
    header {{ background:#1a202c; color:#fff; padding:24px 40px; display:flex; align-items:center; gap:16px; }}
    header .shield {{ font-size:2.2em; }}
    header h1 {{ font-size:1.5em; font-weight:700; }}
    header p  {{ font-size:0.9em; opacity:0.7; margin-top:4px; }}
    .container {{ max-width:1200px; margin:0 auto; padding:32px 24px; }}
    .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:16px; margin-bottom:32px; }}
    .card {{ background:#fff; border-radius:12px; padding:20px; text-align:center; box-shadow:0 2px 8px rgba(0,0,0,.07); }}
    .card .value {{ font-size:2.4em; font-weight:800; }}
    .card .label {{ font-size:0.82em; color:#718096; margin-top:4px; text-transform:uppercase; letter-spacing:.05em; }}
    .card.danger  .value {{ color:#e74c3c; }}
    .card.warning .value {{ color:#e67e22; }}
    .card.ok      .value {{ color:#2ecc71; }}
    .card.info    .value {{ color:#3498db; }}
    .score-ring {{ width:100px; height:100px; border-radius:50%; border:10px solid {risk_color};
                   display:flex; flex-direction:column; align-items:center; justify-content:center; margin:0 auto 8px; }}
    .score-ring .num {{ font-size:1.6em; font-weight:800; color:{risk_color}; }}
    .score-ring .lbl {{ font-size:0.65em; color:#718096; text-transform:uppercase; }}
    .section {{ background:#fff; border-radius:12px; padding:24px; box-shadow:0 2px 8px rgba(0,0,0,.07); margin-bottom:28px; }}
    .section h2 {{ font-size:1.1em; font-weight:700; margin-bottom:18px; padding-bottom:10px; border-bottom:2px solid #e2e8f0; }}
    .chart-wrap {{ max-width:500px; margin:0 auto; }}
    table  {{ width:100%; border-collapse:collapse; font-size:0.88em; }}
    th     {{ background:#f7fafc; padding:10px 12px; text-align:left; font-size:0.78em;
              text-transform:uppercase; letter-spacing:.05em; color:#718096; border-bottom:2px solid #e2e8f0; }}
    td     {{ padding:10px 12px; border-bottom:1px solid #edf2f7; vertical-align:top; }}
    tr:hover td {{ background:#f7fafc; }}
    code   {{ background:#edf2f7; padding:2px 6px; border-radius:4px; font-size:0.9em; }}
    .empty {{ text-align:center; padding:40px; color:#a0aec0; font-size:1.1em; }}
    footer {{ text-align:center; color:#a0aec0; font-size:0.8em; padding:32px; }}
  </style>
</head>
<body>
<header>
  <div class="shield">&#128737;</div>
  <div>
    <h1>Linux Security Misconfiguration Report</h1>
    <p>Host: <strong>{hostname}</strong> &nbsp;|&nbsp; Scan: {scan_time}</p>
  </div>
</header>
<div class="container">
  <div class="cards">
    <div class="card">
      <div class="score-ring">
        <span class="num">{risk_score}</span>
        <span class="lbl">Score</span>
      </div>
      <div class="label">Security Score / 100</div>
    </div>
    <div class="card {crit_class}">
      <div class="value">{crit_n}</div>
      <div class="label">Critical</div>
    </div>
    <div class="card {high_class}">
      <div class="value">{high_n}</div>
      <div class="label">High</div>
    </div>
    <div class="card info">
      <div class="value">{med_low_n}</div>
      <div class="label">Med / Low</div>
    </div>
    <div class="card ok">
      <div class="value">{comp_n}</div>
      <div class="label">Compliant</div>
    </div>
    <div class="card info">
      <div class="value">{total}</div>
      <div class="label">Total Checks</div>
    </div>
  </div>
  <div class="section">
    <h2>&#128202; Severity Distribution</h2>
    <div class="chart-wrap"><canvas id="sevChart"></canvas></div>
  </div>
  <div class="section">
    <h2>&#9888;&#65039; Misconfigurations Found ({vuln_n})</h2>
    {vuln_table}
  </div>
  <div class="section">
    <h2>&#9989; Compliant Checks ({comp_n})</h2>
    {comp_table}
  </div>
</div>
<footer>Generated by Linux Security Misconfiguration Detection System | Hybrid Rule-Based + ML | CIS Benchmark</footer>
<script>
  new Chart(document.getElementById('sevChart').getContext('2d'), {{
    type: 'bar',
    data: {{
      labels: {chart_labels},
      datasets: [{{ label: 'Findings', data: {chart_data},
        backgroundColor: {chart_colors}, borderRadius: 6, borderSkipped: false }}]
    }},
    options: {{
      responsive: true,
      plugins: {{ legend: {{ display: false }} }},
      scales: {{ y: {{ beginAtZero: true, ticks: {{ stepSize: 1 }} }}, x: {{ grid: {{ display: false }} }} }}
    }}
  }});
</script>
</body>
</html>""".format(
        hostname=hostname, scan_time=scan_time,
        risk_color=risk_color, risk_score=risk_score,
        crit_class=crit_class, crit_n=sev_count["CRITICAL"],
        high_class=high_class, high_n=sev_count["HIGH"],
        med_low_n=sev_count["MEDIUM"] + sev_count["LOW"],
        comp_n=comp_n, total=total, vuln_n=vuln_n,
        chart_labels=chart_labels, chart_data=chart_data, chart_colors=chart_colors,
        vuln_table=vuln_table, comp_table=comp_table,
    )


def generate(findings, hostname="localhost", output_dir="reports"):
    """Build and write HTML + JSON reports. Returns (html_path, json_path)."""
    os.makedirs(output_dir, exist_ok=True)
    ts        = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html_path = os.path.join(output_dir, "report_{}.html".format(ts))
    json_path = os.path.join(output_dir, "report_{}.json".format(ts))

    with open(html_path, "w") as f:
        f.write(build_html(findings, hostname, scan_time))

    vulnerable = [f for f in findings if f["is_vulnerable"]]
    sev_count  = {s: 0 for s in SEV_ORDER}
    for f in vulnerable:
        sev_count[f["final_severity"]] += 1

    report_json = {
        "metadata": {
            "hostname"        : hostname,
            "scan_time"       : scan_time,
            "total_checks"    : len(findings),
            "vulnerable"      : len(vulnerable),
            "compliant"       : len(findings) - len(vulnerable),
            "severity_summary": sev_count,
            "generated_by"    : "Linux Security Misconfiguration Detection System v1.0",
        },
        "findings": [f for f in findings if f["is_vulnerable"]],
        "compliant_checks": [
            {"rule_id": f["rule_id"], "category": f["category"], "description": f["description"]}
            for f in findings if not f["is_vulnerable"]
        ],
    }
    with open(json_path, "w") as f:
        json.dump(report_json, f, indent=2)

    print("  HTML report saved -> {}".format(html_path))
    print("  JSON report saved -> {}".format(json_path))
    return html_path, json_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate security reports")
    parser.add_argument("--findings", required=True, help="JSON file with findings list")
    parser.add_argument("--output",   default="reports", help="Output directory")
    args = parser.parse_args()

    with open(args.findings) as f:
        data = json.load(f)

    findings_list = data.get("findings", data) if isinstance(data, dict) else data
    hostname      = data.get("hostname", "localhost") if isinstance(data, dict) else "localhost"
    generate(findings_list, hostname, args.output)
