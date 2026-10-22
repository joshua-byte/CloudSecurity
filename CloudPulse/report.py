
"""Generate a self-contained HTML investigation report for CloudPulse."""

from datetime import datetime, timezone
import html
import json

import pandas as pd


# ============================================================
# CONSTANTS
# ============================================================

SEVERITIES = ["Critical", "High", "Medium", "Low"]

# Keep this consistent with the revised rules.py.
STATUSES = ["Confirmed", "Rule match", "Needs review"]

ALERT_COLUMNS = [
    "alert_id",
    "time",
    "status",
    "severity",
    "user",
    "sourceIP",
    "eventName",
    "rule_id",
    "rule_name",
    "mitre",
    "z_peak",
    "window_id",
    "evidence_count",
    "description",
]


# ============================================================
# SAFE FORMATTING
# ============================================================

def esc(value):
    """HTML-escape a value, treating missing values as blank."""

    if value is None:
        return ""

    if isinstance(value, (dict, list, tuple)):
        value = json.dumps(value, default=str, ensure_ascii=False)

    try:
        if pd.isna(value):
            return ""
    except (TypeError, ValueError):
        pass

    return html.escape(str(value), quote=True)


def safe_frame(value):
    """Return a copy of a DataFrame or an empty DataFrame."""

    if value is None:
        return pd.DataFrame()

    if not isinstance(value, pd.DataFrame):
        raise TypeError(
            "Report inputs must be pandas DataFrames or None."
        )

    return value.copy()


def safe_count(frame, column, value):
    """Count exact matches in a column, handling missing columns."""

    if column not in frame.columns:
        return 0

    return int(
        frame[column]
        .fillna("")
        .astype(str)
        .eq(value)
        .sum()
    )


def format_number(value):
    """Format a numeric metric safely."""

    try:
        return f"{int(value):,}"
    except (TypeError, ValueError, OverflowError):
        return "Unavailable"


def format_time(value):
    """Format a timestamp consistently in UTC."""

    if value is None:
        return "Unavailable"

    parsed = pd.to_datetime(
        value,
        utc=True,
        errors="coerce",
    )

    if pd.isna(parsed):
        return "Unavailable"

    return parsed.strftime("%Y-%m-%d %H:%M UTC")


def format_parameter(value, default="Not specified"):
    """Display a parameter without exposing Python null values."""

    if value is None:
        return default

    try:
        if pd.isna(value):
            return default
    except (TypeError, ValueError):
        pass

    result = str(value).strip()

    if result.lower() in {"", "none", "nan", "null"}:
        return default

    return result


def make_rows(rows, columns, empty_message, css_class=""):
    """Build escaped HTML table rows."""

    if not rows:
        colspan = len(columns)

        return (
            f'<tr><td colspan="{colspan}" class="empty">'
            f"{esc(empty_message)}</td></tr>"
        )

    result = []

    for row in rows:
        cells = []

        for column in columns:
            value = row.get(column, "")

            if column == "severity":
                severity = format_parameter(value, "Unknown")
                css = severity.lower()

                cells.append(
                    f'<td><span class="severity {esc(css)}">'
                    f"{esc(severity)}</span></td>"
                )

            elif column == "status":
                status = format_parameter(value, "Unknown")
                css = (
                    status.lower()
                    .replace(" ", "-")
                )

                cells.append(
                    f'<td><span class="status {esc(css)}">'
                    f"{esc(status)}</span></td>"
                )

            else:
                cells.append(f"<td>{esc(value)}</td>")

        result.append(
            f'<tr class="{esc(css_class)}">'
            + "".join(cells)
            + "</tr>"
        )

    return "".join(result)


# ============================================================
# DATA PREPARATION
# ============================================================

def prepare_alerts(alerts):
    """Normalize alert columns and sort by severity and time."""

    if alerts.empty:
        return pd.DataFrame(columns=ALERT_COLUMNS)

    result = alerts.copy()

    for column in ALERT_COLUMNS:
        if column not in result.columns:
            result[column] = ""

    severity_rank = {
        severity: index
        for index, severity in enumerate(SEVERITIES)
    }

    result["_severity_rank"] = (
        result["severity"]
        .fillna("")
        .astype(str)
        .str.title()
        .map(severity_rank)
        .fillna(-1)
    )

    result["_sort_time"] = pd.to_datetime(
        result["time"],
        utc=True,
        errors="coerce",
    )

    result = (
        result.sort_values(
            ["_severity_rank", "_sort_time"],
            ascending=[False, True],
            kind="stable",
            na_position="last",
        )
        .drop(columns=["_severity_rank", "_sort_time"])
        .reset_index(drop=True)
    )

    return result


def prepare_rules(rules):
    """Index rule definitions by their ID."""

    lookup = {}

    if not isinstance(rules, (list, tuple)):
        return lookup

    for rule in rules:
        if not isinstance(rule, dict):
            continue

        rule_id = format_parameter(rule.get("id"), "")

        if rule_id:
            lookup[rule_id] = rule

    return lookup


def collect_recommendations(alerts, rules_lookup):
    """Collect distinct rule-specific recommendations."""

    recommendations = []
    seen = set()

    if alerts.empty or "rule_id" not in alerts.columns:
        return recommendations

    rule_ids = (
        alerts["rule_id"]
        .fillna("")
        .astype(str)
        .unique()
    )

    for rule_id in rule_ids:
        rule = rules_lookup.get(rule_id, {})
        response = rule.get("response", [])

        if isinstance(response, str):
            response = [response]

        if not isinstance(response, (list, tuple)):
            continue

        for item in response:
            item = format_parameter(item, "")

            if item and item not in seen:
                seen.add(item)
                recommendations.append(item)

    return recommendations


# ============================================================
# REPORT GENERATION
# ============================================================

def generate_report(
    alerts,
    windows,
    events,
    params=None,
    rules=None,
):
    """
    Generate a self-contained HTML investigation report.

    Parameters
    ----------
    alerts:
        DataFrame containing rule matches and review findings.

    windows:
        DataFrame containing statistical anomaly windows.

    events:
        DataFrame containing normalized events.

    params:
        Optional settings and data-quality metadata.

    rules:
        Optional list of rule definitions from rules.json.

    Returns
    -------
    str
        A complete HTML document.
    """

    params = params or {}

    if not isinstance(params, dict):
        raise TypeError("params must be a dictionary or None.")

    alerts = safe_frame(alerts)
    windows = safe_frame(windows)
    events = safe_frame(events)

    alerts = prepare_alerts(alerts)
    rules_lookup = prepare_rules(rules)

    generated = datetime.now(timezone.utc).strftime(
        "%Y-%m-%d %H:%M UTC"
    )

    # --------------------------------------------------------
    # Dataset metrics
    # --------------------------------------------------------

    if "time" in events.columns:
        times = pd.to_datetime(
            events["time"],
            utc=True,
            errors="coerce",
        ).dropna()
    else:
        times = pd.Series(
            dtype="datetime64[ns, UTC]"
        )

    first = (
        format_time(times.min())
        if not times.empty
        else "Unavailable"
    )

    last = (
        format_time(times.max())
        if not times.empty
        else "Unavailable"
    )

    if "user" in events.columns:
        users = events["user"].fillna("").astype(str).str.strip()
        unique_users = int(users[users.ne("")].nunique())
    else:
        unique_users = 0

    if "is_failure" in events.columns:
        failures = events["is_failure"].map(
            lambda value: str(value).strip().lower()
            in {"true", "1", "yes", "y"}
        ).sum()
        failure_count = int(failures)

    elif "errorCode" in events.columns:
        errors = events["errorCode"].fillna("").astype(str).str.strip()
        failure_count = int(
            errors.ne("")
            & ~errors.str.lower().isin(
                {"none", "null", "nan", "n/a"}
            )
        ).sum()

    else:
        failure_count = 0

    status_counts = {
        status: safe_count(alerts, "status", status)
        for status in STATUSES
    }

    severity_counts = {
        severity: safe_count(
            alerts,
            "severity",
            severity,
        )
        for severity in SEVERITIES
    }

    # --------------------------------------------------------
    # Summary tables
    # --------------------------------------------------------

    status_rows = "".join(
        f"<tr><td>{esc(status)}</td>"
        f"<td>{format_number(count)}</td></tr>"
        for status, count in status_counts.items()
    )

    severity_rows = "".join(
        f"<tr><td>{esc(severity)}</td>"
        f"<td>{format_number(severity_counts[severity])}</td></tr>"
        for severity in SEVERITIES
    )

    # --------------------------------------------------------
    # Top alerts
    # --------------------------------------------------------

    top = alerts.head(10)

    top_columns = [
        "time",
        "severity",
        "status",
        "rule_id",
        "rule_name",
        "user",
        "sourceIP",
        "mitre",
        "evidence_count",
        "description",
    ]

    top_rows = make_rows(
        top.to_dict("records"),
        top_columns,
        "No alerts were generated for this analysis.",
    )

    # --------------------------------------------------------
    # Detection settings
    # --------------------------------------------------------

    source = format_parameter(
        params.get("source"),
        "Not specified",
    )

    threshold = format_parameter(
        params.get("K", params.get("threshold")),
        "Not specified",
    )

    baseline = format_parameter(
        params.get("window", params.get("baseline_window")),
        "Not specified",
    )

    frequency = format_parameter(
        params.get("frequency", params.get("freq")),
        "5min",
    )

    # --------------------------------------------------------
    # Data quality metadata, when supplied
    # --------------------------------------------------------

    quality = params.get("data_quality", {})

    if not isinstance(quality, dict):
        quality = {}

    quality_rows = []

    quality_labels = {
        "input_rows": "Input rows",
        "valid_timestamp_rows": "Rows with valid timestamps",
        "invalid_timestamps": "Invalid timestamps",
        "duplicate_event_id_rows": "Rows with duplicate event IDs",
    }

    for key, label in quality_labels.items():
        if key in quality:
            quality_rows.append(
                f"<tr><td>{esc(label)}</td>"
                f"<td>{esc(format_number(quality[key]))}</td></tr>"
            )

    quality_html = ""

    if quality_rows:
        quality_html = (
            "<section><h2>Data quality</h2>"
            "<p class='muted'>Data-quality metadata supplied "
            "by the analysis pipeline.</p>"
            "<div class='table-wrap'><table>"
            "<thead><tr><th>Check</th><th>Count</th></tr></thead>"
            "<tbody>"
            + "".join(quality_rows)
            + "</tbody></table></div></section>"
        )

    # --------------------------------------------------------
    # Investigation recommendations
    # --------------------------------------------------------

    recommendations = collect_recommendations(
        alerts,
        rules_lookup,
    )

    recommendation_items = "".join(
        f"<li>{esc(item)}</li>"
        for item in recommendations
    )

    if not recommendation_items:
        recommendation_items = (
            "<li>No rule-specific recommendations were supplied. "
            "Review the relevant CloudTrail records and validate "
            "whether the activity was authorized.</li>"
        )

    # --------------------------------------------------------
    # Output HTML
    # --------------------------------------------------------

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<title>CloudPulse Security Report</title>
<style>
:root {{
    color-scheme: light;
    --ink: #182235;
    --muted: #64748b;
    --line: #e2e8f0;
    --surface: #ffffff;
    --page: #f3f6fb;
    --accent: #234b84;
}}
* {{ box-sizing: border-box; }}
body {{
    margin: 0;
    background: var(--page);
    color: var(--ink);
    font-family: "Segoe UI", Arial, sans-serif;
    font-size: 14px;
    line-height: 1.6;
}}
main {{
    width: min(1200px, 100%);
    margin: 28px auto;
    padding: 0 20px 40px;
}}
header {{
    background: #142541;
    color: #ffffff;
    padding: 28px;
    border-radius: 12px;
}}
header h1 {{
    margin: 0 0 8px;
    font-size: 28px;
    line-height: 1.25;
}}
header p {{ margin: 6px 0; }}
section {{
    background: var(--surface);
    margin-top: 18px;
    padding: 22px;
    border: 1px solid var(--line);
    border-radius: 10px;
}}
h2 {{
    margin: 0 0 14px;
    font-size: 19px;
}}
h3 {{
    font-size: 15px;
    margin: 22px 0 10px;
}}
p {{ overflow-wrap: anywhere; }}
.muted {{ color: var(--muted); }}
.metrics {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 12px;
}}
.metric {{
    background: #f5f8fc;
    border: 1px solid var(--line);
    border-radius: 8px;
    padding: 15px;
    min-width: 0;
}}
.metric-label {{ color: var(--muted); }}
.metric strong {{
    display: block;
    font-size: 27px;
    line-height: 1.3;
    margin-top: 5px;
    overflow-wrap: anywhere;
}}
.table-wrap {{
    width: 100%;
    overflow-x: auto;
}}
table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
}}
th, td {{
    padding: 10px;
    text-align: left;
    vertical-align: top;
    border-bottom: 1px solid var(--line);
    overflow-wrap: anywhere;
}}
th {{
    background: #f5f7fb;
    font-weight: 600;
    white-space: nowrap;
}}
tbody tr:last-child td {{ border-bottom: none; }}
.empty {{
    padding: 20px;
    color: var(--muted);
    text-align: center;
}}
.severity, .status {{
    display: inline-block;
    padding: 3px 8px;
    border-radius: 5px;
    font-size: 12px;
    font-weight: 600;
    white-space: nowrap;
}}
.severity.critical {{
    background: #fee2e2;
    color: #991b1b;
}}
.severity.high {{
    background: #ffedd5;
    color: #9a3412;
}}
.severity.medium {{
    background: #fef3c7;
    color: #92400e;
}}
.severity.low {{
    background: #e2e8f0;
    color: #334155;
}}
.status.confirmed {{
    background: #dcfce7;
    color: #166534;
}}
.status.rule-match {{
    background: #dbeafe;
    color: #1e40af;
}}
.status.needs-review {{
    background: #fef3c7;
    color: #92400e;
}}
ul {{ padding-left: 22px; }}
li {{ margin: 7px 0; overflow-wrap: anywhere; }}
footer {{
    padding: 18px 4px;
    color: var(--muted);
    font-size: 12px;
}}
@media (max-width: 600px) {{
    main {{ margin: 12px auto; padding: 0 10px 24px; }}
    header, section {{ padding: 16px; }}
    header h1 {{ font-size: 23px; }}
    .metric strong {{ font-size: 23px; }}
}}
@media print {{
    body {{ background: #ffffff; }}
    main {{ width: 100%; margin: 0; padding: 0; }}
    header, section {{ break-inside: avoid; }}
    section {{ border: 1px solid #cccccc; }}
    .table-wrap {{ overflow: visible; }}
    table {{ font-size: 10px; }}
}}
</style>
</head>
<body>
<main>

<header>
    <h1>CloudPulse Security Analysis</h1>
    <p>CloudTrail anomaly detection and rule-based investigation findings</p>
    <p class="muted">
        Generated {esc(generated)} |
        Source: {esc(source)}
    </p>
</header>

<section>
    <h2>Executive summary</h2>
    <div class="metrics">
        <div class="metric">
            <div class="metric-label">Events analysed</div>
            <strong>{format_number(len(events))}</strong>
        </div>
        <div class="metric">
            <div class="metric-label">Anomaly windows</div>
            <strong>{format_number(len(windows))}</strong>
        </div>
        <div class="metric">
            <div class="metric-label">Security alerts</div>
            <strong>{format_number(len(alerts))}</strong>
        </div>
        <div class="metric">
            <div class="metric-label">Critical alerts</div>
            <strong>{format_number(severity_counts["Critical"])}</strong>
        </div>
        <div class="metric">
            <div class="metric-label">Failed events</div>
            <strong>{format_number(failure_count)}</strong>
        </div>
        <div class="metric">
            <div class="metric-label">Unique users</div>
            <strong>{format_number(unique_users)}</strong>
        </div>
    </div>
    <p><strong>Event time range:</strong>
        {esc(first)} to {esc(last)}
    </p>
    <p><strong>Detection settings:</strong>
        Threshold={esc(threshold)};
        baseline window={esc(baseline)} bins;
        frequency={esc(frequency)}.
    </p>
</section>

<section>
    <h2>Method and interpretation</h2>
    <p>
        CloudPulse analyses event counts and failure counts using
        a rolling median and median absolute deviation (MAD)
        baseline. It also evaluates selected CloudTrail security
        rules for potentially sensitive activity.
    </p>
    <p>
        Statistical anomalies identify unusual patterns; they do
        not establish malicious intent. Rule matches identify
        events or activity patterns satisfying configured
        conditions and may reflect legitimate administrative work.
    </p>
    <ul>
        <li><strong>Confirmed:</strong> Reserved for findings
            explicitly confirmed through an external investigation
            or trusted confirmation input.</li>
        <li><strong>Rule match:</strong> A configured security rule
            matched. This is not, by itself, proof of an attack.</li>
        <li><strong>Needs review:</strong> A statistical anomaly
            has no associated matching security rule in this report.</li>
    </ul>
</section>

<section>
    <h2>Alerts by status</h2>
    <div class="table-wrap">
        <table>
            <thead><tr><th>Status</th><th>Count</th></tr></thead>
            <tbody>{status_rows}</tbody>
        </table>
    </div>

    <h3>Alerts by severity</h3>
    <div class="table-wrap">
        <table>
            <thead><tr><th>Severity</th><th>Count</th></tr></thead>
            <tbody>{severity_rows}</tbody>
        </table>
    </div>
</section>

<section>
    <h2>Priority alerts</h2>
    <p class="muted">
        Up to ten alerts ordered by severity and then timestamp.
        Validate the underlying events before taking action.
    </p>
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>Time</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Rule ID</th>
                    <th>Rule name</th>
                    <th>User</th>
                    <th>Source IP</th>
                    <th>MITRE ATT&amp;CK</th>
                    <th>Evidence</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>{top_rows}</tbody>
        </table>
    </div>
</section>

<section>
    <h2>Investigation recommendations</h2>
    <ul>{recommendation_items}</ul>
</section>

{quality_html}

<section>
    <h2>Limitations and cautions</h2>
    <ul>
        <li>Detection relies on the supplied dataset, selected
            rules, statistical settings, and available fields.</li>
        <li>Missing or incomplete CloudTrail records can affect
            the reliability of findings.</li>
        <li>Duplicate event IDs are data-quality signals and should
            be investigated before records are discarded.</li>
        <li>Rule matches and statistical anomalies require
            contextual validation before being treated as incidents.</li>
        <li>This report describes analysis of supplied data. It does
            not establish that AWS resources were compromised and
            does not perform remediation.</li>
    </ul>
</section>

<footer>
    CloudPulse | Generated {esc(generated)}.
    Report metrics reflect the data supplied to the report generator.
</footer>

</main>
</body>
</html>"""
