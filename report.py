"""Generate a self-contained HTML summary report for CloudPulse."""
from datetime import datetime, timezone
import html
import pandas as pd


def esc(value):
    """HTML-escape a value before inserting it into the report."""
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except (TypeError, ValueError):
        pass
    return html.escape(str(value))


def generate_report(alerts, windows, events, params=None, rules=None):
    """Build and return an HTML investigation report from analysis outputs."""
    params, rules = params or {}, rules or []
    alerts = alerts.copy() if alerts is not None else pd.DataFrame()
    windows = windows.copy() if windows is not None else pd.DataFrame()
    events = events.copy() if events is not None else pd.DataFrame()
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    times = pd.to_datetime(events.get("time", pd.Series(dtype=str)), utc=True, errors="coerce").dropna()
    first = times.min().strftime("%Y-%m-%d %H:%M UTC") if not times.empty else "Unavailable"
    last = times.max().strftime("%Y-%m-%d %H:%M UTC") if not times.empty else "Unavailable"

    def status_count(value):
        return int(alerts.get("status", pd.Series(dtype=str)).astype(str).eq(value).sum())

    def severity_count(value):
        return int(alerts.get("severity", pd.Series(dtype=str)).astype(str).eq(value).sum())

    status_rows = "".join(f"<tr><td>{esc(s)}</td><td>{status_count(s)}</td></tr>" for s in ["Confirmed", "Rule-only", "Needs review"])
    severity_rows = "".join(f"<tr><td>{esc(s)}</td><td>{severity_count(s)}</td></tr>" for s in ["Critical", "High", "Medium", "Low"])
    top = alerts.copy()
    if not top.empty:
        rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        top["_rank"] = top.get("severity", pd.Series(dtype=str)).map(rank).fillna(0)
        top = top.sort_values(["_rank", "time"], ascending=[False, True]).head(5)
    top_rows = "".join(
        "<tr>" + "".join(f"<td>{esc(row.get(c, ''))}</td>" for c in ["time", "severity", "rule_id", "rule_name", "user", "sourceIP", "mitre", "evidence_count"]) + "</tr>"
        for _, row in top.iterrows()
    ) or '<tr><td colspan="8">No alerts generated.</td></tr>'

    lookup = {r.get("id"): r for r in rules}
    advice = []
    if not alerts.empty and "rule_id" in alerts:
        for rid in alerts["rule_id"].dropna().astype(str).unique():
            rule = lookup.get(rid, {})
            response = rule.get("response", [])
            if isinstance(response, str):
                response = [response]
            for item in response:
                if item and item not in advice:
                    advice.append(item)
    advice_html = "".join(f"<li>{esc(item)}</li>" for item in advice) or "<li>No rule-specific recommendations are available.</li>"

    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CloudPulse Security Report</title>
<style>body{{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f2f5fa;color:#182235}}main{{max-width:1100px;margin:30px auto;padding:0 18px 40px}}header{{background:#12213b;color:white;padding:26px;border-radius:12px}}section{{background:white;margin-top:16px;padding:20px;border-radius:10px}}table{{width:100%;border-collapse:collapse;font-size:14px}}td,th{{padding:9px;border-bottom:1px solid #e5eaf1;text-align:left;overflow-wrap:anywhere}}th{{background:#f5f7fb}}.metrics{{display:flex;gap:12px;flex-wrap:wrap}}.metric{{background:#f4f7fb;border-radius:8px;padding:14px;min-width:130px}}.metric strong{{display:block;font-size:24px;margin-top:6px}}.muted{{color:#68758a}}</style></head><body><main>
<header><h1>CloudPulse Security Analysis</h1><p>CloudTrail anomaly detection and explainable rule-based findings</p><p class="muted">Generated {esc(generated)} · Source: {esc(params.get('source','Not specified'))}</p></header>
<section><h2>Dataset overview</h2><div class="metrics"><div class="metric">Events analysed<strong>{len(events):,}</strong></div><div class="metric">Anomaly windows<strong>{len(windows):,}</strong></div><div class="metric">Security alerts<strong>{len(alerts):,}</strong></div><div class="metric">Critical alerts<strong>{severity_count('Critical')}</strong></div></div><p>Time range: {esc(first)} to {esc(last)}</p><p>Settings: K={esc(params.get('K','default'))}; baseline window={esc(params.get('window','default'))} five-minute bins.</p></section>
<section><h2>Method and interpretation</h2><p>CloudPulse detects unusual event-count and failure-count activity using a rolling median and median absolute deviation (MAD), then evaluates selected CloudTrail security rules. Single-event rules can alert without a statistical spike because rare high-impact actions may not create a volume anomaly.</p><p>Confirmed means a rule match overlaps statistical evidence; it does not prove an attack. Rule-only means a rule matched without overlapping statistical evidence. Needs review indicates an unexplained statistical anomaly.</p></section>
<section><h2>Alerts by status</h2><table><tr><th>Status</th><th>Count</th></tr>{status_rows}</table><h2>Alerts by severity</h2><table><tr><th>Severity</th><th>Count</th></tr>{severity_rows}</table></section>
<section><h2>Top alerts</h2><table><tr><th>Time</th><th>Severity</th><th>Rule ID</th><th>Rule name</th><th>User</th><th>Source IP</th><th>MITRE</th><th>Evidence</th></tr>{top_rows}</table></section>
<section><h2>Investigation recommendations</h2><ul>{advice_html}</ul></section>
<section><h2>Limitations</h2><ul><li>Detection uses fixed thresholds and selected rules; it may miss activity outside their coverage.</li><li>Public or sample data may not represent a complete production audit trail.</li><li>Rule matches may reflect legitimate administrative activity and require analyst validation.</li><li>This version processes local files only; it does not ingest live AWS events or remediate findings.</li></ul></section></main></body></html>'''
