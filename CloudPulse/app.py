"""CloudPulse Streamlit dashboard and one-click analysis pipeline."""
import gzip
import json
import io
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

import detection_engine
import json_to_csv
import rules
from report import generate_report

BASE = Path(__file__).resolve().parent
DATA_DIR = BASE / "data"
LOGGED_DIR = BASE / "logged"
OUTPUT_DIR = BASE / "outputs"
DEFAULT_CSV = DATA_DIR / "cloudpulse.csv"


def read_upload(upload):
    """Read uploaded CloudTrail JSON, compressed JSON, or CSV into a DataFrame."""
    name, raw = upload.name.lower(), upload.getvalue()
    if name.endswith(".json.gz") or name.endswith(".gz"):
        raw = gzip.decompress(raw)
    if name.endswith((".json", ".json.gz", ".gz")):
        data = json.loads(raw.decode("utf-8-sig"))
        records = data.get("Records", []) if isinstance(data, dict) else data
        if not isinstance(records, list):
            raise ValueError("CloudTrail JSON must contain a Records list or be a list of events.")
        rows = [json_to_csv.flatten_event(e, upload.name) for e in records if isinstance(e, dict)]
        if not rows:
            raise ValueError("No event records were found in the uploaded JSON.")
        return pd.DataFrame(rows)
    if name.endswith(".csv"):
        frame = pd.read_csv(io.BytesIO(raw), low_memory=False)
        if frame.empty:
            raise ValueError("The uploaded CSV is empty.")
        return frame
    raise ValueError("Upload a .json, .json.gz, .gz, or .csv file.")


def canonicalize(events):
    """Add the standard identity, source, time, and failure fields used by rules.py."""
    frame = events.copy()
    aliases = {
        "time": ["eventTime", "event_time", "timestamp"],
        "eventID": ["eventId", "event_id"],
        "eventName": ["event_name"],
        "eventSource": ["event_source"],
        "userType": ["userIdentityType", "user_identity_type"],
        "sourceIP": ["sourceIPAddress", "sourceIp", "source_ip"],
        "mfaUsed": ["MFAUsed", "mfa_used"],
        "errorCode": ["error_code"],
        "requestParameters": ["request_parameters"],
        "responseElements": ["response_elements"],
    }
    for target, candidates in aliases.items():
        if target not in frame.columns:
            for candidate in candidates:
                if candidate in frame.columns:
                    frame[target] = frame[candidate]
                    break
        if target not in frame.columns:
            frame[target] = ""
    if "user" not in frame.columns:
        arn = frame.get("userIdentityArn", pd.Series("", index=frame.index)).fillna("").astype(str)
        username = frame.get("userName", pd.Series("", index=frame.index)).fillna("").astype(str)
        frame["user"] = arn.where(arn.str.strip().ne(""), username)
        frame.loc[frame["userType"].astype(str).str.lower().eq("root"), "user"] = "Root"
    frame["time"] = pd.to_datetime(frame["time"], utc=True, errors="coerce")
    frame = frame.dropna(subset=["time"]).copy()
    if frame.empty:
        raise ValueError("No rows have valid event timestamps.")
    old_failure = frame.get("is_failure", pd.Series(False, index=frame.index)).astype(str).str.lower().isin(["true", "1", "yes"])
    error_failure = frame["errorCode"].fillna("").astype(str).str.strip().ne("")
    response_failure = frame["responseElements"].fillna("").astype(str).str.lower().str.contains("failure")
    login_failure = frame["eventName"].astype(str).eq("ConsoleLogin") & response_failure
    frame["is_failure"] = old_failure | error_failure | login_failure
    return frame.sort_values("time").reset_index(drop=True)


def run_pipeline(frame, k, baseline_window):
    """Run the detector, normalize its events, then execute the security rules."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOGGED_DIR.mkdir(parents=True, exist_ok=True)
    input_path = DATA_DIR / "current_analysis_input.csv"
    frame.to_csv(input_path, index=False)
    detection_engine.ANOMALY_THRESHOLD = float(k)
    detection_engine.BASELINE_WINDOW = int(baseline_window)
    detected = detection_engine.run_detection_engine(input_path, output_dir=LOGGED_DIR)
    normalized = canonicalize(detected["events"])
    normalized.to_csv(LOGGED_DIR / "normalized_events.csv", index=False)
    alerts = rules.run_rules()
    return normalized, detected["signals"], detected["anomaly_windows"], detected["suspicious_events"], alerts


def read_csv(path):
    """Load an existing CSV artifact if present."""
    if not path.exists():
        return pd.DataFrame()
    try:
        return pd.read_csv(path, low_memory=False)
    except (pd.errors.EmptyDataError, OSError):
        return pd.DataFrame()


def timeline(signals, windows, name):
    """Plot the selected event-count signal and anomaly peaks."""
    if signals.empty or "time" not in signals or name not in signals:
        st.info("No timeline is available. Run an analysis first.")
        return
    data = signals.copy()
    data["time"] = pd.to_datetime(data["time"], utc=True, errors="coerce")
    data = data.dropna(subset=["time"]).sort_values("time")
    fig = go.Figure(go.Scatter(x=data["time"], y=data[name], mode="lines", name=f"{name.title()} events"))
    if not windows.empty and {"peak_time", "signal"}.issubset(windows.columns):
        peaks = windows[windows["signal"].astype(str).eq(name)].copy()
        peaks["peak_time"] = pd.to_datetime(peaks["peak_time"], utc=True, errors="coerce")
        peaks = peaks.dropna(subset=["peak_time"])
        if not peaks.empty:
            indexed = data.set_index("time")[name]
            xs, ys = [], []
            for stamp in peaks["peak_time"]:
                idx = (data["time"] - stamp).abs().idxmin()
                xs.append(stamp)
                ys.append(data.loc[idx, name])
            fig.add_trace(go.Scatter(x=xs, y=ys, mode="markers", name="Anomaly peaks", marker={"symbol": "x", "size": 9}))
    fig.update_layout(height=350, margin={"l": 5, "r": 5, "t": 20, "b": 5}, xaxis_title="Time (UTC)", yaxis_title="Events per 5 minutes")
    st.plotly_chart(fig, use_container_width=True)


def main():
    """Render the CloudPulse dashboard and analysis controls."""
    st.set_page_config(page_title="CloudPulse Security Dashboard", layout="wide")
    st.title("CloudPulse")
    st.caption("CloudTrail log analysis · Statistical anomaly detection · Explainable security rules")
    with st.sidebar:
        st.header("Analysis settings")
        k = st.slider("Anomaly threshold (K)", 3.0, 8.0, 4.0, 0.5)
        baseline_window = st.slider("Baseline window (5-minute bins)", 24, 96, 48, 8)
        upload = st.file_uploader("Upload CloudTrail JSON, JSON.GZ, or CSV", type=["json", "gz", "csv"])
        use_default = st.checkbox("Use included dataset if no upload", value=True)
        run = st.button("Run analysis", type="primary", use_container_width=True)
        st.caption("Local processing only. No AWS credentials or external API calls.")

    if run:
        try:
            with st.spinner("Running CloudPulse analysis..."):
                if upload is not None:
                    source_frame, source_label = read_upload(upload), upload.name
                elif use_default and DEFAULT_CSV.exists():
                    source_frame, source_label = pd.read_csv(DEFAULT_CSV, low_memory=False), "data/cloudpulse.csv"
                else:
                    st.error("Upload a file or enable the included dataset.")
                    return
                events, signals, windows, suspicious, alerts = run_pipeline(source_frame, k, baseline_window)
                st.session_state["cp_results"] = {"events": events, "signals": signals, "windows": windows, "suspicious": suspicious, "alerts": alerts, "k": k, "baseline_window": baseline_window, "source": source_label}
            st.success(f"Analysis completed: {source_label}")
        except Exception as exc:
            st.error(f"Analysis failed: {exc}")
            st.exception(exc)

    if "cp_results" in st.session_state:
        r = st.session_state["cp_results"]
        events, signals, windows, suspicious, alerts = r["events"], r["signals"], r["windows"], r["suspicious"], r["alerts"]
        k, baseline_window, source = r["k"], r["baseline_window"], r["source"]
    else:
        events = read_csv(LOGGED_DIR / "normalized_events.csv")
        signals = read_csv(LOGGED_DIR / "time_signals.csv")
        windows = read_csv(LOGGED_DIR / "anomaly_windows.csv")
        suspicious = read_csv(LOGGED_DIR / "suspicious_events.csv")
        alerts = read_csv(OUTPUT_DIR / "alerts.csv")
        k, baseline_window, source = 4.0, 48, "Existing project outputs"
    if events.empty and alerts.empty:
        st.info("Upload CloudTrail logs and click Run analysis, or use the included dataset.")
        st.stop()

    st.caption(f"Dataset: {source}")
    sev = alerts.get("severity", pd.Series(dtype=str)).astype(str)
    status = alerts.get("status", pd.Series(dtype=str)).astype(str)
    cols = st.columns(4)
    cols[0].metric("Events analysed", f"{len(events):,}")
    cols[1].metric("Anomaly windows", f"{len(windows):,}")
    cols[2].metric("Security alerts", f"{len(alerts):,}")
    cols[3].metric("Critical alerts", f"{int(sev.eq('Critical').sum()):,}")

    st.subheader("Activity timeline")
    sig = st.radio("Signal", ["total", "failed"], horizontal=True, format_func=lambda x: "All events" if x == "total" else "Failed events")
    timeline(signals, windows, sig)

    st.subheader("Security alerts")
    if alerts.empty:
        st.success("No security alerts were generated for this dataset.")
    else:
        a, b, c = st.columns(3)
        severities = sorted(sev.unique())
        statuses = sorted(status.unique())
        with a:
            chosen_sev = st.multiselect("Severity", severities, default=severities)
        with b:
            chosen_status = st.multiselect("Status", statuses, default=statuses)
        with c:
            rule_query = st.text_input("Search rule ID/name")
        filtered = alerts[sev.isin(chosen_sev) & status.isin(chosen_status)].copy()
        if rule_query.strip():
            q = rule_query.strip().lower()
            filtered = filtered[filtered.get("rule_id", pd.Series("", index=filtered.index)).fillna("").astype(str).str.lower().str.contains(q) | filtered.get("rule_name", pd.Series("", index=filtered.index)).fillna("").astype(str).str.lower().str.contains(q)]
        columns = [c for c in ["alert_id", "time", "status", "severity", "rule_id", "rule_name", "user", "sourceIP", "eventName", "evidence_count"] if c in filtered.columns]
        st.dataframe(filtered[columns], use_container_width=True, hide_index=True)
        if not filtered.empty:
            chosen = st.selectbox("Inspect alert", filtered["alert_id"].astype(str).tolist())
            alert = filtered[filtered["alert_id"].astype(str).eq(chosen)].iloc[0]
            with st.expander("Alert details", expanded=True):
                st.write(f"**Rule:** {alert.get('rule_id', '')} — {alert.get('rule_name', '')}")
                st.write(f"**Reason:** {alert.get('description', '')}")
                st.write(f"**MITRE ATT&CK:** {alert.get('mitre', '') or 'Not mapped'}")
                st.write(f"**Evidence count:** {alert.get('evidence_count', 1)}")
                st.caption("Confirmed means rule evidence overlapped statistical evidence; it is not proof of an attack." if alert.get("status") == "Confirmed" else "Rule-only means a security rule matched without overlapping statistical evidence." if alert.get("status") == "Rule-only" else "This statistical anomaly needs analyst review.")
        st.download_button("Download filtered alerts (CSV)", filtered.to_csv(index=False).encode("utf-8-sig"), "cloudpulse_alerts.csv", "text/csv")

    st.subheader("Detection effectiveness")
    effectiveness = pd.DataFrame([
        {"Measure": "Statistical anomaly windows", "Count": len(windows)},
        {"Measure": "Rule + statistical evidence", "Count": int(status.eq("Confirmed").sum())},
        {"Measure": "Rule-only alerts", "Count": int(status.eq("Rule-only").sum())},
        {"Measure": "Anomalies needing review", "Count": int(status.eq("Needs review").sum())},
    ])
    st.dataframe(effectiveness, use_container_width=True, hide_index=True)
    with st.expander("Suspicious event log"):
        if suspicious.empty:
            st.info("No suspicious event rows were logged.")
        else:
            st.dataframe(suspicious.head(500), use_container_width=True, hide_index=True)
            st.caption(f"Showing up to 500 of {len(suspicious):,} rows.")

    report_html = generate_report(alerts, windows, events, {"K": k, "window": baseline_window, "source": source}, rules.load_rules())
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUTPUT_DIR / "report.html").write_text(report_html, encoding="utf-8")
    st.subheader("Investigation report")
    st.download_button("Generate and download HTML report", report_html.encode("utf-8"), "cloudpulse_report.html", "text/html")
    st.caption(f"Report saved locally to {OUTPUT_DIR / 'report.html'}.")


if __name__ == "__main__":
    main()
