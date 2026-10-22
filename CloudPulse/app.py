
"""CloudPulse Streamlit dashboard and upload-first analysis pipeline."""

from __future__ import annotations

import gzip
import io
import json
import tempfile
from pathlib import Path
from typing import Any

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

import detection_engine
import json_to_csv
import rules
from report import generate_report


BASE = Path(__file__).resolve().parent

SUPPORTED_EXTENSIONS = {".json", ".gz", ".csv"}


# ============================================================
# INPUT HANDLING
# ============================================================

def read_upload(upload) -> pd.DataFrame:
    """Read uploaded CloudTrail JSON, JSON.GZ, or CSV."""

    filename = Path(upload.name).name
    name = filename.lower()
    raw = upload.getvalue()

    if not raw:
        raise ValueError("The uploaded file is empty.")

    if name.endswith(".gz"):
        try:
            raw = gzip.decompress(raw)
        except (OSError, EOFError) as exc:
            raise ValueError(
                "The uploaded GZIP file is invalid or corrupted."
            ) from exc

    if name.endswith((".json", ".json.gz", ".gz")):
        try:
            data = json.loads(raw.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(
                "The uploaded file is not valid UTF-8 JSON."
            ) from exc

        if isinstance(data, dict):
            records = data.get("Records")

            # Also permit a single event object.
            if records is None and (
                "eventTime" in data or "eventName" in data
            ):
                records = [data]
        elif isinstance(data, list):
            records = data
        else:
            records = None

        if not isinstance(records, list):
            raise ValueError(
                "CloudTrail JSON must contain a Records list "
                "or be a list of event objects."
            )

        rows = [
            json_to_csv.flatten_event(event, filename)
            for event in records
            if isinstance(event, dict)
        ]

        if not rows:
            raise ValueError(
                "No event records were found in the JSON file."
            )

        return pd.DataFrame(rows)

    if name.endswith(".csv"):
        try:
            frame = pd.read_csv(
                io.BytesIO(raw),
                low_memory=False,
            )
        except (pd.errors.ParserError, UnicodeDecodeError) as exc:
            raise ValueError(
                "The uploaded CSV could not be parsed."
            ) from exc

        if frame.empty:
            raise ValueError(
                "The uploaded CSV contains no rows."
            )

        if not frame.columns.is_unique:
            raise ValueError(
                "The CSV contains duplicate column names."
            )

        return frame

    raise ValueError(
        "Unsupported file type. Upload .json, .json.gz, .gz, or .csv."
    )


# ============================================================
# CANONICAL EVENT SCHEMA
# ============================================================

def canonicalize(events: pd.DataFrame) -> pd.DataFrame:
    """
    Normalize event columns for detection and security rules.

    Preserve original columns while adding canonical names.
    Invalid timestamps are excluded from analysis.
    """

    if not isinstance(events, pd.DataFrame) or events.empty:
        raise ValueError("No event data was supplied.")

    frame = events.copy()

    if not frame.columns.is_unique:
        raise ValueError(
            "The dataset contains duplicate column names."
        )

    aliases = {
        "time": [
            "eventTime",
            "event_time",
            "timestamp",
        ],
        "eventID": [
            "eventId",
            "event_id",
        ],
        "eventName": [
            "event_name",
        ],
        "eventSource": [
            "event_source",
        ],
        "userType": [
            "userIdentityType",
            "user_identity_type",
        ],
        "sourceIP": [
            "sourceIPAddress",
            "sourceIp",
            "source_ip",
        ],
        "mfaUsed": [
            "MFAUsed",
            "mfa_used",
        ],
        "errorCode": [
            "error_code",
        ],
        "errorMessage": [
            "error_message",
        ],
        "requestParameters": [
            "request_parameters",
        ],
        "responseElements": [
            "response_elements",
        ],
    }

    lower_columns = {
        str(column).strip().lower(): column
        for column in frame.columns
    }

    for target, candidates in aliases.items():
        if target in frame.columns:
            continue

        for candidate in candidates:
            original = lower_columns.get(candidate.lower())

            if original is not None:
                frame[target] = frame[original]
                break

    for column in [
        "time",
        "eventID",
        "eventName",
        "eventSource",
        "userType",
        "sourceIP",
        "mfaUsed",
        "errorCode",
        "errorMessage",
        "requestParameters",
        "responseElements",
    ]:
        if column not in frame.columns:
            frame[column] = ""

    # Construct a usable identity when one was not already supplied.
    if "user" not in frame.columns:
        arn = frame.get(
            "userIdentityArn",
            pd.Series("", index=frame.index),
        ).fillna("").astype(str)

        username = frame.get(
            "userName",
            pd.Series("", index=frame.index),
        ).fillna("").astype(str)

        frame["user"] = arn.where(
            arn.str.strip().ne(""),
            username,
        )

    root_mask = (
        frame["userType"]
        .fillna("")
        .astype(str)
        .str.lower()
        .eq("root")
    )

    frame.loc[root_mask, "user"] = "Root"

    frame["time"] = pd.to_datetime(
        frame["time"],
        utc=True,
        errors="coerce",
    )

    invalid_timestamps = int(frame["time"].isna().sum())

    frame = frame.dropna(subset=["time"]).copy()

    if frame.empty:
        raise ValueError(
            "No rows have valid event timestamps."
        )

    # Normalize missing strings without changing actual values.
    for column in [
        "eventID",
        "eventName",
        "eventSource",
        "user",
        "userType",
        "sourceIP",
        "mfaUsed",
        "errorCode",
        "errorMessage",
    ]:
        frame[column] = frame[column].fillna("").astype(str).str.strip()

    old_failure = (
        frame.get(
            "is_failure",
            pd.Series(False, index=frame.index),
        )
        .map(rules.truthy)
    )

    error_failure = (
        frame["errorCode"].map(bool)
        | frame["errorMessage"].map(bool)
    )

    response_failure = (
        frame["responseElements"]
        .fillna("")
        .astype(str)
        .str.lower()
        .str.contains("failure", regex=False)
    )

    # A ConsoleLogin response may encode failure as a JSON field.
    # This simple text check is a fallback, not authoritative parsing.
    login_failure = (
        frame["eventName"].eq("ConsoleLogin")
        & response_failure
    )

    frame["is_failure"] = (
        old_failure | error_failure | login_failure
    ).astype(bool)

    frame.attrs["data_quality"] = {
        "input_rows": int(len(events)),
        "valid_timestamp_rows": int(len(frame)),
        "invalid_timestamps": invalid_timestamps,
        "duplicate_event_id_rows": int(
            frame.loc[
                frame["eventID"].ne(""),
                "eventID",
            ].duplicated(keep=False).sum()
        ),
    }

    return (
        frame.sort_values("time", kind="stable")
        .reset_index(drop=True)
    )


# ============================================================
# CURRENT-RUN ANALYSIS PIPELINE
# ============================================================

def run_pipeline(
    source_frame: pd.DataFrame,
    k: float,
    baseline_window: int,
    source_label: str = "Uploaded dataset",
) -> dict[str, Any]:
    """
    Run detection and rules for one dataset.

    Intermediate files are isolated in a temporary directory.
    No existing logged/ or outputs/ CSVs are used as inputs.
    """

    if source_frame is None or source_frame.empty:
        raise ValueError("The input dataset contains no events.")

    if not 3.0 <= float(k) <= 8.0:
        raise ValueError(
            "The anomaly threshold must be between 3 and 8."
        )

    if int(baseline_window) < 2:
        raise ValueError(
            "The baseline window must be at least 2 bins."
        )

    # Normalize the uploaded input before passing it to the detector.
    normalized_input = canonicalize(source_frame)

    data_quality = dict(
        normalized_input.attrs.get("data_quality", {})
    )

    selected_rules = rules.load_rules()

    # Isolate temporary artifacts from the repository and other runs.
    with tempfile.TemporaryDirectory(
        prefix="cloudpulse_"
    ) as temporary_directory:
        temp_root = Path(temporary_directory)
        input_path = temp_root / "input.csv"
        detection_output = temp_root / "detection"

        normalized_input.to_csv(
            input_path,
            index=False,
        )

        detected = detection_engine.run_detection_engine(
            input_path,
            output_dir=detection_output,
            baseline_window=int(baseline_window),
            anomaly_threshold=float(k),
        )

        # The detector returns its own normalized event representation.
        events = canonicalize(detected["events"])

        # Reuse the in-memory rule interface rather than reading
        # previous normalized_events.csv or alerts.csv files.
        signals = detected["signals"].copy()
        windows = detected["anomaly_windows"].copy()
        suspicious = detected["suspicious_events"].copy()

        alerts = rules.build_alerts(
            all_events=events,
            suspicious=suspicious,
            windows=windows,
            rules=selected_rules,
        )

        detector_metadata = dict(
            detected.get("metadata", {})
        )

    data_quality["detector"] = detector_metadata.get(
        "data_quality", {}
    )

    return {
        "events": events,
        "signals": signals,
        "windows": windows,
        "suspicious": suspicious,
        "alerts": alerts,
        "rules": selected_rules,
        "source": source_label,
        "k": float(k),
        "baseline_window": int(baseline_window),
        "data_quality": data_quality,
        "detector_metadata": detector_metadata,
    }


# ============================================================
# TIMELINE
# ============================================================

def timeline(
    signals: pd.DataFrame,
    windows: pd.DataFrame,
    signal_name: str,
) -> None:
    """Plot event-count signals and anomaly peaks."""

    if (
        signals.empty
        or "time" not in signals.columns
        or signal_name not in signals.columns
    ):
        st.info("No timeline is available for this analysis.")
        return

    data = signals.copy()

    data["time"] = pd.to_datetime(
        data["time"],
        utc=True,
        errors="coerce",
    )

    data = (
        data.dropna(subset=["time"])
        .sort_values("time")
        .reset_index(drop=True)
    )

    if data.empty:
        st.info("No valid time-series data is available.")
        return

    fig = go.Figure()

    fig.add_trace(
        go.Scatter(
            x=data["time"],
            y=data[signal_name],
            mode="lines",
            name=(
                "All events"
                if signal_name == "total"
                else "Failed events"
            ),
        )
    )

    if (
        not windows.empty
        and {"peak_time", "signal"}.issubset(windows.columns)
    ):
        peaks = windows[
            windows["signal"].astype(str).eq(signal_name)
        ].copy()

        peaks["peak_time"] = pd.to_datetime(
            peaks["peak_time"],
            utc=True,
            errors="coerce",
        )

        peaks = peaks.dropna(subset=["peak_time"])

        if not peaks.empty:
            signal_times = data["time"].astype("int64").to_numpy()
            peak_times = peaks["peak_time"].astype("int64").to_numpy()

            # Locate the nearest plotted bucket for each peak.
            import numpy as np

            positions = np.abs(
                signal_times[:, None] - peak_times[None, :]
            ).argmin(axis=0)

            fig.add_trace(
                go.Scatter(
                    x=peaks["peak_time"],
                    y=data.iloc[positions][signal_name].to_numpy(),
                    mode="markers",
                    name="Anomaly peaks",
                    marker={
                        "symbol": "x",
                        "size": 9,
                    },
                    customdata=peaks[
                        ["window_id", "z_peak"]
                    ].to_numpy()
                    if {"window_id", "z_peak"}.issubset(
                        peaks.columns
                    )
                    else None,
                    hovertemplate=(
                        "Time: %{x}<br>"
                        "Count: %{y}<extra>Anomaly peak</extra>"
                    ),
                )
            )

    fig.update_layout(
        height=360,
        margin={"l": 5, "r": 5, "t": 25, "b": 5},
        xaxis_title="Time (UTC)",
        yaxis_title="Events per time bucket",
        legend={"orientation": "h"},
    )

    st.plotly_chart(
        fig,
        use_container_width=True,
    )


# ============================================================
# DASHBOARD
# ============================================================

def main() -> None:
    """Render the CloudPulse dashboard."""

    st.set_page_config(
        page_title="CloudPulse Security Dashboard",
        page_icon="CP",
        layout="wide",
    )

    st.title("CloudPulse")
    st.caption(
        "CloudTrail analysis · Statistical anomaly detection · "
        "Explainable security rules"
    )

    # --------------------------------------------------------
    # Sidebar controls
    # --------------------------------------------------------

    with st.sidebar:
        st.header("Analysis settings")

        k = st.slider(
            "Anomaly threshold (K)",
            min_value=3.0,
            max_value=8.0,
            value=4.0,
            step=0.5,
        )

        baseline_window = st.slider(
            "Baseline window (5-minute bins)",
            min_value=24,
            max_value=96,
            value=48,
            step=8,
        )

        upload = st.file_uploader(
            "Upload CloudTrail JSON, JSON.GZ, or CSV",
            type=["json", "gz", "csv"],
            help=(
                "Select the dataset to analyse. Existing saved results "
                "are not loaded automatically."
            ),
        )

        run = st.button(
            "Run analysis",
            type="primary",
            use_container_width=True,
        )

        reset = st.button(
            "Reset analysis",
            use_container_width=True,
        )

        st.caption(
            "Processing runs locally. This dashboard does not connect "
            "to AWS or call external APIs."
        )

    if reset:
        st.session_state.pop("cp_results", None)
        st.rerun()

    # --------------------------------------------------------
    # Run only when explicitly requested
    # --------------------------------------------------------

    if run:
        if upload is None:
            st.error(
                "Upload a dataset before running the analysis."
            )
        else:
            try:
                with st.spinner(
                    "Validating data and running CloudPulse..."
                ):
                    source_frame = read_upload(upload)

                    result = run_pipeline(
                        source_frame=source_frame,
                        k=k,
                        baseline_window=baseline_window,
                        source_label=Path(upload.name).name,
                    )

                # Replace the active session results only after the
                # entire pipeline has succeeded.
                st.session_state["cp_results"] = result

                st.success(
                    f"Analysis completed for {result['source']}."
                )

            except Exception as exc:
                st.error(
                    f"Analysis failed: {exc}"
                )

                with st.expander("Technical details"):
                    st.exception(exc)

    # --------------------------------------------------------
    # No active analysis: show a clean welcome screen
    # --------------------------------------------------------

    result = st.session_state.get("cp_results")

    if not result:
        st.info(
            "Welcome to CloudPulse. Upload a CloudTrail dataset "
            "in the sidebar, choose your detection settings, and "
            "click Run analysis to begin."
        )

        st.markdown(
            """
            **Supported inputs**
            - CloudTrail JSON containing a `Records` list
            - JSON event lists
            - GZIP-compressed JSON
            - CSV containing timestamps and event names

            **Workflow**

            1. Select a dataset.
            2. Configure the detection threshold and baseline.
            3. Run the analysis.
            4. Inspect alerts and download the investigation report.
            """
        )

        # Critical: never read existing logged/ or outputs/ files
        # merely because this session has no analysis.
        st.stop()

    # --------------------------------------------------------
    # Current analysis results
    # --------------------------------------------------------

    events = result["events"]
    signals = result["signals"]
    windows = result["windows"]
    suspicious = result["suspicious"]
    alerts = result["alerts"]

    source = result["source"]
    k = result["k"]
    baseline_window = result["baseline_window"]

    st.caption(
        f"Dataset: {source} | "
        f"Threshold K={k:g} | "
        f"Baseline={baseline_window} bins"
    )

    severity = (
        alerts.get("severity", pd.Series(dtype=str))
        .fillna("")
        .astype(str)
    )

    status = (
        alerts.get("status", pd.Series(dtype=str))
        .fillna("")
        .astype(str)
    )

    # --------------------------------------------------------
    # Summary metrics
    # --------------------------------------------------------

    columns = st.columns(4)

    columns[0].metric(
        "Events analysed",
        f"{len(events):,}",
    )

    columns[1].metric(
        "Anomaly windows",
        f"{len(windows):,}",
    )

    columns[2].metric(
        "Security alerts",
        f"{len(alerts):,}",
    )

    columns[3].metric(
        "Critical alerts",
        f"{int(severity.eq('Critical').sum()):,}",
    )

    # --------------------------------------------------------
    # Timeline
    # --------------------------------------------------------

    st.subheader("Activity timeline")

    selected_signal = st.radio(
        "Signal",
        ["total", "failed"],
        horizontal=True,
        format_func=lambda value: (
            "All events"
            if value == "total"
            else "Failed events"
        ),
    )

    timeline(
        signals,
        windows,
        selected_signal,
    )

    # --------------------------------------------------------
    # Alert table and investigation
    # --------------------------------------------------------

    st.subheader("Security alerts")

    if alerts.empty:
        st.info(
            "No security alerts were generated for this dataset. "
            "This does not guarantee the absence of malicious activity."
        )

    else:
        a, b, c = st.columns([1, 1, 2])

        severities = sorted(
            severity.unique().tolist()
        )

        statuses = sorted(
            status.unique().tolist()
        )

        with a:
            chosen_severities = st.multiselect(
                "Severity",
                severities,
                default=severities,
            )

        with b:
            chosen_statuses = st.multiselect(
                "Status",
                statuses,
                default=statuses,
            )

        with c:
            rule_query = st.text_input(
                "Search rule, user, or description"
            )

        filtered = alerts[
            severity.isin(chosen_severities)
            & status.isin(chosen_statuses)
        ].copy()

        if rule_query.strip():
            query = rule_query.strip().lower()

            searchable = [
                column
                for column in [
                    "rule_id",
                    "rule_name",
                    "user",
                    "description",
                    "eventName",
                    "sourceIP",
                ]
                if column in filtered.columns
            ]

            mask = pd.Series(
                False,
                index=filtered.index,
            )

            for column in searchable:
                mask |= (
                    filtered[column]
                    .fillna("")
                    .astype(str)
                    .str.lower()
                    .str.contains(query, regex=False)
                )

            filtered = filtered[mask]

        display_columns = [
            column
            for column in [
                "alert_id",
                "time",
                "status",
                "severity",
                "rule_id",
                "rule_name",
                "user",
                "sourceIP",
                "eventName",
                "evidence_count",
            ]
            if column in filtered.columns
        ]

        st.dataframe(
            filtered[display_columns],
            use_container_width=True,
            hide_index=True,
        )

        if not filtered.empty and "alert_id" in filtered.columns:
            selected_alert_id = st.selectbox(
                "Inspect alert",
                filtered["alert_id"].astype(str).tolist(),
            )

            selected = filtered[
                filtered["alert_id"].astype(str).eq(
                    selected_alert_id
                )
            ].iloc[0]

            with st.expander(
                "Alert details",
                expanded=True,
            ):
                st.write(
                    f"**Rule:** {selected.get('rule_id', '')} — "
                    f"{selected.get('rule_name', '')}"
                )

                st.write(
                    f"**Reason:** "
                    f"{selected.get('description', '')}"
                )

                st.write(
                    f"**MITRE ATT&CK:** "
                    f"{selected.get('mitre', '') or 'Not mapped'}"
                )

                st.write(
                    f"**Evidence count:** "
                    f"{selected.get('evidence_count', 1)}"
                )

                st.write(
                    f"**Anomaly window:** "
                    f"{selected.get('window_id', '') or 'Not linked'}"
                )

                selected_status = str(
                    selected.get("status", "")
                )

                if selected_status == "Confirmed":
                    st.caption(
                        "This status requires explicit confirmation "
                        "from an investigation or trusted confirmation source."
                    )
                elif selected_status == "Rule match":
                    st.caption(
                        "A security rule matched. This is not proof "
                        "of a confirmed incident."
                    )
                else:
                    st.caption(
                        "Review the underlying events and contextual evidence."
                    )

        st.download_button(
            "Download filtered alerts (CSV)",
            data=filtered.to_csv(index=False).encode("utf-8-sig"),
            file_name="cloudpulse_alerts.csv",
            mime="text/csv",
        )

    # --------------------------------------------------------
    # Detection effectiveness
    # --------------------------------------------------------

    st.subheader("Detection overview")

    effectiveness = pd.DataFrame([
        {
            "Measure": "Statistical anomaly windows",
            "Count": len(windows),
        },
        {
            "Measure": "Explicitly confirmed alerts",
            "Count": int(status.eq("Confirmed").sum()),
        },
        {
            "Measure": "Rule matches",
            "Count": int(status.eq("Rule match").sum()),
        },
        {
            "Measure": "Anomalies needing review",
            "Count": int(status.eq("Needs review").sum()),
        },
    ])

    st.dataframe(
        effectiveness,
        use_container_width=True,
        hide_index=True,
    )

    # --------------------------------------------------------
    # Suspicious event evidence
    # --------------------------------------------------------

    with st.expander("Suspicious event log"):
        if suspicious.empty:
            st.info(
                "No events were associated with detected anomaly windows."
            )
        else:
            st.dataframe(
                suspicious.head(500),
                use_container_width=True,
                hide_index=True,
            )

            st.caption(
                f"Showing up to 500 of {len(suspicious):,} rows."
            )

            st.download_button(
                "Download suspicious events (CSV)",
                data=suspicious.to_csv(
                    index=False
                ).encode("utf-8-sig"),
                file_name="cloudpulse_suspicious_events.csv",
                mime="text/csv",
            )

    # --------------------------------------------------------
    # HTML investigation report
    # --------------------------------------------------------

    st.subheader("Investigation report")

    report_params = {
        "K": k,
        "threshold": k,
        "window": baseline_window,
        "baseline_window": baseline_window,
        "frequency": detection_engine.FREQ,
        "source": source,
        "data_quality": result.get("data_quality", {}),
    }

    report_html = generate_report(
        alerts=alerts,
        windows=windows,
        events=events,
        params=report_params,
        rules=result["rules"],
    )

    st.download_button(
        "Download HTML investigation report",
        data=report_html.encode("utf-8"),
        file_name="cloudpulse_report.html",
        mime="text/html",
    )

    st.caption(
        "The report is generated from the current analysis. "
        "It is not automatically saved over previous reports."
    )


if __name__ == "__main__":
    main()
