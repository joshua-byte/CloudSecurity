
from pathlib import Path

import numpy as np
import pandas as pd


# ==================================================
# NETWATCH DETECTION CONFIGURATION
# ==================================================

FREQ = "5min"
BASELINE_WINDOW = 48
ANOMALY_THRESHOLD = 4.0
GAP_THRESHOLD_HOURS = 24

OUTPUT_DIR = Path("logged")


# ==================================================
# COLUMN HELPERS
# ==================================================

def find_column(df, candidates):
    """Find a column without depending on capitalization."""
    columns = {str(col).lower(): col for col in df.columns}

    for candidate in candidates:
        if candidate.lower() in columns:
            return columns[candidate.lower()]

    return None


def parse_boolean(value):
    """Interpret common CSV representations of true."""
    return str(value).strip().lower() in {
        "true", "1", "yes", "y"
    }


# ==================================================
# 1. LOAD AND NORMALIZE EVENTS
# ==================================================

def load_events(csv_path):
    """Load CSV events and normalize fields used by detection."""

    csv_path = Path(csv_path)

    if not csv_path.exists():
        raise FileNotFoundError(
            f"Input CSV not found: {csv_path}"
        )

    df = pd.read_csv(
        csv_path,
        dtype=str,
        keep_default_na=False,
        low_memory=False,
    )

    if df.empty:
        raise ValueError("The input CSV contains no events.")

    time_col = find_column(
        df, ["time", "eventTime", "event_time", "timestamp"]
    )
    event_col = find_column(
        df, ["eventName", "event_name"]
    )

    if time_col is None:
        raise ValueError(
            "No event timestamp column found."
        )

    if event_col is None:
        raise ValueError(
            "No eventName column found."
        )

    df["time"] = pd.to_datetime(
        df[time_col],
        utc=True,
        errors="coerce",
    )

    invalid_timestamps = int(df["time"].isna().sum())

    # Invalid timestamps cannot be placed into time buckets.
    df = df.loc[df["time"].notna()].copy()

    if df.empty:
        raise ValueError(
            "No events have valid timestamps."
        )

    df["eventName"] = df[event_col].astype(str).str.strip()

    # Preserve event IDs when available.
    event_id_col = find_column(
        df, ["eventID", "eventId", "event_id"]
    )

    if event_id_col is not None:
        df["eventID"] = df[event_id_col].astype(str)
    else:
        df["eventID"] = ""

    # Use an existing failure flag where available.
    failure_col = find_column(
        df, ["is_failure", "isFailure", "failed"]
    )
    error_col = find_column(
        df, ["errorCode", "error_code"]
    )
    message_col = find_column(
        df, ["errorMessage", "error_message"]
    )

    if failure_col is not None:
        failures = df[failure_col].map(parse_boolean)
    else:
        failures = pd.Series(False, index=df.index)

    if error_col is not None:
        failures = failures | df[error_col].astype(str).str.strip().ne("")

    if message_col is not None:
        failures = failures | df[message_col].astype(str).str.strip().ne("")

    df["is_failure"] = failures.astype(bool)

    # Sort chronologically and assign a unique internal row ID.
    df = df.sort_values("time").reset_index(drop=True)
    df["event_row"] = np.arange(len(df), dtype=int)

    # Split activity into separate segments across long gaps.
    time_difference = df["time"].diff()

    df["segment_id"] = (
        time_difference.gt(
            pd.Timedelta(hours=GAP_THRESHOLD_HOURS)
        )
        .cumsum()
        .astype(int)
    )

    return df, invalid_timestamps


# ==================================================
# 2. BUILD FIVE-MINUTE SIGNALS
# ==================================================

def build_signals(events):
    """
    Build event-count and failure-count signals.

    Each segment is processed separately so a long gap
    does not create thousands of artificial zero buckets.
    """

    segments = []

    for segment_id, group in events.groupby("segment_id"):
        indexed = group.set_index("time").sort_index()

        signals = pd.DataFrame({
            "total": indexed["eventName"].resample(FREQ).count(),
            "failed": indexed["is_failure"].resample(FREQ).sum(),
        })

        full_index = pd.date_range(
            start=indexed.index.min().floor(FREQ),
            end=indexed.index.max().floor(FREQ),
            freq=FREQ,
            tz="UTC",
        )

        signals = signals.reindex(
            full_index,
            fill_value=0,
        )

        signals.index.name = "time"
        signals["segment_id"] = int(segment_id)

        segments.append(signals)

    if not segments:
        raise ValueError("No time signals could be generated.")

    return pd.concat(segments).sort_index()


# ==================================================
# 3. DETECT ANOMALOUS WINDOWS
# ==================================================

def detect_segment_anomalies(
    signals,
    signal_name,
    segment_id,
):
    """Apply the rolling median/MAD threshold to one signal."""

    values = signals[signal_name].astype(float)

    # Shift ensures the current bucket is not part of its baseline.
    history = values.shift(1)

    rolling_median = history.rolling(
        window=BASELINE_WINDOW,
        min_periods=BASELINE_WINDOW,
    ).median()

    def median_absolute_deviation(window_values):
        median = np.median(window_values)
        return np.median(np.abs(window_values - median))

    rolling_mad = history.rolling(
        window=BASELINE_WINDOW,
        min_periods=BASELINE_WINDOW,
    ).apply(
        median_absolute_deviation,
        raw=True,
    )

    # Robust standard-deviation estimate.
    scale = (1.4826 * rolling_mad).clip(lower=1.0)

    z_score = (values - rolling_median) / scale

    # Only buckets with a complete historical baseline are tested.
    anomaly_mask = (
        rolling_median.notna()
        & z_score.abs().gt(ANOMALY_THRESHOLD)
    )

    anomaly_times = values.index[anomaly_mask]

    columns = [
        "window_id",
        "segment_id",
        "signal",
        "start",
        "end",
        "peak_time",
        "peak_count",
        "z_peak",
        "mass",
        "flagged_bins",
    ]

    if len(anomaly_times) == 0:
        return pd.DataFrame(columns=columns)

    # Merge consecutive anomalous five-minute buckets.
    time_series = pd.Series(
        anomaly_times,
        index=anomaly_times,
    )

    new_group = (
        time_series.index.to_series()
        .diff()
        .ne(pd.Timedelta(FREQ))
        .cumsum()
    )

    records = []

    for _, group in time_series.groupby(new_group):
        bucket_times = group.to_list()

        local_scores = z_score.loc[bucket_times]
        peak_time = local_scores.abs().idxmax()

        records.append({
            "window_id": "",
            "segment_id": int(segment_id),
            "signal": signal_name,
            "start": bucket_times[0],
            "end": bucket_times[-1],
            "peak_time": peak_time,
            "peak_count": int(values.loc[peak_time]),
            "z_peak": round(float(z_score.loc[peak_time]), 3),
            "mass": int(values.loc[bucket_times].sum()),
            "flagged_bins": len(bucket_times),
        })

    return pd.DataFrame(records, columns=columns)


def detect_anomalies(signals):
    """Detect anomalies in total and failed event counts."""

    detected = []

    for segment_id, group in signals.groupby("segment_id"):
        for signal_name in ("total", "failed"):
            result = detect_segment_anomalies(
                group,
                signal_name,
                segment_id,
            )

            if not result.empty:
                detected.append(result)

    columns = [
        "window_id",
        "segment_id",
        "signal",
        "start",
        "end",
        "peak_time",
        "peak_count",
        "z_peak",
        "mass",
        "flagged_bins",
    ]

    if not detected:
        return pd.DataFrame(columns=columns)

    windows = pd.concat(detected, ignore_index=True)

    windows = windows.sort_values(
        ["start", "signal"]
    ).reset_index(drop=True)

    windows["window_id"] = [
        f"ANOM-{number:04d}"
        for number in range(1, len(windows) + 1)
    ]

    return windows[columns]


# ==================================================
# 4. LOG SUSPICIOUS EVENTS
# ==================================================

def log_suspicious_events(events, windows):
    """
    Extract the original event rows that fall within
    statistically anomalous windows.

    Security-rule matching is handled separately by rules.py.
    """

    if windows.empty:
        logged = events.iloc[0:0].copy()
        logged["anomaly_window_ids"] = ""
        logged["anomaly_signals"] = ""
        logged["anomaly_peak_z"] = ""
        logged["detection_reason"] = ""
        return logged

    # Map each event row to the anomaly windows that flagged it.
    event_matches = {}

    for window in windows.itertuples(index=False):
        # The end of a bucket is exclusive.
        end_exclusive = (
            window.end + pd.Timedelta(FREQ)
        )

        mask = (
            events["time"].ge(window.start)
            & events["time"].lt(end_exclusive)
            & events["segment_id"].eq(window.segment_id)
        )

        for row_id in events.loc[mask, "event_row"]:
            event_matches.setdefault(int(row_id), []).append(
                window
            )

    if not event_matches:
        logged = events.iloc[0:0].copy()
        logged["anomaly_window_ids"] = ""
        logged["anomaly_signals"] = ""
        logged["anomaly_peak_z"] = ""
        logged["detection_reason"] = ""
        return logged

    suspicious_ids = set(event_matches)

    logged = events[
        events["event_row"].isin(suspicious_ids)
    ].copy()

    logged["anomaly_window_ids"] = logged["event_row"].map(
        lambda row_id: "; ".join(
            sorted({
                window.window_id
                for window in event_matches[int(row_id)]
            })
        )
    )

    logged["anomaly_signals"] = logged["event_row"].map(
        lambda row_id: "; ".join(
            sorted({
                window.signal
                for window in event_matches[int(row_id)]
            })
        )
    )

    logged["anomaly_peak_z"] = logged["event_row"].map(
        lambda row_id: max(
            (
                abs(float(window.z_peak))
                for window in event_matches[int(row_id)]
            ),
            default=0.0,
        )
    )

    logged["detection_reason"] = (
        "Event occurred inside a statistically anomalous window."
    )

    return logged.sort_values("time").reset_index(drop=True)


# ==================================================
# 5. RUN DETECTION ENGINE
# ==================================================

def run_detection_engine(
    csv_path,
    output_dir=OUTPUT_DIR,
):
    """Run detection and save files for downstream components."""

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    events, invalid_timestamps = load_events(csv_path)

    signals = build_signals(events)
    windows = detect_anomalies(signals)

    suspicious = log_suspicious_events(
        events,
        windows,
    )

    signals_output = signals.reset_index()

    signals_output.to_csv(
        output_dir / "time_signals.csv",
        index=False,
    )

    windows.to_csv(
        output_dir / "anomaly_windows.csv",
        index=False,
    )

    suspicious.to_csv(
        output_dir / "suspicious_events.csv",
        index=False,
    )

    print("\nCLOUDPULSE DETECTION ENGINE")
    print("=" * 36)
    print(f"Events loaded: {len(events):,}")
    print(f"Invalid timestamps excluded: {invalid_timestamps:,}")
    print(f"Anomaly windows: {len(windows):,}")
    print(f"Suspicious event rows logged: {len(suspicious):,}")
    print(f"Output directory: {output_dir.resolve()}")
    print(
        "\nDetection results indicate statistical anomalies, "
        "not confirmed attacks."
    )

    return {
        "events": events,
        "signals": signals_output,
        "anomaly_windows": windows,
        "suspicious_events": suspicious,
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="CloudPulse statistical detection engine"
    )

    parser.add_argument(
        "input_csv",
        help="Path to the CSV produced by the converter.",
    )

    parser.add_argument(
        "--output-dir",
        default=str(OUTPUT_DIR),
        help="Directory for detection output files.",
    )

    args = parser.parse_args()

    run_detection_engine(
        args.input_csv,
        args.output_dir,
    )
